use std::path::Path;

use anyhow::{Context, Result};
use colored::Colorize;

use crate::analyzer::{AnalysisResult, FunctionAnalysis};

// ---------------------------------------------------------------------------
// Diff types
// ---------------------------------------------------------------------------

/// Result of comparing a current analysis against a saved baseline.
#[derive(Debug)]
pub struct BaselineDiff {
    /// Change in total CU. Positive = regression, negative = improvement.
    pub total_cu_change: i64,
    /// Per-function CU changes for functions present in both current and baseline.
    pub function_changes: Vec<FunctionDiff>,
    /// Functions that exist in current but not in the baseline.
    pub new_functions: Vec<String>,
    /// Functions that existed in the baseline but are absent from current.
    pub removed_functions: Vec<String>,
}

/// CU change for a single function between baseline and current analysis.
#[derive(Debug)]
pub struct FunctionDiff {
    pub name: String,
    pub old_cu: u64,
    pub new_cu: u64,
    /// new_cu - old_cu as signed. Positive = regression.
    pub cu_change: i64,
    /// Percentage change relative to old_cu.
    pub change_pct: f64,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Serialize an `AnalysisResult` to JSON and write it to `path`.
pub fn save_baseline(result: &AnalysisResult, path: &Path) -> Result<()> {
    let json = serde_json::to_string_pretty(result)
        .context("Failed to serialize analysis result to JSON")?;
    std::fs::write(path, json)
        .with_context(|| format!("Failed to write baseline to {}", path.display()))?;
    Ok(())
}

/// Read and deserialize an `AnalysisResult` from a JSON baseline file at `path`.
pub fn load_baseline(path: &Path) -> Result<AnalysisResult> {
    let json = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read baseline from {}", path.display()))?;
    let result: AnalysisResult = serde_json::from_str(&json)
        .with_context(|| format!("Failed to parse baseline JSON from {}", path.display()))?;
    Ok(result)
}

/// Compare a current `AnalysisResult` against a previous baseline.
///
/// Functions are matched by name. The returned diff contains:
/// - `function_changes`: functions present in both, sorted by absolute CU change descending
/// - `new_functions`: functions only in `current`
/// - `removed_functions`: functions only in `baseline`
pub fn diff_results(current: &AnalysisResult, baseline: &AnalysisResult) -> BaselineDiff {
    if current.cost_model_version != baseline.cost_model_version {
        eprintln!(
            "Warning: cost model version mismatch: current={}, baseline={}",
            current.cost_model_version, baseline.cost_model_version
        );
    }

    // Use i128 intermediate to avoid wrapping when u64 values exceed i64::MAX.
    let total_cu_change = (current.total_estimated_cu as i128 - baseline.total_estimated_cu as i128)
        .clamp(i64::MIN as i128, i64::MAX as i128) as i64;

    // Build lookup maps by function name.
    let current_by_name: std::collections::HashMap<&str, &FunctionAnalysis> = current
        .functions
        .iter()
        .map(|f| (f.name.as_str(), f))
        .collect();

    let baseline_by_name: std::collections::HashMap<&str, &FunctionAnalysis> = baseline
        .functions
        .iter()
        .map(|f| (f.name.as_str(), f))
        .collect();

    let mut function_changes = Vec::new();
    let mut new_functions = Vec::new();

    // Walk current functions.
    for func in &current.functions {
        match baseline_by_name.get(func.name.as_str()) {
            Some(old_func) => {
                let cu_change = (func.estimated_cu as i128 - old_func.estimated_cu as i128)
                    .clamp(i64::MIN as i128, i64::MAX as i128)
                    as i64;
                let change_pct = if old_func.estimated_cu == 0 {
                    if func.estimated_cu == 0 {
                        0.0
                    } else {
                        f64::INFINITY
                    }
                } else {
                    (cu_change as f64 / old_func.estimated_cu as f64) * 100.0
                };
                function_changes.push(FunctionDiff {
                    name: func.name.clone(),
                    old_cu: old_func.estimated_cu,
                    new_cu: func.estimated_cu,
                    cu_change,
                    change_pct,
                });
            }
            None => {
                new_functions.push(func.name.clone());
            }
        }
    }

    // Find removed functions (in baseline but not in current).
    let removed_functions: Vec<String> = baseline
        .functions
        .iter()
        .filter(|f| !current_by_name.contains_key(f.name.as_str()))
        .map(|f| f.name.clone())
        .collect();

    // Sort function_changes by absolute cu_change descending (biggest impact first).
    function_changes.sort_by(|a, b| b.cu_change.unsigned_abs().cmp(&a.cu_change.unsigned_abs()));

    BaselineDiff {
        total_cu_change,
        function_changes,
        new_functions,
        removed_functions,
    }
}

/// Print a colored terminal report for a baseline diff.
pub fn print_diff(diff: &BaselineDiff) {
    let separator = "═".repeat(57);
    println!("{}", separator.bold());
    println!("{}", "  BASELINE COMPARISON".bold());
    println!("{}", separator.bold());
    println!();

    // Total CU change line.
    let sign = if diff.total_cu_change > 0 { "+" } else { "" };
    let total_str = format!(
        "Total CU: {}{} CU",
        sign,
        crate::format_number(diff.total_cu_change.unsigned_abs())
    );

    if diff.total_cu_change > 0 {
        println!("  {}", total_str.red().bold());
    } else if diff.total_cu_change < 0 {
        println!("  {}", total_str.green().bold());
    } else {
        println!("  {}", "Total CU: no change".dimmed());
    }
    println!();

    // Function changes.
    if !diff.function_changes.is_empty() {
        println!("{}", "Function Changes (sorted by impact):".bold());

        // Determine the longest function name for alignment.
        let max_name_len = diff
            .function_changes
            .iter()
            .map(|f| f.name.len())
            .max()
            .unwrap_or(0);

        for fc in &diff.function_changes {
            let padded_name = format!("{:width$}", fc.name, width = max_name_len);
            let old_str = crate::format_number(fc.old_cu);
            let new_str = crate::format_number(fc.new_cu);

            if fc.cu_change > 0 {
                let line = format!(
                    "  ▲ {}: {} → {} (+{} CU, +{:.1}%)",
                    padded_name,
                    old_str,
                    new_str,
                    crate::format_number(fc.cu_change.unsigned_abs()),
                    fc.change_pct
                );
                println!("{}", line.red());
            } else if fc.cu_change < 0 {
                let line = format!(
                    "  ▼ {}: {} → {} (-{} CU, {:.1}%)",
                    padded_name,
                    old_str,
                    new_str,
                    crate::format_number(fc.cu_change.unsigned_abs()),
                    fc.change_pct
                );
                println!("{}", line.green());
            } else {
                let line = format!("  = {padded_name}: {old_str} → {new_str} (no change)");
                println!("{}", line.dimmed());
            }
        }
        println!();
    }

    // New functions.
    if !diff.new_functions.is_empty() {
        println!(
            "{} {}",
            "New functions:".bold(),
            diff.new_functions.join(", ")
        );
    }

    // Removed functions.
    if !diff.removed_functions.is_empty() {
        println!(
            "{} {}",
            "Removed functions:".bold(),
            diff.removed_functions.join(", ")
        );
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::{LoopInfo, SyscallInfo};
    use tempfile::tempdir;

    fn make_result(functions: Vec<(&str, u64)>, name: &str) -> AnalysisResult {
        let funcs: Vec<FunctionAnalysis> = functions
            .into_iter()
            .map(|(fname, cu)| FunctionAnalysis {
                name: fname.to_string(),
                entry_pc: 0,
                instruction_count: cu as usize,
                estimated_cu: cu,
                worst_case_cu: cu,
                confidence_pct: 100.0,
                interprocedural_cu: cu,
                loops: vec![],
                syscalls: vec![],
            })
            .collect();
        let total: u64 = funcs.iter().map(|f| f.estimated_cu).sum();
        AnalysisResult {
            functions: funcs,
            total_estimated_cu: total,
            reachable_estimated_cu: total,
            program_name: name.to_string(),
            cost_model_version: crate::cost_model::COST_MODEL_VERSION.to_string(),
        }
    }

    #[test]
    fn test_diff_no_change() {
        let a = make_result(vec![("foo", 100), ("bar", 200)], "test");
        let b = make_result(vec![("foo", 100), ("bar", 200)], "test");
        let diff = diff_results(&a, &b);
        assert_eq!(diff.total_cu_change, 0);
        assert_eq!(diff.function_changes.len(), 2);
        assert!(diff.new_functions.is_empty());
        assert!(diff.removed_functions.is_empty());
        for fc in &diff.function_changes {
            assert_eq!(fc.cu_change, 0);
        }
    }

    #[test]
    fn test_diff_regression() {
        let baseline = make_result(vec![("foo", 100), ("bar", 200)], "test");
        let current = make_result(vec![("foo", 150), ("bar", 200)], "test");
        let diff = diff_results(&current, &baseline);
        assert_eq!(diff.total_cu_change, 50);
        assert_eq!(diff.function_changes[0].name, "foo");
        assert_eq!(diff.function_changes[0].cu_change, 50);
        assert!((diff.function_changes[0].change_pct - 50.0).abs() < 0.01);
    }

    #[test]
    fn test_diff_improvement() {
        let baseline = make_result(vec![("foo", 1000)], "test");
        let current = make_result(vec![("foo", 900)], "test");
        let diff = diff_results(&current, &baseline);
        assert_eq!(diff.total_cu_change, -100);
        assert_eq!(diff.function_changes[0].cu_change, -100);
        assert!((diff.function_changes[0].change_pct - (-10.0)).abs() < 0.01);
    }

    #[test]
    fn test_diff_new_and_removed() {
        let baseline = make_result(vec![("old_func", 500)], "test");
        let current = make_result(vec![("new_func", 300)], "test");
        let diff = diff_results(&current, &baseline);
        assert_eq!(diff.new_functions, vec!["new_func"]);
        assert_eq!(diff.removed_functions, vec!["old_func"]);
        assert!(diff.function_changes.is_empty());
    }

    #[test]
    fn test_diff_sorted_by_impact() {
        let baseline = make_result(vec![("a", 100), ("b", 200), ("c", 300)], "test");
        let current = make_result(vec![("a", 110), ("b", 100), ("c", 310)], "test");
        let diff = diff_results(&current, &baseline);
        assert_eq!(diff.function_changes[0].name, "b");
        assert_eq!(diff.function_changes[0].cu_change, -100);
    }

    #[test]
    fn test_save_and_load_roundtrip() {
        let original = make_result(
            vec![("verify_sig", 42000), ("transfer", 18000)],
            "my_program",
        );
        let dir = tempdir().expect("tempdir should succeed");
        let path = dir.path().join("sbpf_baseline_test.json");

        save_baseline(&original, &path).expect("save should succeed");
        let loaded = load_baseline(&path).expect("load should succeed");

        assert_eq!(loaded.program_name, original.program_name);
        assert_eq!(loaded.total_estimated_cu, original.total_estimated_cu);
        assert_eq!(loaded.functions.len(), original.functions.len());
        for (orig, loaded) in original.functions.iter().zip(loaded.functions.iter()) {
            assert_eq!(orig.name, loaded.name);
            assert_eq!(orig.estimated_cu, loaded.estimated_cu);
            assert_eq!(orig.instruction_count, loaded.instruction_count);
        }
    }

    #[test]
    fn test_load_nonexistent_file() {
        let result = load_baseline(std::path::Path::new("/nonexistent/path/baseline.json"));
        assert!(result.is_err());
    }

    #[test]
    fn test_print_diff_does_not_panic() {
        let baseline = make_result(vec![("foo", 1000), ("bar", 500)], "test");
        let current = make_result(vec![("foo", 1200), ("bar", 500), ("baz", 300)], "test");
        let diff = diff_results(&current, &baseline);
        print_diff(&diff);
    }

    #[test]
    fn test_save_load_with_loops_and_syscalls() {
        let result = AnalysisResult {
            program_name: "complex_program".to_string(),
            total_estimated_cu: 50000,
            reachable_estimated_cu: 50000,
            cost_model_version: crate::cost_model::COST_MODEL_VERSION.to_string(),
            functions: vec![FunctionAnalysis {
                name: "process".to_string(),
                entry_pc: 10,
                instruction_count: 200,
                estimated_cu: 50000,
                worst_case_cu: 45000,
                confidence_pct: 80.0,
                interprocedural_cu: 45000,
                loops: vec![LoopInfo {
                    start_pc: 20,
                    end_pc: 40,
                    scc_id: 1,
                    instruction_count: 15,
                    estimated_cu_per_iteration: 500,
                    estimated_iterations: 10,
                    bound_source: crate::analyzer::LoopBoundSource::DefaultAssumption,
                    contains_syscalls: vec![SyscallInfo {
                        pc: 25,
                        name: "sol_log_".to_string(),
                        hash: 0xAABBCCDD,
                        base_cost: 100,
                        estimated_total_cost: 100,
                        category: crate::cost_model::SyscallCategory::Logging,
                    }],
                }],
                syscalls: vec![SyscallInfo {
                    pc: 50,
                    name: "sol_sha256".to_string(),
                    hash: 0x11223344,
                    base_cost: 300,
                    estimated_total_cost: 300,
                    category: crate::cost_model::SyscallCategory::Crypto,
                }],
            }],
        };

        let dir = tempdir().expect("tempdir should succeed");
        let path = dir.path().join("sbpf_baseline_complex_test.json");

        save_baseline(&result, &path).expect("save should succeed");
        let loaded = load_baseline(&path).expect("load should succeed");

        assert_eq!(loaded.functions.len(), 1);
        let func = &loaded.functions[0];
        assert_eq!(func.name, "process");
        assert_eq!(func.loops.len(), 1);
        assert_eq!(func.loops[0].start_pc, 20);
        assert_eq!(func.loops[0].contains_syscalls.len(), 1);
        assert_eq!(func.loops[0].contains_syscalls[0].name, "sol_log_");
        assert_eq!(func.syscalls.len(), 1);
        assert_eq!(func.syscalls[0].name, "sol_sha256");
    }
}

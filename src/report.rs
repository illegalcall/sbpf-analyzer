use std::io::Write;

use colored::Colorize;
use serde::Serialize;

use crate::analyzer::{AnalysisResult, FunctionAnalysis, LoopBoundSource};
use crate::baseline::BaselineDiff;
use crate::format_number;
use crate::patterns::{PatternMatch, Severity};

// ---------------------------------------------------------------------------
// Terminal report
// ---------------------------------------------------------------------------

/// Render a colored terminal report to stdout.
pub fn print_report(result: &AnalysisResult, patterns: &[PatternMatch]) {
    write_report(&mut std::io::stdout(), result, patterns).expect("write to stdout failed");
}

/// Render a colored terminal report to the given writer.
pub fn write_report(
    w: &mut impl Write,
    result: &AnalysisResult,
    patterns: &[PatternMatch],
) -> std::io::Result<()> {
    let separator_heavy = "═".repeat(55);
    let separator_light = "─".repeat(55);

    // Header
    writeln!(w, "{}", separator_heavy.cyan().bold())?;
    writeln!(w, "{}", "  SBPF STATIC ANALYSIS REPORT".cyan().bold())?;
    writeln!(w, "  Program: {}", result.program_name.green().bold())?;
    writeln!(
        w,
        "  Total estimated CU: {} (reachable: {})",
        format_number(result.total_estimated_cu).yellow().bold(),
        format_number(result.reachable_estimated_cu).yellow().bold(),
    )?;
    writeln!(w, "{}", separator_heavy.cyan().bold())?;

    // Functions
    for func in &result.functions {
        writeln!(w)?;
        write_function(w, func)?;
    }

    // Optimization opportunities
    if !patterns.is_empty() {
        writeln!(w)?;
        writeln!(w, "{}", separator_light.cyan().bold())?;
        writeln!(w, "{}", "OPTIMIZATION OPPORTUNITIES".cyan().bold())?;
        writeln!(w, "{}", separator_light.cyan().bold())?;

        for pat in patterns {
            write_pattern(w, pat)?;
        }
    }

    Ok(())
}

/// Write a single function's analysis.
fn write_function(w: &mut impl Write, func: &FunctionAnalysis) -> std::io::Result<()> {
    writeln!(
        w,
        "{} {} (worst-case: {} CU, upper-bound: {} CU) ({:.0}% static)",
        "FUNCTION:".bold(),
        func.name.green().bold(),
        format_number(func.worst_case_cu).yellow().bold(),
        format_number(func.estimated_cu).yellow().bold(),
        func.confidence_pct,
    )?;

    if func.interprocedural_cu != func.worst_case_cu {
        writeln!(
            w,
            "  Including callees: {} CU",
            format_number(func.interprocedural_cu).yellow().bold(),
        )?;
    }

    writeln!(
        w,
        "  Instructions: {} | Entry: 0x{:x}",
        func.instruction_count, func.entry_pc,
    )?;

    // Syscalls summary
    if !func.syscalls.is_empty() {
        let syscall_strs: Vec<String> = func
            .syscalls
            .iter()
            .map(|s| {
                if s.estimated_total_cost != s.base_cost {
                    format!(
                        "{} ({} CU, ~{} CU with data)",
                        s.name,
                        format_number(s.base_cost),
                        format_number(s.estimated_total_cost)
                    )
                } else {
                    format!("{} ({} CU)", s.name, format_number(s.base_cost))
                }
            })
            .collect();
        writeln!(w, "  Syscalls: {}", syscall_strs.join(", "))?;
    }

    // Loops
    for loop_info in &func.loops {
        let bound_label = match loop_info.bound_source {
            LoopBoundSource::StaticImmediate => {
                format!("{} iters (static)", loop_info.estimated_iterations)
            }
            LoopBoundSource::DefaultAssumption => {
                format!("~{} iters (assumed)", loop_info.estimated_iterations)
            }
        };
        writeln!(
            w,
            "  {} Loop at 0x{:x}\u{2013}0x{:x}: {} insns \u{00d7} {} CU/iter \u{00d7} {}",
            "\u{26a0}".yellow(),
            loop_info.start_pc,
            loop_info.end_pc,
            loop_info.instruction_count,
            format_number(loop_info.estimated_cu_per_iteration)
                .yellow()
                .bold(),
            bound_label,
        )?;

        if !loop_info.contains_syscalls.is_empty() {
            let loop_syscall_strs: Vec<String> = loop_info
                .contains_syscalls
                .iter()
                .map(|s| format!("{} ({} CU)", s.name, format_number(s.base_cost)))
                .collect();
            writeln!(w, "     Syscalls in loop: {}", loop_syscall_strs.join(", "))?;
        }
    }

    Ok(())
}

/// Write a single pattern match finding.
fn write_pattern(w: &mut impl Write, pat: &PatternMatch) -> std::io::Result<()> {
    let (icon, colored_label) = match pat.severity {
        Severity::Critical => ("\u{1f534}", "[CRITICAL]".red().bold().to_string()),
        Severity::Warning => ("\u{1f7e1}", "[WARNING]".yellow().to_string()),
        Severity::Info => ("\u{1f535}", "[INFO]".blue().to_string()),
    };

    writeln!(
        w,
        "  {} {} at 0x{:x}: {}",
        icon, colored_label, pat.pc, pat.description,
    )?;
    writeln!(
        w,
        "     {} (est. impact: {} CU)",
        format!("\u{2192} {}", pat.suggestion).dimmed().italic(),
        format_number(pat.estimated_cu_impact).yellow().bold(),
    )?;

    Ok(())
}

// ---------------------------------------------------------------------------
// JSON report
// ---------------------------------------------------------------------------

/// Serializable wrapper for the combined JSON output.
#[derive(Serialize)]
struct JsonReport<'a> {
    program_name: &'a str,
    total_estimated_cu: u64,
    reachable_estimated_cu: u64,
    cost_model_version: &'a str,
    functions: &'a [FunctionAnalysis],
    patterns: Vec<JsonPattern<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    baseline_diff: Option<JsonBaselineDiff<'a>>,
}

/// Serializable representation of a pattern match.
#[derive(Serialize)]
struct JsonPattern<'a> {
    pc: usize,
    pattern: String,
    severity: &'static str,
    description: &'a str,
    suggestion: &'a str,
    estimated_cu_impact: u64,
}

#[derive(Serialize)]
struct JsonBaselineDiff<'a> {
    total_cu_change: i64,
    function_changes: Vec<JsonFunctionDiff<'a>>,
    new_functions: &'a [String],
    removed_functions: &'a [String],
}

#[derive(Serialize)]
struct JsonFunctionDiff<'a> {
    name: &'a str,
    old_cu: u64,
    new_cu: u64,
    cu_change: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    change_pct: Option<f64>,
}

fn json_severity(severity: &Severity) -> &'static str {
    match severity {
        Severity::Critical => "critical",
        Severity::Warning => "warning",
        Severity::Info => "info",
    }
}

fn build_json_report(
    result: &AnalysisResult,
    patterns: &[PatternMatch],
    baseline_diff: Option<&BaselineDiff>,
) -> String {
    let json_patterns: Vec<JsonPattern> = patterns
        .iter()
        .map(|p| JsonPattern {
            pc: p.pc,
            pattern: format!("{:?}", p.pattern),
            severity: json_severity(&p.severity),
            description: &p.description,
            suggestion: &p.suggestion,
            estimated_cu_impact: p.estimated_cu_impact,
        })
        .collect();

    let json_baseline_diff = baseline_diff.map(|diff| JsonBaselineDiff {
        total_cu_change: diff.total_cu_change,
        function_changes: diff
            .function_changes
            .iter()
            .map(|change| JsonFunctionDiff {
                name: &change.name,
                old_cu: change.old_cu,
                new_cu: change.new_cu,
                cu_change: change.cu_change,
                change_pct: change.change_pct.is_finite().then_some(change.change_pct),
            })
            .collect(),
        new_functions: &diff.new_functions,
        removed_functions: &diff.removed_functions,
    });

    let report = JsonReport {
        program_name: &result.program_name,
        total_estimated_cu: result.total_estimated_cu,
        reachable_estimated_cu: result.reachable_estimated_cu,
        cost_model_version: &result.cost_model_version,
        functions: &result.functions,
        patterns: json_patterns,
        baseline_diff: json_baseline_diff,
    };

    serde_json::to_string_pretty(&report).expect("serialization of JsonReport should not fail")
}

/// Output the combined analysis result and patterns as pretty-printed JSON to stdout.
pub fn print_json(result: &AnalysisResult, patterns: &[PatternMatch]) {
    print_json_with_baseline(result, patterns, None);
}

/// Output the combined analysis result, patterns, and optional baseline diff as JSON to stdout.
pub fn print_json_with_baseline(
    result: &AnalysisResult,
    patterns: &[PatternMatch],
    baseline_diff: Option<&BaselineDiff>,
) {
    write_json(&mut std::io::stdout(), result, patterns, baseline_diff)
        .expect("write to stdout failed");
}

/// Write the combined analysis result and patterns as pretty-printed JSON.
pub fn write_json(
    w: &mut impl Write,
    result: &AnalysisResult,
    patterns: &[PatternMatch],
    baseline_diff: Option<&BaselineDiff>,
) -> std::io::Result<()> {
    let json = build_json_report(result, patterns, baseline_diff);
    writeln!(w, "{json}")?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::{
        AnalysisResult, FunctionAnalysis, LoopBoundSource, LoopInfo, SyscallInfo,
    };
    use crate::patterns::{PatternKind, PatternMatch, Severity};

    #[test]
    fn test_format_cu_small() {
        assert_eq!(format_number(0), "0");
        assert_eq!(format_number(1), "1");
        assert_eq!(format_number(42), "42");
        assert_eq!(format_number(999), "999");
    }

    #[test]
    fn test_format_cu_thousands() {
        assert_eq!(format_number(1_000), "1,000");
        assert_eq!(format_number(12_345), "12,345");
        assert_eq!(format_number(999_999), "999,999");
    }

    #[test]
    fn test_format_cu_millions() {
        assert_eq!(format_number(1_000_000), "1,000,000");
        assert_eq!(format_number(1_400_000), "1,400,000");
        assert_eq!(format_number(123_456_789), "123,456,789");
    }

    fn sample_result() -> AnalysisResult {
        AnalysisResult {
            program_name: "test_program".to_string(),
            total_estimated_cu: 50_000,
            reachable_estimated_cu: 50_000,
            cost_model_version: crate::cost_model::COST_MODEL_VERSION.to_string(),
            functions: vec![FunctionAnalysis {
                name: "process_instruction".to_string(),
                entry_pc: 0x100,
                instruction_count: 200,
                estimated_cu: 50_000,
                worst_case_cu: 45_000,
                confidence_pct: 82.0,
                interprocedural_cu: 45_000,
                loops: vec![LoopInfo {
                    start_pc: 0x120,
                    end_pc: 0x140,
                    scc_id: 1,
                    instruction_count: 20,
                    estimated_cu_per_iteration: 500,
                    estimated_iterations: 10,
                    bound_source: LoopBoundSource::DefaultAssumption,
                    contains_syscalls: vec![SyscallInfo {
                        pc: 0x130,
                        name: "sol_log_".to_string(),
                        hash: 0xAABBCCDD,
                        base_cost: 100,
                        estimated_total_cost: 100,
                        category: crate::cost_model::SyscallCategory::Logging,
                    }],
                }],
                syscalls: vec![SyscallInfo {
                    pc: 0x130,
                    name: "sol_log_".to_string(),
                    hash: 0xAABBCCDD,
                    base_cost: 100,
                    estimated_total_cost: 100,
                    category: crate::cost_model::SyscallCategory::Logging,
                }],
            }],
        }
    }

    fn sample_patterns() -> Vec<PatternMatch> {
        vec![
            PatternMatch {
                pc: 0x130,
                pattern: PatternKind::LoggingInLoop,
                severity: Severity::Warning,
                description: "Logging syscall `sol_log_` inside a loop (100 CU each)".to_string(),
                suggestion: "Remove logging from hot loops".to_string(),
                estimated_cu_impact: 1_000,
            },
            PatternMatch {
                pc: 0x200,
                pattern: PatternKind::MultiplyByPowerOfTwo,
                severity: Severity::Info,
                description: "mul64 by 8 (2^3) can be replaced with a left shift".to_string(),
                suggestion: "Use `lsh64 r1, 3` instead".to_string(),
                estimated_cu_impact: 1,
            },
        ]
    }

    #[test]
    fn test_write_report_to_buffer() {
        let result = sample_result();
        let patterns = sample_patterns();
        let mut buf = Vec::new();
        write_report(&mut buf, &result, &patterns).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("SBPF STATIC ANALYSIS REPORT"));
        assert!(output.contains("test_program"));
        assert!(output.contains("FUNCTION:"));
        assert!(output.contains("OPTIMIZATION OPPORTUNITIES"));
    }

    #[test]
    fn test_write_report_no_patterns() {
        let result = sample_result();
        let mut buf = Vec::new();
        write_report(&mut buf, &result, &[]).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(!output.contains("OPTIMIZATION OPPORTUNITIES"));
    }

    #[test]
    fn test_write_json_to_buffer() {
        let result = sample_result();
        let patterns = sample_patterns();
        let mut buf = Vec::new();
        write_json(&mut buf, &result, &patterns, None).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("test_program"));
        assert!(output.contains("50000"));
        assert!(output.contains("LoggingInLoop"));
        assert!(output.contains("warning"));
        assert!(output.contains("reachable_estimated_cu"));
    }

    #[test]
    fn test_write_json_empty_patterns() {
        let result = sample_result();
        let mut buf = Vec::new();
        write_json(&mut buf, &result, &[], None).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("\"patterns\": []"));
    }

    #[test]
    fn test_json_pattern_severity_strings() {
        let critical = PatternMatch {
            pc: 0,
            pattern: PatternKind::UnboundedLoop,
            severity: Severity::Critical,
            description: "test".to_string(),
            suggestion: "test".to_string(),
            estimated_cu_impact: 0,
        };

        let jp = JsonPattern {
            pc: critical.pc,
            pattern: format!("{:?}", critical.pattern),
            severity: json_severity(&critical.severity),
            description: &critical.description,
            suggestion: &critical.suggestion,
            estimated_cu_impact: critical.estimated_cu_impact,
        };

        assert_eq!(jp.severity, "critical");
        assert_eq!(jp.pattern, "UnboundedLoop");
    }

    #[test]
    fn test_write_json_with_baseline_diff() {
        let result = sample_result();
        let baseline_result = AnalysisResult {
            program_name: result.program_name.clone(),
            total_estimated_cu: 49_000,
            reachable_estimated_cu: 49_000,
            cost_model_version: crate::cost_model::COST_MODEL_VERSION.to_string(),
            functions: vec![FunctionAnalysis {
                name: "process_instruction".to_string(),
                entry_pc: 0x100,
                instruction_count: 190,
                estimated_cu: 49_000,
                worst_case_cu: 44_000,
                confidence_pct: 85.0,
                interprocedural_cu: 44_000,
                loops: vec![],
                syscalls: vec![],
            }],
        };

        let diff = crate::baseline::diff_results(&result, &baseline_result);
        let mut buf = Vec::new();
        write_json(&mut buf, &result, &sample_patterns(), Some(&diff)).unwrap();
        let output = String::from_utf8(buf).unwrap();

        assert!(output.contains("\"baseline_diff\""));
        assert!(output.contains("\"total_cu_change\""));
        assert!(output.contains("\"function_changes\""));
    }
}

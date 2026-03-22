use std::collections::HashMap;
use std::path::Path;

use crate::analyzer::AnalysisResult;
use crate::cost_model;
use anyhow::{Context, Result};
use colored::Colorize;
use serde::Serialize;

/// Results from analyzing multiple programs together.
#[derive(Debug, Clone, Serialize)]
pub struct MultiProgramAnalysis {
    /// Individual program analysis results, keyed by file name.
    pub programs: HashMap<String, AnalysisResult>,
    /// Cross-program CPI edges: (caller_program, caller_function) -> callee_program.
    pub cpi_edges: Vec<CpiEdge>,
    /// Total estimated CU across all programs (upper bound for a full CPI chain).
    pub aggregate_estimated_cu: u64,
}

/// A detected CPI call site within a program.
#[derive(Debug, Clone, Serialize)]
pub struct CpiEdge {
    /// Name of the program containing the CPI call (derived from filename).
    pub caller_program: String,
    /// Name of the function that makes the CPI call.
    pub caller_function: String,
    /// Program counter of the CPI call instruction.
    pub caller_pc: usize,
    /// Target program being invoked. `None` if unresolved (the common case for
    /// static analysis, since the program ID lives in account data at runtime).
    pub callee_program: Option<String>,
}

// Precompute the CPI syscall hashes so we only hash once.
fn cpi_syscall_hashes() -> [u32; 2] {
    [
        cost_model::compute_syscall_hash("sol_invoke_signed_c"),
        cost_model::compute_syscall_hash("sol_invoke_signed_rust"),
    ]
}

/// Load all `.so` files from a directory and analyze them.
///
/// For each program binary found, this function:
/// 1. Loads and parses the ELF via `crate::loader`
/// 2. Runs the full analysis pipeline via `crate::analyzer`
/// 3. Scans for CPI call sites (`sol_invoke_signed_c` / `sol_invoke_signed_rust`)
/// 4. Records CPI edges with caller metadata
///
/// The `callee_program` field on each `CpiEdge` will always be `None` in this
/// implementation because CPI targets cannot be resolved statically (the target
/// program ID is embedded in account data at runtime).
pub fn analyze_programs(dir: &Path) -> Result<MultiProgramAnalysis> {
    anyhow::ensure!(
        dir.exists() && dir.is_dir(),
        "Directory does not exist or is not a directory: {}",
        dir.display()
    );

    let cpi_hashes = cpi_syscall_hashes();

    let mut programs: HashMap<String, AnalysisResult> = HashMap::new();
    let mut cpi_edges: Vec<CpiEdge> = Vec::new();
    let mut aggregate_estimated_cu: u64 = 0;

    // Collect .so files from the directory.
    let mut so_files: Vec<_> = std::fs::read_dir(dir)
        .with_context(|| format!("Failed to read directory: {}", dir.display()))?
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("so") {
                Some(path)
            } else {
                None
            }
        })
        .collect();

    so_files.sort();

    for so_path in &so_files {
        let file_name = so_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown")
            .to_string();

        // Load ELF and run analysis; skip files that fail to load.
        let executable = match crate::loader::load_and_analyze(so_path) {
            Ok(exec) => exec,
            Err(e) => {
                eprintln!(
                    "{}: skipping {} — {}",
                    "warning".yellow().bold(),
                    file_name,
                    e
                );
                continue;
            }
        };

        let static_analysis = match crate::loader::analyze(&executable) {
            Ok(a) => a,
            Err(e) => {
                eprintln!(
                    "{}: skipping {} — analysis failed: {}",
                    "warning".yellow().bold(),
                    file_name,
                    e
                );
                continue;
            }
        };

        let analysis_result = match crate::analyzer::run_analysis(&static_analysis) {
            Ok(r) => r,
            Err(e) => {
                eprintln!(
                    "{}: skipping {} — run_analysis failed: {}",
                    "warning".yellow().bold(),
                    file_name,
                    e
                );
                continue;
            }
        };

        // Scan for CPI call sites across all functions.
        for func in &analysis_result.functions {
            for syscall in &func.syscalls {
                if cpi_hashes.contains(&syscall.hash) {
                    cpi_edges.push(CpiEdge {
                        caller_program: file_name.clone(),
                        caller_function: func.name.clone(),
                        caller_pc: syscall.pc,
                        callee_program: None,
                    });
                }
            }
        }

        aggregate_estimated_cu =
            aggregate_estimated_cu.saturating_add(analysis_result.reachable_estimated_cu);

        programs.insert(file_name, analysis_result);
    }

    Ok(MultiProgramAnalysis {
        programs,
        cpi_edges,
        aggregate_estimated_cu,
    })
}

/// Print a colored summary of cross-program CPI relationships.
pub fn print_cpi_summary(analysis: &MultiProgramAnalysis) {
    println!(
        "\n{}",
        "═══ Multi-Program CPI Analysis ═══".bright_cyan().bold()
    );

    // Per-program CU estimates.
    println!("\n{}", "── Program CU Estimates ──".bright_white().bold());

    let mut program_names: Vec<&String> = analysis.programs.keys().collect();
    program_names.sort();

    for name in &program_names {
        if let Some(result) = analysis.programs.get(*name) {
            println!(
                "  {} {} (reachable: {}, total: {})",
                "▸".bright_green(),
                name.bright_yellow(),
                crate::format_number(result.reachable_estimated_cu)
                    .bright_white()
                    .bold(),
                crate::format_number(result.total_estimated_cu).dimmed(),
            );
        }
    }

    // CPI call sites.
    println!("\n{}", "── CPI Call Sites ──".bright_white().bold());

    if analysis.cpi_edges.is_empty() {
        println!("  {} No CPI calls detected.", "ℹ".bright_blue());
    } else {
        // Group edges by caller program for readability.
        let mut edges_by_program: HashMap<&str, Vec<&CpiEdge>> = HashMap::new();
        for edge in &analysis.cpi_edges {
            edges_by_program
                .entry(&edge.caller_program)
                .or_default()
                .push(edge);
        }

        let mut sorted_programs: Vec<&&str> = edges_by_program.keys().collect();
        sorted_programs.sort();

        for program in sorted_programs {
            let edges = &edges_by_program[*program];
            println!(
                "  {} {} ({} CPI call site{})",
                "▸".bright_green(),
                program.bright_yellow(),
                edges.len(),
                if edges.len() == 1 { "" } else { "s" },
            );

            for edge in edges {
                let target = match &edge.callee_program {
                    Some(name) => name.bright_cyan().to_string(),
                    None => "<unresolved>".dimmed().to_string(),
                };
                println!(
                    "    {} {} (pc: {}) → {}",
                    "├".dimmed(),
                    edge.caller_function.bright_white(),
                    format!("{:#x}", edge.caller_pc).dimmed(),
                    target,
                );
            }
        }
    }

    // Aggregate CU.
    println!(
        "\n{} {} CU",
        "Aggregate estimated CU (upper bound):"
            .bright_white()
            .bold(),
        crate::format_number(analysis.aggregate_estimated_cu)
            .bright_green()
            .bold(),
    );

    println!();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_analyze_empty_dir() {
        let tmp = TempDir::new().expect("failed to create temp dir");
        let result = analyze_programs(tmp.path()).expect("should succeed on empty dir");

        assert!(result.programs.is_empty());
        assert!(result.cpi_edges.is_empty());
        assert_eq!(result.aggregate_estimated_cu, 0);
    }

    #[test]
    fn test_analyze_nonexistent_dir() {
        let path = Path::new("/tmp/sbpf_test_nonexistent_dir_12345");
        // Make sure it really doesn't exist.
        let _ = fs::remove_dir_all(path);

        let result = analyze_programs(path);
        assert!(result.is_err(), "expected error for nonexistent directory");
    }

    #[test]
    fn test_cpi_hashes_are_consistent() {
        let hashes = cpi_syscall_hashes();
        assert_eq!(
            hashes[0],
            cost_model::compute_syscall_hash("sol_invoke_signed_c")
        );
        assert_eq!(
            hashes[1],
            cost_model::compute_syscall_hash("sol_invoke_signed_rust")
        );
        // They should be different from each other.
        assert_ne!(hashes[0], hashes[1]);
    }

    #[test]
    fn test_multi_program_analysis_serializable() {
        let analysis = MultiProgramAnalysis {
            programs: HashMap::new(),
            cpi_edges: vec![CpiEdge {
                caller_program: "test.so".to_string(),
                caller_function: "process_instruction".to_string(),
                caller_pc: 0x100,
                callee_program: None,
            }],
            aggregate_estimated_cu: 0,
        };
        let json = serde_json::to_string(&analysis).expect("should serialize");
        assert!(json.contains("test.so"));
        assert!(json.contains("process_instruction"));
        assert!(json.contains("callee_program"));
    }
}

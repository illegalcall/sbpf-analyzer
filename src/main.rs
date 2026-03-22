use std::path::PathBuf;
use std::process;

use anyhow::{Context, Result};
use clap::Parser;

use sbpf_analyzer::analyzer::AnalysisConfig;
use sbpf_analyzer::{analyzer, baseline, loader, patterns, report};

#[derive(Parser)]
#[command(name = "sbpf-analyze")]
#[command(about = "Static compute unit analyzer for Solana sBPF programs")]
struct Cli {
    /// Path to the .so file to analyze
    path: PathBuf,

    /// Output results as JSON instead of colored terminal report
    #[arg(long)]
    json: bool,

    /// Path to a previous baseline JSON file to compare against
    #[arg(long, value_name = "FILE")]
    baseline: Option<PathBuf>,

    /// Save current analysis as a baseline JSON file
    #[arg(long, value_name = "FILE")]
    save_baseline: Option<PathBuf>,

    /// Default loop iteration count for CU estimation when no bound can be inferred.
    #[arg(long, default_value_t = analyzer::DEFAULT_LOOP_ITERATIONS, value_name = "N")]
    loop_iterations: u64,

    /// Exit with code 1 if any function's estimated CU exceeds this threshold.
    #[arg(long, value_name = "CU")]
    fail_above: Option<u64>,

    /// Exit with code 1 if baseline comparison shows a regression exceeding this percentage.
    #[arg(long, value_name = "PCT")]
    fail_regression: Option<f64>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // 1. Load and parse the ELF
    let executable = loader::load_and_analyze(&cli.path)
        .with_context(|| format!("Failed to load {}", cli.path.display()))?;

    // 2. Build the CFG + static analysis
    let analysis = loader::analyze(&executable)?;

    // 3. Run CU estimation with config
    let config = AnalysisConfig {
        default_loop_iterations: cli.loop_iterations,
    };
    let result = analyzer::run_analysis_with_config(&analysis, &config)?;

    // 4. Detect patterns
    let pattern_matches = patterns::detect_patterns(&analysis);

    // 5. Baseline comparison (if requested)
    let mut regression_pct: Option<f64> = None;
    let baseline_diff = if let Some(baseline_path) = &cli.baseline {
        let prev = baseline::load_baseline(baseline_path)
            .with_context(|| format!("Failed to load baseline from {}", baseline_path.display()))?;
        let diff = baseline::diff_results(&result, &prev);

        // Compute overall regression percentage for --fail-regression
        // Use reachable CU for both numerator and denominator to avoid mismatch.
        let reachable_change = (result.reachable_estimated_cu as i128
            - prev.reachable_estimated_cu as i128)
            .clamp(i64::MIN as i128, i64::MAX as i128) as i64;
        if prev.reachable_estimated_cu > 0 {
            regression_pct =
                Some((reachable_change as f64 / prev.reachable_estimated_cu as f64) * 100.0);
        }
        Some(diff)
    } else {
        None
    };

    // 6. Output report
    if cli.json {
        report::print_json_with_baseline(&result, &pattern_matches, baseline_diff.as_ref());
    } else {
        report::print_report(&result, &pattern_matches);
        if let Some(diff) = baseline_diff.as_ref() {
            baseline::print_diff(diff);
        }
    }

    // 7. Save baseline (if requested)
    if let Some(save_path) = &cli.save_baseline {
        baseline::save_baseline(&result, save_path)
            .with_context(|| format!("Failed to save baseline to {}", save_path.display()))?;
        eprintln!("Baseline saved to {}", save_path.display());
    }

    // 8. CI gate checks
    if let Some(threshold) = cli.fail_above {
        let violators: Vec<_> = result
            .functions
            .iter()
            .filter(|f| f.estimated_cu > threshold)
            .collect();
        if !violators.is_empty() {
            eprintln!();
            eprintln!(
                "CI GATE FAILED: {} function(s) exceed {} CU threshold:",
                violators.len(),
                sbpf_analyzer::format_number(threshold),
            );
            for f in &violators {
                eprintln!(
                    "  {} — {} CU",
                    f.name,
                    sbpf_analyzer::format_number(f.estimated_cu)
                );
            }
            process::exit(1);
        }
    }

    if let Some(max_regression) = cli.fail_regression {
        if let Some(pct) = regression_pct {
            if pct > max_regression {
                eprintln!();
                eprintln!("CI GATE FAILED: CU regression of {pct:.1}% exceeds {max_regression:.1}% threshold");
                process::exit(1);
            }
        }
    }

    Ok(())
}

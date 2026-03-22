mod helpers;

use sbpf_analyzer::{analyzer, baseline, patterns, report};
use solana_sbpf::{ebpf, program::SBPFVersion};
use tempfile::NamedTempFile;

/// Encode a single sBPF instruction into 8 bytes (little-endian).
fn encode_insn(opc: u8, dst: u8, src: u8, off: i16, imm: i32) -> [u8; 8] {
    let off_bytes = off.to_le_bytes();
    let imm_bytes = imm.to_le_bytes();
    [
        opc,
        (src << 4) | (dst & 0x0f),
        off_bytes[0],
        off_bytes[1],
        imm_bytes[0],
        imm_bytes[1],
        imm_bytes[2],
        imm_bytes[3],
    ]
}

/// Build bytecode from a list of instructions.
fn build_bytecode(insns: &[(u8, u8, u8, i16, i32)]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for &(opc, dst, src, off, imm) in insns {
        bytes.extend_from_slice(&encode_insn(opc, dst, src, off, imm));
    }
    bytes
}

// ─────────────────────────────────────────────────────────────────────────────
// Analyzer tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_simple_function_analysis() {
    // A minimal function: mov r0, 0; exit
    let bytecode = build_bytecode(&[
        (ebpf::MOV64_IMM, 0, 0, 0, 0), // mov r0, 0
        (ebpf::EXIT, 0, 0, 0, 0),      // exit
    ]);

    let exe = helpers::executable_from_bytecode(&bytecode, &[(0, "simple_fn")]);
    let analysis = solana_sbpf::static_analysis::Analysis::from_executable(&exe).unwrap();
    let result = analyzer::run_analysis(&analysis).unwrap();

    assert!(!result.functions.is_empty());
    // Function names may be mangled by the runtime; just verify we got analysis
    assert!(result.functions[0].instruction_count >= 2);
    assert!(result.functions[0].loops.is_empty());
    assert!(result.total_estimated_cu > 0);
}

#[test]
fn test_multiple_functions() {
    // Two functions: fn1 at pc=0, fn2 at pc=3
    let bytecode = build_bytecode(&[
        // fn1: 3 instructions
        (ebpf::MOV64_IMM, 0, 0, 0, 0),  // pc=0
        (ebpf::MOV64_IMM, 1, 0, 0, 42), // pc=1
        (ebpf::EXIT, 0, 0, 0, 0),       // pc=2
        // fn2: 2 instructions
        (ebpf::MOV64_IMM, 0, 0, 0, 1), // pc=3
        (ebpf::EXIT, 0, 0, 0, 0),      // pc=4
    ]);

    let exe =
        helpers::executable_from_bytecode(&bytecode, &[(0, "function_one"), (3, "function_two")]);
    let analysis = solana_sbpf::static_analysis::Analysis::from_executable(&exe).unwrap();
    let result = analyzer::run_analysis(&analysis).unwrap();

    // Should detect at least 2 functions (runtime may add its own entrypoint)
    assert!(
        result.functions.len() >= 2,
        "Expected at least 2 functions, got {}",
        result.functions.len()
    );
}

#[test]
fn test_v3_relative_internal_calls_are_reachable_and_interprocedural() {
    let bytecode = build_bytecode(&[
        (ebpf::CALL_IMM, 0, 1, 0, 1),  // pc=0: call pc=2 (next_pc + 1)
        (ebpf::EXIT, 0, 0, 0, 0),      // pc=1
        (ebpf::MOV64_IMM, 0, 0, 0, 7), // pc=2: callee body
        (ebpf::EXIT, 0, 0, 0, 0),      // pc=3
    ]);

    let exe = helpers::executable_from_bytecode_with_version(
        &bytecode,
        &[(0, "entrypoint"), (2, "helper")],
        SBPFVersion::V3,
    );
    let analysis = solana_sbpf::static_analysis::Analysis::from_executable(&exe).unwrap();
    let result = analyzer::run_analysis(&analysis).unwrap();

    assert_eq!(result.total_estimated_cu, 4);
    assert_eq!(result.reachable_estimated_cu, 4);

    let entry = result
        .functions
        .iter()
        .find(|func| func.entry_pc == 0)
        .expect("entry function should be present");
    assert_eq!(entry.worst_case_cu, 2);
    assert_eq!(entry.interprocedural_cu, 4);
}

#[test]
fn test_syscall_size_inference_stays_within_current_function() {
    let sha256_hash = sbpf_analyzer::cost_model::compute_syscall_hash("sol_sha256");
    let bytecode = build_bytecode(&[
        (ebpf::MOV64_IMM, 2, 0, 0, 1024), // pc=0: previous function sets r2
        (ebpf::EXIT, 0, 0, 0, 0),         // pc=1
        (ebpf::CALL_IMM, 0, 0, 0, sha256_hash as i32), // pc=2: next function starts with syscall
        (ebpf::EXIT, 0, 0, 0, 0),         // pc=3
    ]);

    let exe = helpers::executable_from_bytecode(&bytecode, &[(0, "setter"), (2, "hasher")]);
    let analysis = solana_sbpf::static_analysis::Analysis::from_executable(&exe).unwrap();
    let result = analyzer::run_analysis(&analysis).unwrap();

    let hasher = result
        .functions
        .iter()
        .find(|func| func.entry_pc == 2)
        .expect("hasher function should be present");
    assert_eq!(hasher.syscalls.len(), 1);
    assert_eq!(hasher.syscalls[0].estimated_total_cost, 85);
    assert_eq!(hasher.estimated_cu, 87);
}

#[test]
fn test_transitive_internal_calls_are_counted_interprocedurally() {
    let bytecode = build_bytecode(&[
        (ebpf::CALL_IMM, 0, 1, 0, 1),  // pc=0: entry -> helper1
        (ebpf::EXIT, 0, 0, 0, 0),      // pc=1
        (ebpf::CALL_IMM, 0, 1, 0, 1),  // pc=2: helper1 -> helper2
        (ebpf::EXIT, 0, 0, 0, 0),      // pc=3
        (ebpf::MOV64_IMM, 0, 0, 0, 7), // pc=4: helper2 body
        (ebpf::EXIT, 0, 0, 0, 0),      // pc=5
    ]);

    let exe = helpers::executable_from_bytecode_with_version(
        &bytecode,
        &[(0, "entrypoint"), (2, "helper1"), (4, "helper2")],
        SBPFVersion::V3,
    );
    let analysis = solana_sbpf::static_analysis::Analysis::from_executable(&exe).unwrap();
    let result = analyzer::run_analysis(&analysis).unwrap();

    let entry = result
        .functions
        .iter()
        .find(|func| func.entry_pc == 0)
        .expect("entry function should be present");
    let helper1 = result
        .functions
        .iter()
        .find(|func| func.entry_pc == 2)
        .expect("helper1 function should be present");

    assert_eq!(entry.interprocedural_cu, 6);
    assert_eq!(helper1.interprocedural_cu, 4);
}

#[test]
fn test_analysis_result_serializable() {
    let bytecode = build_bytecode(&[(ebpf::MOV64_IMM, 0, 0, 0, 0), (ebpf::EXIT, 0, 0, 0, 0)]);

    let exe = helpers::executable_from_bytecode(&bytecode, &[(0, "test_fn")]);
    let analysis = solana_sbpf::static_analysis::Analysis::from_executable(&exe).unwrap();
    let result = analyzer::run_analysis(&analysis).unwrap();

    let json = serde_json::to_string_pretty(&result).unwrap();
    assert!(json.contains("total_estimated_cu"));
    assert!(json.contains("functions"));
}

// ─────────────────────────────────────────────────────────────────────────────
// Pattern detection tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_detect_multiply_by_power_of_two() {
    // mul64 r0, 8 (8 = 2^3) → should detect
    let bytecode = build_bytecode(&[
        (ebpf::MOV64_IMM, 0, 0, 0, 1),
        (ebpf::MUL64_IMM, 0, 0, 0, 8), // mul r0, 8
        (ebpf::EXIT, 0, 0, 0, 0),
    ]);

    let exe = helpers::executable_from_bytecode(&bytecode, &[(0, "mul_fn")]);
    let analysis = solana_sbpf::static_analysis::Analysis::from_executable(&exe).unwrap();
    let matches = patterns::detect_patterns(&analysis);

    let mul_matches: Vec<_> = matches
        .iter()
        .filter(|m| m.pattern == patterns::PatternKind::MultiplyByPowerOfTwo)
        .collect();

    assert!(
        !mul_matches.is_empty(),
        "Should detect multiply by power of 2"
    );
    assert!(mul_matches[0].description.contains("2^3"));
}

#[test]
fn test_detect_divide_by_power_of_two() {
    let bytecode = build_bytecode(&[
        (ebpf::MOV64_IMM, 0, 0, 0, 100),
        (ebpf::DIV64_IMM, 0, 0, 0, 4), // div r0, 4
        (ebpf::EXIT, 0, 0, 0, 0),
    ]);

    let exe = helpers::executable_from_bytecode(&bytecode, &[(0, "div_fn")]);
    let analysis = solana_sbpf::static_analysis::Analysis::from_executable(&exe).unwrap();
    let matches = patterns::detect_patterns(&analysis);

    let div_matches: Vec<_> = matches
        .iter()
        .filter(|m| m.pattern == patterns::PatternKind::DivideByPowerOfTwo)
        .collect();

    assert!(
        !div_matches.is_empty(),
        "Should detect divide by power of 2"
    );
}

#[test]
fn test_no_false_positives_for_non_power_of_two() {
    // mul64 r0, 7 → NOT a power of 2, should NOT trigger
    let bytecode = build_bytecode(&[
        (ebpf::MOV64_IMM, 0, 0, 0, 1),
        (ebpf::MUL64_IMM, 0, 0, 0, 7),
        (ebpf::EXIT, 0, 0, 0, 0),
    ]);

    let exe = helpers::executable_from_bytecode(&bytecode, &[(0, "mul_fn")]);
    let analysis = solana_sbpf::static_analysis::Analysis::from_executable(&exe).unwrap();
    let matches = patterns::detect_patterns(&analysis);

    let mul_matches: Vec<_> = matches
        .iter()
        .filter(|m| m.pattern == patterns::PatternKind::MultiplyByPowerOfTwo)
        .collect();

    assert!(
        mul_matches.is_empty(),
        "Should not flag non-power-of-2 multiply"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Report tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_report_does_not_panic() {
    let bytecode = build_bytecode(&[
        (ebpf::MOV64_IMM, 0, 0, 0, 0),
        (ebpf::MUL64_IMM, 0, 0, 0, 16), // pattern: mul by power of 2
        (ebpf::EXIT, 0, 0, 0, 0),
    ]);

    let exe = helpers::executable_from_bytecode(&bytecode, &[(0, "test_fn")]);
    let analysis = solana_sbpf::static_analysis::Analysis::from_executable(&exe).unwrap();
    let result = analyzer::run_analysis(&analysis).unwrap();
    let pattern_matches = patterns::detect_patterns(&analysis);

    // Should not panic
    report::print_report(&result, &pattern_matches);
    report::print_json(&result, &pattern_matches);
}

// ─────────────────────────────────────────────────────────────────────────────
// Baseline tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_baseline_save_load_roundtrip() {
    let bytecode = build_bytecode(&[(ebpf::MOV64_IMM, 0, 0, 0, 0), (ebpf::EXIT, 0, 0, 0, 0)]);

    let exe = helpers::executable_from_bytecode(&bytecode, &[(0, "roundtrip_fn")]);
    let analysis = solana_sbpf::static_analysis::Analysis::from_executable(&exe).unwrap();
    let result = analyzer::run_analysis(&analysis).unwrap();

    let tmp = NamedTempFile::new().unwrap();
    baseline::save_baseline(&result, tmp.path()).unwrap();
    let loaded = baseline::load_baseline(tmp.path()).unwrap();

    assert_eq!(loaded.total_estimated_cu, result.total_estimated_cu);
    assert_eq!(loaded.functions.len(), result.functions.len());
    assert_eq!(loaded.functions[0].name, result.functions[0].name);
}

#[test]
fn test_baseline_diff_detects_regression() {
    let bytecode_v1 = build_bytecode(&[(ebpf::MOV64_IMM, 0, 0, 0, 0), (ebpf::EXIT, 0, 0, 0, 0)]);
    let bytecode_v2 = build_bytecode(&[
        (ebpf::MOV64_IMM, 0, 0, 0, 0),
        (ebpf::MOV64_IMM, 1, 0, 0, 1),
        (ebpf::ADD64_IMM, 0, 0, 0, 5),
        (ebpf::EXIT, 0, 0, 0, 0),
    ]);

    let exe_v1 = helpers::executable_from_bytecode(&bytecode_v1, &[(0, "shared_fn")]);
    let exe_v2 = helpers::executable_from_bytecode(&bytecode_v2, &[(0, "shared_fn")]);
    let a1 = solana_sbpf::static_analysis::Analysis::from_executable(&exe_v1).unwrap();
    let a2 = solana_sbpf::static_analysis::Analysis::from_executable(&exe_v2).unwrap();
    let result_v1 = analyzer::run_analysis(&a1).unwrap();
    let result_v2 = analyzer::run_analysis(&a2).unwrap();

    let diff = baseline::diff_results(&result_v2, &result_v1);

    // v2 has more instructions → CU should increase
    assert!(diff.total_cu_change > 0, "Should detect CU regression");
    assert!(!diff.function_changes.is_empty());
    assert!(diff.function_changes[0].cu_change > 0);
}

// ─────────────────────────────────────────────────────────────────────────────
// Full pipeline test
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_full_pipeline() {
    // Build a program with interesting patterns
    let bytecode = build_bytecode(&[
        (ebpf::MOV64_IMM, 0, 0, 0, 0),  // pc=0
        (ebpf::MOV64_IMM, 1, 0, 0, 10), // pc=1
        (ebpf::MUL64_IMM, 0, 0, 0, 16), // pc=2: pattern - mul by power of 2
        (ebpf::ADD64_IMM, 0, 0, 0, 1),  // pc=3
        (ebpf::EXIT, 0, 0, 0, 0),       // pc=4
    ]);

    let exe = helpers::executable_from_bytecode(&bytecode, &[(0, "pipeline_fn")]);

    // Step 1: Analysis (single pass, shared)
    let analysis_obj = solana_sbpf::static_analysis::Analysis::from_executable(&exe).unwrap();
    let result = analyzer::run_analysis(&analysis_obj).unwrap();

    assert!(!result.functions.is_empty());
    assert!(result.total_estimated_cu > 0);

    // Step 2: Pattern detection
    let pattern_matches = patterns::detect_patterns(&analysis_obj);
    // Should find the mul-by-16 pattern
    assert!(
        pattern_matches
            .iter()
            .any(|m| m.pattern == patterns::PatternKind::MultiplyByPowerOfTwo),
        "Should detect mul by power of 2 in pipeline"
    );

    // Step 3: Report (just verify no panic)
    report::print_report(&result, &pattern_matches);

    // Step 4: JSON output (verify valid JSON)
    report::print_json(&result, &pattern_matches);

    // Step 5: Baseline save/load
    let tmp = NamedTempFile::new().unwrap();
    baseline::save_baseline(&result, tmp.path()).unwrap();
    let loaded = baseline::load_baseline(tmp.path()).unwrap();
    assert_eq!(loaded.total_estimated_cu, result.total_estimated_cu);

    // Step 6: Diff
    let diff = baseline::diff_results(&result, &loaded);
    assert_eq!(
        diff.total_cu_change, 0,
        "Same data should produce zero diff"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// CLI error handling tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_cli_missing_file() {
    use assert_cmd::Command;

    let mut cmd = Command::cargo_bin("sbpf-analyze").unwrap();
    cmd.arg("/nonexistent/file.so");
    cmd.assert().failure();
}

#[test]
fn test_cli_invalid_elf() {
    use assert_cmd::Command;

    let tmp = NamedTempFile::new().unwrap();
    std::fs::write(tmp.path(), b"this is not an elf").unwrap();

    let mut cmd = Command::cargo_bin("sbpf-analyze").unwrap();
    cmd.arg(tmp.path());
    cmd.assert().failure();
}

#[test]
fn test_cli_help() {
    use assert_cmd::Command;

    let mut cmd = Command::cargo_bin("sbpf-analyze").unwrap();
    cmd.arg("--help");
    cmd.assert()
        .success()
        .stdout(predicates::str::contains("Static compute unit analyzer"));
}

// ─────────────────────────────────────────────────────────────────────────────
// Loop detection tests (issue #3 from review)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_loop_detection_simple_back_edge() {
    // Build a simple loop: pc=0 init, pc=1 body, pc=2 conditional back-edge to pc=1, pc=3 exit
    let bytecode = build_bytecode(&[
        (ebpf::MOV64_IMM, 0, 0, 0, 0),   // pc=0: r0 = 0
        (ebpf::ADD64_IMM, 0, 0, 0, 1),   // pc=1: r0 += 1 (loop body)
        (ebpf::JLT64_IMM, 0, 0, -2, 10), // pc=2: if r0 < 10, jump to pc=1 (back-edge)
        (ebpf::EXIT, 0, 0, 0, 0),        // pc=3: exit
    ]);

    let exe = helpers::executable_from_bytecode(&bytecode, &[(0, "loop_fn")]);
    let analysis = solana_sbpf::static_analysis::Analysis::from_executable(&exe).unwrap();
    let result = analyzer::run_analysis(&analysis).unwrap();

    // Find the function with the loop
    let func = result.functions.iter().find(|f| !f.loops.is_empty());

    assert!(func.is_some(), "Should detect a loop via back-edge");
    let func = func.unwrap();
    assert!(
        !func.loops.is_empty(),
        "Function should have at least one loop"
    );
    assert!(
        func.loops[0].instruction_count > 0,
        "Loop should have instructions"
    );
    assert!(
        func.loops[0].estimated_cu_per_iteration > 0,
        "Loop CU per iteration should be positive"
    );
    // With loops, estimated CU should be higher than just instruction count
    assert!(
        func.estimated_cu > func.instruction_count as u64,
        "Loop overhead should increase estimated CU"
    );
}

#[test]
fn test_no_loop_in_straight_line_code() {
    let bytecode = build_bytecode(&[
        (ebpf::MOV64_IMM, 0, 0, 0, 1),
        (ebpf::MOV64_IMM, 1, 0, 0, 2),
        (ebpf::ADD64_IMM, 0, 0, 0, 3),
        (ebpf::EXIT, 0, 0, 0, 0),
    ]);

    let exe = helpers::executable_from_bytecode(&bytecode, &[(0, "no_loop_fn")]);
    let analysis = solana_sbpf::static_analysis::Analysis::from_executable(&exe).unwrap();
    let result = analyzer::run_analysis(&analysis).unwrap();

    for func in &result.functions {
        assert!(
            func.loops.is_empty(),
            "Straight-line code should have no loops, but {} has {}",
            func.name,
            func.loops.len()
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Loop bound extraction tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_static_loop_bound_extraction() {
    // Loop: r0 = 0; loop: r0 += 1; if r0 < 32, goto loop; exit
    // The JLT64_IMM with imm=32 should give us a static bound of 32.
    let bytecode = build_bytecode(&[
        (ebpf::MOV64_IMM, 0, 0, 0, 0),   // pc=0: r0 = 0
        (ebpf::ADD64_IMM, 0, 0, 0, 1),   // pc=1: r0 += 1 (loop body)
        (ebpf::JLT64_IMM, 0, 0, -2, 32), // pc=2: if r0 < 32, goto pc=1
        (ebpf::EXIT, 0, 0, 0, 0),        // pc=3: exit
    ]);

    let exe = helpers::executable_from_bytecode(&bytecode, &[(0, "bounded_loop")]);
    let analysis = solana_sbpf::static_analysis::Analysis::from_executable(&exe).unwrap();
    let result = analyzer::run_analysis(&analysis).unwrap();

    let func = result.functions.iter().find(|f| !f.loops.is_empty());
    assert!(func.is_some(), "Should detect loop");
    let loop_info = &func.unwrap().loops[0];

    assert_eq!(
        loop_info.bound_source,
        analyzer::LoopBoundSource::StaticImmediate,
        "Should extract static bound from JLT64_IMM"
    );
    assert_eq!(
        loop_info.estimated_iterations, 32,
        "Should extract bound of 32 from jlt r0, 32"
    );
}

#[test]
fn test_custom_loop_iterations_config() {
    // Loop with no immediate bound (uses register comparison)
    // → should fall back to the configured default
    let bytecode = build_bytecode(&[
        (ebpf::MOV64_IMM, 0, 0, 0, 0),  // pc=0
        (ebpf::ADD64_IMM, 0, 0, 0, 1),  // pc=1
        (ebpf::JLT64_IMM, 0, 0, -2, 5), // pc=2: bound=5 via immediate
        (ebpf::EXIT, 0, 0, 0, 0),       // pc=3
    ]);

    let exe = helpers::executable_from_bytecode(&bytecode, &[(0, "config_loop")]);
    let analysis = solana_sbpf::static_analysis::Analysis::from_executable(&exe).unwrap();

    // With default config (10 iterations) — but static bound of 5 should win
    let result_default = analyzer::run_analysis(&analysis).unwrap();
    let loop_default = result_default
        .functions
        .iter()
        .find(|f| !f.loops.is_empty())
        .unwrap()
        .loops[0]
        .clone();

    assert_eq!(loop_default.estimated_iterations, 5);
    assert_eq!(
        loop_default.bound_source,
        analyzer::LoopBoundSource::StaticImmediate
    );

    // With custom config (50 iterations) — static bound of 5 should still win
    let config = analyzer::AnalysisConfig {
        default_loop_iterations: 50,
    };
    let result_custom = analyzer::run_analysis_with_config(&analysis, &config).unwrap();
    let loop_custom = result_custom
        .functions
        .iter()
        .find(|f| !f.loops.is_empty())
        .unwrap()
        .loops[0]
        .clone();

    // Static bound should override the config
    assert_eq!(loop_custom.estimated_iterations, 5);
}

#[test]
fn test_loop_initializer_does_not_cross_function_boundary() {
    let bytecode = build_bytecode(&[
        (ebpf::MOV64_IMM, 0, 0, 0, 0),   // pc=0: previous function zeroes r0
        (ebpf::EXIT, 0, 0, 0, 0),        // pc=1
        (ebpf::ADD64_IMM, 0, 0, 0, 1),   // pc=2: new function has no local zero init
        (ebpf::JLT64_IMM, 0, 0, -2, 32), // pc=3
        (ebpf::EXIT, 0, 0, 0, 0),        // pc=4
    ]);

    let exe = helpers::executable_from_bytecode(&bytecode, &[(0, "init"), (2, "loop_fn")]);
    let analysis = solana_sbpf::static_analysis::Analysis::from_executable(&exe).unwrap();
    let result = analyzer::run_analysis(&analysis).unwrap();

    let loop_fn = result
        .functions
        .iter()
        .find(|func| func.entry_pc == 2)
        .expect("loop function should be present");
    assert_eq!(loop_fn.loops.len(), 1);
    assert_eq!(
        loop_fn.loops[0].bound_source,
        analyzer::LoopBoundSource::DefaultAssumption
    );
    assert_eq!(loop_fn.loops[0].estimated_iterations, 10);
}

#[test]
fn test_internal_conditional_does_not_override_loop_guard() {
    let bytecode = build_bytecode(&[
        (ebpf::MOV64_IMM, 0, 0, 0, 0),   // pc=0: r0 = 0
        (ebpf::JNE64_IMM, 1, 0, 1, 1),   // pc=1: internal branch, both paths stay in loop
        (ebpf::MOV64_IMM, 2, 0, 0, 0),   // pc=2
        (ebpf::ADD64_IMM, 0, 0, 0, 1),   // pc=3: r0 += 1
        (ebpf::JLT64_IMM, 0, 0, -4, 32), // pc=4: if r0 < 32, goto pc=1
        (ebpf::EXIT, 0, 0, 0, 0),        // pc=5
    ]);

    let exe = helpers::executable_from_bytecode(&bytecode, &[(0, "guarded_loop")]);
    let analysis = solana_sbpf::static_analysis::Analysis::from_executable(&exe).unwrap();
    let result = analyzer::run_analysis(&analysis).unwrap();

    let loop_info = result
        .functions
        .iter()
        .find(|f| !f.loops.is_empty())
        .unwrap()
        .loops[0]
        .clone();

    assert_eq!(
        loop_info.bound_source,
        analyzer::LoopBoundSource::StaticImmediate
    );
    assert_eq!(loop_info.estimated_iterations, 32);
}

#[test]
fn test_unbounded_loop_with_internal_condition_still_flagged() {
    let bytecode = build_bytecode(&[
        (ebpf::MOV64_IMM, 0, 0, 0, 0), // pc=0
        (ebpf::JNE64_IMM, 0, 0, 1, 1), // pc=1: both edges stay in SCC
        (ebpf::ADD64_IMM, 0, 0, 0, 1), // pc=2
        (ebpf::JA, 0, 0, -3, 0),       // pc=3: jump back to pc=1
        (ebpf::EXIT, 0, 0, 0, 0),      // pc=4: unreachable
    ]);

    let exe = helpers::executable_from_bytecode(&bytecode, &[(0, "infinite_loop")]);
    let analysis = solana_sbpf::static_analysis::Analysis::from_executable(&exe).unwrap();
    let matches = patterns::detect_patterns(&analysis);

    assert!(
        matches
            .iter()
            .any(|m| m.pattern == patterns::PatternKind::UnboundedLoop),
        "internal loop condition should not suppress an UnboundedLoop finding"
    );
}

#[test]
fn test_loop_worst_case_uses_single_branch_per_iteration() {
    let bytecode = build_bytecode(&[
        (ebpf::MOV64_IMM, 0, 0, 0, 0),   // pc=0: loop counter = 0
        (ebpf::JNE64_IMM, 1, 0, 2, 0),   // pc=1: if r1 != 0 jump to pc=4
        (ebpf::MOV64_IMM, 2, 0, 0, 1),   // pc=2: then-arm
        (ebpf::JA, 0, 0, 1, 0),          // pc=3: skip else-arm, jump to pc=5
        (ebpf::MOV64_IMM, 3, 0, 0, 1),   // pc=4: else-arm
        (ebpf::ADD64_IMM, 0, 0, 0, 1),   // pc=5: increment
        (ebpf::JLT64_IMM, 0, 0, -6, 32), // pc=6: back-edge to pc=1
        (ebpf::EXIT, 0, 0, 0, 0),        // pc=7
    ]);

    let exe = helpers::executable_from_bytecode(&bytecode, &[(0, "branchy_loop")]);
    let analysis = solana_sbpf::static_analysis::Analysis::from_executable(&exe).unwrap();
    let result = analyzer::run_analysis(&analysis).unwrap();

    let func = result
        .functions
        .iter()
        .find(|func| !func.loops.is_empty())
        .expect("loop function should be present");
    assert_eq!(func.worst_case_cu, 161);
}

// ─────────────────────────────────────────────────────────────────────────────
// Critical pattern tests (issue #8 from review)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_pattern_expensive_crypto_op() {
    // Construct CALL_IMM with the hash of sol_secp256k1_recover (25K CU)
    let hash = sbpf_analyzer::cost_model::compute_syscall_hash("sol_secp256k1_recover");

    let bytecode = build_bytecode(&[
        (ebpf::MOV64_IMM, 0, 0, 0, 0),
        (ebpf::CALL_IMM, 0, 0, 0, hash as i32), // expensive crypto
        (ebpf::EXIT, 0, 0, 0, 0),
    ]);

    let exe = helpers::executable_from_bytecode(&bytecode, &[(0, "crypto_fn")]);
    let analysis = solana_sbpf::static_analysis::Analysis::from_executable(&exe).unwrap();
    let matches = patterns::detect_patterns(&analysis);

    let crypto_matches: Vec<_> = matches
        .iter()
        .filter(|m| m.pattern == patterns::PatternKind::ExpensiveCryptoOp)
        .collect();

    assert!(
        !crypto_matches.is_empty(),
        "Should detect expensive crypto operation"
    );
    assert_eq!(crypto_matches[0].estimated_cu_impact, 25_000);
}

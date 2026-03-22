use std::collections::{HashMap, HashSet};

use solana_sbpf::ebpf;
use solana_sbpf::static_analysis::Analysis;

use crate::cost_model::{self, SyscallCategory};

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// A single detected pattern match in the analyzed bytecode.
#[derive(Debug, Clone)]
pub struct PatternMatch {
    /// Program counter (instruction index) where the pattern was found.
    pub pc: usize,
    /// The kind of pattern detected.
    pub pattern: PatternKind,
    /// How severe the finding is.
    pub severity: Severity,
    /// Human-readable description of the finding.
    pub description: String,
    /// Actionable suggestion for the developer.
    pub suggestion: String,
    /// Estimated CU impact of this pattern (per occurrence or per iteration).
    pub estimated_cu_impact: u64,
}

/// Severity levels for pattern findings.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

/// The kinds of patterns the detector can identify.
#[derive(Debug, Clone, PartialEq)]
pub enum PatternKind {
    /// MUL by a power-of-two immediate — can be replaced with a left shift.
    MultiplyByPowerOfTwo,
    /// DIV by a power-of-two immediate — can be replaced with a right shift.
    DivideByPowerOfTwo,
    /// An expensive syscall (base_cost > 1000) called inside a loop.
    ExpensiveSyscallInLoop,
    /// A CPI invoke called inside a loop.
    CpiInLoop,
    /// A logging syscall called inside a loop.
    LoggingInLoop,
    /// A loop (SCC) with no CFG exit edge leaving the SCC.
    UnboundedLoop,
    /// A very expensive cryptographic operation (regardless of loop context).
    ExpensiveCryptoOp,
    /// An indirect call (CALL_REG / function pointer) that cannot be resolved statically.
    IndirectCall,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Returns `true` when `n` is a positive power of two.
fn is_power_of_two(n: i64) -> bool {
    n > 0 && (n & (n - 1)) == 0
}

/// Log-base-2 of a power of two. Panics if `n` is not a power of two.
fn log2(n: i64) -> u32 {
    debug_assert!(is_power_of_two(n));
    (n as u64).trailing_zeros()
}

/// Threshold above which a crypto operation is considered "expensive" and
/// flagged even outside of loops.
const EXPENSIVE_CRYPTO_THRESHOLD: u64 = 2_000;

/// Threshold above which a syscall inside a loop is flagged as expensive.
const EXPENSIVE_LOOP_SYSCALL_THRESHOLD: u64 = 1_000;

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

/// Scan the analysed bytecode for expensive or suboptimal patterns.
///
/// Returns all findings sorted by severity (Critical first) then by estimated
/// CU impact (descending).
pub fn detect_patterns(analysis: &Analysis<'_>) -> Vec<PatternMatch> {
    let mut matches = Vec::new();

    // -- Step 1: build loop-membership information from the CFG. --------
    //
    // An instruction index is "in a loop" when its owning CfgNode belongs to
    // a strongly-connected component (SCC) that contains more than one node.

    // scc_id -> set of cfg_node keys in that SCC
    let mut scc_groups: HashMap<usize, Vec<usize>> = HashMap::new();
    for (&node_key, node) in &analysis.cfg_nodes {
        let scc_id = node.topo_index.scc_id;
        if scc_id != usize::MAX {
            scc_groups.entry(scc_id).or_default().push(node_key);
        }
    }

    // Set of SCC ids that form real loops:
    // - multi-node SCCs, OR
    // - single-node SCCs with a self-edge (back-edge to itself).
    let loop_scc_ids: HashSet<usize> = scc_groups
        .iter()
        .filter(|(_, members)| {
            if members.len() > 1 {
                return true;
            }
            // Single-node SCC: check for self-loop
            if members.len() == 1 {
                if let Some(node) = analysis.cfg_nodes.get(&members[0]) {
                    return node.destinations.contains(&members[0]);
                }
            }
            false
        })
        .map(|(&id, _)| id)
        .collect();

    // Set of instruction indices that live inside a loop.
    let mut in_loop: HashSet<usize> = HashSet::new();
    for node in analysis.cfg_nodes.values() {
        let scc_id = node.topo_index.scc_id;
        if loop_scc_ids.contains(&scc_id) {
            for idx in node.instructions.clone() {
                in_loop.insert(idx);
            }
        }
    }

    // -- Step 2: detect unbounded loops. --------------------------------
    //
    // For each SCC that forms a loop, check whether *any* node in the SCC has
    // a CFG edge (destination) that exits the SCC. If none do, the loop has no
    // statically visible exit path and is potentially unbounded.

    for (scc_id, member_keys) in &scc_groups {
        if !loop_scc_ids.contains(scc_id) {
            continue;
        }

        let member_set: HashSet<usize> = member_keys.iter().copied().collect();

        let mut has_exit = false;
        for &key in member_keys {
            if let Some(node) = analysis.cfg_nodes.get(&key) {
                for &dest in &node.destinations {
                    if !member_set.contains(&dest) {
                        has_exit = true;
                        break;
                    }
                }
                if has_exit {
                    break;
                }
            }
        }

        if !has_exit {
            // Report on the first instruction of the first member node.
            let first_key = member_keys.iter().copied().min().unwrap_or(0);
            let pc = analysis
                .cfg_nodes
                .get(&first_key)
                .and_then(|n| analysis.instructions.get(n.instructions.start))
                .map(|insn| insn.ptr)
                .unwrap_or(first_key);

            matches.push(PatternMatch {
                pc,
                pattern: PatternKind::UnboundedLoop,
                severity: Severity::Critical,
                description: format!(
                    "Loop (SCC {scc_id}) has no CFG edge exiting the loop — \
                     potentially unbounded",
                ),
                suggestion: "Add a bounded loop counter or exit condition to prevent \
                             excessive CU consumption"
                    .into(),
                estimated_cu_impact: 200_000, // potential full-budget drain
            });
        }
    }

    // -- Step 3: linear scan of all instructions. -----------------------

    for (idx, insn) in analysis.instructions.iter().enumerate() {
        let pc = insn.ptr;
        let opc = insn.opc;
        let imm = insn.imm;
        let is_in_loop = in_loop.contains(&idx);

        // 3a. Multiply by power of two
        if (opc == ebpf::MUL64_IMM || opc == ebpf::MUL32_IMM) && is_power_of_two(imm) {
            let shift = log2(imm);
            let width = if opc == ebpf::MUL64_IMM { 64 } else { 32 };
            matches.push(PatternMatch {
                pc,
                pattern: PatternKind::MultiplyByPowerOfTwo,
                severity: Severity::Info,
                description: format!(
                    "mul{width} by {imm} (2^{shift}) can be replaced with a left shift",
                ),
                suggestion: format!("Use `lsh{} r{}, {}` instead", width, insn.dst, shift),
                estimated_cu_impact: 1,
            });
        }

        // 3b. Divide by power of two
        if (opc == ebpf::DIV64_IMM || opc == ebpf::DIV32_IMM) && is_power_of_two(imm) {
            let shift = log2(imm);
            let width = if opc == ebpf::DIV64_IMM { 64 } else { 32 };
            matches.push(PatternMatch {
                pc,
                pattern: PatternKind::DivideByPowerOfTwo,
                severity: Severity::Info,
                description: format!(
                    "div{width} by {imm} (2^{shift}) can be replaced with a right shift",
                ),
                suggestion: format!("Use `rsh{} r{}, {}` instead", width, insn.dst, shift),
                estimated_cu_impact: 1,
            });
        }

        // 3c. CALL_IMM — syscall analysis
        if opc == ebpf::CALL_IMM {
            let hash = imm as u32;

            if let Some(cost) = cost_model::syscall_cost_by_hash(hash) {
                // --- CPI in loop ---
                if is_in_loop && cost.category == SyscallCategory::CrossProgramInvocation {
                    matches.push(PatternMatch {
                        pc,
                        pattern: PatternKind::CpiInLoop,
                        severity: Severity::Critical,
                        description: format!(
                            "CPI call `{}` inside a loop — each invocation costs {}+ CU",
                            cost.name, cost.base_cost,
                        ),
                        suggestion: "Move CPI outside the loop or batch operations \
                                     into a single CPI call"
                            .into(),
                        estimated_cu_impact: cost.base_cost * 10, // assume ~10 iterations
                    });
                }
                // --- Logging in loop ---
                else if is_in_loop && cost.category == SyscallCategory::Logging {
                    matches.push(PatternMatch {
                        pc,
                        pattern: PatternKind::LoggingInLoop,
                        severity: Severity::Warning,
                        description: format!(
                            "Logging syscall `{}` inside a loop ({} CU each)",
                            cost.name, cost.base_cost,
                        ),
                        suggestion: "Remove logging from hot loops or gate behind a \
                                     debug flag / conditional"
                            .into(),
                        estimated_cu_impact: cost.base_cost * 10,
                    });
                }
                // --- Expensive syscall in loop (generic) ---
                else if is_in_loop && cost.base_cost > EXPENSIVE_LOOP_SYSCALL_THRESHOLD {
                    matches.push(PatternMatch {
                        pc,
                        pattern: PatternKind::ExpensiveSyscallInLoop,
                        severity: Severity::Critical,
                        description: format!(
                            "Expensive syscall `{}` ({} CU) called inside a loop",
                            cost.name, cost.base_cost,
                        ),
                        suggestion: "Hoist the syscall out of the loop if possible, \
                                     or reduce the number of iterations"
                            .into(),
                        estimated_cu_impact: cost.base_cost * 10,
                    });
                }

                // --- Expensive crypto op (regardless of loop) ---
                if cost.category == SyscallCategory::Crypto
                    && cost.base_cost >= EXPENSIVE_CRYPTO_THRESHOLD
                {
                    matches.push(PatternMatch {
                        pc,
                        pattern: PatternKind::ExpensiveCryptoOp,
                        severity: Severity::Warning,
                        description: format!(
                            "Expensive cryptographic operation `{}` costs {} CU per call",
                            cost.name, cost.base_cost,
                        ),
                        suggestion: "Ensure this crypto operation is necessary; consider \
                                     caching results or using a cheaper alternative if \
                                     available"
                            .into(),
                        estimated_cu_impact: cost.base_cost,
                    });
                }
            }
        }

        // 3d. CALL_REG — indirect call (function pointer / vtable dispatch)
        if opc == ebpf::CALL_REG {
            matches.push(PatternMatch {
                pc,
                pattern: PatternKind::IndirectCall,
                severity: Severity::Warning,
                description: format!(
                    "Indirect call via register r{} — target cannot be resolved statically",
                    insn.imm,
                ),
                suggestion: "CU cost of the callee is unknown; consider using direct calls \
                             where possible for more predictable compute usage"
                    .into(),
                estimated_cu_impact: 0, // unknown
            });
        }
    }

    // -- Step 4: sort by severity (Critical > Warning > Info) then by
    //    estimated CU impact descending. ---------------------------------

    matches.sort_by(|a, b| {
        // Reverse severity order: Critical (2) > Warning (1) > Info (0)
        let sev_a = severity_rank(&a.severity);
        let sev_b = severity_rank(&b.severity);
        sev_b
            .cmp(&sev_a)
            .then_with(|| b.estimated_cu_impact.cmp(&a.estimated_cu_impact))
    });

    matches
}

/// Map severity to a numeric rank for sorting (higher = more severe).
fn severity_rank(s: &Severity) -> u8 {
    match s {
        Severity::Info => 0,
        Severity::Warning => 1,
        Severity::Critical => 2,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_power_of_two() {
        assert!(is_power_of_two(1));
        assert!(is_power_of_two(2));
        assert!(is_power_of_two(4));
        assert!(is_power_of_two(8));
        assert!(is_power_of_two(1024));
        assert!(!is_power_of_two(0));
        assert!(!is_power_of_two(-1));
        assert!(!is_power_of_two(3));
        assert!(!is_power_of_two(6));
        assert!(!is_power_of_two(7));
    }

    #[test]
    fn test_log2() {
        assert_eq!(log2(1), 0);
        assert_eq!(log2(2), 1);
        assert_eq!(log2(4), 2);
        assert_eq!(log2(8), 3);
        assert_eq!(log2(256), 8);
        assert_eq!(log2(1024), 10);
    }

    #[test]
    fn test_severity_ordering() {
        assert!(severity_rank(&Severity::Critical) > severity_rank(&Severity::Warning));
        assert!(severity_rank(&Severity::Warning) > severity_rank(&Severity::Info));
    }
}

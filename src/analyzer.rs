use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};

use anyhow::Result;
use serde::{Deserialize, Serialize};
use solana_sbpf::{ebpf, static_analysis::Analysis};

use crate::cost_model;

/// Default assumed loop iteration count when no bound can be inferred.
pub const DEFAULT_LOOP_ITERATIONS: u64 = 10;

/// Configuration for the analysis pass.
#[derive(Debug, Clone)]
pub struct AnalysisConfig {
    /// Fallback iteration count for loops where no bound can be statically inferred.
    pub default_loop_iterations: u64,
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        Self {
            default_loop_iterations: DEFAULT_LOOP_ITERATIONS,
        }
    }
}

/// Full analysis result for an sBPF program.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResult {
    /// Per-function analysis, sorted by estimated CU descending.
    pub functions: Vec<FunctionAnalysis>,
    /// Upper-bound estimated CU summed across all functions.
    /// Note: this sums every function in the binary, including unreachable ones.
    /// A single transaction will only execute a subset of these functions.
    pub total_estimated_cu: u64,
    /// Estimated CU summed across only functions reachable from the entrypoint.
    pub reachable_estimated_cu: u64,
    /// Program name (derived from entrypoint function name or "unknown").
    pub program_name: String,
    /// Version tag of the cost model used for this analysis.
    pub cost_model_version: String,
}

/// Analysis of a single function in the program.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionAnalysis {
    /// Demangled function name.
    pub name: String,
    /// Entry PC (instruction offset).
    pub entry_pc: usize,
    /// Total number of instructions in this function.
    pub instruction_count: usize,
    /// All-paths upper-bound estimated compute units (sums every basic block).
    pub estimated_cu: u64,
    /// Worst-case CU along a single execution path through the CFG (longest path
    /// in the condensed DAG with SCCs collapsed).
    pub worst_case_cu: u64,
    /// Confidence percentage (0.0–100.0). Indicates what fraction of the CU
    /// estimate is based on static facts vs default assumptions (e.g. loop bounds).
    pub confidence_pct: f64,
    /// Worst-case CU including costs of internal (non-syscall) callees.
    /// Equals `worst_case_cu` when no internal calls are present.
    pub interprocedural_cu: u64,
    /// Detected loops (SCCs with more than one node or self-loops).
    pub loops: Vec<LoopInfo>,
    /// Syscall invocations found in this function.
    pub syscalls: Vec<SyscallInfo>,
}

/// How the loop iteration bound was determined.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum LoopBoundSource {
    /// Extracted from a conditional branch with an immediate operand (e.g., `jlt r0, 32`).
    StaticImmediate,
    /// No bound could be inferred; using the configured default.
    DefaultAssumption,
}

/// Information about a detected loop.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoopInfo {
    /// PC of the loop header (lowest PC in the SCC).
    pub start_pc: usize,
    /// PC of the last instruction in the loop (highest PC in the SCC).
    pub end_pc: usize,
    /// Strongly connected component ID from Tarjan's algorithm.
    pub scc_id: usize,
    /// Number of instructions in the loop body.
    pub instruction_count: usize,
    /// Estimated CU per single iteration of the loop.
    pub estimated_cu_per_iteration: u64,
    /// Estimated number of iterations for this loop.
    pub estimated_iterations: u64,
    /// How the iteration bound was determined.
    pub bound_source: LoopBoundSource,
    /// Syscalls invoked within the loop body.
    pub contains_syscalls: Vec<SyscallInfo>,
}

/// Information about a syscall invocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallInfo {
    /// PC where the CALL_IMM instruction occurs.
    pub pc: usize,
    /// Human-readable syscall name.
    pub name: String,
    /// Murmur3 hash used by the sBPF runtime.
    pub hash: u32,
    /// Base CU cost of this syscall.
    pub base_cost: u64,
    /// Estimated total cost including per-byte costs (if data size could be inferred).
    /// Falls back to base_cost when data size is unknown.
    pub estimated_total_cost: u64,
    /// Category of the syscall.
    pub category: crate::cost_model::SyscallCategory,
}

/// Run the full static analysis pipeline with default config.
pub fn run_analysis(analysis: &Analysis<'_>) -> Result<AnalysisResult> {
    run_analysis_with_config(analysis, &AnalysisConfig::default())
}

/// Run the full static analysis pipeline with custom config.
///
/// 1. Walks each function's basic blocks
/// 2. Detects loops via SCC analysis
/// 3. Extracts loop bounds only for simple counted loops where the pattern is unambiguous
/// 4. Estimates compute unit costs (all-paths upper bound and worst-case single path)
/// 5. Computes interprocedural CU by resolving internal CALL_IMM targets
/// 6. Returns results sorted by estimated CU (hottest first)
pub fn run_analysis_with_config(
    analysis: &Analysis<'_>,
    config: &AnalysisConfig,
) -> Result<AnalysisResult> {
    let function_entry_pcs: BTreeSet<usize> = analysis.functions.keys().copied().collect();
    let hash_to_pc: HashMap<u32, usize> = analysis
        .functions
        .iter()
        .map(|(&pc, (hash, _))| (*hash, pc))
        .collect();

    let program_name = analysis
        .functions
        .get(&analysis.entrypoint)
        .map(|(_, name)| name.clone())
        .unwrap_or_else(|| "unknown".to_string());

    let mut functions = Vec::new();
    // Cache function node sets to avoid recomputing for reachability analysis.
    let mut function_node_cache: HashMap<usize, Vec<usize>> = HashMap::new();

    for (&entry_pc, (_hash, name)) in &analysis.functions {
        let nodes = collect_function_nodes(entry_pc, analysis, &function_entry_pcs);
        let func_analysis = analyze_function_from_nodes(&nodes, entry_pc, name, analysis, config)?;
        function_node_cache.insert(entry_pc, nodes);
        functions.push(func_analysis);
    }

    // --- Interprocedural CU propagation ---
    let entry_pc_to_worst_cu: HashMap<usize, u64> = functions
        .iter()
        .map(|func| (func.entry_pc, func.worst_case_cu))
        .collect();
    let direct_callees = build_direct_callee_map(analysis, &function_node_cache, &hash_to_pc);
    let mut transitive_callee_cache: HashMap<usize, HashSet<usize>> = HashMap::new();

    for func in &mut functions {
        let transitive_callees = collect_transitive_callees(
            func.entry_pc,
            &direct_callees,
            &mut transitive_callee_cache,
            &mut HashSet::new(),
        );
        let callee_cu: u64 = transitive_callees
            .iter()
            .filter_map(|target_pc| entry_pc_to_worst_cu.get(target_pc))
            .copied()
            .sum();
        func.interprocedural_cu = func.worst_case_cu.saturating_add(callee_cu);
    }

    functions.sort_by(|a, b| b.estimated_cu.cmp(&a.estimated_cu));

    let total_estimated_cu: u64 = functions.iter().map(|f| f.estimated_cu).sum();

    // Reachability: walk CALL_IMM targets from entrypoint using cached nodes.
    let reachable_pcs = compute_reachable_functions(analysis, &function_node_cache, &hash_to_pc);
    let reachable_estimated_cu: u64 = functions
        .iter()
        .filter(|f| reachable_pcs.contains(&f.entry_pc))
        .map(|f| f.estimated_cu)
        .sum();

    Ok(AnalysisResult {
        functions,
        total_estimated_cu,
        reachable_estimated_cu,
        program_name,
        cost_model_version: cost_model::COST_MODEL_VERSION.to_string(),
    })
}

/// Analyze a single function from pre-computed CFG nodes.
fn analyze_function_from_nodes(
    function_nodes: &[usize],
    entry_pc: usize,
    name: &str,
    analysis: &Analysis<'_>,
    config: &AnalysisConfig,
) -> Result<FunctionAnalysis> {
    if function_nodes.is_empty() {
        return Ok(FunctionAnalysis {
            name: name.to_string(),
            entry_pc,
            instruction_count: 0,
            estimated_cu: 0,
            worst_case_cu: 0,
            confidence_pct: 100.0,
            interprocedural_cu: 0,
            loops: vec![],
            syscalls: vec![],
        });
    }
    let mut instruction_count: usize = 0;
    let mut syscalls = Vec::new();
    let mut base_cu: u64 = 0;

    // Per-block weight for worst-case path computation.
    let mut block_weight: HashMap<usize, u64> = HashMap::new();

    let mut scc_groups: HashMap<usize, Vec<usize>> = HashMap::new();

    for &node_pc in function_nodes {
        if let Some(cfg_node) = analysis.cfg_nodes.get(&node_pc) {
            let block_insn_count = cfg_node.instructions.len();
            instruction_count += block_insn_count;
            base_cu += block_insn_count as u64;
            let mut bw: u64 = block_insn_count as u64;

            for idx in cfg_node.instructions.clone() {
                if idx < analysis.instructions.len() {
                    let insn = &analysis.instructions[idx];
                    if insn.opc == ebpf::CALL_IMM {
                        let data_size = infer_data_size(idx, analysis);
                        if let Some(syscall_info) = resolve_syscall(insn, data_size) {
                            base_cu += syscall_info.estimated_total_cost;
                            bw += syscall_info.estimated_total_cost;
                            syscalls.push(syscall_info);
                        }
                    }
                }
            }

            block_weight.insert(node_pc, bw);

            let scc_id = cfg_node.topo_index.scc_id;
            if scc_id != usize::MAX {
                scc_groups.entry(scc_id).or_default().push(node_pc);
            }
        }
    }

    let loops = detect_loops(&scc_groups, analysis, config);

    let loop_overhead: u64 = loops
        .iter()
        .map(|l| l.estimated_cu_per_iteration * (l.estimated_iterations.saturating_sub(1)))
        .sum();
    let estimated_cu = base_cu + loop_overhead;

    // --- Worst-case CU via condensed DAG longest path ---
    let worst_case_cu = compute_worst_case_cu(
        function_nodes,
        &block_weight,
        &scc_groups,
        &loops,
        analysis,
        estimated_cu,
    );

    // --- Confidence percentage ---
    let assumed_loop_cu: u64 = loops
        .iter()
        .filter(|l| l.bound_source == LoopBoundSource::DefaultAssumption)
        .map(|l| l.estimated_cu_per_iteration * l.estimated_iterations.saturating_sub(1))
        .sum();
    let confidence_pct = if worst_case_cu > 0 {
        let pct =
            ((worst_case_cu.saturating_sub(assumed_loop_cu)) as f64 / worst_case_cu as f64) * 100.0;
        pct.clamp(0.0, 100.0)
    } else {
        100.0
    };

    Ok(FunctionAnalysis {
        name: name.to_string(),
        entry_pc,
        instruction_count,
        estimated_cu,
        worst_case_cu,
        confidence_pct,
        interprocedural_cu: worst_case_cu, // Updated later in interprocedural pass
        loops,
        syscalls,
    })
}

/// Compute worst-case CU along a single execution path using a condensed DAG.
///
/// 1. Map each CFG node to a condensed ID (loop members share min-PC, others keep own PC)
/// 2. Compute condensed node weights (loops: worst single iteration path * iterations)
/// 3. Build condensed DAG edges (skip intra-SCC edges)
/// 4. Topological sort via Kahn's algorithm
/// 5. DP longest path
/// 6. Fall back to estimated_cu if topo sort fails (unexpected cycle)
fn compute_worst_case_cu(
    function_nodes: &[usize],
    block_weight: &HashMap<usize, u64>,
    scc_groups: &HashMap<usize, Vec<usize>>,
    loops: &[LoopInfo],
    analysis: &Analysis<'_>,
    fallback_cu: u64,
) -> u64 {
    if function_nodes.is_empty() {
        return 0;
    }

    // Build a set of all SCC node PCs for quick membership checks, and map each
    // node PC to its condensed ID (min PC in its SCC for loop members).
    let mut node_to_condensed: HashMap<usize, usize> = HashMap::new();
    let mut scc_id_to_loop: HashMap<usize, &LoopInfo> = HashMap::new();

    for loop_info in loops {
        // Find the SCC group that matches this loop by scc_id.
        if let Some(members) = scc_groups.get(&loop_info.scc_id) {
            let min_pc = *members.iter().min().unwrap_or(&loop_info.start_pc);
            for &pc in members {
                node_to_condensed.insert(pc, min_pc);
            }
            scc_id_to_loop.insert(loop_info.scc_id, loop_info);
        }
    }

    // Non-loop nodes map to themselves.
    for &pc in function_nodes {
        node_to_condensed.entry(pc).or_insert(pc);
    }

    // Compute condensed node weights.
    let mut condensed_weight: HashMap<usize, u64> = HashMap::new();

    // For loop condensed nodes: worst single iteration path * iterations.
    for (&scc_id, members) in scc_groups {
        if let Some(loop_info) = scc_id_to_loop.get(&scc_id) {
            let min_pc = *members.iter().min().unwrap_or(&0);
            let single_iteration_weight =
                compute_loop_single_iteration_weight(members, block_weight, analysis);
            let weight = single_iteration_weight * loop_info.estimated_iterations;
            // Accumulate in case multiple SCC groups condense to same node (shouldn't happen,
            // but be safe).
            *condensed_weight.entry(min_pc).or_insert(0) += weight;
        }
    }

    // For non-loop nodes: just their block weight. Loop nodes already have
    // their condensed weight set above, so `or_insert_with` is a no-op for them.
    for &pc in function_nodes {
        let cid = node_to_condensed[&pc];
        condensed_weight
            .entry(cid)
            .or_insert_with(|| block_weight.get(&pc).copied().unwrap_or(0));
    }

    // Build condensed DAG edges.
    let mut condensed_nodes: HashSet<usize> = HashSet::new();
    let mut condensed_edges: HashMap<usize, HashSet<usize>> = HashMap::new();
    let mut in_degree: HashMap<usize, usize> = HashMap::new();

    for &pc in function_nodes {
        let from_cid = node_to_condensed[&pc];
        condensed_nodes.insert(from_cid);
    }

    for &cid in &condensed_nodes {
        in_degree.entry(cid).or_insert(0);
    }

    for &pc in function_nodes {
        let from_cid = node_to_condensed[&pc];
        if let Some(cfg_node) = analysis.cfg_nodes.get(&pc) {
            for &dest in &cfg_node.destinations {
                if let Some(&to_cid) = node_to_condensed.get(&dest) {
                    if from_cid != to_cid
                        && condensed_edges.entry(from_cid).or_default().insert(to_cid)
                    {
                        *in_degree.entry(to_cid).or_insert(0) += 1;
                    }
                }
            }
        }
    }

    // Kahn's topological sort.
    let mut queue: VecDeque<usize> = VecDeque::new();
    for (&node, &deg) in &in_degree {
        if deg == 0 {
            queue.push_back(node);
        }
    }

    let mut topo_order: Vec<usize> = Vec::new();
    let mut remaining_in_degree = in_degree.clone();

    while let Some(node) = queue.pop_front() {
        topo_order.push(node);
        if let Some(neighbors) = condensed_edges.get(&node) {
            for &next in neighbors {
                let deg = remaining_in_degree.get_mut(&next).unwrap();
                *deg -= 1;
                if *deg == 0 {
                    queue.push_back(next);
                }
            }
        }
    }

    // If topo sort didn't visit all nodes, there's an unexpected cycle. Fall back.
    if topo_order.len() != condensed_nodes.len() {
        return fallback_cu;
    }

    // DP longest path: dist[node] = weight[node] + max(dist[predecessors]).
    // We need predecessors, so build a reverse adjacency list.
    let mut reverse_edges: HashMap<usize, Vec<usize>> = HashMap::new();
    for (&from, tos) in &condensed_edges {
        for &to in tos {
            reverse_edges.entry(to).or_default().push(from);
        }
    }

    let mut dist: HashMap<usize, u64> = HashMap::new();
    for &node in &topo_order {
        let w = condensed_weight.get(&node).copied().unwrap_or(0);
        let max_pred = reverse_edges
            .get(&node)
            .and_then(|preds| preds.iter().filter_map(|p| dist.get(p)).max().copied())
            .unwrap_or(0);
        dist.insert(node, w + max_pred);
    }

    dist.values().copied().max().unwrap_or(0)
}

fn compute_loop_single_iteration_weight(
    members: &[usize],
    block_weight: &HashMap<usize, u64>,
    analysis: &Analysis<'_>,
) -> u64 {
    if members.is_empty() {
        return 0;
    }

    let member_set: HashSet<usize> = members.iter().copied().collect();
    let mut forward_edges: HashMap<usize, HashSet<usize>> = HashMap::new();
    let mut in_degree: HashMap<usize, usize> = members.iter().map(|&pc| (pc, 0)).collect();

    // Approximate one loop iteration by keeping only forward intra-SCC edges.
    // This preserves mutually exclusive branches but excludes the back-edge that
    // would otherwise force us to charge every SCC block every iteration.
    for &pc in members {
        let Some(cfg_node) = analysis.cfg_nodes.get(&pc) else {
            continue;
        };
        for &dest in &cfg_node.destinations {
            if member_set.contains(&dest)
                && dest > pc
                && forward_edges.entry(pc).or_default().insert(dest)
            {
                *in_degree.entry(dest).or_insert(0) += 1;
            }
        }
    }

    let mut topo_order = Vec::new();
    let mut queue: VecDeque<usize> = in_degree
        .iter()
        .filter_map(|(&pc, &deg)| (deg == 0).then_some(pc))
        .collect();
    let mut remaining_in_degree = in_degree.clone();

    while let Some(pc) = queue.pop_front() {
        topo_order.push(pc);
        if let Some(neighbors) = forward_edges.get(&pc) {
            for &next in neighbors {
                let deg = remaining_in_degree.get_mut(&next).unwrap();
                *deg -= 1;
                if *deg == 0 {
                    queue.push_back(next);
                }
            }
        }
    }

    if topo_order.len() != members.len() {
        return members
            .iter()
            .map(|pc| block_weight.get(pc).copied().unwrap_or(0))
            .sum();
    }

    let mut reverse_edges: HashMap<usize, Vec<usize>> = HashMap::new();
    for (&from, tos) in &forward_edges {
        for &to in tos {
            reverse_edges.entry(to).or_default().push(from);
        }
    }

    let mut dist: HashMap<usize, u64> = HashMap::new();
    for &pc in &topo_order {
        let weight = block_weight.get(&pc).copied().unwrap_or(0);
        let max_pred = reverse_edges
            .get(&pc)
            .and_then(|preds| {
                preds
                    .iter()
                    .filter_map(|pred| dist.get(pred))
                    .max()
                    .copied()
            })
            .unwrap_or(0);
        dist.insert(pc, weight + max_pred);
    }

    dist.values().copied().max().unwrap_or(0)
}

/// Collect all CFG node PCs that belong to a specific function.
fn collect_function_nodes(
    entry_pc: usize,
    analysis: &Analysis<'_>,
    function_entry_pcs: &BTreeSet<usize>,
) -> Vec<usize> {
    let mut visited = HashSet::new();
    let mut stack = vec![entry_pc];
    let mut nodes = Vec::new();

    while let Some(pc) = stack.pop() {
        if !visited.insert(pc) {
            continue;
        }
        if pc != entry_pc && function_entry_pcs.contains(&pc) {
            continue;
        }
        if let Some(cfg_node) = analysis.cfg_nodes.get(&pc) {
            nodes.push(pc);
            for &dest_pc in &cfg_node.destinations {
                if !visited.contains(&dest_pc) {
                    stack.push(dest_pc);
                }
            }
        }
    }

    nodes.sort_unstable();
    nodes
}

/// Compute the set of function entry PCs reachable from the entrypoint via CALL_IMM.
/// Uses pre-computed function node sets to avoid duplicate CFG traversals.
fn compute_reachable_functions(
    analysis: &Analysis<'_>,
    function_node_cache: &HashMap<usize, Vec<usize>>,
    hash_to_pc: &HashMap<u32, usize>,
) -> HashSet<usize> {
    let mut reachable = HashSet::new();
    let mut stack = vec![analysis.entrypoint];

    while let Some(entry_pc) = stack.pop() {
        if !reachable.insert(entry_pc) {
            continue;
        }

        let Some(nodes) = function_node_cache.get(&entry_pc) else {
            continue;
        };

        for &node_pc in nodes {
            let Some(cfg_node) = analysis.cfg_nodes.get(&node_pc) else {
                continue;
            };

            for idx in cfg_node.instructions.clone() {
                if let Some(insn) = analysis.instructions.get(idx) {
                    if let Some(target_pc) =
                        resolve_internal_call_target_pc(insn, analysis, hash_to_pc)
                    {
                        if !reachable.contains(&target_pc) {
                            stack.push(target_pc);
                        }
                    }
                }
            }
        }
    }

    reachable
}

fn resolve_internal_call_target_pc(
    insn: &ebpf::Insn,
    analysis: &Analysis<'_>,
    hash_to_pc: &HashMap<u32, usize>,
) -> Option<usize> {
    if insn.opc != ebpf::CALL_IMM {
        return None;
    }

    // SBPF v3+ encodes internal calls as PC-relative CALL_IMM with src == 1.
    if insn.src == 1 {
        let target_pc = (insn.ptr as i64).saturating_add(insn.imm).saturating_add(1);
        if target_pc < 0 {
            return None;
        }
        let target_pc = target_pc as usize;
        return analysis
            .functions
            .contains_key(&target_pc)
            .then_some(target_pc);
    }

    let hash = insn.imm as u32;
    if cost_model::syscall_cost_by_hash(hash).is_some() {
        None
    } else {
        hash_to_pc.get(&hash).copied()
    }
}

fn build_direct_callee_map(
    analysis: &Analysis<'_>,
    function_node_cache: &HashMap<usize, Vec<usize>>,
    hash_to_pc: &HashMap<u32, usize>,
) -> HashMap<usize, HashSet<usize>> {
    function_node_cache
        .iter()
        .map(|(&entry_pc, nodes)| {
            let mut callees = HashSet::new();
            for &node_pc in nodes {
                let Some(cfg_node) = analysis.cfg_nodes.get(&node_pc) else {
                    continue;
                };
                for idx in cfg_node.instructions.clone() {
                    if let Some(insn) = analysis.instructions.get(idx) {
                        if let Some(target_pc) =
                            resolve_internal_call_target_pc(insn, analysis, hash_to_pc)
                        {
                            callees.insert(target_pc);
                        }
                    }
                }
            }
            (entry_pc, callees)
        })
        .collect()
}

fn collect_transitive_callees(
    entry_pc: usize,
    direct_callees: &HashMap<usize, HashSet<usize>>,
    cache: &mut HashMap<usize, HashSet<usize>>,
    visiting: &mut HashSet<usize>,
) -> HashSet<usize> {
    if let Some(cached) = cache.get(&entry_pc) {
        return cached.clone();
    }
    if !visiting.insert(entry_pc) {
        return HashSet::new();
    }

    let mut transitive = HashSet::new();
    if let Some(direct) = direct_callees.get(&entry_pc) {
        for &callee in direct {
            if visiting.contains(&callee) {
                continue;
            }
            transitive.insert(callee);
            transitive.extend(collect_transitive_callees(
                callee,
                direct_callees,
                cache,
                visiting,
            ));
        }
    }

    visiting.remove(&entry_pc);
    cache.insert(entry_pc, transitive.clone());
    transitive
}

/// Resolve a CALL_IMM instruction to syscall information, if it's a known syscall.
/// `data_size_hint` is an optional inferred data size from constant propagation.
fn resolve_syscall(insn: &ebpf::Insn, data_size_hint: Option<u64>) -> Option<SyscallInfo> {
    let hash = insn.imm as u32;
    cost_model::syscall_cost_by_hash(hash).map(|cost| {
        let estimated_total_cost = match (cost.per_byte_cost, data_size_hint) {
            (Some(per_byte), Some(size)) => cost.base_cost + per_byte * size,
            _ => cost.base_cost,
        };
        SyscallInfo {
            pc: insn.ptr,
            name: cost.name.to_string(),
            hash,
            base_cost: cost.base_cost,
            estimated_total_cost,
            category: cost.category,
        }
    })
}

/// Try to infer the data size passed to a syscall by looking backward from the
/// call site for a MOV64_IMM that loads the "length" register.
///
/// Solana syscalls typically take the data size in one of the argument registers
/// (r2-r5). We do a simple backward scan for the most recent MOV_IMM to any
/// of these registers.
/// Maximum data size we consider plausible (Solana max account size is ~10MB).
const MAX_INFERRED_DATA_SIZE: u64 = 10 * 1024 * 1024;

fn infer_data_size(call_idx: usize, analysis: &Analysis<'_>) -> Option<u64> {
    // Scan backward up to 8 instructions looking for MOV64_IMM to r2-r5.
    // `insn.imm` is i64; the `> 0` guard filters out negative values (which
    // arise from sign-extended i32 immediates), so the `as u64` cast is safe.
    let start = call_idx.saturating_sub(8);
    for idx in (start..call_idx).rev() {
        if let Some(insn) = analysis.instructions.get(idx) {
            if insn.opc == ebpf::EXIT {
                break;
            }
            if insn.opc == ebpf::MOV64_IMM && (2..=5).contains(&insn.dst) && insn.imm > 0 {
                let size = insn.imm as u64;
                if size <= MAX_INFERRED_DATA_SIZE {
                    return Some(size);
                }
            }
        }
    }
    None
}

fn boundary_loop_guard_bound(insn: &ebpf::Insn, scc_set: &HashSet<usize>) -> Option<u64> {
    let class = insn.opc & ebpf::BPF_CLS_MASK;
    let is_imm = (insn.opc & ebpf::BPF_X) == 0;
    if (class != ebpf::BPF_JMP64 && class != ebpf::BPF_JMP32) || !is_imm || insn.imm <= 0 {
        return None;
    }

    let op = insn.opc & ebpf::BPF_ALU_OP_MASK;
    let target_pc = (insn.ptr as i64 + insn.off as i64 + 1) as usize;
    let fallthrough_pc = insn.ptr + 1;
    let target_in_loop = scc_set.contains(&target_pc);
    let fallthrough_in_loop = scc_set.contains(&fallthrough_pc);

    // Only use guards that form the loop boundary: exactly one path stays in the SCC
    // and the other exits it.
    if target_in_loop == fallthrough_in_loop {
        return None;
    }

    match op {
        ebpf::BPF_JLT | ebpf::BPF_JSLT => Some(insn.imm as u64),
        ebpf::BPF_JLE | ebpf::BPF_JSLE => Some((insn.imm as u64).saturating_add(1)),
        _ => None,
    }
}

fn has_unit_step_increment(reg: u8, node_pcs: &[usize], analysis: &Analysis<'_>) -> bool {
    node_pcs.iter().any(|pc| {
        let Some(cfg_node) = analysis.cfg_nodes.get(pc) else {
            return false;
        };

        cfg_node.instructions.clone().any(|idx| {
            analysis.instructions.get(idx).is_some_and(|insn| {
                insn.dst == reg
                    && insn.imm == 1
                    && matches!(insn.opc, ebpf::ADD64_IMM | ebpf::ADD32_IMM)
            })
        })
    })
}

fn has_nearby_zero_initializer(reg: u8, guard_idx: usize, analysis: &Analysis<'_>) -> bool {
    let start = guard_idx.saturating_sub(8);
    for idx in (start..guard_idx).rev() {
        let Some(insn) = analysis.instructions.get(idx) else {
            continue;
        };
        if insn.opc == ebpf::EXIT {
            break;
        }
        if insn.dst == reg && insn.imm == 0 && matches!(insn.opc, ebpf::MOV64_IMM | ebpf::MOV32_IMM)
        {
            return true;
        }
    }
    false
}

/// Try to extract a static loop bound from the instructions in an SCC.
///
/// This is intentionally conservative: we only infer a bound for a canonical
/// counted loop with a single boundary guard, a unit-step increment inside the
/// loop body, and a nearby zero initializer for the compared register.
fn extract_loop_bound(node_pcs: &[usize], analysis: &Analysis<'_>) -> Option<u64> {
    let scc_set: HashSet<usize> = node_pcs.iter().copied().collect();
    let mut candidates = Vec::new();

    for &pc in node_pcs {
        let Some(cfg_node) = analysis.cfg_nodes.get(&pc) else {
            continue;
        };
        if cfg_node.instructions.is_empty() {
            continue;
        }

        let last_idx = cfg_node.instructions.end - 1;
        let Some(insn) = analysis.instructions.get(last_idx) else {
            continue;
        };
        let Some(bound) = boundary_loop_guard_bound(insn, &scc_set) else {
            continue;
        };

        // Reject implausibly large bounds and loops that do not look like a
        // canonical `for i in 0..N` pattern.
        let has_increment = has_unit_step_increment(insn.dst, node_pcs, analysis);
        let has_initializer = has_nearby_zero_initializer(insn.dst, last_idx, analysis);
        if bound > 100_000 || !has_increment || !has_initializer {
            continue;
        }

        candidates.push(bound);
    }

    if candidates.len() == 1 {
        candidates.pop()
    } else {
        None
    }
}

/// Detect loops from SCC groupings.
fn detect_loops(
    scc_groups: &HashMap<usize, Vec<usize>>,
    analysis: &Analysis<'_>,
    config: &AnalysisConfig,
) -> Vec<LoopInfo> {
    let mut loops = Vec::new();

    for (&scc_id, node_pcs) in scc_groups {
        let is_multi_node_scc = node_pcs.len() > 1;
        let is_self_loop = node_pcs.len() == 1 && {
            let pc = node_pcs[0];
            analysis
                .cfg_nodes
                .get(&pc)
                .map(|n| n.destinations.contains(&pc))
                .unwrap_or(false)
        };

        if !is_multi_node_scc && !is_self_loop {
            continue;
        }

        let mut instruction_count: usize = 0;
        let mut cu_per_iteration: u64 = 0;
        let mut loop_syscalls = Vec::new();
        let mut start_pc = usize::MAX;
        let mut end_pc: usize = 0;

        for &pc in node_pcs {
            if pc < start_pc {
                start_pc = pc;
            }

            if let Some(cfg_node) = analysis.cfg_nodes.get(&pc) {
                let block_len = cfg_node.instructions.len();
                instruction_count += block_len;
                cu_per_iteration += block_len as u64;

                if !cfg_node.instructions.is_empty() {
                    let last_idx = cfg_node.instructions.end - 1;
                    if last_idx < analysis.instructions.len() {
                        let last_insn_pc = analysis.instructions[last_idx].ptr;
                        if last_insn_pc > end_pc {
                            end_pc = last_insn_pc;
                        }
                    }
                }

                for idx in cfg_node.instructions.clone() {
                    if idx < analysis.instructions.len() {
                        let insn = &analysis.instructions[idx];
                        if insn.opc == ebpf::CALL_IMM {
                            let data_size = infer_data_size(idx, analysis);
                            if let Some(syscall_info) = resolve_syscall(insn, data_size) {
                                cu_per_iteration += syscall_info.estimated_total_cost;
                                loop_syscalls.push(syscall_info);
                            }
                        }
                    }
                }
            }
        }

        if start_pc == usize::MAX {
            start_pc = 0;
        }

        // Try to extract a static bound; fall back to configured default.
        let (estimated_iterations, bound_source) = match extract_loop_bound(node_pcs, analysis) {
            Some(bound) => (bound, LoopBoundSource::StaticImmediate),
            None => (
                config.default_loop_iterations,
                LoopBoundSource::DefaultAssumption,
            ),
        };

        loops.push(LoopInfo {
            start_pc,
            end_pc,
            scc_id,
            instruction_count,
            estimated_cu_per_iteration: cu_per_iteration,
            estimated_iterations,
            bound_source,
            contains_syscalls: loop_syscalls,
        });
    }

    loops.sort_by_key(|l| l.start_pc);
    loops
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_syscall_info_serialization() {
        let info = SyscallInfo {
            pc: 42,
            name: "sol_log_".to_string(),
            hash: 0x12345678,
            base_cost: 100,
            estimated_total_cost: 100,
            category: cost_model::SyscallCategory::Logging,
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("sol_log_"));
        assert!(json.contains("Logging"));
    }

    #[test]
    fn test_loop_bound_source_serialization() {
        let json = serde_json::to_string(&LoopBoundSource::StaticImmediate).unwrap();
        assert!(json.contains("StaticImmediate"));
        let json = serde_json::to_string(&LoopBoundSource::DefaultAssumption).unwrap();
        assert!(json.contains("DefaultAssumption"));
    }

    #[test]
    fn test_analysis_config_default() {
        let config = AnalysisConfig::default();
        assert_eq!(config.default_loop_iterations, DEFAULT_LOOP_ITERATIONS);
    }
}

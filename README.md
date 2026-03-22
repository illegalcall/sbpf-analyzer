# sbpf-analyzer

Static compute unit analyzer for Solana sBPF programs. Feed it a compiled `.so` file, get back a ranked report of which functions burn the most CUs, where the loops are, and what to optimize — before you deploy.

```
$ sbpf-analyze program.so

═══════════════════════════════════════════════════════
  SBPF STATIC ANALYSIS REPORT
  Program: entrypoint
  Total estimated CU: 191,884 (reachable: 56)
═══════════════════════════════════════════════════════

FUNCTION: process_instruction (worst-case: 6,721 CU, upper-bound: 15,034 CU) (0% static)
  Instructions: 2400 | Entry: 0x7979
  Syscalls: sol_log_ (100 CU, ~118 CU with data), abort (100 CU) ...
  ⚠ Loop at 0x7c8e–0x82bd: 188 insns × 523 CU/iter × ~10 iters (assumed)
     Syscalls in loop: abort (100 CU), sol_log_ (100 CU)

OPTIMIZATION OPPORTUNITIES
───────────────────────────────────────────────────────
  🔴 [CRITICAL] Unbounded loop — no exit edge detected (est. 200,000 CU)
  🟡 [WARNING]  sol_log_ inside a loop (100 CU × iterations)
  🟡 [WARNING]  Indirect call — target unresolvable statically
```

## Why

Solana programs have a hard **1.4M CU cap per transaction**. Exceed it and the transaction fails — the user still pays fees. Every serious protocol team manually audits for CU efficiency. There is no good open-source static analysis tooling for this.

`sbpf-analyzer` is the tool that should exist but doesn't.

## Install

```bash
cargo install --path .
```

Or build from source:

```bash
git clone https://github.com/illegalcall/sbpf-analyzer.git
cd sbpf-analyzer
cargo build --release
# Binary at ./target/release/sbpf-analyze
```

## Quick Start

### Analyze a local `.so` file

```bash
# Analyze a compiled Solana program
sbpf-analyze target/deploy/my_program.so

# JSON output (for CI/tooling)
sbpf-analyze target/deploy/my_program.so --json
```

### Analyze a deployed mainnet program

```bash
# Dump any deployed program from mainnet
solana program dump -u m TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA spl_token.so

# Analyze it
sbpf-analyze spl_token.so
```

### CI integration

```bash
# Fail CI if any function exceeds 200K CU
sbpf-analyze target/deploy/my_program.so --fail-above 200000

# Fail CI if CU regresses more than 5% from baseline
sbpf-analyze target/deploy/my_program.so --baseline baseline.json --fail-regression 5.0

# Save a baseline for future comparisons
sbpf-analyze target/deploy/my_program.so --save-baseline baseline.json
```

## What It Detects

### Compute Unit Estimation

| Metric | Description |
|---|---|
| **Worst-case CU** | Longest single execution path through the function's CFG |
| **Upper-bound CU** | Sum of all basic blocks (every path taken) |
| **Interprocedural CU** | Worst-case including all callee functions |
| **Confidence %** | How much of the estimate is based on static facts vs assumptions |
| **Reachable CU** | Only functions reachable from the entrypoint |

### Pattern Detection (7 detectors)

| Pattern | Severity | Description |
|---|---|---|
| Unbounded Loop | Critical | SCC with no exit edge — potential full-budget drain |
| CPI in Loop | Critical | `sol_invoke_signed` inside a loop — 1,000+ CU per iteration |
| Expensive Syscall in Loop | Critical | Syscall with >1,000 CU base cost inside a loop |
| Logging in Loop | Warning | `sol_log_` in a hot loop — 100 CU per call adds up |
| Expensive Crypto Op | Warning | `sol_secp256k1_recover` (25K CU), elliptic curve ops, etc. |
| Indirect Call | Warning | `CALL_REG` — CU cost cannot be resolved statically |
| MUL/DIV by Power of Two | Info | Can be replaced with shift instructions |

### Loop Analysis

- **SCC-based detection** via Tarjan's algorithm (from `solana-sbpf`)
- **Static bound extraction** for canonical counted loops (`for i in 0..N`)
- **Worst-case single-iteration path** via condensed DAG longest-path
- **Configurable default iterations** for unbounded loops (`--loop-iterations N`)

## Architecture

<p align="center">
  <img src="docs/architecture.svg" alt="sbpf-analyzer architecture" width="800">
</p>

```
.so file → ELF parse (solana-sbpf) → CFG + SCC analysis → CU estimation → Pattern detection → Report
```

| Module | Role |
|---|---|
| `loader.rs` | ELF loading, syscall stub registration, `Executable` → `Analysis` |
| `analyzer.rs` | CFG walk, SCC loop detection, worst-case DAG, interprocedural CU |
| `cost_model.rs` | 38 Solana syscalls with Murmur3 hash lookup, per-byte costs |
| `patterns.rs` | 7 pattern detectors with severity classification |
| `report.rs` | Colored terminal output + JSON report generation |
| `baseline.rs` | Save/load/diff baselines for regression detection |
| `debug_info.rs` | DWARF parsing for source-level PC → file:line mapping |

## Demo: Real Mainnet Programs

Tested against deployed Solana programs dumped from mainnet:

| Program | Size | Analysis Time | Functions | Loops | Findings |
|---|---|---|---|---|---|
| Memo V2 | 73 KB | ~600ms | 11 | 2 | 1 critical |
| SPL Token | 131 KB | ~600ms | 36 | 19 | 0 critical |
| Serum DEX V3 | 483 KB | ~800ms | 37 | 28 | 1 critical, 2 warnings |
| Metaplex Token Metadata | 776 KB | ~900ms | 58 | 32 | 0 critical |
| Raydium AMM V4 | 1.3 MB | ~2s | 55 | 70 | 2 critical, 3 warnings |
| Jupiter V6 | 2.8 MB | ~3s | 55 | 62 | 1 critical |
| Drift V2 | 6.4 MB | ~11s | 289 | 299 | 5 critical |

### Example: Raydium AMM V4

```
$ solana program dump -u m 675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8 raydium.so
$ sbpf-analyze raydium.so

OPTIMIZATION OPPORTUNITIES
  🔴 [CRITICAL] Loop (SCC 2018) has no CFG edge exiting the loop — potentially unbounded
     → Add a bounded loop counter or exit condition (est. impact: 200,000 CU)
  🔴 [CRITICAL] Loop (SCC 11920) has no CFG edge exiting the loop — potentially unbounded
     → Add a bounded loop counter or exit condition (est. impact: 200,000 CU)
  🟡 [WARNING]  sol_log_ inside a loop (100 CU each)
     → Remove logging from hot loops or gate behind a debug flag
```

## GitHub Actions

```yaml
name: CU Analysis
on: [push, pull_request]

jobs:
  analyze:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable

      - name: Install sbpf-analyzer
        run: cargo install --path tools/sbpf-analyzer  # or from git

      - name: Build program
        run: anchor build  # or cargo build-sbf

      - name: Analyze CU usage
        run: |
          sbpf-analyze target/deploy/my_program.so \
            --json \
            --fail-above 500000 \
            --save-baseline cu-baseline.json

      - name: Check for regressions
        if: github.event_name == 'pull_request'
        run: |
          # Download baseline from main branch
          git show origin/main:cu-baseline.json > prev-baseline.json 2>/dev/null || true
          if [ -f prev-baseline.json ]; then
            sbpf-analyze target/deploy/my_program.so \
              --baseline prev-baseline.json \
              --fail-regression 10.0
          fi
```

## CLI Reference

```
sbpf-analyze [OPTIONS] <PATH>

Arguments:
  <PATH>  Path to the .so file to analyze

Options:
  --json                     Output as JSON instead of colored terminal report
  --baseline <FILE>          Compare against a previous baseline JSON file
  --save-baseline <FILE>     Save current analysis as a baseline
  --loop-iterations <N>      Default loop iteration assumption [default: 10]
  --fail-above <CU>          Exit code 1 if any function exceeds this CU threshold
  --fail-regression <PCT>    Exit code 1 if regression exceeds this percentage
  -h, --help                 Print help
```

## Cost Model

Based on **Agave v2.1** compute budget. Key syscall costs:

| Syscall | Base CU | Per-Byte | Category |
|---|---|---|---|
| `sol_secp256k1_recover` | 25,000 | — | Crypto |
| `sol_alt_bn128_group_op` | 10,000 | — | Crypto |
| `sol_big_mod_exp` | 10,000 | — | Crypto |
| `sol_poseidon` | 3,000 | — | Crypto |
| `sol_curve_group_op` | 2,208 | — | Crypto |
| `sol_create_program_address` | 1,500 | — | PDA |
| `sol_try_find_program_address` | 1,500 | — | PDA |
| `sol_invoke_signed_rust` | 1,000 | — | CPI |
| `sol_log_` | 100 | 1 CU/byte | Logging |
| `sol_sha256` | 85 | 1 CU/byte | Crypto |
| `sol_memcpy_` | 10 | — | Memory |

Each sBPF instruction costs 1 CU. Cost differentiation comes from syscalls and loop iteration counts.

## Limitations

- **Stripped binaries**: Mainnet programs have no symbol names. Functions are identified by entry PC only. Build with debug info for better output.
- **Loop bounds**: Only canonical `for i in 0..N` patterns are statically extracted. Complex loops fall back to the default assumption (10 iterations).
- **CPI targets**: The target program of a CPI call lives in account data at runtime — it cannot be resolved statically.
- **No execution**: This is pure static analysis. It cannot detect data-dependent behavior or runtime-only paths.

## License

Apache-2.0

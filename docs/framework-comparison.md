# Framework Comparison: Anchor vs Pinocchio vs Quasar

We compiled the same vault program with three Solana frameworks and analyzed the resulting sBPF bytecode with [sbpf-analyzer](https://github.com/illegalcall/sbpf-analyzer).

## Methodology

- **Program**: A simple SOL vault — deposit into a PDA, withdraw back. Two instructions, same logic across all three.
- **Source**: All three implementations from [blueshift-gg/quasar/examples](https://github.com/blueshift-gg/quasar/tree/master/examples) (`vault/`, `pinocchio-vault/`, `anchor-vault/`)
- **Toolchain**: Agave edge, platform-tools v1.53, cargo-build-sbf 4.0.0
- **Analysis**: `sbpf-analyze <program>.so --json` on each compiled binary
- **Frameworks**: Anchor 0.32.0, Pinocchio 0.10.2, Quasar 0.0.0 (beta)

## Results

| Metric | Anchor | Pinocchio | Quasar |
|---|---|---|---|
| **Binary size** | 171 KB | 8.3 KB | 6.3 KB |
| **Functions** | 234 | 6 | 8 |
| **Loops** | 69 | 1 | 3 |
| **Total instructions** | 16,369 | 746 | 474 |
| **Total estimated CU** | 39,393 | 5,917 | 6,939 |
| **Syscalls** | 40 | 4 | 7 |
| **Critical findings** | 0 | 0 | 1 |
| **Total findings** | 72 | 0 | 1 |

> **Note on Total CU**: Anchor's total includes unreachable framework code — serialization helpers, error handlers, dispatch logic for both instructions. Not all of it executes in a single transaction. Pinocchio and Quasar inline nearly everything, so their totals closely reflect actual per-transaction cost.

### Ratios vs Anchor

| | Pinocchio | Quasar |
|---|---|---|
| Binary size | **21x smaller** | **27x smaller** |
| Functions | **39x fewer** | **29x fewer** |
| Instructions | **22x fewer** | **35x fewer** |
| Total CU | **6.7x less** | **5.7x less** |

## What's Going On

### Anchor (171 KB, 234 functions)

Anchor generates 234 functions for a 2-instruction vault. The framework produces serialization/deserialization helpers, account validators, error handlers, trait implementations, and dispatch logic. Most of these are overhead that never executes in any single transaction path, but all of it ships on-chain and consumes rent.

- 69 loops, mostly in framework-generated validation code
- 40 syscalls across all functions
- 72 pattern findings (all warnings — indirect calls from framework dispatch)

### Pinocchio (8.3 KB, 6 functions)

Pinocchio compiles the same vault into 6 functions. Zero-copy, zero-allocation architecture — reads input parameters directly from the SBF loader's serialized byte array with no copies.

- 1 loop
- 4 syscalls
- Zero pattern findings — the cleanest output of all three

### Quasar (6.3 KB, 8 functions)

Quasar produces the smallest binary. Nearly everything is inlined into the entrypoint function, which does PDA derivation inline with `sol_sha256` and `sol_curve_validate_point` syscalls.

- 3 loops (PDA derivation)
- 7 syscalls
- 1 critical finding (likely a compiler artifact — self-loop at a single node)

## The Key Insight

The real gap isn't between Pinocchio and Quasar — they're close (5,917 vs 6,939 CU). The gap is between **"framework with abstraction layers"** (Anchor) and **"zero-copy / inline everything"** (Pinocchio, Quasar).

Anchor generates 234 functions and 171 KB for a 2-instruction vault. Pinocchio: 6 functions, 8.3 KB. Quasar: 8 functions, 6.3 KB. That's the framework overhead made visible at the bytecode level.

## Reproduce This

```bash
# Install the analyzer
cargo install sbpf-analyzer

# Clone the examples
git clone https://github.com/blueshift-gg/quasar.git
cd quasar

# Build all three (requires agave edge for Quasar/Anchor compatibility)
cargo-build-sbf --manifest-path examples/vault/Cargo.toml
cargo-build-sbf --manifest-path examples/pinocchio-vault/Cargo.toml
cargo-build-sbf --manifest-path examples/anchor-vault/Cargo.toml

# Analyze
sbpf-analyze target/deploy/quasar_vault.so
sbpf-analyze target/deploy/pinocchio_vault.so
sbpf-analyze examples/anchor-vault/target/deploy/anchor_vault.so
```

## Caveats

- Anchor version is 0.32.0. Older or newer versions may produce different results.
- Quasar is beta (v0.0.0) — APIs may change, not audited.
- This is a simple 2-instruction program. Differences may be more or less dramatic on complex programs.
- Total CU is a static estimate. Actual runtime CU depends on execution path and input data.
- Building requires agave edge (platform-tools v1.53) due to dependency version requirements.

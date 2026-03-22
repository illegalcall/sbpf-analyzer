use anyhow::{Context, Result};
use solana_sbpf::{
    elf::Executable,
    program::{BuiltinCodegen, BuiltinFunction, BuiltinProgram, JitCompiler},
    static_analysis::Analysis,
    vm::Config,
};
use std::path::Path;
use std::sync::Arc;

use crate::cost_model;

/// Minimal ContextObject -- we never execute, only analyze.
pub struct StaticContext;

impl solana_sbpf::vm::ContextObject for StaticContext {
    fn consume(&mut self, _amount: u64) {}
    fn get_remaining(&self) -> u64 {
        u64::MAX
    }
}

/// No-op builtin function for syscall stubs (never called during static analysis).
fn noop_builtin(
    _vm: *mut solana_sbpf::vm::EbpfVm<StaticContext>,
    _: u64,
    _: u64,
    _: u64,
    _: u64,
    _: u64,
) {
}

/// No-op JIT codegen stub (never called during static analysis).
fn noop_codegen(_jit: &mut JitCompiler<StaticContext>) {}

/// Build a loader with all known syscalls registered as no-ops.
fn build_loader() -> Arc<BuiltinProgram<StaticContext>> {
    let mut loader = BuiltinProgram::<StaticContext>::new_loader(Config::default());
    for name in cost_model::known_syscall_names() {
        // Register with no-op function; ignore errors for already-registered names
        let _ = loader.register_function(
            name,
            (
                noop_builtin as BuiltinFunction<StaticContext>,
                noop_codegen as BuiltinCodegen<StaticContext>,
            ),
        );
    }
    Arc::new(loader)
}

/// Maximum file size we'll read (Solana programs are capped at ~10MB on-chain).
const MAX_FILE_SIZE: u64 = 20 * 1024 * 1024; // 20 MB

/// Load a .so file, parse the ELF, and return the Executable.
pub fn load_and_analyze(path: &Path) -> Result<Box<Executable<StaticContext>>> {
    let bytes =
        std::fs::read(path).with_context(|| format!("Failed to read file: {}", path.display()))?;
    anyhow::ensure!(
        bytes.len() as u64 <= MAX_FILE_SIZE,
        "File too large ({} bytes, max {} bytes)",
        bytes.len(),
        MAX_FILE_SIZE
    );

    let loader = build_loader();

    let executable = Executable::load(&bytes, loader)
        .map_err(|e| anyhow::anyhow!("Failed to parse ELF: {e:?}"))?;

    Ok(Box::new(executable))
}

/// Create Analysis from a loaded executable.
/// The executable must outlive the returned Analysis.
pub fn analyze<'a>(executable: &'a Executable<StaticContext>) -> Result<Analysis<'a>> {
    Analysis::from_executable(executable)
        .map_err(|e| anyhow::anyhow!("Static analysis failed: {e:?}"))
}

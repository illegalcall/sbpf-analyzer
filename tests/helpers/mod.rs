use sbpf_analyzer::loader::StaticContext;
use solana_sbpf::{
    elf::Executable,
    program::{BuiltinProgram, FunctionRegistry, SBPFVersion},
    vm::Config,
};
use std::sync::Arc;

/// Create an Executable from raw sBPF bytecode (for testing without .so files).
/// `functions` is a list of (pc_offset, name) pairs.
pub fn executable_from_bytecode(
    bytecode: &[u8],
    functions: &[(usize, &str)],
) -> Executable<StaticContext> {
    executable_from_bytecode_with_version(bytecode, functions, SBPFVersion::V0)
}

/// Create an Executable from raw sBPF bytecode using an explicit SBPF version.
pub fn executable_from_bytecode_with_version(
    bytecode: &[u8],
    functions: &[(usize, &str)],
    version: SBPFVersion,
) -> Executable<StaticContext> {
    let loader = Arc::new(BuiltinProgram::<StaticContext>::new_loader(
        Config::default(),
    ));
    let mut function_registry = FunctionRegistry::default();
    for &(pc, name) in functions {
        function_registry
            .register_function(pc as u32, name.as_bytes().to_vec(), pc)
            .unwrap();
    }
    Executable::new_from_text_bytes(bytecode, loader, version, function_registry).unwrap()
}

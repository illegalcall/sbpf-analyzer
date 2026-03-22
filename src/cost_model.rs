use std::collections::HashMap;
use std::sync::LazyLock;

/// Version tag identifying which Agave cost model these values correspond to.
pub const COST_MODEL_VERSION: &str = "agave-v2.1";

/// CU cost information for a single syscall.
#[derive(Debug, Clone)]
pub struct SyscallCost {
    pub name: &'static str,
    pub base_cost: u64,
    /// Some syscalls have per-byte costs (e.g., SHA256: 1 CU/byte)
    pub per_byte_cost: Option<u64>,
    pub category: SyscallCategory,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SyscallCategory {
    Logging,
    Crypto,
    ProgramDerived,
    CrossProgramInvocation,
    Memory,
    Sysvar,
    Misc,
}

/// Compute the Murmur3 32-bit hash of a syscall name (what sBPF uses for CALL_IMM).
/// Uses solana-sbpf's own hash function to guarantee matching hashes.
pub fn compute_syscall_hash(name: &str) -> u32 {
    solana_sbpf::ebpf::hash_symbol_name(name.as_bytes())
}

/// Shared syscall registry for both ELF loading and CU accounting.
///
/// The names track the current Solana syscall surface from `solana-define-syscall`,
/// while retaining legacy aliases where they still appear in older programs.
const SYSCALL_TABLE: &[SyscallCost] = &[
    // Logging
    SyscallCost {
        name: "sol_log_",
        base_cost: 100,
        per_byte_cost: Some(1),
        category: SyscallCategory::Logging,
    },
    SyscallCost {
        name: "sol_log_64_",
        base_cost: 100,
        per_byte_cost: None,
        category: SyscallCategory::Logging,
    },
    SyscallCost {
        name: "sol_log_pubkey",
        base_cost: 100,
        per_byte_cost: None,
        category: SyscallCategory::Logging,
    },
    SyscallCost {
        name: "sol_log_compute_units_",
        base_cost: 100,
        per_byte_cost: None,
        category: SyscallCategory::Logging,
    },
    SyscallCost {
        name: "sol_log_data",
        base_cost: 100,
        per_byte_cost: Some(1),
        category: SyscallCategory::Logging,
    },
    // Crypto
    SyscallCost {
        name: "sol_sha256",
        base_cost: 85,
        per_byte_cost: Some(1),
        category: SyscallCategory::Crypto,
    },
    SyscallCost {
        name: "sol_keccak256",
        base_cost: 85,
        per_byte_cost: Some(1),
        category: SyscallCategory::Crypto,
    },
    SyscallCost {
        name: "sol_blake3",
        base_cost: 85,
        per_byte_cost: Some(1),
        category: SyscallCategory::Crypto,
    },
    SyscallCost {
        name: "sol_secp256k1_recover",
        base_cost: 25_000,
        per_byte_cost: None,
        category: SyscallCategory::Crypto,
    },
    SyscallCost {
        name: "sol_poseidon",
        base_cost: 3_000,
        per_byte_cost: None,
        category: SyscallCategory::Crypto,
    },
    SyscallCost {
        name: "sol_alt_bn128_group_op",
        base_cost: 10_000,
        per_byte_cost: None,
        category: SyscallCategory::Crypto,
    },
    SyscallCost {
        name: "sol_alt_bn128_compression",
        base_cost: 10_000,
        per_byte_cost: None,
        category: SyscallCategory::Crypto,
    },
    SyscallCost {
        name: "sol_curve_validate_point",
        base_cost: 159,
        per_byte_cost: None,
        category: SyscallCategory::Crypto,
    },
    SyscallCost {
        name: "sol_curve_group_op",
        base_cost: 2_208,
        per_byte_cost: None,
        category: SyscallCategory::Crypto,
    },
    SyscallCost {
        name: "sol_curve_multiscalar_mul",
        base_cost: 2_208,
        per_byte_cost: None,
        category: SyscallCategory::Crypto,
    },
    SyscallCost {
        name: "sol_curve_pairing_map",
        base_cost: 2_208,
        per_byte_cost: None,
        category: SyscallCategory::Crypto,
    },
    SyscallCost {
        name: "sol_big_mod_exp",
        base_cost: 10_000,
        per_byte_cost: None,
        category: SyscallCategory::Crypto,
    },
    // PDA
    SyscallCost {
        name: "sol_create_program_address",
        base_cost: 1_500,
        per_byte_cost: None,
        category: SyscallCategory::ProgramDerived,
    },
    SyscallCost {
        name: "sol_try_find_program_address",
        base_cost: 1_500,
        per_byte_cost: None,
        category: SyscallCategory::ProgramDerived,
    },
    // CPI
    SyscallCost {
        name: "sol_invoke_signed_c",
        base_cost: 1_000,
        per_byte_cost: None,
        category: SyscallCategory::CrossProgramInvocation,
    },
    SyscallCost {
        name: "sol_invoke_signed_rust",
        base_cost: 1_000,
        per_byte_cost: None,
        category: SyscallCategory::CrossProgramInvocation,
    },
    // Memory
    SyscallCost {
        name: "sol_memcpy_",
        base_cost: 10,
        per_byte_cost: None,
        category: SyscallCategory::Memory,
    },
    SyscallCost {
        name: "sol_memmove_",
        base_cost: 10,
        per_byte_cost: None,
        category: SyscallCategory::Memory,
    },
    SyscallCost {
        name: "sol_memcmp_",
        base_cost: 10,
        per_byte_cost: None,
        category: SyscallCategory::Memory,
    },
    SyscallCost {
        name: "sol_memset_",
        base_cost: 10,
        per_byte_cost: None,
        category: SyscallCategory::Memory,
    },
    // Sysvar and return data
    SyscallCost {
        name: "sol_get_sysvar",
        base_cost: 100,
        per_byte_cost: None,
        category: SyscallCategory::Sysvar,
    },
    SyscallCost {
        name: "sol_get_clock_sysvar",
        base_cost: 100,
        per_byte_cost: None,
        category: SyscallCategory::Sysvar,
    },
    SyscallCost {
        name: "sol_get_epoch_schedule_sysvar",
        base_cost: 100,
        per_byte_cost: None,
        category: SyscallCategory::Sysvar,
    },
    SyscallCost {
        name: "sol_get_rent_sysvar",
        base_cost: 100,
        per_byte_cost: None,
        category: SyscallCategory::Sysvar,
    },
    SyscallCost {
        name: "sol_get_fees_sysvar",
        base_cost: 100,
        per_byte_cost: None,
        category: SyscallCategory::Sysvar,
    },
    SyscallCost {
        name: "sol_get_epoch_rewards_sysvar",
        base_cost: 100,
        per_byte_cost: None,
        category: SyscallCategory::Sysvar,
    },
    SyscallCost {
        name: "sol_get_last_restart_slot",
        base_cost: 100,
        per_byte_cost: None,
        category: SyscallCategory::Sysvar,
    },
    SyscallCost {
        name: "sol_get_epoch_stake",
        base_cost: 100,
        per_byte_cost: None,
        category: SyscallCategory::Sysvar,
    },
    SyscallCost {
        name: "sol_get_stack_height",
        base_cost: 100,
        per_byte_cost: None,
        category: SyscallCategory::Sysvar,
    },
    SyscallCost {
        name: "sol_get_return_data",
        base_cost: 100,
        per_byte_cost: None,
        category: SyscallCategory::Sysvar,
    },
    SyscallCost {
        name: "sol_set_return_data",
        base_cost: 100,
        per_byte_cost: None,
        category: SyscallCategory::Sysvar,
    },
    // Misc
    SyscallCost {
        name: "sol_get_processed_sibling_instruction",
        base_cost: 100,
        per_byte_cost: None,
        category: SyscallCategory::Misc,
    },
    SyscallCost {
        name: "sol_remaining_compute_units",
        base_cost: 100,
        per_byte_cost: None,
        category: SyscallCategory::Misc,
    },
    SyscallCost {
        name: "sol_get_remaining_compute_units",
        base_cost: 100,
        per_byte_cost: None,
        category: SyscallCategory::Misc,
    },
    SyscallCost {
        name: "abort",
        base_cost: 100,
        per_byte_cost: None,
        category: SyscallCategory::Misc,
    },
    SyscallCost {
        name: "sol_panic_",
        base_cost: 100,
        per_byte_cost: None,
        category: SyscallCategory::Misc,
    },
    SyscallCost {
        name: "sol_alloc_free_",
        base_cost: 100,
        per_byte_cost: None,
        category: SyscallCategory::Misc,
    },
];

pub fn known_syscall_names() -> impl Iterator<Item = &'static str> {
    SYSCALL_TABLE.iter().map(|syscall| syscall.name)
}

/// Lookup tables indexed by name and by hash.
static SYSCALL_BY_NAME: LazyLock<HashMap<&'static str, &'static SyscallCost>> =
    LazyLock::new(|| {
        SYSCALL_TABLE
            .iter()
            .map(|syscall| (syscall.name, syscall))
            .collect()
    });

static SYSCALL_BY_HASH: LazyLock<HashMap<u32, &'static SyscallCost>> = LazyLock::new(|| {
    SYSCALL_TABLE
        .iter()
        .map(|syscall| (compute_syscall_hash(syscall.name), syscall))
        .collect()
});

pub fn syscall_cost_by_name(name: &str) -> Option<&'static SyscallCost> {
    SYSCALL_BY_NAME.get(name).copied()
}

pub fn syscall_cost_by_hash(hash: u32) -> Option<&'static SyscallCost> {
    SYSCALL_BY_HASH.get(&hash).copied()
}

pub fn all_syscalls() -> Vec<&'static SyscallCost> {
    SYSCALL_TABLE.iter().collect()
}

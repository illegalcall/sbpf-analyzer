use sbpf_analyzer::cost_model;

#[test]
fn test_known_syscall_by_name() {
    let cost = cost_model::syscall_cost_by_name("sol_log_");
    assert!(cost.is_some());
    assert_eq!(cost.unwrap().base_cost, 100);
}

#[test]
fn test_expensive_syscall() {
    let cost = cost_model::syscall_cost_by_name("sol_secp256k1_recover");
    assert!(cost.is_some());
    assert_eq!(cost.unwrap().base_cost, 25_000);
}

#[test]
fn test_cpi_cost() {
    let cost = cost_model::syscall_cost_by_name("sol_invoke_signed_rust");
    assert!(cost.is_some());
    assert_eq!(cost.unwrap().base_cost, 1_000);
}

#[test]
fn test_unknown_syscall_returns_none() {
    let cost = cost_model::syscall_cost_by_name("nonexistent_syscall");
    assert!(cost.is_none());
}

#[test]
fn test_syscall_by_hash() {
    let hash = cost_model::compute_syscall_hash("sol_log_");
    let cost = cost_model::syscall_cost_by_hash(hash);
    assert!(cost.is_some());
    assert_eq!(cost.unwrap().name, "sol_log_");
}

#[test]
fn test_all_syscalls_have_costs() {
    let all = cost_model::all_syscalls();
    assert!(all.len() >= 15, "Expected at least 15 known syscalls");
    for sc in &all {
        assert!(sc.base_cost > 0, "Syscall {} has zero cost", sc.name);
    }
}

#[test]
fn test_current_syscall_surface_present() {
    for name in [
        "sol_remaining_compute_units",
        "sol_get_remaining_compute_units",
        "sol_get_sysvar",
        "sol_get_epoch_stake",
        "sol_curve_pairing_map",
        "sol_big_mod_exp",
    ] {
        assert!(
            cost_model::syscall_cost_by_name(name).is_some(),
            "missing syscall registry entry for {name}"
        );
    }
}

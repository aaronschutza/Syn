// src/tests/difficulty_tests.rs

use crate::difficulty::{calculate_next_difficulty, NetworkState};
use crate::units::{LddParams, SlotDuration, Probability};
use fixed::types::U64F64;

#[test]
fn test_liveness_repair_halting_scenario() {
    // Setup: Simulate a state where the chain was previously unstable or transitioning.
    let current_params = LddParams::default();
    
    // Simulate "Appendix A" conditions:
    // High Latency (e.g., 5s) which is > default psi (2s).
    // Normal Load.
    let network_state = NetworkState {
        consensus_delay: SlotDuration(5),
        consensus_load: Probability::from_num(0.5),
        security_threat: Probability::from_num(0.0),
    };

    let target_block_time = SlotDuration(15);

    // Execution
    let new_params = calculate_next_difficulty(
        &current_params,
        network_state,
        target_block_time
    );

    // Assertions

    // 1. Check Autonomous Slot Gap (Psi)
    // psi_new = consensus_delay + safety_margin (1s)
    // 5 + 1 = 6
    assert_eq!(new_params.psi.0, 6, "Psi should adapt to delay + margin");

    // 2. Check Gamma constraint
    // Gamma must be > Psi
    assert!(new_params.gamma > new_params.psi, "Gamma must be greater than Psi");

    // 3. Check Beta Stability (The "Halting" Fix)
    // Calculate implied beta for PoW amplitude
    let old_pow = current_params.f_a_pow.to_f64();
    let new_pow = new_params.f_a_pow.to_f64();
    let beta = if old_pow > 0.0 { new_pow / old_pow } else { 1.0 };

    println!("Implied Beta: {:.4}", beta);

    // The fix ensures beta is dimensionless and scaling is correct. 
    // In previous broken math, beta could be ~45.0 or ~0.02.
    // With correct math, it should be near 1.0 for equilibrium, or clamped [0.5, 2.0].
    assert!(beta >= 0.5 && beta <= 2.0, "Beta should be clamped within safety bounds [0.5, 2.0]. Got {}", beta);

    // 4. Dimensional Safety Check
    // Ensure amplitudes didn't vanish
    assert!(new_params.f_a_pow.0 > U64F64::from_num(0), "PoW amplitude must not vanish");
    assert!(new_params.f_a_pos.0 > U64F64::from_num(0), "PoS amplitude must not vanish");
}

#[test]
fn test_high_congestion_safety_floor() {
    // Test that if target_block_time < psi, we enforce safety floor.
    let current_params = LddParams::default();
    
    // Extreme Latency: 20s
    let network_state = NetworkState {
        consensus_delay: SlotDuration(20),
        consensus_load: Probability::from_num(1.0), // High load
        security_threat: Probability::from_num(0.0),
    };

    // Configured target is 15s (impossible given 20s latency)
    let target_block_time = SlotDuration(15);

    let new_params = calculate_next_difficulty(
        &current_params,
        network_state,
        target_block_time
    );

    // Expect Psi = 20 + 1 = 21s
    assert_eq!(new_params.psi.0, 21);

    // Expect Gamma > 21
    assert!(new_params.gamma.0 > 21);

    // The core check is that the calculation didn't panic or error out due to 
    // target < psi. It should have adjusted the target internally.
    // Since gamma is derived from optimal window xi, and xi depends on M_req,
    // ensuring Gamma > Psi implies M_req was calculated with a valid positive time window.
    
    // Check implied beta isn't crazy
    let new_pow = new_params.f_a_pow.to_f64();
    assert!(new_pow > 0.0, "Difficulty should remain positive even under stress");
}
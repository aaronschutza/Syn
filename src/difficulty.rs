// src/difficulty.rs - Authoritative LDD State Management & Core Math Fix

use crate::params::ParamManager;
use crate::units::{LddParams, SlotDuration, Probability, FrequencySquared, PhysicalSlope};
use fixed::types::{U64F64, I64F64};
use std::sync::Arc;
use parking_lot::RwLock;
use log::info;

// Constants for Autonomous Adaptation
const SAFETY_MARGIN_SECONDS: u64 = 1;
const MIN_BLOCK_TIME_SECONDS: u64 = 1;
const BASE_FALLBACK_PROBABILITY: f64 = 0.01;

/// Represents the dynamic state of the LDD amplitudes (f_A parameters).
/// Re-introduced for compatibility with ConsensusEngine and Blockchain.
#[derive(Debug, Clone)]
pub struct DifficultyState {
    pub f_a_pow: I64F64,
    pub f_a_pos: I64F64,
}

/// Represents the observed state of the network from the DCS.
#[derive(Debug, Clone, Copy)]
pub struct NetworkState {
    /// Consensus Delay (Delta_consensus).
    pub consensus_delay: SlotDuration,
    /// Network Load (0.0 - 1.0).
    pub consensus_load: Probability,
    /// Security Threat Level (0.0 - 1.0).
    pub security_threat: Probability,
}

pub struct DynamicDifficultyManager {
    _param_manager: Arc<ParamManager>,
    // The authoritative state is now LddParams using safe types
    state: Arc<RwLock<LddParams>>,
    pow_blocks_count: Arc<RwLock<u32>>,
    pos_blocks_count: Arc<RwLock<u32>>,
}

impl DynamicDifficultyManager {
    pub fn new(param_manager: Arc<ParamManager>) -> Self {
        Self {
            _param_manager: param_manager,
            state: Arc::new(RwLock::new(LddParams::default())),
            pow_blocks_count: Arc::new(RwLock::new(0)),
            pos_blocks_count: Arc::new(RwLock::new(0)),
        }
    }

    /// Retrieves a copy of the current LDD parameters.
    pub fn get_params(&self) -> LddParams {
        self.state.read().clone()
    }

    /// Compatibility method for ConsensusEngine.
    /// Converts the new LddParams (U64F64) to the legacy DifficultyState (I64F64).
    pub fn get_state(&self) -> DifficultyState {
        let params = self.state.read();
        DifficultyState {
            f_a_pow: I64F64::from_num(params.f_a_pow.0.to_num::<f64>()),
            f_a_pos: I64F64::from_num(params.f_a_pos.0.to_num::<f64>()),
        }
    }

    /// Compatibility method for Blockchain sync.
    /// Updates the LDD parameters from external f64 values.
    pub fn set_state(&self, f_a_pow: f64, f_a_pos: f64) {
        let mut params = self.state.write();
        params.f_a_pow = Probability::from_num(f_a_pow);
        params.f_a_pos = Probability::from_num(f_a_pos);
        info!("[LDD-SYNC] Engine view updated via set_state: PoW={:.8}, PoS={:.8}", f_a_pow, f_a_pos);
    }

    /// Updates the LDD parameters based on external inputs (e.g., Block processing).
    pub fn update_params(&self, new_params: LddParams) {
        let mut state = self.state.write();
        *state = new_params;
    }

    /// Records block production to help the node track local performance metrics.
    pub fn record_block(&self, is_pow: bool, _block_height: u32) {
        if is_pow {
            *self.pow_blocks_count.write() += 1;
        } else {
            *self.pos_blocks_count.write() += 1;
        }
    }
}

/// The Core "Liveness" Repair Math.
/// Calculates the next set of LDD parameters based on the current state and network conditions.
///
/// Implements the corrected scaling logic:
/// beta = TargetSlope / ActualSlope
/// where dimensions are strictly enforced.
pub fn calculate_next_difficulty(
    current_params: &LddParams,
    network_state: NetworkState,
    target_block_time_base: SlotDuration,
) -> LddParams {
    // 1. Autonomous Slot Gap (Psi)
    // psi_new = latency + safety_margin
    let psi_new = network_state.consensus_delay + SlotDuration(SAFETY_MARGIN_SECONDS);

    // 2. Autonomous Target Block Time (Mu)
    // Adapt target mu based on load, respecting the safety floor (psi).
    // mu_target = mu_base - (load * (mu_base - (psi + margin)))
    // For simplicity/safety in this iteration, we treat mu as a target duration > psi.
    // If load is high, we could reduce mu, but for Liveness repair, ensuring mu > psi is priority.
    let mu_target = if target_block_time_base > psi_new {
        target_block_time_base
    } else {
        // Enforce safety floor if configured target is too aggressive for current latency
        psi_new + SlotDuration(MIN_BLOCK_TIME_SECONDS)
    };

    // 3. Calculate Required Frequency Squared (M_req)
    // M = pi / (2 * (mu - psi)^2)
    let time_window = mu_target - psi_new;
    // We compute 1 / time_window^2 first
    // Note: time_window.0 is u64 seconds.
    let tw_sq = U64F64::from_num(time_window.0).checked_mul(U64F64::from_num(time_window.0)).unwrap_or(U64F64::from_num(1));
    let pi_over_2 = U64F64::PI / U64F64::from_num(2);
    
    // M_req has units T^-2
    let m_req_val = pi_over_2 / tw_sq;
    let m_req = FrequencySquared(m_req_val);

    // 4. Calculate Optimal Window Length (Xi_optimal)
    // Xi = sqrt(-2 * ln(P_fallback) / M)
    // ln(0.01) approx -4.605. -2 * -4.605 = 9.21
    let numerator = U64F64::from_num(-2.0 * BASE_FALLBACK_PROBABILITY.ln());
    // Xi^2 = numerator / M
    // Xi = sqrt(numerator / M)
    // Since M is T^-2, 1/M is T^2. Sqrt is T. Units match.
    let xi_sq = numerator / m_req.0;
    // Fix E0433: use f64::sqrt from std instead of libm crate
    let xi_val: U64F64 = U64F64::from_num(xi_sq.to_num::<f64>().sqrt()); 
    let xi_optimal = SlotDuration(xi_val.to_num::<u64>().max(1));

    // 5. Calculate Gamma
    let gamma_new = psi_new + xi_optimal;

    // 6. Calculate Scaling Factor (Beta)
    // Target Physical Slope = M_req * 1_slot (T^-2 * T = T^-1)
    let target_slope: PhysicalSlope = m_req * SlotDuration(1);

    // Actual Physical Slope = (f_a_pow + f_a_pos) / xi_optimal
    let amplitude_sum = current_params.f_a_pow + current_params.f_a_pos;
    let actual_slope: PhysicalSlope = amplitude_sum / xi_optimal;

    // Beta = Target / Actual (Dimensionless)
    let beta = if actual_slope.0 == U64F64::ZERO {
        // Initial bootstrap or edge case: default to no scaling (or aggressive growth)
        U64F64::from_num(1)
    } else {
        target_slope.0 / actual_slope.0
    };

    // 7. Apply Beta to Amplitudes
    // We clamp beta to avoid explosive oscillations during the repair phase
    let beta_clamped = beta.min(U64F64::from_num(2.0)).max(U64F64::from_num(0.5));

    let f_a_pow_new = Probability(current_params.f_a_pow.0 * beta_clamped);
    let f_a_pos_new = Probability(current_params.f_a_pos.0 * beta_clamped);

    info!(
        "[LDD REPAIR] Mu: {}s | Psi: {}s | Xi: {}s | Beta: {:.4} | New fA_PoW: {:.8}",
        mu_target.0, psi_new.0, xi_optimal.0, beta_clamped, f_a_pow_new.to_f64()
    );

    LddParams {
        psi: psi_new,
        gamma: gamma_new,
        f_a_pow: f_a_pow_new,
        f_a_pos: f_a_pos_new,
    }
}
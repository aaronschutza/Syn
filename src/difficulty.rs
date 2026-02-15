// src/difficulty.rs - Remediation Step 3: Controller Recalibration

use crate::params::ParamManager;
use crate::units::{LddParams, SlotDuration, Probability};
use fixed::types::{U64F64, I64F64};
use std::sync::Arc;
use parking_lot::RwLock;
use log::info;

// Constants for Autonomous Adaptation
const SAFETY_MARGIN_SECONDS: u64 = 1;
const MIN_BLOCK_TIME_SECONDS: u64 = 1;

/// Represents the dynamic state of the LDD parameters.
#[derive(Debug, Clone)]
pub struct DifficultyState {
    pub f_a_pow: I64F64,
    pub f_a_pos: I64F64,
    pub f_b_pos: I64F64,
    pub psi: u32,
    pub gamma: u32,
}

/// Represents the observed state of the network from the DCS.
#[derive(Debug, Clone, Copy)]
pub struct NetworkState {
    pub consensus_delay: SlotDuration,
    pub consensus_load: Probability,
    pub security_threat: Probability,
}

pub struct DynamicDifficultyManager {
    _param_manager: Arc<ParamManager>,
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

    pub fn get_params(&self) -> LddParams {
        self.state.read().clone()
    }

    pub fn get_state(&self) -> DifficultyState {
        let params = self.state.read();
        let f_b_pos_val = I64F64::from_num(params.f_a_pos.0) / 10;
        
        DifficultyState {
            f_a_pow: I64F64::from_num(params.f_a_pow.0),
            f_a_pos: I64F64::from_num(params.f_a_pos.0),
            f_b_pos: f_b_pos_val,
            psi: params.psi.0 as u32,
            gamma: params.gamma.0 as u32,
        }
    }

    pub fn set_state_from_bits(&self, f_a_pow_bits: u128, f_a_pos_bits: u128, psi: u32, gamma: u32) {
        let mut params = self.state.write();
        params.f_a_pow = Probability::from_bits(f_a_pow_bits);
        params.f_a_pos = Probability::from_bits(f_a_pos_bits);
        params.psi = SlotDuration(psi as u64);
        params.gamma = SlotDuration(gamma as u64);
        info!("[LDD-SYNC] Engine view updated: Psi={}s, Gamma={}s", psi, gamma);
    }

    pub fn record_block(&self, is_pow: bool, _block_height: u32) {
        if is_pow {
            *self.pow_blocks_count.write() += 1;
        } else {
            *self.pos_blocks_count.write() += 1;
        }
    }
}

pub fn calculate_next_difficulty(
    current_params: &LddParams,
    network_state: NetworkState,
    target_mu: SlotDuration,
    observed_mu: SlotDuration, 
    pos_count: usize,
    total_window_blocks: usize,
) -> LddParams {
    //  Calculate new Slot Gap (Psi)
    let psi_new = network_state.consensus_delay + SlotDuration(SAFETY_MARGIN_SECONDS);

    //  Calculate Target Slope (M_req) based on Target Block Time (Mu)
    let mu_calc_target = if target_mu > psi_new {
        target_mu
    } else {
        psi_new + SlotDuration(MIN_BLOCK_TIME_SECONDS)
    };

    // Resource Balancing (Beta & Kappa)
    // REMEDIATION: Quadratic Scaling for Rayleigh Distribution
    // Beta = (Observed / Target)^2
    // M ~ 1 / Mu^2, so to correct M, we scale by (Mu_obs / Mu_target)^2
    
    let ratio = if observed_mu.0 == 0 {
        U64F64::from_num(0.1) 
    } else {
        U64F64::from_num(observed_mu.0) / U64F64::from_num(mu_calc_target.0)
    };
    
    // Apply Quadratic scaling
    let beta = ratio * ratio;

    let kappa = I64F64::from_num(0.1);

    // Retrieve current amplitudes as U64F64
    let current_pow = U64F64::from_bits(current_params.f_a_pow.to_bits());
    let current_pos = U64F64::from_bits(current_params.f_a_pos.to_bits());

    let (f_a_pow_new, f_a_pos_new) = {
        let n_pow = total_window_blocks.saturating_sub(pos_count);
        let p_pow = I64F64::from_num(n_pow) / I64F64::from_num(total_window_blocks);
        let error_val = p_pow - I64F64::from_num(0.5);
        
        let pow_adj = I64F64::from_num(1.0) - kappa * error_val;
        let pos_adj = I64F64::from_num(1.0) + kappa * error_val;
        
        // Multiplicative update: Old * Beta * BalanceAdj
        let pow_val = current_pow * beta * U64F64::from_num(pow_adj);
        let pos_val = current_pos * beta * U64F64::from_num(pos_adj);
        
        // Safety Clamps
        let pow_final = pow_val.min(U64F64::ONE);
        let pos_final = pos_val.min(U64F64::ONE);

        (Probability(pow_final), Probability(pos_final))
    };

    info!(
        "[LDD ADJUST] Mu_target: {}s | Ratio: {:.4} | Beta (Quad): {:.4} | fA_PoW: {:.8} -> {:.8} | fA_PoS: {:.8} -> {:.8}",
        target_mu.0, ratio.to_num::<f64>(), beta.to_num::<f64>(),
        current_pow.to_num::<f64>(), f_a_pow_new.to_f64(), 
        current_pos.to_num::<f64>(), f_a_pos_new.to_f64()
    );

    LddParams {
        psi: current_params.psi,
        gamma: current_params.gamma,
        f_a_pow: f_a_pow_new,
        f_a_pos: f_a_pos_new,
    }
}
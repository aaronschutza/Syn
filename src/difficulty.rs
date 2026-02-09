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
const BASE_FALLBACK_PROBABILITY: f64 = 0.01;

/// Represents the dynamic state of the LDD parameters.
#[derive(Debug, Clone)]
pub struct DifficultyState {
    pub f_a_pow: I64F64,
    pub f_a_pos: I64F64,
    pub f_b_pos: I64F64, // Added for Remediation Step 1 support
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
        // Calculate f_b as derived from f_a (e.g. 1/10th)
        let f_b_pos_val = params.f_a_pos.0.to_num::<f64>() / 10.0;
        DifficultyState {
            f_a_pow: I64F64::from_num(params.f_a_pow.0.to_num::<f64>()),
            f_a_pos: I64F64::from_num(params.f_a_pos.0.to_num::<f64>()),
            f_b_pos: I64F64::from_num(f_b_pos_val),
            psi: params.psi.0 as u32,
            gamma: params.gamma.0 as u32,
        }
    }

    pub fn set_state(&self, f_a_pow: f64, f_a_pos: f64, psi: u32, gamma: u32) {
        let mut params = self.state.write();
        params.f_a_pow = Probability::from_num(f_a_pow);
        params.f_a_pos = Probability::from_num(f_a_pos);
        params.psi = SlotDuration(psi as u64);
        params.gamma = SlotDuration(gamma as u64);
        info!("[LDD-SYNC] Engine view updated: PoW={:.8}, PoS={:.8}, Psi={}s, Gamma={}s", f_a_pow, f_a_pos, psi, gamma);
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
    // 1. Calculate new Slot Gap (Psi)
    let psi_new = network_state.consensus_delay + SlotDuration(SAFETY_MARGIN_SECONDS);

    // 2. Calculate Target Slope (M_req) based on Target Block Time (Mu)
    // Equation (2): M_req = pi / (2 * (mu - psi)^2)
    let mu_calc_target = if target_mu > psi_new {
        target_mu
    } else {
        psi_new + SlotDuration(MIN_BLOCK_TIME_SECONDS)
    };

    let tw = mu_calc_target - psi_new;
    let tw_sq = U64F64::from_num(tw.0).checked_mul(U64F64::from_num(tw.0)).unwrap_or(U64F64::from_num(1));
    let pi_over_2 = U64F64::PI / U64F64::from_num(2);
    
    // This is the Target Slope required to achieve Mu_target
    let m_req = pi_over_2 / tw_sq; 

    // 3. Calculate new Window Size (Gamma)
    // Gamma is chosen such that the probability of failure (p_fallback) is low.
    let xi_optimal = (U64F64::from_num(-2.0 * BASE_FALLBACK_PROBABILITY.ln()) / m_req).to_num::<f64>().sqrt();
    let gamma_new = psi_new + SlotDuration(xi_optimal.ceil() as u64);

    // Remediation Step 3: Recalibrate the Feedback Controller
    // Align physical units: f_A = M_req * (gamma - psi)
    // We calculate a baseline Amplitude that physically corresponds to the target Slope.
    let window_duration = gamma_new - psi_new;
    let window_u64 = U64F64::from_num(window_duration.0);
    
    // Eq (3): f_A = Slope * Window
    let f_a_base = m_req * window_u64;

    // 4. Resource Balancing (Beta & Kappa)
    // We adjust the baseline f_A for PoW and PoS relative to their observed contribution
    // to maintain the 50/50 split.
    
    let beta = if observed_mu.0 == 0 {
        U64F64::from_num(0.1) 
    } else {
        U64F64::from_num(observed_mu.0) / U64F64::from_num(mu_calc_target.0)
    };
    let beta_clamped = beta.min(U64F64::from_num(2.0)).max(U64F64::from_num(0.01));
    let kappa = I64F64::from_num(0.1);

    let (f_a_pow_new, f_a_pos_new) = if pos_count == 0 {
        // Bootstrap Mode: Boost PoS to bootstrap
        let pow_new = Probability(f_a_base * beta_clamped);
        let pos_new = Probability((current_params.f_a_pos.0 * U64F64::from_num(2.0)).min(U64F64::from_num(1.0)));
        (pow_new, pos_new)
    } else {
        let n_pow = total_window_blocks.saturating_sub(pos_count);
        let p_pow = I64F64::from_num(n_pow) / I64F64::from_num(total_window_blocks);
        let error_val = p_pow - I64F64::from_num(0.5);
        
        let pow_adj = I64F64::from_num(1.0) - kappa * error_val;
        let pos_adj = I64F64::from_num(1.0) + kappa * error_val;
        
        // Apply adjustments to the PHYSICALLY DERIVED base amplitude
        let pow_val = f_a_base * U64F64::from_num(pow_adj.max(I64F64::from_num(0.01)));
        let pos_val = f_a_base * U64F64::from_num(pos_adj.max(I64F64::from_num(0.01)));
        
        (Probability(pow_val), Probability(pos_val))
    };

    info!(
        "[LDD ADJUST] Mu_target: {}s | M_req: {:.8} | Window: {}s | fA_Base: {:.8} | fA_PoW: {:.8} | fA_PoS: {:.8}",
        target_mu.0, m_req.to_num::<f64>(), window_duration.0, f_a_base.to_num::<f64>(), 
        f_a_pow_new.to_f64(), f_a_pos_new.to_f64()
    );

    LddParams {
        psi: psi_new,
        gamma: gamma_new,
        f_a_pow: f_a_pow_new,
        f_a_pos: f_a_pos_new,
    }
}
// src/difficulty.rs

use fixed::types::I64F64;
use crate::params::ParamManager;
use std::sync::Arc;
use parking_lot::RwLock;
use log::{info, debug, warn};

// Type alias for clarity
type Amplitude = I64F64;

// CORRECTED: Define as a primitive f64 const
const KAPPA_F64: f64 = 0.1;

/// Represents the dynamic state of the LDD amplitudes.
#[derive(Debug, Clone)]
pub struct DifficultyState {
    pub f_a_pow: Amplitude,
    pub f_a_pos: Amplitude,
}

impl Default for DifficultyState {
    fn default() -> Self {
        // Initial values (must be calibrated based on expected initial resources).
        Self {
            f_a_pow: I64F64::from_num(0.05),
            f_a_pos: I64F64::from_num(0.05),
        }
    }
}

/// Manages the Dynamic Slope Adjustment Scheme (Section 11).
pub struct DynamicDifficultyManager {
    _param_manager: Arc<ParamManager>,
    state: Arc<RwLock<DifficultyState>>,
    pow_blocks_count: Arc<RwLock<u32>>,
    pos_blocks_count: Arc<RwLock<u32>>,
}

impl DynamicDifficultyManager {
    pub fn new(param_manager: Arc<ParamManager>) -> Self {
        Self {
            _param_manager: param_manager,
            state: Arc::new(RwLock::new(DifficultyState::default())),
            pow_blocks_count: Arc::new(RwLock::new(0)),
            pos_blocks_count: Arc::new(RwLock::new(0)),
        }
    }

    pub fn get_state(&self) -> DifficultyState {
        self.state.read().clone()
    }

    /// Records a block and checks if the adjustment window is complete.
    pub fn record_block(&self, is_pow: bool, block_height: u32) {
        if is_pow {
            *self.pow_blocks_count.write() += 1;
        } else {
            *self.pos_blocks_count.write() += 1;
        }

        // Placeholder: Adjustment window size (N) should be governed by parameters.
        const ADJUSTMENT_WINDOW: u32 = 288; // e.g., ~1 hour at 15s blocks

        if block_height % ADJUSTMENT_WINDOW == 0 && block_height > 0 {
            self.adjust_difficulty(block_height);
        }
    }

    /// Executes the Dynamic Slope Adjustment algorithm (Section 11.4).
    fn adjust_difficulty(&self, height: u32) {
        let n_pow = *self.pow_blocks_count.read();
        let n_pos = *self.pos_blocks_count.read();
        let n_total = n_pow + n_pos;

        if n_total == 0 {
            warn!("Difficulty adjustment triggered but no blocks recorded in window. Skipping.");
            return;
        }

        // 1. Calculate Observed Proportion (P_PoW) and Error (E).
        // Uses deterministic fixed-point arithmetic.
        let p_pow = I64F64::from_num(n_pow) / I64F64::from_num(n_total);
        
        // Target proportion (50%). Placeholder: Should be from ParamManager.
        let target_pow = I64F64::from_num(0.5); 

        let error_e = p_pow - target_pow;

        info!("Difficulty Adjustment at height {}. Observed PoW: {:.4} (Target: {:.4}). Error: {:.4}", height, p_pow, target_pow, error_e);

        // 2. Calculate Proportional Adjustment (Section 11.4, Eq. 7 & 8).
        let mut state = self.state.write();
        let f_a_pow_old = state.f_a_pow;
        let f_a_pos_old = state.f_a_pos;

        // CORRECTED: Use the f64 const here
        let kappa = I64F64::from_num(KAPPA_F64);

        // f_new = f_old * (1 - kappa * E)
        let adjustment_pow = I64F64::from_num(1) - (kappa * error_e);
        // f_new = f_old * (1 + kappa * E)
        let adjustment_pos = I64F64::from_num(1) + (kappa * error_e);

        let f_a_pow_new = f_a_pow_old * adjustment_pow;
        let f_a_pos_new = f_a_pos_old * adjustment_pos;

        // 3. Stability Scaling (Beta) (Section 11.3).
        // Simplified approach: M_req is based on the initial default state.
        // A full implementation must calculate M_req based on the target vs observed block time (requires timestamp tracking).
        
        let m_req = DifficultyState::default().f_a_pow + DifficultyState::default().f_a_pos; // Placeholder M_req
        let m_actual_new = f_a_pow_new + f_a_pos_new;

        // Calculate Beta = M_req / M_actual_new (Eq. 1)
        let beta = if m_actual_new > I64F64::from_num(0) {
            m_req / m_actual_new
        } else {
            I64F64::from_num(1)
        };

        // Apply scaling (Eq. 2 & 3)
        state.f_a_pow = f_a_pow_new * beta;
        state.f_a_pos = f_a_pos_new * beta;

        debug!("New Amplitudes (Scaled by Beta={:.4}): f_A_PoW={:.6}, f_A_PoS={:.6}", beta, state.f_a_pow, state.f_a_pos);

        // Reset counters for the next window.
        *self.pow_blocks_count.write() = 0;
        *self.pos_blocks_count.write() = 0;
    }
}
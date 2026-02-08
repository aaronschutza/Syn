// src/difficulty.rs - Authoritative LDD State Management

use fixed::types::I64F64;
use crate::params::ParamManager;
use std::sync::Arc;
use parking_lot::RwLock;
use log::debug;

/// Represents the dynamic state of the LDD amplitudes (f_A parameters).
/// These are stored as fixed-point values for cross-platform determinism.
#[derive(Debug, Clone)]
pub struct DifficultyState {
    pub f_a_pow: I64F64,
    pub f_a_pos: I64F64,
}

impl Default for DifficultyState {
    fn default() -> Self {
        Self {
            // Initial conservative amplitudes to prevent block flooding during bootstrap
            f_a_pow: I64F64::from_num(0.002),
            f_a_pos: I64F64::from_num(0.002),
        }
    }
}

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

    /// Retrieves a copy of the current LDD amplitudes.
    pub fn get_state(&self) -> DifficultyState {
        self.state.read().clone()
    }

    /// Audited: Allows the Blockchain to push the authoritative LDD amplitudes 
    /// calculated via the whitepaper logic into the engine's view.
    pub fn set_state(&self, f_a_pow: f64, f_a_pos: f64) {
        let mut state = self.state.write();
        state.f_a_pow = I64F64::from_num(f_a_pow);
        state.f_a_pos = I64F64::from_num(f_a_pos);
        debug!("[LDD-SYNC] Engine view updated: PoW Amplitide={:.6}, PoS Amplitude={:.6}", f_a_pow, f_a_pos);
    }

    /// Records block production to help the node track local performance metrics.
    pub fn record_block(&self, is_pow: bool, _block_height: u32) {
        if is_pow {
            *self.pow_blocks_count.write() += 1;
        } else {
            *self.pos_blocks_count.write() += 1;
        }
        // Adjustment windows are now handled authoritatively by Blockchain::adjust_ldd.
    }
}
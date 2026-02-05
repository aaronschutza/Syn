// src/engine.rs - Fully Deterministic Consensus Logic

use crate::params::{ParamManager, ConsensusParams};
use crate::stk_module::{StakingModule};
use crate::gov_module::GovernanceModule;
use crate::difficulty::DynamicDifficultyManager; 
use crate::fixed_point::Fixed;
use std::sync::Arc;
use num_bigint::BigUint;

#[derive(Debug)]
pub enum ConsensusError {
    StakingError(crate::stk_module::StakingError),
    GovernanceError(crate::gov_module::GovernanceError),
}

use crate::block::Block;

pub struct ConsensusEngine {
    _param_manager: Arc<ParamManager>,
    pub staking_module: Arc<StakingModule>,
    pub governance_module: Arc<GovernanceModule>,
    pub difficulty_manager: Arc<DynamicDifficultyManager>,
    pub params: ConsensusParams,
}

impl ConsensusEngine {
    pub fn new(
        param_manager: Arc<ParamManager>,
        staking_module: Arc<StakingModule>,
        governance_module: Arc<GovernanceModule>,
        difficulty_manager: Arc<DynamicDifficultyManager>,
        params: ConsensusParams,
    ) -> Self {
        Self { _param_manager: param_manager, staking_module, governance_module, difficulty_manager, params }
    }

    pub fn process_block(&self, block: &Block) -> Result<(), ConsensusError> {
        for tx in &block.transactions {
            let _ = tx; 
        }
        self.governance_module.end_block_logic(block.height);
        self.staking_module.end_block_logic(block.height);
        let is_pow = block.header.vrf_proof.is_none();
        self.difficulty_manager.record_block(is_pow, block.height);
        Ok(())
    }

    pub fn adjust_target_slope(&mut self, previous_block_size: u64) {
        if !self.params.enable_dynamic_slope { return; }
        let target_block_size = self.params.target_block_size;
        let max_change = self.params.max_slope_change_per_block;
        let current_slope = self.params.max_slope_change_per_block;

        let new_slope = if previous_block_size > target_block_size {
            let increase_factor = (previous_block_size - target_block_size) as f64 / target_block_size as f64;
            current_slope + (increase_factor * max_change)
        } else if previous_block_size < target_block_size {
            let decrease_factor = (target_block_size - previous_block_size) as f64 / target_block_size as f64;
            current_slope - (decrease_factor * max_change)
        } else {
            current_slope
        };
        self.params.max_slope_change_per_block = new_slope;
    }

    pub fn check_pos_eligibility(
        &self,
        stakeholder_address: &String,
        delta_seconds: u32,
        vrf_output: &[u8],
    ) -> bool {
        let stake = self.staking_module.get_voting_power(stakeholder_address);
        if stake == 0 { return false; }
        
        let total_stake = self.staking_module.get_total_bonded_supply();
        if total_stake == 0 { return false; }
        
        let alpha_i = Fixed::from_integer(stake as u64) / Fixed::from_integer(total_stake as u64);
    
        let diff_state = self.difficulty_manager.get_state();
        let psi = Fixed::from_integer(5); 
        let gamma = Fixed::from_integer(45);
        
        // Use Fixed-Point conversion from the difficulty manager state
        let f_a = Fixed::from_f64(diff_state.f_a_pos.to_num::<f64>());
        let delta = Fixed::from_integer(delta_seconds as u64);

        let f_delta = if delta < psi {
            Fixed(0)
        } else if delta < gamma {
            f_a * ((delta - psi) / (gamma - psi))
        } else {
            f_a / Fixed::from_integer(10)
        };

        let threshold = f_delta.pow_approx(alpha_i);

        let vrf_val = BigUint::from_bytes_be(vrf_output);
        let max_vrf = BigUint::from(1u32) << 256;
        
        // Final Fix for E0282: Use explicit BigUint variables and intermediate binding
        let numerator: BigUint = vrf_val << 64;
        let division_result: BigUint = numerator / max_vrf;
        
        // Convert the BigUint result directly to u128 for the Fixed struct
        let normalized_bits: u128 = division_result.try_into().unwrap_or(u128::MAX);
        let normalized_vrf = Fixed(normalized_bits);

        normalized_vrf < threshold
    }
}
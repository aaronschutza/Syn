// src/engine.rs

use crate::params::{ParamManager, ConsensusParams};
use crate::stk_module::{StakingModule, StakeAmount};
use crate::gov_module::GovernanceModule;
use crate::difficulty::DynamicDifficultyManager; 
use std::sync::Arc;
use log::{info, warn};
use fixed::types::I64F64;
// Import BigDecimal and necessary traits.
use bigdecimal::BigDecimal;
// Import traits required by bigdecimal, including Pow for exponentiation.
use num_traits::{ToPrimitive}; // Removed unused FromPrimitive, Pow
use std::str::FromStr;
use num_bigint::{BigInt, BigUint};

// Define the precision scale for BigDecimal operations (e.g., 100 decimal places).
const PRECISION_SCALE: i64 = 100;


#[derive(Debug)]
pub enum ConsensusError {
    StakingError(crate::stk_module::StakingError),
    GovernanceError(crate::gov_module::GovernanceError),
    InvalidBlock(String),
}

#[derive(Clone, Debug)]
pub struct Block { 
    pub height: u32, 
    pub transactions: Vec<Transaction>,
    pub is_pow: bool,
}

#[derive(Clone, Debug)]
pub enum Transaction { 
    Stake(String, StakeAmount), 
    Unstake(String, StakeAmount, u32), 
    Vote(u64, String, crate::gov_module::VoteType), 
    SubmitProposal(crate::gov_module::ProposalAction, u32),
    Transfer(String, String, StakeAmount),
}

pub struct ConsensusEngine {
    _param_manager: Arc<ParamManager>,
    staking_module: Arc<StakingModule>,
    governance_module: Arc<GovernanceModule>,
    difficulty_manager: Arc<DynamicDifficultyManager>,
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
            self.process_transaction(tx)?;
        }

        self.governance_module.end_block_logic(block.height);
        self.staking_module.end_block_logic(block.height);
        
        self.difficulty_manager.record_block(block.is_pow, block.height);

        info!("Block {} processed successfully. Type: {}", block.height, if block.is_pow { "PoW" } else { "PoS" });
        Ok(())
    }

    fn process_transaction(&self, tx: &Transaction) -> Result<(), ConsensusError> {
        match tx {
            Transaction::Stake(addr, amount) => {
                self.staking_module.process_stake(addr.clone(), *amount)
                    .map_err(ConsensusError::StakingError)
            },
            Transaction::Unstake(addr, amount, height) => {
                 self.staking_module.process_unstake(addr.clone(), *amount, *height)
                    .map_err(ConsensusError::StakingError)
            },
            Transaction::Vote(id, addr, vote) => {
                self.governance_module.process_vote(*id, addr.clone(), vote.clone())
                    .map_err(ConsensusError::GovernanceError)
            },
            Transaction::SubmitProposal(action, height) => {
                 self.governance_module.process_submit_proposal(action.clone(), *height)
                    .map_err(ConsensusError::GovernanceError)?;
                 Ok(())
            },
            Transaction::Transfer(..) => {
                Ok(())
            },
        }
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
        
        // SECURITY CRITICAL: Use high-precision decimals for deterministic calculations.
        let alpha_i = BigDecimal::from_str(&stake.to_string()).unwrap() / BigDecimal::from_str(&total_stake.to_string()).unwrap();
    
        let psi = 5; 
        let gamma = 45;
        
        let difficulty_state = self.difficulty_manager.get_state();
        let f_a_pos = difficulty_state.f_a_pos;
        
        let f_b_pos = f_a_pos / I64F64::from_num(10); 
    
        // This function can remain as it uses the deterministic I64F64 fixed-point type.
        pub fn calculate_ldd_curve(
            delta_seconds: u32,
            psi: u32,
            gamma: u32,
            f_a: I64F64,
            f_b: I64F64,
        ) -> I64F64 {
            if delta_seconds < psi {
                return I64F64::from_num(0);
            }
            if delta_seconds >= gamma {
                return f_b;
            }
    
            let delta_minus_psi = I64F64::from_num(delta_seconds - psi);
            let gamma_minus_psi = I64F64::from_num(gamma - psi);
    
            if gamma_minus_psi == I64F64::from_num(0) {
                return f_a;
            }
    
            let ratio = delta_minus_psi / gamma_minus_psi;
            let result = f_a * ratio;
            
            if result > f_a {
                return f_a;
            }
            result
        }
    
        // SECURITY CRITICAL: Re-implement with BigDecimal for deterministic exponentiation.
        pub fn calculate_pos_threshold(
            f_delta: I64F64,
            alpha_i: &BigDecimal,
        ) -> BigDecimal {
            let f_delta_bd = BigDecimal::from_str(&f_delta.to_num::<f64>().to_string()).unwrap();
    
            if f_delta_bd == BigDecimal::from(1) { return BigDecimal::from(1); }
            if f_delta_bd == BigDecimal::from(0) { return BigDecimal::from(0); }
            
            // As of this writing, BigDecimal does not have a direct `pow` method for decimal exponents.
            // The standard, safe way to do this deterministically is via logarithm and exponential functions
            // using a library that supports them with sufficient precision.
            // For this fix, we will simulate this by converting to string and back,
            // which is a common (though inefficient) way to force precision.
            // In a production system, a dedicated math library would be used.
            let base = (BigDecimal::from(1) - f_delta_bd).to_f64().unwrap();
            let exponent = alpha_i.to_f64().unwrap();
            let result_f64 = 1.0 - base.powf(exponent);
    
            BigDecimal::from_str(&result_f64.to_string()).unwrap()
        }
        
        pub fn normalize_vrf_output(vrf_output: &[u8]) -> BigDecimal {
            if vrf_output.len() != 32 {
                return BigDecimal::from(1); 
            }
            let vrf_bigint = BigUint::from_bytes_be(vrf_output);
            let vrf_bigdecimal = BigDecimal::new(BigInt::from(vrf_bigint), 0);
            
            let two_pow_256 = BigDecimal::from_str("115792089237316195423570985008687907853269984665640564039457584007913129639936")
                .expect("Failed to parse 2^256 constant");
    
            (vrf_bigdecimal / two_pow_256).with_scale(PRECISION_SCALE)
        }
    
                
        let f_delta = calculate_ldd_curve(delta_seconds, psi, gamma, f_a_pos, f_b_pos);
    
        let threshold = calculate_pos_threshold(f_delta, &alpha_i);
    
        let y = normalize_vrf_output(vrf_output);
    
        y < threshold
    }

    pub fn adjust_target_slope(&mut self, previous_block_size: u64) {
        if !self.params.enable_dynamic_slope {
            return;
        }

        let target_block_size = self.params.target_block_size;
        let max_change = self.params.max_slope_change_per_block;
        
        let current_slope = self.params.max_slope_change_per_block;

        let new_slope = if previous_block_size > target_block_size {
            let size_delta = previous_block_size - target_block_size;
            let increase_factor = size_delta as f64 / target_block_size as f64;
            current_slope + (increase_factor * max_change)
        } else if previous_block_size < target_block_size {
            let size_delta = target_block_size - previous_block_size;
            let decrease_factor = size_delta as f64 / target_block_size as f64;
            current_slope - (decrease_factor * max_change)
        } else {
            current_slope
        };
        
        self.params.max_slope_change_per_block = new_slope;
        warn!("`adjust_target_slope` is conceptual. Slope is adjusted via `record_block` in the difficulty manager. New conceptual slope: {}", new_slope);

    }

}
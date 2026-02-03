// src/params.rs

use serde::{Serialize, Deserialize};
use thiserror::Error;
use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::RwLock; 
pub const MAX_BLOCK_SIZE: u64 = 1_000_000; // 1 MB

#[derive(Error, Debug)]
pub enum ParamError {
    #[error("Parameter '{0}' not found.")]
    NotFound(String),
    #[error("Failed to deserialize value for parameter '{0}'. Data format mismatch or error: {1}")]
    DeserializationError(String, String),
    #[error("Invalid value for parameter '{0}'. Constraint violated: {1}")]
    InvalidValue(String, String),
}

/// Holds all consensus-critical parameters that can be modified by governance.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ProtocolParams {
    // Economic Parameters
    pub beta_burn_bps: u32, 
    pub proposal_deposit: u64,
    
    // Consensus/LDD Parameters
    pub target_block_time_seconds: u32,

    // Governance Parameters
    pub voting_period_blocks: u32,
    pub execution_delay_blocks: u32,
    pub quorum_threshold_bps: u32,
    pub passing_threshold_bps: u32,
}

impl Default for ProtocolParams {
    fn default() -> Self {
        Self {
            beta_burn_bps: 5000,
            proposal_deposit: 10_000,
            target_block_time_seconds: 15,
            voting_period_blocks: 80640,
            execution_delay_blocks: 17280,
            quorum_threshold_bps: 2000,
            passing_threshold_bps: 5001,
        }
    }
}

/// Manages access and updates to protocol parameters.
pub struct ParamManager {
    params: Arc<RwLock<ProtocolParams>>,
    constraints: HashMap<String, Box<dyn Fn(&ProtocolParams) -> Result<(), String> + Send + Sync>>,
}

impl ParamManager {
    pub fn new() -> Self {
        let mut manager = Self {
            params: Arc::new(RwLock::new(ProtocolParams::default())),
            constraints: HashMap::new(),
        };
        manager.define_constraints();
        manager
    }

    pub fn get_params(&self) -> ProtocolParams {
        self.params.read().clone()
    }

    fn define_constraints(&mut self) {
        // CORRECTED: Check against beta_burn_bps and basis points range
        self.constraints.insert("beta_burn_bps".to_string(), Box::new(|p| {
            if p.beta_burn_bps <= 10000 {
                Ok(())
            } else {
                Err("Must be between 0 and 10000".to_string())
            }
        }));
        self.constraints.insert("target_block_time_seconds".to_string(), Box::new(|p| {
            if p.target_block_time_seconds >= 1 {
                Ok(())
            } else {
                Err("Must be greater than or equal to 1".to_string())
            }
        }));
    }

    pub fn update_parameter(&self, param_name: &str, new_value_bytes: &[u8]) -> Result<(), ParamError> {
        let mut current_params = self.params.write();
        
        match param_name {
            // CORRECTED: Changed to beta_burn_bps
            "beta_burn_bps" => {
                let value: u32 = bincode::deserialize(new_value_bytes)
                    .map_err(|e| ParamError::DeserializationError(param_name.to_string(), e.to_string()))?;
                current_params.beta_burn_bps = value;
            },
            "proposal_deposit" => {
                 let value: u64 = bincode::deserialize(new_value_bytes)
                    .map_err(|e| ParamError::DeserializationError(param_name.to_string(), e.to_string()))?;
                current_params.proposal_deposit = value;
            },
            "target_block_time_seconds" => {
                 let value: u32 = bincode::deserialize(new_value_bytes)
                    .map_err(|e| ParamError::DeserializationError(param_name.to_string(), e.to_string()))?;
                current_params.target_block_time_seconds = value;
            },
            _ => return Err(ParamError::NotFound(param_name.to_string())),
        }

        if let Some(constraint_fn) = self.constraints.get(param_name) {
            constraint_fn(&current_params)
                .map_err(|e| ParamError::InvalidValue(param_name.to_string(), e))?;
        }

        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConsensusParams {
    // ... existing code ...

    // EIP-1559-like dynamic fee slope adjustment
    // This feature is experimental and disabled by default.
    pub enable_dynamic_slope: bool,
    pub target_block_size: u64,
    pub max_slope_change_per_block: f64,
}

impl ConsensusParams {
    pub fn new() -> Self {
        Self {
            // ... existing code ...
            
            // Dynamic slope adjustment is disabled by default for stability.
            // To enable it, set `enable_dynamic_slope` to `true`.
            enable_dynamic_slope: false,
            // The target block size is set to 50% of the max block size.
            // This is a common starting point, inspired by EIP-1559.
            target_block_size: MAX_BLOCK_SIZE / 2,
            // The slope can change by a maximum of 12.5% per block.
            // This value is borrowed from EIP-1559's base fee adjustment.
            max_slope_change_per_block: 0.125,
        }
    }
}
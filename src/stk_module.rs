// src/stk_module.rs

use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::RwLock;
use serde::{Serialize, Deserialize};
use log::{info, warn, debug};
use thiserror::Error;

// CORRECTED: Made type aliases public
pub type Address = String;
pub type StakeAmount = u128;

/// Security parameter: The duration (in blocks) that stake remains locked after an unstake request.
const UNBONDING_PERIOD: u32 = 80640;

#[derive(Error, Debug)]
pub enum StakingError {
    #[error("Insufficient funds available for staking.")]
    InsufficientFunds,
    #[error("Validator not found or not bonded.")]
    ValidatorNotActive,
    #[error("Cannot unstake more than the currently bonded amount.")]
    InvalidUnstakeAmount,
    #[error("Bank module error: {0}")]
    BankError(String),
}

/// Represents the lifecycle state of a validator's stake.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum ValidatorStatus {
    Bonded,
    Unbonding,
    Unbonded,
}

/// Represents a single validator and their associated stake.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Validator {
    pub address: Address,
    pub status: ValidatorStatus,
    pub bonded_stake: StakeAmount,
    pub unbonding_queue: Vec<UnbondingEntry>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UnbondingEntry {
    pub amount: StakeAmount,
    pub completion_height: u32,
}

pub struct BankModule {
    // ... internal state (e.g., balances map or UTXO set) ...
}

impl BankModule {
    fn lock_tokens(&self, address: &Address, amount: StakeAmount) -> Result<(), StakingError> {
        debug!("Bank: Locked {} SYN for address {}", amount, address);
        Ok(())
    }
    fn release_tokens(&self, address: &Address, amount: StakeAmount) -> Result<(), StakingError> {
        debug!("Bank: Released {} SYN to address {}", amount, address);
        Ok(())
    }
}

pub struct StakingModule {
    validators: Arc<RwLock<HashMap<Address, Validator>>>,
    total_bonded_supply: Arc<RwLock<StakeAmount>>,
    bank: Arc<BankModule>,
}

impl StakingModule {
    pub fn new(bank: Arc<BankModule>) -> Self {
        Self {
            validators: Arc::new(RwLock::new(HashMap::new())),
            total_bonded_supply: Arc::new(RwLock::new(0)),
            bank,
        }
    }

    pub fn process_stake(&self, address: Address, amount: StakeAmount) -> Result<(), StakingError> {
        self.bank.lock_tokens(&address, amount)?;

        let mut validators = self.validators.write();
        
        let validator = validators.entry(address.clone()).or_insert(Validator {
            address: address.clone(),
            status: ValidatorStatus::Unbonded,
            bonded_stake: 0,
            unbonding_queue: Vec::new(),
        });

        validator.bonded_stake = validator.bonded_stake.saturating_add(amount);
        
        if validator.status != ValidatorStatus::Bonded {
            info!("Validator {} transitioning to Bonded.", address);
            validator.status = ValidatorStatus::Bonded;
        }
        
        info!("Stake processed for {}: Amount {}, New Total Bonded {}", address, amount, validator.bonded_stake);

        let mut total_supply = self.total_bonded_supply.write();
        *total_supply = total_supply.saturating_add(amount);

        Ok(())
    }

    pub fn process_unstake(&self, address: Address, amount: StakeAmount, current_height: u32) -> Result<(), StakingError> {
        let mut validators = self.validators.write();

        let validator = validators.get_mut(&address).ok_or(StakingError::ValidatorNotActive)?;

        if amount > validator.bonded_stake {
            return Err(StakingError::InvalidUnstakeAmount);
        }

        validator.bonded_stake = validator.bonded_stake.saturating_sub(amount);
        let completion_height = current_height + UNBONDING_PERIOD;
        
        validator.unbonding_queue.push(UnbondingEntry {
            amount,
            completion_height,
        });

        if validator.bonded_stake == 0 && validator.status == ValidatorStatus::Bonded {
            validator.status = ValidatorStatus::Unbonding;
            info!("Validator {} initiated full unstake. Transitioning to Unbonding.", address);
        } else {
            info!("Validator {} initiated partial unstake of {} SYN. Remains Bonded.", address, amount);
        }

        let mut total_supply = self.total_bonded_supply.write();
        *total_supply = total_supply.saturating_sub(amount);

        Ok(())
    }

    pub fn end_block_logic(&self, block_height: u32) {
        let mut validators = self.validators.write();
        
        for (address, validator) in validators.iter_mut() {
            let mut completed_indices = Vec::new();
            let mut total_released: StakeAmount = 0;

            for (index, entry) in validator.unbonding_queue.iter().enumerate() {
                if block_height >= entry.completion_height {
                    if self.bank.release_tokens(address, entry.amount).is_ok() {
                        total_released = total_released.saturating_add(entry.amount);
                        completed_indices.push(index);
                    } else {
                        warn!("CRITICAL: Failed to release tokens for {} during unbonding completion. Retrying next block.", address);
                    }
                }
            }

            for index in completed_indices.iter().rev() {
                validator.unbonding_queue.remove(*index);
            }

            if total_released > 0 {
                info!("Unbonding complete for {}. Released {} SYN.", address, total_released);
                
                if validator.status == ValidatorStatus::Unbonding && validator.unbonding_queue.is_empty() {
                    validator.status = ValidatorStatus::Unbonded;
                    info!("Validator {} transitioned to Unbonded.", address);
                }
            }
        }
    }

    pub fn get_voting_power(&self, address: &Address) -> StakeAmount {
        let validators = self.validators.read();
        validators.get(address)
            .map(|v| if v.status == ValidatorStatus::Bonded { v.bonded_stake } else { 0 })
            .unwrap_or(0)
    }

    pub fn get_total_bonded_supply(&self) -> StakeAmount {
        *self.total_bonded_supply.read()
    }

    pub fn get_active_validator_set(&self) -> HashMap<Address, StakeAmount> {
        let validators = self.validators.read();
        validators.iter()
            .filter(|(_, v)| v.status == ValidatorStatus::Bonded && v.bonded_stake > 0)
            .map(|(addr, v)| (addr.clone(), v.bonded_stake))
            .collect()
    }
}
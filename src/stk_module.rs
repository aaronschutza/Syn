// src/stk_module.rs - Centralized staking types and logic

use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::RwLock;
use serde::{Serialize, Deserialize};
use log::debug;
use thiserror::Error;

pub type Address = String;
pub type StakeAmount = u128;

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

/// Information about a stakeholder's balance and asset type.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct StakeInfo {
    pub asset: String,
    pub amount: u64,
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

pub struct BankModule {}

impl BankModule {
    pub fn lock_tokens(&self, address: &Address, amount: StakeAmount) -> Result<(), StakingError> {
        debug!("Bank: Locked {} SYN for address {}", amount, address);
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
        validator.status = ValidatorStatus::Bonded;
        let mut total_supply = self.total_bonded_supply.write();
        *total_supply = total_supply.saturating_add(amount);
        Ok(())
    }

    /// Reduces the stake for a validator. Used during chain reorganization rollback.
    pub fn reduce_stake(&self, address: &Address, amount: StakeAmount) -> Result<(), StakingError> {
        let mut validators = self.validators.write();
        if let Some(validator) = validators.get_mut(address) {
            if validator.bonded_stake < amount {
                return Err(StakingError::InvalidUnstakeAmount);
            }
            validator.bonded_stake -= amount;
            if validator.bonded_stake == 0 {
                validator.status = ValidatorStatus::Unbonded;
            }
            let mut total_supply = self.total_bonded_supply.write();
            *total_supply = total_supply.saturating_sub(amount);
            Ok(())
        } else {
            Err(StakingError::ValidatorNotActive)
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

    pub fn end_block_logic(&self, _block_height: u32) {}
}
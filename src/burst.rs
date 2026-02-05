// src/burst.rs - Execution-Driven Burst Finality

use crate::block::Block;
use log::info;
use bitcoin_hashes::Hash;

/// Manages the state of the Burst Finality mechanism.
#[derive(Debug, Clone)]
pub struct BurstFinalityManager {
    pub burst_active: bool,
    pub burst_end_height: u32,
    pub burst_origin_hash: Vec<u8>,
    pub burst_fee_share: u64,
    pub k_burst: u32,
    pub fee_burst_threshold: u64,
    pub psi_min: u32,
}

impl Default for BurstFinalityManager {
    fn default() -> Self {
        Self {
            burst_active: false,
            burst_end_height: 0,
            burst_origin_hash: Vec::new(),
            burst_fee_share: 0,
            k_burst: 24, 
            fee_burst_threshold: 1_000_000, 
            psi_min: 0, 
        }
    }
}

impl BurstFinalityManager {
    pub fn new(k_burst: u32, fee_threshold: u64) -> Self {
        let mut mgr = Self::default();
        // FIXED: Ensure k_burst is never zero to prevent divide-by-zero panics
        mgr.k_burst = k_burst.max(1); 
        mgr.fee_burst_threshold = fee_threshold;
        mgr
    }

    /// Checks a new block for high-fee transactions that trigger Burst Mode.
    pub fn check_and_activate(&mut self, block: &Block, total_fees: u64) -> bool {
        if !self.burst_active && total_fees >= self.fee_burst_threshold {
            info!("🚀 BURST MODE ACTIVATED at height {}", block.height);
            self.burst_active = true;
            self.burst_end_height = block.height + self.k_burst;
            self.burst_origin_hash = block.header.hash().to_byte_array().to_vec();
            
            // FIXED: Divide by k_burst which is now guaranteed to be >= 1
            self.burst_fee_share = total_fees / self.k_burst as u64;
            return true;
        }
        false
    }

    /// Updates the state based on the latest block processing.
    pub fn update_state(&mut self, current_height: u32) {
        if self.burst_active {
            if current_height >= self.burst_end_height {
                info!("🏁 BURST MODE COMPLETED at height {}", current_height);
                self.burst_active = false;
                self.burst_fee_share = 0;
            } else {
                info!(">> Burst Mode Active: {} blocks remaining", self.burst_end_height - current_height);
            }
        }
    }

    /// Returns aggressive parameters if Burst Mode is active.
    pub fn get_burst_parameters(&self) -> Option<(u32, u64)> {
        if self.burst_active {
            Some((self.psi_min, 1)) 
        } else {
            None
        }
    }
}
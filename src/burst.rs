// src/burst.rs

use crate::block::Block;
use log::info;
use bitcoin_hashes::Hash; // Imported to use to_byte_array()

/// Manages the state of the Burst Finality mechanism.
/// (Whitepaper Section 13.2)
#[derive(Debug, Clone)]
pub struct BurstFinalityManager {
    /// Is the network currently in Burst Mode?
    pub burst_active: bool,
    /// The block height at which the current burst will end.
    pub burst_end_height: u32,
    /// The hash of the block that triggered the burst.
    pub burst_origin_hash: Vec<u8>,
    /// The bonus fee share to be distributed to each block in the burst.
    pub burst_fee_share: u64,
    /// Configuration: Number of blocks in a burst sequence (k_burst).
    pub k_burst: u32,
    /// Configuration: Minimum fee required to trigger a burst.
    pub fee_burst_threshold: u64,
    /// Configuration: Minimal slot gap during burst (psi_min).
    pub psi_min: u32,
}

impl Default for BurstFinalityManager {
    fn default() -> Self {
        Self {
            burst_active: false,
            burst_end_height: 0,
            burst_origin_hash: Vec::new(),
            burst_fee_share: 0,
            k_burst: 24, // Per whitepaper recommendation
            fee_burst_threshold: 1_000_000, // Placeholder, should be config
            psi_min: 0, // Minimal slot gap for max speed
        }
    }
}

impl BurstFinalityManager {
    pub fn new(k_burst: u32, fee_threshold: u64) -> Self {
        let mut mgr = Self::default();
        mgr.k_burst = k_burst;
        mgr.fee_burst_threshold = fee_threshold;
        mgr
    }

    /// Checks a new block for high-fee transactions that trigger Burst Mode.
    /// Returns true if Burst Mode was activated.
    pub fn check_and_activate(&mut self, block: &Block, total_fees: u64) -> bool {
        // In a real implementation, we would check individual transaction fees.
        // For simplicity here, we check if the total fees in the block exceed the threshold.
        // This simulates a "Burst Trigger Transaction" being included.
        if !self.burst_active && total_fees >= self.fee_burst_threshold {
            info!("🚀 BURST MODE ACTIVATED at height {}", block.height);
            self.burst_active = true;
            self.burst_end_height = block.height + self.k_burst;
            // FIX: Use to_byte_array().to_vec() for unambiguous conversion
            self.burst_origin_hash = block.header.hash().to_byte_array().to_vec();
            
            // Calculate fee share per burst block (simplified)
            // Real logic: (1 - beta_burn) * trigger_fee / k_burst
            self.burst_fee_share = total_fees / self.k_burst as u64;
            return true;
        }
        false
    }

    /// Updates the state based on the latest block processing.
    /// Should be called after a block is added to the chain.
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

    /// Returns the LDD parameters to use for the next slot.
    /// If Burst Mode is active, returns aggressive parameters.
    /// Otherwise, returns None (indicating use standard adaptive LDD).
    pub fn get_burst_parameters(&self) -> Option<(u32, u64)> {
        if self.burst_active {
            // Return (psi, target_block_time)
            // During burst: psi = psi_min (0), target = minimal (e.g. 1s or less)
            Some((self.psi_min, 1)) 
        } else {
            None
        }
    }
}
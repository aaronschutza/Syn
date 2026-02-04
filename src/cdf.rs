// src/cdf.rs

use bitcoin_hashes::{sha256d, Hash};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Chromo-Dynamic Finality (CDF) Colors for PoS Votes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Color {
    Red = 0,
    Green = 1,
    Blue = 2,
}

/// Chromo-Dynamic Finality (CDF) Anti-Colors for PoW Blocks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AntiColor {
    AntiRed = 0,
    AntiGreen = 1,
    AntiBlue = 2,
}

impl AntiColor {
    /// Deterministically assigns an Anti-Color based on block hash (Whitepaper Section 13.6).
    pub fn from_hash(hash: &sha256d::Hash) -> Self {
        // Use the first byte of the hash modulo 3
        let byte = hash.to_byte_array()[0];
        match byte % 3 {
            0 => AntiColor::AntiRed,
            1 => AntiColor::AntiGreen,
            _ => AntiColor::AntiBlue,
        }
    }
}

/// A vote cast by a PoS staker for a specific checkpoint block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalityVote {
    pub voter_public_key: Vec<u8>,
    pub checkpoint_hash: sha256d::Hash,
    pub color: Color,
    pub signature: Vec<u8>,
}

/// Tracks the state of the Chromo-Dynamic Finality mechanism.
#[derive(Debug, Default, Clone)]
pub struct FinalityGadget {
    /// The hash of the block currently being finalized.
    pub target_checkpoint: Option<sha256d::Hash>,
    /// Whether the gadget is actively collecting votes.
    pub active: bool,
    /// Is the checkpoint finalized?
    pub finalized: bool,

    // PoS Votes Tracking (Voter PKs)
    pub red_votes: HashSet<Vec<u8>>,
    pub green_votes: HashSet<Vec<u8>>,
    pub blue_votes: HashSet<Vec<u8>>,
    
    // Weighted Vote Counts
    pub red_weight: u64,
    pub green_weight: u64,
    pub blue_weight: u64,

    // PoW Blocks Tracking (Count of blocks extending checkpoint)
    pub anti_red_blocks: u32,
    pub anti_green_blocks: u32,
    pub anti_blue_blocks: u32,

    // Thresholds
    pub stake_threshold: u64,
    pub work_threshold: u32,
}

impl FinalityGadget {
    pub fn new() -> Self {
        Self::default()
    }

    /// Activates the gadget for a specific checkpoint.
    pub fn activate(&mut self, checkpoint: sha256d::Hash, total_stake: u64) {
        self.target_checkpoint = Some(checkpoint);
        self.active = true;
        self.finalized = false;
        self.reset_votes();
        
        // Threshold Calculation per Whitepaper Section 13.7
        // Safety requires T_pos > alpha_A * N / 3
        // We set a robust threshold of 20% of total stake per color to ensure safety against alpha_A < 0.5.
        self.stake_threshold = total_stake / 5; 
        
        // Work threshold: 5 blocks of each anti-color.
        self.work_threshold = 5; 
    }

    fn reset_votes(&mut self) {
        self.red_votes.clear();
        self.green_votes.clear();
        self.blue_votes.clear();
        self.red_weight = 0;
        self.green_weight = 0;
        self.blue_weight = 0;
        self.anti_red_blocks = 0;
        self.anti_green_blocks = 0;
        self.anti_blue_blocks = 0;
    }

    /// Processes a PoS vote.
    pub fn process_vote(&mut self, vote: &FinalityVote, stake: u64) {
        if !self.active || self.finalized { return; }
        if Some(vote.checkpoint_hash) != self.target_checkpoint { return; }

        match vote.color {
            Color::Red => {
                if self.red_votes.insert(vote.voter_public_key.clone()) {
                    self.red_weight += stake;
                }
            }
            Color::Green => {
                if self.green_votes.insert(vote.voter_public_key.clone()) {
                    self.green_weight += stake;
                }
            }
            Color::Blue => {
                if self.blue_votes.insert(vote.voter_public_key.clone()) {
                    self.blue_weight += stake;
                }
            }
        }
    }

    /// Processes a PoW block that extends the checkpoint.
    pub fn process_pow_block(&mut self, block_hash: &sha256d::Hash) {
        if !self.active || self.finalized { return; }
        
        match AntiColor::from_hash(block_hash) {
            AntiColor::AntiRed => self.anti_red_blocks += 1,
            AntiColor::AntiGreen => self.anti_green_blocks += 1,
            AntiColor::AntiBlue => self.anti_blue_blocks += 1,
        }
    }

    /// Checks if finality conditions are met.
    pub fn check_finality(&mut self) -> bool {
        if !self.active || self.finalized { return self.finalized; }

        let stake_quorum = self.red_weight >= self.stake_threshold 
            && self.green_weight >= self.stake_threshold 
            && self.blue_weight >= self.stake_threshold;

        let work_quorum = self.anti_red_blocks >= self.work_threshold
            && self.anti_green_blocks >= self.work_threshold
            && self.anti_blue_blocks >= self.work_threshold;

        if stake_quorum && work_quorum {
            self.finalized = true;
            // Note: We don't disable 'active' immediately to allow late propagation/verification if needed,
            // but effectively the checkpoint is done.
            return true;
        }
        false
    }
}
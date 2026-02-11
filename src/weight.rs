// src/weight.rs - Synergistic Weight Calculation (PoW + PoB)

use crate::block::BlockHeader;
use crate::units::Probability;
use num_bigint::BigUint;
use num_traits::ToPrimitive;

/// Conversion factor to normalize PoW Difficulty into "Satoshi-equivalent" units.
/// Assumption: 1 Unit of Difficulty requires approximately 1,000,000 units of economic cost (hashes).
/// This constant ensures that PoW and PoS weights are commensurate in the ASW metric.
const WORK_TO_STAKE_RATIO: u64 = 1_000_000;

/// Defines how the consensus weight of a block is calculated.
/// This replaces the legacy Accumulated Synergistic Work (ASW) logic.
pub trait SynergisticWeight {
    /// Calculates the weight of the block based on its type (PoW vs PoS).
    /// PoW: Weight = Difficulty * WORK_TO_STAKE_RATIO
    /// PoS: Weight = Proven Burn (Economic Cost)
    fn calculate_synergistic_weight(&self, current_burn_rate: Probability) -> u64;
}

impl SynergisticWeight for BlockHeader {
    fn calculate_synergistic_weight(&self, _current_burn_rate: Probability) -> u64 {
        if self.vrf_proof.is_none() {
            // --- Proof-of-Work Weight ---
            // Weight = (Reference_Target / Actual_Target) * Scaling_Factor
            let target = BlockHeader::calculate_target(self.bits);
            // 0x207fffff is the standard "easiest" target (max target)
            let easiest = BlockHeader::calculate_target(0x207fffff);
            
            if target == BigUint::from(0u32) {
                return u64::MAX; 
            }
            
            // Calculate raw difficulty
            let difficulty = easiest / target;
            let difficulty_u64 = difficulty.to_u64().unwrap_or(u64::MAX);

            // AUDIT FIX: Dimensional Consistency
            // Scale difficulty to be comparable with Burn Amount (Satoshis)
            difficulty_u64.saturating_mul(WORK_TO_STAKE_RATIO)
        } else {
            // --- Proof-of-Stake (Proof-of-Burn) Weight ---
            // Weight = Proven Burn Amount
            // Since WORK_TO_STAKE_RATIO scales PoW up, we can use raw burn amount here
            // assuming the market equilibrium 1 Diff ~= 1M Sats.
            self.proven_burn
        }
    }
}
// src/weight.rs - Synergistic Weight Calculation (PoW + PoB)

use crate::block::BlockHeader;
use crate::units::Probability;
use num_bigint::BigUint;
use num_traits::ToPrimitive;

/// Defines how the consensus weight of a block is calculated.
/// This replaces the legacy Accumulated Synergistic Work (ASW) logic.
pub trait SynergisticWeight {
    /// Calculates the weight of the block based on its type (PoW vs PoS).
    /// PoW: Weight = Difficulty (1 / Target)
    /// PoS: Weight = Proven Burn (Economic Cost)
    fn calculate_synergistic_weight(&self, current_burn_rate: Probability) -> u64;
}

impl SynergisticWeight for BlockHeader {
    fn calculate_synergistic_weight(&self, _current_burn_rate: Probability) -> u64 {
        if self.vrf_proof.is_none() {
            // --- Proof-of-Work Weight ---
            // Weight = Reference_Target / Actual_Target
            // This is standard Nakamoto work calculation.
            let target = BlockHeader::calculate_target(self.bits);
            // 0x207fffff is the standard "easiest" target (max target)
            let easiest = BlockHeader::calculate_target(0x207fffff);
            
            if target == BigUint::from(0u32) {
                return u64::MAX; 
            }
            
            let work = easiest / target;
            work.to_u64().unwrap_or(u64::MAX)
        } else {
            // --- Proof-of-Stake (Proof-of-Burn) Weight ---
            // Weight = Proven Burn Amount
            // This implements the security fix: costless simulation is prevented
            // because the weight is directly tied to a verifiable economic cost.
            // We assume 1 Unit of Burn ~= 1 Unit of Work Difficulty for the ASW metric.
            self.proven_burn
        }
    }
}
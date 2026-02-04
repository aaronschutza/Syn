// src/dcs.rs - Integer-only consensus aggregation

use crate::block::{Beacon, BeaconData};

/// The Decentralized Consensus Service (F_DCS)
/// Responsible for aggregating on-chain beacons to provide BFT-robust consensus values.
#[derive(Debug, Clone, Default)]
pub struct DecentralizedConsensusService {
    // Caches for the current interval's beacons
    time_beacons: Vec<u64>,
    stake_beacons: Vec<u64>,
    delay_beacons: Vec<u32>,
    load_beacons: Vec<u64>, // Scaled integer (fixed point 10^6)
    orphan_rates: Vec<u32>,
    reorg_depths: Vec<u32>,
    branching_factors: Vec<u64>, // Scaled integer (fixed point 10^6)
}

pub struct ConsensusValues {
    pub median_time: u64,
    pub median_total_stake: u64,
    pub consensus_delay: u32,
    pub consensus_load: u64,         // Scaled integer
    pub consensus_threat_level: u64, // Scaled integer (0 to 1,000,000)
    pub chain_health_score: u64,     // Scaled integer
}

impl DecentralizedConsensusService {
    pub fn new() -> Self {
        Self::default()
    }

    /// Resets internal cache. Called at the start of a new DCS interval.
    pub fn reset_interval(&mut self) {
        self.time_beacons.clear();
        self.stake_beacons.clear();
        self.delay_beacons.clear();
        self.load_beacons.clear();
        self.orphan_rates.clear();
        self.reorg_depths.clear();
        self.branching_factors.clear();
    }

    /// Ingests beacons from a valid block. 
    pub fn process_beacons(&mut self, beacons: &[Beacon]) {
        for beacon in beacons {
            match &beacon.data {
                BeaconData::Time(t) => self.time_beacons.push(*t),
                BeaconData::Stake(s) => self.stake_beacons.push(*s),
                BeaconData::Delay(d) => self.delay_beacons.push(*d),
                BeaconData::Load(l) => self.load_beacons.push(*l),
                BeaconData::Security(orphan_count, reorg_depth) => {
                    self.orphan_rates.push(*orphan_count);
                    self.reorg_depths.push(*reorg_depth);
                }
                BeaconData::Topology(branching, _) => {
                    self.branching_factors.push(*branching);
                }
            }
        }
    }

    /// Computes the BFT-robust consensus values for the current set of beacons.
    pub fn calculate_consensus(&self) -> ConsensusValues {
        // Calculate Threat Level (S_threat) using integer logic
        let p90_orphan = self.calculate_percentile(&self.orphan_rates, 90).unwrap_or(0);
        let p90_reorg = self.calculate_percentile(&self.reorg_depths, 90).unwrap_or(0);
        
        // Simple normalization: 1.0 is represented by 1,000,000
        let threat_orphan = (p90_orphan as u64 * 1_000_000 / 50).min(1_000_000);
        let threat_reorg = (p90_reorg as u64 * 1_000_000 / 3).min(1_000_000);
        let s_threat = threat_orphan.max(threat_reorg);

        // Calculate Chain Health (H_chain)
        let p90_branching = self.calculate_percentile_u64(&self.branching_factors, 90).unwrap_or(1_000_000);
        // Normalize: 1.0 (1M) is healthy, > 2.0 (2M) is highly contested
        let h_chain = p90_branching.saturating_sub(1_000_000).min(1_000_000);

        ConsensusValues {
            median_time: self.calculate_median(&self.time_beacons).unwrap_or(0),
            median_total_stake: self.calculate_median(&self.stake_beacons).unwrap_or(0),
            consensus_delay: self.calculate_percentile(&self.delay_beacons, 95).unwrap_or(0),
            consensus_load: self.calculate_median_u64(&self.load_beacons).unwrap_or(0),
            consensus_threat_level: s_threat,
            chain_health_score: h_chain,
        }
    }

    fn calculate_median(&self, values: &[u64]) -> Option<u64> {
        if values.is_empty() { return None; }
        let mut v = values.to_vec();
        v.sort_unstable();
        let mid = v.len() / 2;
        if v.len() % 2 == 0 {
            Some((v[mid - 1] + v[mid]) / 2)
        } else {
            Some(v[mid])
        }
    }

    fn calculate_median_u64(&self, values: &[u64]) -> Option<u64> {
        self.calculate_median(values)
    }

    fn calculate_percentile(&self, values: &[u32], percentile: u32) -> Option<u32> {
        if values.is_empty() { return None; }
        let mut v = values.to_vec();
        v.sort_unstable();
        let idx = ((v.len() as u64 - 1) * percentile as u64 / 100) as usize;
        Some(v[idx.min(v.len() - 1)])
    }

    fn calculate_percentile_u64(&self, values: &[u64], percentile: u32) -> Option<u64> {
        if values.is_empty() { return None; }
        let mut v = values.to_vec();
        v.sort_unstable();
        let idx = ((v.len() as u64 - 1) * percentile as u64 / 100) as usize;
        Some(v[idx.min(v.len() - 1)])
    }
}
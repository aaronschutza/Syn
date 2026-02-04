// src/dcs.rs

use crate::block::{Beacon, BeaconData};

/// The Decentralized Consensus Service (F_DCS)
/// Responsible for aggregating on-chain beacons to provide BFT-robust consensus values.
#[derive(Debug, Clone, Default)]
pub struct DecentralizedConsensusService {
    // Caches for the current interval's beacons
    time_beacons: Vec<u64>,
    stake_beacons: Vec<u64>,
    delay_beacons: Vec<u32>,
    load_beacons: Vec<f64>,
    
    // Security metrics
    orphan_rates: Vec<u32>,
    reorg_depths: Vec<u32>,
    
    // Topology metrics
    branching_factors: Vec<f64>,
}

pub struct ConsensusValues {
    pub median_time: u64,
    pub median_total_stake: u64,
    pub consensus_delay: u32,
    pub consensus_load: f64,
    pub consensus_threat_level: f64, // Normalized 0.0 - 1.0
    pub chain_health_score: f64,     // Normalized 0.0 - 1.0
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
        // Calculate Threat Level (S_threat)
        // High percentile of orphan rates and reorg depths
        let p90_orphan = self.calculate_percentile(&self.orphan_rates, 0.90).unwrap_or(0) as f64;
        let p90_reorg = self.calculate_percentile(&self.reorg_depths, 0.90).unwrap_or(0) as f64;
        
        // Simple normalization model for threat level:
        // Threat = 1.0 if > 50% orphans or > 3 block reorgs
        // This effectively triggers high-alert mode.
        let threat_orphan = (p90_orphan / 50.0).min(1.0);
        let threat_reorg = (p90_reorg / 3.0).min(1.0);
        let s_threat = threat_orphan.max(threat_reorg);

        // Calculate Chain Health (H_chain)
        // Based on branching factor
        let p90_branching = self.calculate_percentile_float(&self.branching_factors, 0.90).unwrap_or(1.0);
        // Normalize: 1.0 is healthy, > 2.0 is highly contested
        let h_chain = ((p90_branching - 1.0) / 1.0).max(0.0).min(1.0);

        ConsensusValues {
            median_time: self.calculate_median(&self.time_beacons).unwrap_or(0),
            median_total_stake: self.calculate_median(&self.stake_beacons).unwrap_or(0),
            consensus_delay: self.calculate_percentile(&self.delay_beacons, 0.95).unwrap_or(0),
            consensus_load: self.calculate_median_float(&self.load_beacons).unwrap_or(0.0),
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

    fn calculate_median_float(&self, values: &[f64]) -> Option<f64> {
        if values.is_empty() { return None; }
        let mut v = values.to_vec();
        v.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let mid = v.len() / 2;
        Some(v[mid])
    }

    fn calculate_percentile(&self, values: &[u32], percentile: f64) -> Option<u32> {
        if values.is_empty() { return None; }
        let mut v = values.to_vec();
        v.sort_unstable();
        let idx = ((v.len() as f64 - 1.0) * percentile).round() as usize;
        Some(v[idx.min(v.len() - 1)])
    }

    fn calculate_percentile_float(&self, values: &[f64], percentile: f64) -> Option<f64> {
        if values.is_empty() { return None; }
        let mut v = values.to_vec();
        v.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let idx = ((v.len() as f64 - 1.0) * percentile).round() as usize;
        Some(v[idx.min(v.len() - 1)])
    }
}
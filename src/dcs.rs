// src/dcs.rs - BFT-robust telemetry aggregation for adaptive security

use crate::block::{Beacon, BeaconData};

/// The Decentralized Consensus Service (F_DCS)
/// Aggregates on-chain beacons to provide metrics for Adaptive Protocol Homeostasis.
#[derive(Debug, Clone, Default)]
pub struct DecentralizedConsensusService {
    time_beacons: Vec<u64>,
    stake_beacons: Vec<u64>,
    delay_beacons: Vec<u32>,
    load_beacons: Vec<u64>, 
    orphan_rates: Vec<u32>,
    reorg_depths: Vec<u32>,
    branching_factors: Vec<u64>,
}

/// Consolidated metrics derived from BFT-secure beacon medians/percentiles.
pub struct ConsensusValues {
    pub median_time: u64,
    pub median_total_stake: u64,
    pub consensus_delay: u32,
    pub consensus_load: f64,
    pub security_threat_level: f64, // S_threat [0.0 - 1.0]
    pub chain_health_score: f64,     // H_chain [0.0 - 1.0]
}

impl DecentralizedConsensusService {
    pub fn new() -> Self { Self::default() }

    pub fn reset_interval(&mut self) {
        self.time_beacons.clear();
        self.stake_beacons.clear();
        self.delay_beacons.clear();
        self.load_beacons.clear();
        self.orphan_rates.clear();
        self.reorg_depths.clear();
        self.branching_factors.clear();
    }

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

    /// Computes the BFT-robust consensus values.
    /// Uses 90th percentiles for threat detection as per whitepaper Section 15.2.
    pub fn calculate_consensus(&self) -> ConsensusValues {
        // 1. Calculate Security Threat Level (S_threat)
        // High orphan rates or reorg depths pull S_threat towards 1.0
        let p90_orphan = self.calculate_percentile(&self.orphan_rates, 90).unwrap_or(0);
        let p90_reorg = self.calculate_percentile(&self.reorg_depths, 90).unwrap_or(0);
        
        let threat_orphan = (p90_orphan as f64 / 10.0).min(1.0); // Baseline: 10 orphans/window is max threat
        let threat_reorg = (p90_reorg as f64 / 6.0).min(1.0);   // Baseline: 6 block reorg is max threat
        let s_threat = threat_orphan.max(threat_reorg);

        // 2. Calculate Chain Health Score (H_chain)
        // High branching factors pull H_chain towards 1.0
        let p90_branching = self.calculate_percentile_u64(&self.branching_factors, 90).unwrap_or(1_000_000);
        let h_chain = ((p90_branching as f64 / 1_000_000.0) - 1.0).max(0.0).min(1.0);

        ConsensusValues {
            median_time: self.calculate_median(&self.time_beacons).unwrap_or(0),
            median_total_stake: self.calculate_median(&self.stake_beacons).unwrap_or(0),
            consensus_delay: self.calculate_percentile(&self.delay_beacons, 95).unwrap_or(0),
            consensus_load: self.calculate_median_u64(&self.load_beacons).unwrap_or(0) as f64 / 1_000_000.0,
            security_threat_level: s_threat,
            chain_health_score: h_chain,
        }
    }

    fn calculate_median(&self, values: &[u64]) -> Option<u64> {
        if values.is_empty() { return None; }
        let mut v = values.to_vec();
        v.sort_unstable();
        Some(v[v.len() / 2])
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
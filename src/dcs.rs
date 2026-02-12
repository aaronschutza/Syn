// src/dcs.rs - BFT-robust telemetry aggregation for adaptive security

use crate::block::{Beacon, BeaconData};
use crate::difficulty::NetworkState;
use crate::units::{SlotDuration, Probability};
use fixed::types::U64F64;
use serde::{Deserialize, Serialize};

/// The Decentralized Consensus Service (F_DCS)
/// Aggregates on-chain beacons to provide metrics for Adaptive Protocol Homeostasis.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
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
    pub consensus_load: U64F64,
    pub security_threat_level: U64F64, // S_threat [0.0 - 1.0]
    pub chain_health_score: U64F64,     // H_chain [0.0 - 1.0]
}

/// Interface for supplying network state to the LDD controller.
pub trait ConsensusOracle {
    fn get_consensus_state(&self) -> NetworkState;
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
        let p90_orphan = self.calculate_percentile(&self.orphan_rates, 90).unwrap_or(0);
        let p90_reorg = self.calculate_percentile(&self.reorg_depths, 90).unwrap_or(0);
        
        let orphan_u64 = U64F64::from_num(p90_orphan);
        let ten = U64F64::from_num(10);
        let threat_orphan = (orphan_u64 / ten).min(U64F64::ONE);

        let reorg_u64 = U64F64::from_num(p90_reorg);
        let six = U64F64::from_num(6);
        let threat_reorg = (reorg_u64 / six).min(U64F64::ONE);
        
        let s_threat = threat_orphan.max(threat_reorg);

        // 2. Calculate Chain Health Score (H_chain)
        let p90_branching = self.calculate_percentile_u64(&self.branching_factors, 90).unwrap_or(1_000_000);
        
        let branching_u64 = U64F64::from_num(p90_branching);
        let million = U64F64::from_num(1_000_000);
        let ratio = branching_u64 / million;
        let h_chain = ratio.saturating_sub(U64F64::ONE).min(U64F64::ONE);

        // Consensus Load
        let median_load_u64 = self.calculate_median_u64(&self.load_beacons).unwrap_or(0);
        let consensus_load = U64F64::from_num(median_load_u64) / million;

        ConsensusValues {
            median_time: self.calculate_median(&self.time_beacons).unwrap_or(0),
            median_total_stake: self.calculate_median(&self.stake_beacons).unwrap_or(0),
            consensus_delay: self.calculate_percentile(&self.delay_beacons, 95).unwrap_or(0),
            consensus_load,
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

impl ConsensusOracle for DecentralizedConsensusService {
    fn get_consensus_state(&self) -> NetworkState {
        let values = self.calculate_consensus();
        
        // Convert primitives to Type-Safe Units
        let consensus_delay = SlotDuration((values.consensus_delay as u64 / 1000).max(1)); 
        let consensus_load = Probability(values.consensus_load);
        let security_threat = Probability(values.security_threat_level);

        NetworkState {
            consensus_delay,
            consensus_load,
            security_threat,
        }
    }
}

// Mock Oracle for Simulation/Testing
pub struct MockOracle {
    pub delay: u64,
    pub load: f64,
    pub threat: f64,
}

impl ConsensusOracle for MockOracle {
    fn get_consensus_state(&self) -> NetworkState {
        NetworkState {
            consensus_delay: SlotDuration(self.delay),
            consensus_load: Probability(U64F64::from_num(self.load)),
            security_threat: Probability(U64F64::from_num(self.threat)),
        }
    }
}
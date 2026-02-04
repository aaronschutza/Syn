// src/block.rs

use crate::transaction::Transaction;
use bitcoin_hashes::{sha256d, Hash, HashEngine};
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, Bytes};

/// Represents the specific type of data carried by a consensus beacon.
/// Corresponds to the beacon types defined in Whitepaper Section 9.12.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum BeaconData {
    /// Time Beacon: Miner's local timestamp. Used for DTC.
    Time(u64),
    /// Stake Beacon: Validator's view of Total Network Stake. Used for DSC.
    Stake(u64),
    /// Delay Beacon: Observed block propagation delay (in ms). Used for Adaptive Slot Gap.
    Delay(u32),
    /// Load Beacon: Observed transaction load (normalized 0.0-1.0). Used for Adaptive Target Slope.
    Load(f64),
    /// Security Beacon: Observed threat metrics. Used for Adaptive Burn Rate.
    /// (orphan_count, max_reorg_depth)
    Security(u32, u32), 
    /// Topology Beacon: Observed chain structure. Used for Adaptive Burst Threshold.
    /// (branching_factor, max_orphan_chain_length)
    Topology(f64, u32),
}

#[serde_as]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Beacon {
    /// The public key of the node producing the beacon (Miner or Validator).
    #[serde_as(as = "Bytes")]
    pub public_key: Vec<u8>,
    
    /// The actual measurement data.
    pub data: BeaconData,
    
    /// Signature proving the node attested to this data.
    #[serde_as(as = "Bytes")]
    pub signature: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct BlockHeader {
    pub version: i32,
    #[serde(with = "serde_hash")]
    pub prev_blockhash: sha256d::Hash,
    #[serde(with = "serde_hash")]
    pub merkle_root: sha256d::Hash,
    #[serde(with = "serde_hash")]
    pub utxo_root: sha256d::Hash,
    pub time: u32,
    pub bits: u32,
    pub nonce: u32,
    /// VRF Proof for PoS blocks. None for PoW blocks.
    pub vrf_proof: Option<Vec<u8>>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Block {
    pub header: BlockHeader,
    pub height: u32,
    pub transactions: Vec<Transaction>,
    pub synergistic_work: u64,
    pub total_work: u64,
    /// Beacons included in this block to support the DCS (Decentralized Consensus Service).
    pub beacons: Vec<Beacon>,
}

impl BlockHeader {
    pub fn hash(&self) -> sha256d::Hash {
        sha256d::Hash::hash(&bincode::serialize(self).unwrap())
    }

    pub fn calculate_target(bits: u32) -> BigUint {
        let exponent = bits >> 24;
        let mantissa = bits & 0x007fffff;
        let target = if exponent > 3 {
            let shift = 8 * (exponent - 3);
            BigUint::from(mantissa) << shift
        } else {
            BigUint::from(mantissa) >> (8 * (3 - exponent))
        };
        target
    }
}

impl Block {
    pub fn new(
        time: u32,
        transactions: Vec<Transaction>,
        prev_blockhash: sha256d::Hash,
        bits: u32,
        height: u32,
        version: i32,
    ) -> Self {
        let merkle_root = Block::compute_merkle_root(&transactions);
        Block {
            header: BlockHeader {
                version,
                prev_blockhash,
                merkle_root,
                utxo_root: sha256d::Hash::all_zeros(),
                time,
                bits,
                nonce: 0,
                vrf_proof: None,
            },
            height,
            transactions,
            synergistic_work: 0,
            total_work: 0,
            beacons: Vec::new(),
        }
    }

    pub fn compute_merkle_root(transactions: &[Transaction]) -> sha256d::Hash {
        if transactions.is_empty() {
            return sha256d::Hash::all_zeros();
        }
        let mut merkle_tree: Vec<sha256d::Hash> = transactions.iter().map(|tx| tx.id()).collect();
        if merkle_tree.len() % 2 == 1 {
            if let Some(last) = merkle_tree.last().cloned() {
                merkle_tree.push(last);
            }
        }
        while merkle_tree.len() > 1 {
            let mut next_level = vec![];
            for chunk in merkle_tree.chunks(2) {
                let mut engine = sha256d::Hash::engine();
                engine.input(&chunk[0][..]);
                engine.input(&chunk[1][..]);
                next_level.push(sha256d::Hash::from_engine(engine));
            }
            merkle_tree = next_level;
            if merkle_tree.len() % 2 == 1 && merkle_tree.len() > 1 {
                if let Some(last) = merkle_tree.last().cloned() {
                    merkle_tree.push(last);
                }
            }
        }
        merkle_tree.pop().unwrap_or_else(sha256d::Hash::all_zeros)
    }

    pub fn create_genesis_block(
        reward: u64,
        time: u32,
        bits: u32,
        coinbase_data: String,
        address: String,
        block_version: i32,
        transaction_version: i32,
    ) -> Self {
        let coinbase_tx = Transaction::new_coinbase(coinbase_data, address, reward, transaction_version);
        let transactions = vec![coinbase_tx];
        Block::new(time, transactions, sha256d::Hash::all_zeros(), bits, 0, block_version)
    }

    pub fn get_size(&self) -> u64 {
        bincode::serialize(self).map_or(0, |v| v.len() as u64)
    }
}

pub mod serde_hash {
    use bitcoin_hashes::{sha256d, Hash};
    use serde::{self, Deserializer, Serializer};

    pub fn serialize<S>(hash: &sha256d::Hash, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(hash.as_ref())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<sha256d::Hash, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: &[u8] = serde::Deserialize::deserialize(deserializer)?;
        sha256d::Hash::from_slice(bytes).map_err(serde::de::Error::custom)
    }
}
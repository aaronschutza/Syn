// src/client.rs

use crate::storage::{StorageError, HeaderStore};
use bitcoin::hash_types::BlockHash;
// CORRECTED: Import U256 for the math, remove unused CompactTarget
use bitcoin::{block::Header as BitcoinHeader, Target, Work};
use primitive_types::U256;
use std::sync::Arc;
use log::{info, warn, debug};
use std::collections::{HashMap, VecDeque};
use parking_lot::RwLock;
use std::str::FromStr;


use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredHeader {
    pub header: BitcoinHeader,
    pub height: u32,
    pub total_work: Work,
}

// Configuration constant for security hardening
const MAX_ORPHAN_HEADERS: usize = 512;

// Bitcoin Consensus Parameters for DAA
const TARGET_TIMESPAN: u32 = 14 * 24 * 60 * 60; // 14 days (in seconds)
const TARGET_SPACING: u32 = 10 * 60; // 10 minutes (in seconds)
const RETARGET_INTERVAL: u32 = TARGET_TIMESPAN / TARGET_SPACING; // 2016 blocks

lazy_static::lazy_static! {
    // CORRECTED: Create POW_LIMIT by first parsing a U256 from the hex string.
    static ref POW_LIMIT_U256: U256 = U256::from_str("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff").unwrap();
}


#[derive(Debug)]
pub enum SpvSyncError {
    Storage(StorageError),
    InvalidHeader(String),
    OrphanPoolFull,
}

impl From<StorageError> for SpvSyncError {
    fn from(e: StorageError) -> Self { SpvSyncError::Storage(e) }
}
/// The concrete implementation of the SPV Client State.
#[derive(Clone)]
pub struct SpvClientState {
    store: HeaderStore,
    sync_lock: Arc<RwLock<()>>,
    orphan_pool: Arc<RwLock<HashMap<BlockHash, VecDeque<BitcoinHeader>>>>,
}

impl SpvClientState {
    pub fn new(store: HeaderStore) -> Self {
        Self {
            store,
            sync_lock: Arc::new(RwLock::new(())),
            orphan_pool: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    
    // Placeholder implementations for methods used in other parts of the code
    pub fn get_header_height(&self, _hash: &BlockHash) -> Result<Option<u32>, StorageError> { Ok(None) }
    pub fn get_tip_height(&self) -> Result<u32, StorageError> { Ok(0) }


    pub fn ingest_headers(&self, headers: Vec<BitcoinHeader>) -> Result<(), SpvSyncError> {
        let _lock = self.sync_lock.write();

        for header in headers {
            match self.process_single_header(&header) {
                Ok(hash) => {
                    self.process_orphans(hash)?;
                }
                Err(SpvSyncError::InvalidHeader(msg)) => {
                    if msg.contains("Parent not found") {
                        self.add_to_orphan_pool(header)?;
                    } else {
                        return Err(SpvSyncError::InvalidHeader(msg));
                    }
                }
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
    
    fn handle_reorg(&self, new_tip_hash: BlockHash, _new_tip_header: &StoredHeader) -> Result<(), SpvSyncError> {
        info!("Chain reorg detected. New tip: {}", new_tip_hash);
        self.store.set_tip(new_tip_hash)?;
        Ok(())
    }

    fn process_single_header(&self, header: &BitcoinHeader) -> Result<BlockHash, SpvSyncError> {
        let hash = header.block_hash();

        if self.store.get_header(&hash).is_ok() {
            return Ok(hash);
        }

        let parent = self.store.get_header(&header.prev_blockhash)
            .map_err(|_| SpvSyncError::InvalidHeader(format!("Parent {} not found (Orphan)", header.prev_blockhash)))?;

        let new_height = parent.height + 1;

        self.validate_daa(header, &parent, new_height)?;

        if header.validate_pow(header.target()).is_err() {
            return Err(SpvSyncError::InvalidHeader("Invalid PoW".into()));
        }

        let work = header.work();
        let total_work = parent.total_work + work;

        let stored_header = StoredHeader { header: header.clone(), height: new_height, total_work };
        self.store.insert_header(hash, &stored_header)?;

        let current_tip = self.store.get_tip();
        let should_reorg = match current_tip {
            Ok((_, tip)) => total_work > tip.total_work,
            Err(StorageError::ProposalNotFound(_)) => true, // Genesis case, adjust error type
            Err(e) => return Err(e.into()),
        };

        if should_reorg {
            self.handle_reorg(hash, &stored_header)?;
        }

        Ok(hash)
    }

    fn validate_daa(&self, header: &BitcoinHeader, parent: &StoredHeader, height: u32) -> Result<(), SpvSyncError> {
        let expected_bits = self.calculate_next_work_required(parent, height)?;

        if header.bits.to_consensus() != expected_bits {
            warn!("Invalid difficulty target (nBits) detected at height {}. Expected: {:x}, Actual: {}", height, expected_bits, header.bits.to_consensus());
            return Err(SpvSyncError::InvalidHeader("Invalid difficulty target (nBits)".into()));
        }

        Ok(())
    }
    
    // CORRECTED: This entire function is refactored to use the modern bitcoin crate API.
    // It now uses `U256` for arithmetic and clamps the result correctly.
    fn calculate_next_work_required(&self, last_block: &StoredHeader, height: u32) -> Result<u32, SpvSyncError> {
        if height % RETARGET_INTERVAL != 0 {
            return Ok(last_block.header.bits.to_consensus());
        }
        
        let first_block_height = height - RETARGET_INTERVAL;
        let first_block = self.store.get_header_by_height(first_block_height)?;
        
        let mut actual_timespan = last_block.header.time - first_block.header.time;
        
        // Clamp the timespan to a factor of 4 to prevent extreme changes.
        if actual_timespan < TARGET_TIMESPAN / 4 {
            actual_timespan = TARGET_TIMESPAN / 4;
        }
        if actual_timespan > TARGET_TIMESPAN * 4 {
            actual_timespan = TARGET_TIMESPAN * 4;
        }
        
        let old_target: U256 = U256::from_little_endian(&last_block.header.target().to_le_bytes());
        
        // new_target = old_target * actual_timespan / TARGET_TIMESPAN
        let mut new_target = old_target * U256::from(actual_timespan);
        new_target = new_target / U256::from(TARGET_TIMESPAN);
        
        // Clamp to the POW limit.
        if new_target > *POW_LIMIT_U256 {
            new_target = *POW_LIMIT_U256;
        }
        
        // Convert the new U256 target back to the compact `bits` format.
        let new_target_bytes = new_target.to_little_endian();
        Ok(Target::from_le_bytes(new_target_bytes).to_compact_lossy().to_consensus())
    }


    fn add_to_orphan_pool(&self, header: BitcoinHeader) -> Result<(), SpvSyncError> {
        let mut pool = self.orphan_pool.write();
        
        let total_orphans: usize = pool.values().map(|q| q.len()).sum();
        if total_orphans >= MAX_ORPHAN_HEADERS {
            warn!("Orphan pool is full. Dropping incoming header.");
            return Err(SpvSyncError::OrphanPoolFull);
        }

        let parent_hash = header.prev_blockhash;
        pool.entry(parent_hash).or_default().push_back(header);
        debug!("Added header to orphan pool, waiting for parent {}", parent_hash);
        Ok(())
    }

    fn process_orphans(&self, parent_hash: BlockHash) -> Result<(), SpvSyncError> {
        let children = {
            let mut pool = self.orphan_pool.write();
            pool.remove(&parent_hash)
        };

        if let Some(children) = children {
            debug!("Processing {} children of {}", children.len(), parent_hash);
            for child in children {
                match self.process_single_header(&child) {
                    Ok(child_hash) => {
                        self.process_orphans(child_hash)?;
                    },
                    Err(e) => {
                        warn!("Discarding invalid orphan header branch: {:?}", e);
                    }
                }
            }
        }
        Ok(())
    }
}
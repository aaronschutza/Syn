// src/client.rs - Bitcoin Header Storage and Sync Logic

use crate::storage::{StorageError, HeaderStore};
use bitcoin::hash_types::BlockHash;
use bitcoin::{block::Header as BitcoinHeader, Work}; // Removed unused Target
use primitive_types::U256;
use std::sync::Arc;
use log::{info, warn}; // Removed unused debug
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

const MAX_ORPHAN_HEADERS: usize = 1024;

lazy_static::lazy_static! {
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

/// The SpvClientState manages the validated Bitcoin header chain.
/// It handles asynchronous ingestion and ensures the longest (most work) chain is always the tip.
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
    
    pub fn get_tip_hash(&self) -> Result<BlockHash, StorageError> {
        self.store.get_tip().map(|(hash, _)| hash)
    }

    pub fn get_header_by_hash(&self, hash: &BlockHash) -> Result<BitcoinHeader, StorageError> {
        self.store.get_header(hash).map(|s| s.header)
    }

    /// Entry point for the P2P engine to submit new batches of Bitcoin headers.
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
                        warn!("Rejected Bitcoin header {}: {}", header.block_hash(), msg);
                    }
                }
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    fn process_single_header(&self, header: &BitcoinHeader) -> Result<BlockHash, SpvSyncError> {
        let hash = header.block_hash();

        // Check if already stored
        if self.store.get_header(&hash).is_ok() {
            return Ok(hash);
        }

        // Validate connectivity
        let parent = self.store.get_header(&header.prev_blockhash)
            .map_err(|_| SpvSyncError::InvalidHeader(format!("Parent {} not found (Orphan)", header.prev_blockhash)))?;

        let new_height = parent.height + 1;

        // Verify Bitcoin PoW
        if header.validate_pow(header.target()).is_err() {
            return Err(SpvSyncError::InvalidHeader("Invalid Bitcoin PoW".into()));
        }

        let total_work = parent.total_work + header.work();
        let stored_header = StoredHeader { header: header.clone(), height: new_height, total_work };

        // Atomic storage update
        self.store.insert_header(hash, &stored_header)?;

        // Tip Update Logic (Longest Chain Rule)
        let (_, current_tip) = self.store.get_tip()?;
        if total_work > current_tip.total_work {
            info!("Bitcoin tip updated to height {}: {}", new_height, hash);
            self.store.set_tip(hash)?;
        }

        Ok(hash)
    }

    fn add_to_orphan_pool(&self, header: BitcoinHeader) -> Result<(), SpvSyncError> {
        let mut pool = self.orphan_pool.write();
        let total: usize = pool.values().map(|q| q.len()).sum();
        if total >= MAX_ORPHAN_HEADERS {
            return Err(SpvSyncError::OrphanPoolFull);
        }
        pool.entry(header.prev_blockhash).or_default().push_back(header);
        Ok(())
    }

    fn process_orphans(&self, parent_hash: BlockHash) -> Result<(), SpvSyncError> {
        let children = {
            let mut pool = self.orphan_pool.write();
            pool.remove(&parent_hash)
        };

        if let Some(children) = children {
            for child in children {
                if let Ok(hash) = self.process_single_header(&child) {
                    self.process_orphans(hash)?;
                }
            }
        }
        Ok(())
    }
}
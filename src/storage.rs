// src/storage.rs

use crate::gov_module::{Proposal, ProposalState, VoteType, ProposalId};
use crate::stk_module::Address;
use sled::Db;
use std::sync::Arc;
use thiserror::Error;
use bincode;
use std::convert::TryInto;
// Added for HeaderStore
use bitcoin::hash_types::BlockHash;
use crate::client::StoredHeader;
use std::collections::BTreeMap;
use parking_lot::RwLock;
// CORRECTED: Import Hash trait
use bitcoin_hashes::Hash;

// Sled Tree definitions
const PROPOSALS_TREE: &str = "gov_proposals";
const STATE_INDEX_TREE: &str = "gov_state_index"; 
const VOTES_TREE: &str = "gov_votes"; 
const METADATA_TREE: &str = "gov_metadata";
const NEXT_PROPOSAL_ID_KEY: &str = "next_proposal_id";
// Added for HeaderStore
const BTC_HEADERS_TREE: &str = "btc_headers";
const BTC_HEIGHT_INDEX_TREE: &str = "btc_height_index";
const BTC_TIP_KEY: &str = "btc_tip";

#[derive(Error, Debug)]
pub enum StorageError {
    #[error("Database error: {0}")]
    SledError(#[from] sled::Error),
    #[error("Serialization error: {0}")]
    SerializationError(#[from] bincode::Error),
    #[error("Proposal not found: {0}")]
    ProposalNotFound(ProposalId),
    #[error("Data integrity error: {0}")]
    DataIntegrityError(String),
}

#[derive(Clone)]
pub struct GovernanceStore {
    db: Arc<Db>,
}

// ... (rest of GovernanceStore implementation) ...

// CORRECTED: Added HeaderStore struct and impl
#[derive(Clone)]
pub struct HeaderStore {
    db: Arc<Db>,
    _headers: Arc<RwLock<BTreeMap<u32, StoredHeader>>>,
    _tip: Arc<RwLock<BlockHash>>,
}

impl HeaderStore {
    pub fn new(db: Arc<Db>) -> Self {
        Self { 
            db,
            _headers: Arc::new(RwLock::new(BTreeMap::new())),
            // CORRECTED: Use all_zeros from Hash trait
            _tip: Arc::new(RwLock::new(BlockHash::all_zeros())),
        }
    }

    pub fn get_header(&self, hash: &BlockHash) -> Result<StoredHeader, StorageError> {
        let headers_tree = self.db.open_tree(BTC_HEADERS_TREE)?;
        // CORRECTED: Specify type for get
        match headers_tree.get(hash.as_ref() as &[u8])? {
            Some(ivec) => Ok(bincode::deserialize(&ivec)?),
            None => Err(StorageError::DataIntegrityError("Header not found".to_string())),
        }
    }

    pub fn get_header_by_height(&self, height: u32) -> Result<StoredHeader, StorageError> {
        let height_index_tree = self.db.open_tree(BTC_HEIGHT_INDEX_TREE)?;
        match height_index_tree.get(height.to_be_bytes())? {
            Some(hash_bytes) => {
                // CORRECTED: Use from_slice from Hash trait
                let hash = BlockHash::from_slice(hash_bytes.as_ref()).map_err(|e| StorageError::DataIntegrityError(e.to_string()))?;
                self.get_header(&hash)
            }
            None => Err(StorageError::DataIntegrityError("Header not found at height".to_string())),
        }
    }

    pub fn insert_header(&self, hash: BlockHash, header: &StoredHeader) -> Result<(), StorageError> {
        let headers_tree = self.db.open_tree(BTC_HEADERS_TREE)?;
        let height_index_tree = self.db.open_tree(BTC_HEIGHT_INDEX_TREE)?;
        
        let serialized_header = bincode::serialize(header)?;
        // CORRECTED: Specify types for insert
        headers_tree.insert(hash.as_ref() as &[u8], serialized_header)?;
        height_index_tree.insert(&header.height.to_be_bytes(), hash.as_ref() as &[u8])?;

        Ok(())
    }

    pub fn get_tip(&self) -> Result<(BlockHash, StoredHeader), StorageError> {
        let metadata_tree = self.db.open_tree(METADATA_TREE)?;
        match metadata_tree.get(BTC_TIP_KEY)? {
            Some(hash_bytes) => {
                // CORRECTED: Use from_slice from Hash trait
                let hash = BlockHash::from_slice(hash_bytes.as_ref()).map_err(|e| StorageError::DataIntegrityError(e.to_string()))?;
                let header = self.get_header(&hash)?;
                Ok((hash, header))
            }
            None => Err(StorageError::ProposalNotFound(0)), // Re-use an existing error type for now
        }
    }

    pub fn set_tip(&self, hash: BlockHash) -> Result<(), StorageError> {
        let metadata_tree = self.db.open_tree(METADATA_TREE)?;
        // CORRECTED: Specify types for insert
        metadata_tree.insert(BTC_TIP_KEY, hash.as_ref() as &[u8])?;
        Ok(())
    }
}
impl GovernanceStore {
    pub fn new(db: Arc<Db>) -> Self {
        Self { db }
    }

    /// Atomically generates the next unique proposal ID using Sled's update_and_fetch.
    pub fn get_next_proposal_id(&self) -> Result<ProposalId, StorageError> {
        let metadata_tree = self.db.open_tree(METADATA_TREE)?;
        
        let next_id_bytes = metadata_tree.update_and_fetch(NEXT_PROPOSAL_ID_KEY, |old| {
            let next = match old {
                Some(bytes) => {
                    let arr = bytes.try_into().unwrap_or([0; 8]);
                    u64::from_be_bytes(arr) + 1
                },
                None => 1, // Start IDs at 1
            };
            Some(next.to_be_bytes().to_vec())
        })?;
        
        match next_id_bytes {
            Some(bytes) => {
                let arr = bytes.as_ref().try_into().map_err(|_| StorageError::DataIntegrityError("Failed to parse proposal ID".into()))?;
                Ok(u64::from_be_bytes(arr))
            },
            None => Ok(1),
        }
    }

    /// Inserts a new proposal and initializes its state index.
    pub fn insert_proposal(&self, proposal: &Proposal) -> Result<(), StorageError> {
        let proposals_tree = self.db.open_tree(PROPOSALS_TREE)?;
        let index_tree = self.db.open_tree(STATE_INDEX_TREE)?;

        let id_bytes = proposal.id.to_be_bytes();
        let serialized_proposal = bincode::serialize(proposal)?;

        proposals_tree.insert(&id_bytes, serialized_proposal)?;
        
        // Create the index entry: Key=(State, ID), Value=ID.
        let index_key = self.format_index_key(&proposal.state, proposal.id)?;
        index_tree.insert(index_key, &id_bytes)?;

        Ok(())
    }

    /// Retrieves a proposal by ID.
    pub fn get_proposal(&self, id: ProposalId) -> Result<Proposal, StorageError> {
        let proposals_tree = self.db.open_tree(PROPOSALS_TREE)?;
        match proposals_tree.get(id.to_be_bytes())? {
            Some(ivec) => Ok(bincode::deserialize(&ivec)?),
            None => Err(StorageError::ProposalNotFound(id)),
        }
    }

    /// Updates an existing proposal. Crucially, it updates the index if the state changes.
    pub fn update_proposal(&self, proposal: &Proposal, old_state: &ProposalState) -> Result<(), StorageError> {
        let proposals_tree = self.db.open_tree(PROPOSALS_TREE)?;
        let index_tree = self.db.open_tree(STATE_INDEX_TREE)?;

        let id_bytes = proposal.id.to_be_bytes();
        let serialized_proposal = bincode::serialize(proposal)?;

        // Update the main proposal data.
        proposals_tree.insert(&id_bytes, serialized_proposal)?;

        // Update the secondary index only if the state has changed.
        if proposal.state != *old_state {
            let old_index_key = self.format_index_key(old_state, proposal.id)?;
            let new_index_key = self.format_index_key(&proposal.state, proposal.id)?;
            
            // Remove the old index entry and insert the new one.
            index_tree.remove(old_index_key)?;
            index_tree.insert(new_index_key, &id_bytes)?;
        }

        Ok(())
    }

    /// Efficiently retrieves all proposals in a specific state using the secondary index.
    pub fn get_proposals_by_state(&self, state: &ProposalState) -> Result<Vec<Proposal>, StorageError> {
        let index_tree = self.db.open_tree(STATE_INDEX_TREE)?;
        // Serialize the state to use as the prefix for the scan.
        let prefix = bincode::serialize(state)?;
        
        let mut proposals = Vec::new();
        // Scan the index tree using the state prefix.
        for item in index_tree.scan_prefix(prefix) {
            let (_, value) = item?;
            // The value stored in the index is the Proposal ID.
            let id_bytes: [u8; 8] = value.as_ref().try_into().map_err(|_| StorageError::DataIntegrityError("Invalid ID in index".into()))?;
            let id = u64::from_be_bytes(id_bytes);
            
            // Fetch the full proposal data.
            match self.get_proposal(id) {
                Ok(proposal) => proposals.push(proposal),
                Err(e) => return Err(e), // Propagate errors during retrieval
            }
        }
        Ok(proposals)
    }

    // --- Vote Tracking ---

    /// Checks if a voter has already voted.
    pub fn has_voted(&self, proposal_id: ProposalId, voter: &Address) -> Result<bool, StorageError> {
        let votes_tree = self.db.open_tree(VOTES_TREE)?;
        let key = self.format_vote_key(proposal_id, voter);
        Ok(votes_tree.contains_key(key)?)
    }

    /// Stores the vote receipt.
    pub fn store_vote(&self, proposal_id: ProposalId, voter: &Address, vote: &VoteType) -> Result<(), StorageError> {
        let votes_tree = self.db.open_tree(VOTES_TREE)?;
        let key = self.format_vote_key(proposal_id, voter);
        let serialized_vote = bincode::serialize(vote)?;
        votes_tree.insert(key, serialized_vote)?;
        Ok(())
    }

    // Helper to format the composite index key (State + ID).
    fn format_index_key(&self, state: &ProposalState, id: ProposalId) -> Result<Vec<u8>, StorageError> {
        let mut key = bincode::serialize(state)?;
        key.extend_from_slice(&id.to_be_bytes());
        Ok(key)
    }

    // Helper to format the vote key (ProposalID + VoterAddress).
    fn format_vote_key(&self, proposal_id: ProposalId, voter: &Address) -> Vec<u8> {
        let mut key = proposal_id.to_be_bytes().to_vec();
        key.extend_from_slice(voter.as_bytes());
        key
    }
}
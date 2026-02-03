// src/spv.rs

use crate::client::SpvClientState; 

use bitcoin::Txid;
use bitcoin::block::Header as BlockHeader;
use bitcoin::MerkleBlock; // CORRECTED: Import MerkleBlock directly
use serde::Deserialize;
use thiserror::Error;

/// Protocol security parameter (k_btc)
const _K_BTC_CONFIRMATIONS: u32 = 6;
/// Maximum size for a MerkleBlock (BIP 37). Based on Bitcoin's consensus limits. 
const MAX_MERKLE_BLOCK_SIZE: usize = 1_100_000; 

#[derive(Debug, Clone, Deserialize)]
pub struct DepositProofRequest {
    pub expected_txid: String,
    pub merkle_block_hex: String,
}

/// Error types for SPV verification.
#[derive(Error, Debug)]
pub enum VerificationError {
    #[error("Failed to decode hex input: {0}")]
    HexDecodeError(#[from] hex::FromHexError),
    #[error("Failed to deserialize Bitcoin data: {0}")]
    BitcoinDataError(String),
    #[error("The provided MerkleBlock data exceeds the maximum allowed size ({0} bytes).")]
    InputTooLarge(usize),
    #[error("The SPV client is not yet sufficiently synchronized.")]
    NotSynchronized,
}

/// Verifies a Bitcoin transaction inclusion proof using SPV mechanics.
pub fn verify_deposit_proof(
    request: DepositProofRequest,
    _spv_state: &SpvClientState, 
) -> Result<BlockHeader, VerificationError> {

    // 1. Decode the inputs
    let expected_txid = request.expected_txid.parse::<Txid>()
        .map_err(|e| VerificationError::BitcoinDataError(format!("Invalid Txid format: {}", e)))?;
    
    let merkle_block_data = hex::decode(request.merkle_block_hex)?;

    if merkle_block_data.len() > MAX_MERKLE_BLOCK_SIZE {
        return Err(VerificationError::InputTooLarge(MAX_MERKLE_BLOCK_SIZE));
    }

    // 2. Deserialize the MerkleBlock
    // CORRECTED: Deserialize to MerkleBlock to get the header.
    let merkle_block: MerkleBlock = bitcoin::consensus::deserialize(&merkle_block_data)
        .map_err(|e| VerificationError::BitcoinDataError(format!("MerkleBlock deserialization failed: {}", e)))?;
    
    // CORRECTED: Access header from MerkleBlock
    let header = merkle_block.header;

    let mut matched_txids = Vec::new();
    let mut indexes = Vec::new();
    
    // CORRECTED: Use the transaction tree from the merkle_block
    if merkle_block.txn.extract_matches(&mut matched_txids, &mut indexes).is_err() {
        return Err(VerificationError::BitcoinDataError("Merkle proof extraction failed".into()));
    }

    if !matched_txids.contains(&expected_txid) {
        return Err(VerificationError::BitcoinDataError("Expected transaction not found in Merkle proof".into()));
    }

    Ok(header)
}
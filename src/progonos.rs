// src/progonos.rs

use crate::{blockchain::Blockchain, config::ProgonosConfig, transaction::Transaction};
use crate::transaction::{TxOut};
// CORRECTED: Updated import paths for bitcoin v0.31+
use bitcoin::{Txid, BlockHash, Address, Amount, Psbt, absolute::LockTime, Transaction as BtcTransaction};
use bitcoin::block::Header as BitcoinHeader;
// CORRECTED: The module is `merkle_tree`, not `merkle`.
use bitcoin::merkle_tree::PartialMerkleTree;
use bitcoin::consensus::encode::deserialize;
use bitcoin_hashes::sha256d;
use log::{info, warn};
use std::collections::BTreeMap;
use base64::{engine::general_purpose, Engine as _};
use anyhow::Result;

/// Manages a chain of Bitcoin block headers for Simple Payment Verification (SPV).
#[derive(Debug, Clone)]
pub struct SpvClient {
    headers: BTreeMap<u32, BitcoinHeader>,
    tip: BlockHash,
    height: u32,
}

impl SpvClient {
    /// Creates a new SPV client, starting with the Bitcoin genesis block.
    pub fn new(progonos_config: &ProgonosConfig) -> Self {
        let genesis_header: BitcoinHeader = deserialize(&hex::decode(&progonos_config.btc_genesis_header).unwrap()).unwrap();
        let genesis_hash = genesis_header.block_hash();
        let mut headers = BTreeMap::new();
        headers.insert(0, genesis_header);
        SpvClient {
            headers,
            tip: genesis_hash,
            height: 0,
        }
    }

    /// Adds a new block header to the chain, validating its proof-of-work and ensuring it connects to the previous header.
    pub fn add_header(&mut self, header: &BitcoinHeader) -> Result<(), String> {
        let height = self.height + 1;
        
        header.validate_pow(header.target()).map_err(|e| e.to_string())?;
        
        let prev_header = self.headers.get(&(height - 1)).ok_or("Previous header not found for SPV client")?;
        if header.prev_blockhash != prev_header.block_hash() {
            let value = "Header does not connect to the previous block in the chain.";
            return Err(value.to_string());
        }

        self.headers.insert(height, *header);
        self.tip = header.block_hash();
        self.height = height;
        Ok(())
    }

    /// Retrieves a header from the local chain by its hash.
    pub fn get_header_by_hash(&self, hash: &BlockHash) -> Option<(u32, &BitcoinHeader)> {
        self.headers.iter().find(|(_, h)| h.block_hash() == *hash).map(|(height, header)| (*height, header))
    }
    
    pub fn tip(&self) -> BlockHash {
        self.tip
    }
}

/// Represents a proof of a Bitcoin deposit.
#[derive(Debug)]
pub struct DepositProof {
    pub btc_txid: Txid,
    pub btc_block_hash: BlockHash,
    pub merkle_proof: Vec<u8>,
}

/// Represents a request to withdraw sBTC to a Bitcoin address.
#[derive(Debug)]
#[allow(dead_code)]
pub struct WithdrawalRequest {
    pub synergeia_burn_txid: sha256d::Hash,
    pub btc_address: String,
    pub amount: u64,
    pub psbt: Psbt,
}

/// Verifies a Merkle proof against a given block header.
fn verify_merkle_proof(txid: &Txid, merkle_proof: &[u8], header: &BitcoinHeader) -> bool {
    let partial_tree: PartialMerkleTree = match deserialize(merkle_proof) {
        Ok(tree) => tree,
        Err(e) => {
            warn!("Failed to deserialize Merkle proof: {}", e);
            return false;
        }
    };

    let mut matched_txids = Vec::new();
    let mut indexes = Vec::new();

    match partial_tree.extract_matches(&mut matched_txids, &mut indexes) {
        Ok(merkle_root_from_proof) => {
            if merkle_root_from_proof != header.merkle_root {
                warn!("Merkle root mismatch. Header: {}, Proof: {}", header.merkle_root, merkle_root_from_proof);
                return false;
            }
            matched_txids.contains(txid)
        }
        Err(e) => {
            warn!("Failed to extract matches from Merkle proof: {}", e);
            false
        }
    }
}

/// Verifies a Bitcoin deposit proof and mints the corresponding amount of sBTC.
pub async fn verify_and_mint_sbtc(
    bc: &mut Blockchain,
    spv_client: &SpvClient,
    proof: DepositProof,
    mint_to_address: String,
    amount: u64,
    progonos_config: &ProgonosConfig,
) -> Result<(), String> {

    let (tx_block_height, btc_header) = match spv_client.get_header_by_hash(&proof.btc_block_hash) {
        Some((height, header)) => (height, header),
        None => return Err(format!("Bitcoin block header not found in local SPV client: {}", proof.btc_block_hash)),
    };

    if !verify_merkle_proof(&proof.btc_txid, &proof.merkle_proof, &btc_header) {
        return Err("Merkle proof is invalid.".to_string());
    }

    let tip_height = spv_client.height;
    let confirmations = tip_height.saturating_sub(tx_block_height) + 1;

    if confirmations < progonos_config.btc_confirmations {
        return Err(format!("Transaction does not have enough confirmations. Has: {}, Requires: {}", confirmations, progonos_config.btc_confirmations));
    }

    info!("Bitcoin deposit proof for txid {} is valid. Minting {} sBTC.", proof.btc_txid, amount);

    let mint_tx = Transaction {
        version: 1,
        vin: vec![],
        vout: vec![TxOut::new(amount, mint_to_address)],
        lock_time: 0,
    };
    bc.mempool.insert(mint_tx.id(), mint_tx);
    Ok(())
}

/// Creates a partially signed Bitcoin transaction (PSBT) for a withdrawal.
pub fn create_withdrawal_transaction(
    burn_tx: &Transaction,
    btc_address: Address,
    amount: u64,
    _progonos_config: &ProgonosConfig,
) -> Result<String> {

    let unsigned_tx = BtcTransaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::from_time(burn_tx.lock_time as u32)?,
        input: vec![], 
        output: vec![bitcoin::TxOut {
            value: Amount::from_sat(amount),
            script_pubkey: btc_address.script_pubkey(),
        }],
    };

    let psbt = Psbt::from_unsigned_tx(unsigned_tx)?;

    Ok(general_purpose::STANDARD.encode(psbt.serialize()))
}


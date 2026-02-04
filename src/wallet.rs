// src/wallet.rs - Wallet implementation with SIGHASH_ALL support

use crate::{
    config::NodeConfig,
    crypto::{address_from_pubkey_hash, generate_keypair, hash_pubkey},
    pos::StakeInfo,
    transaction::{Transaction, TxOut, SigHashType},
    block::{Beacon, BeaconData},
    cdf::{FinalityVote, Color}, 
};
use anyhow::{anyhow, Result};
use bitcoin_hashes::{sha256d, Hash};
use log::info;
use secp256k1::{ecdsa::Signature, All, Message, PublicKey, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;

/// Serializable structure for persisting wallet state.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
struct WalletData {
    secret_key: [u8; 32],
    sbtc_balance: u64,
    stake_info: Option<StakeInfo>,
}

/// The main Wallet structure for managing keys and signing messages.
pub struct Wallet {
    pub secret_key: SecretKey,
    pub public_key: PublicKey,
    secp: Secp256k1<All>,
    pub sbtc_balance: u64,
    pub stake_info: Option<StakeInfo>,
}

impl Clone for Wallet {
    fn clone(&self) -> Self {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&self.secret_key.secret_bytes()).unwrap();
        let pk = PublicKey::from_secret_key(&secp, &sk);
        Wallet {
            secret_key: sk,
            public_key: pk,
            secp,
            sbtc_balance: self.sbtc_balance,
            stake_info: self.stake_info.clone(),
        }
    }
}

impl Wallet {
    /// Creates a new random wallet.
    pub fn new() -> Self {
        let secp = Secp256k1::new();
        let (sk, pk) = generate_keypair(&secp);
        Wallet {
            secret_key: sk,
            public_key: pk,
            secp,
            sbtc_balance: 0,
            stake_info: None
        }
    }

    /// Loads the wallet from the configured file path.
    pub fn load_from_file(node_config: &NodeConfig) -> Result<Self> {
        if !std::path::Path::new(&node_config.wallet_file).exists() {
            info!("No wallet file found at {}. Creating a new one.", &node_config.wallet_file);
            let new_wallet = Wallet::new();
            new_wallet.save_to_file(node_config)?;
            return Ok(new_wallet);
        }
        
        let data = fs::read(&node_config.wallet_file)?;
        let decoded: WalletData = bincode::deserialize(&data)?;
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&decoded.secret_key)?;
        let pk = PublicKey::from_secret_key(&secp, &sk);
        Ok(Wallet {
            secret_key: sk,
            public_key: pk,
            secp,
            sbtc_balance: decoded.sbtc_balance,
            stake_info: decoded.stake_info
        })
    }

    /// Persists the wallet state to disk.
    pub fn save_to_file(&self, node_config: &NodeConfig) -> Result<()> {
        let data = WalletData {
            secret_key: self.secret_key.secret_bytes(),
            sbtc_balance: self.sbtc_balance,
            stake_info: self.stake_info.clone(),
        };
        fs::write(&node_config.wallet_file, bincode::serialize(&data)?)?;
        Ok(())
    }

    pub fn get_public_key(&self) -> &PublicKey { &self.public_key }
    
    /// Returns the Base58Check encoded address.
    pub fn get_address(&self) -> String { 
        address_from_pubkey_hash(&hash_pubkey(&self.public_key)) 
    }
    
    /// Low-level signature utility.
    pub fn sign(&self, msg: &Message) -> Signature { 
        self.secp.sign_ecdsa(msg, &self.secret_key) 
    }

    /// Signs a transaction using SIGHASH_ALL to prevent malleability.
    /// Commits to all inputs and outputs within the transaction.
    pub fn sign_transaction(&self, tx: &mut Transaction, prev_tx_outputs: HashMap<sha256d::Hash, TxOut>) -> Result<()> {
        if tx.is_coinbase() { return Ok(()); }

        // We iterate through each input to sign it individually
        for i in 0..tx.vin.len() {
            let vin = &tx.vin[i];
            let prev_tx_out = prev_tx_outputs.get(&vin.prev_txid)
                .ok_or_else(|| anyhow!("Previous output missing for tx {}", vin.prev_txid))?;

            // 1. Calculate the SIGHASH_ALL digest for this specific input
            let sighash = tx.calculate_sighash(i, &prev_tx_out.script_pub_key, SigHashType::All);
            let msg = Message::from_digest_slice(sighash.as_ref())?;

            // 2. Sign the digest
            let sig = self.secp.sign_ecdsa(&msg, &self.secret_key);
            
            // 3. Construct the scriptSig (Standard P2PKH: <sig> <pubkey>)
            // We append the SigHashType byte to the DER signature (Bitcoin standard)
            let mut der_sig = sig.serialize_der().to_vec();
            der_sig.push(SigHashType::All as u8);

            let mut final_script_sig = vec![der_sig.len() as u8];
            final_script_sig.extend(der_sig);
            
            let pk_bytes = self.public_key.serialize();
            final_script_sig.push(pk_bytes.len() as u8);
            final_script_sig.extend(pk_bytes);

            // 4. Update the actual transaction input with the unlocking script
            tx.vin[i].script_sig = final_script_sig;
        }
        Ok(())
    }

    /// Signs an on-chain beacon for the Decentralized Consensus Service (DCS).
    pub fn sign_beacon(&self, data: BeaconData) -> Result<Beacon> {
        let msg_hash = sha256d::Hash::hash(&bincode::serialize(&data)?);
        let msg = Message::from_digest_slice(msg_hash.as_ref())?;
        let sig = self.sign(&msg);
        Ok(Beacon {
            public_key: self.public_key.serialize().to_vec(),
            data,
            signature: sig.serialize_compact().to_vec(),
        })
    }

    /// Signs a vote for the Chromo-Dynamic Finality (CDF) mechanism.
    pub fn sign_finality_vote(&self, checkpoint_hash: sha256d::Hash, color: Color) -> Result<FinalityVote> {
        let mut msg_bytes = checkpoint_hash.to_byte_array().to_vec();
        msg_bytes.push(color as u8);
        let msg_hash = sha256d::Hash::hash(&msg_bytes);
        let msg = Message::from_digest_slice(msg_hash.as_ref())?;
        let sig = self.sign(&msg);
        Ok(FinalityVote {
            voter_public_key: self.public_key.serialize().to_vec(),
            checkpoint_hash,
            color,
            signature: sig.serialize_compact().to_vec(),
        })
    }
}
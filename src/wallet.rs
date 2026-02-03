// src/wallet.rs

use crate::{
    config::NodeConfig,
    crypto::{address_from_pubkey_hash, generate_keypair, hash_pubkey},
    pos::StakeInfo,
    transaction::{Transaction, TxOut},
};
use anyhow::{anyhow, Result};
use bitcoin_hashes::{sha256d, Hash};
use log::info;
use secp256k1::{ecdsa::Signature, All, Message, PublicKey, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
struct WalletData {
    secret_key: [u8; 32],
    sbtc_balance: u64,
    stake_info: Option<StakeInfo>,
}

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
    pub fn get_address(&self) -> String { address_from_pubkey_hash(&hash_pubkey(&self.public_key)) }
    
    pub fn sign(&self, msg: &Message) -> Signature { self.secp.sign_ecdsa(msg, &self.secret_key) }

    pub fn sign_transaction(&self, tx: &mut Transaction, prev_tx_outputs: HashMap<sha256d::Hash, TxOut>) -> Result<()> {
        if tx.is_coinbase() { return Ok(()); }

        // --- FIX: Create a single copy of the transaction to be modified for sighashing. ---
        let mut tx_for_signing = tx.clone();

        for i in 0..tx.vin.len() {
            // Clear all input scripts for the signing copy.
            for input in &mut tx_for_signing.vin {
                input.script_sig = vec![];
            }

            let vin = &tx.vin[i];
            let prev_tx_out = prev_tx_outputs.get(&vin.prev_txid).ok_or_else(|| anyhow!("Previous transaction output not found in UTXO set"))?;

            // Set the script of the input being signed in the copy.
            tx_for_signing.vin[i].script_sig = prev_tx_out.script_pub_key.clone();
            
            // Hash the modified copy.
            let sighash = sha256d::Hash::hash(&bincode::serialize(&tx_for_signing).unwrap());
            let digest = sighash.to_byte_array();
            let msg = Message::from_digest_slice(&digest)?;

            let sig = self.secp.sign_ecdsa(&msg, &self.secret_key);

            let mut script_sig_vec = sig.serialize_der().to_vec();
            let pk_vec = self.public_key.serialize().to_vec();

            let mut final_script_sig = vec![script_sig_vec.len() as u8];
            final_script_sig.append(&mut script_sig_vec);

            final_script_sig.push(pk_vec.len() as u8);
            final_script_sig.extend(pk_vec);

            // --- FIX: Apply the final signature to the original transaction. ---
            tx.vin[i].script_sig = final_script_sig;

            // Reset the script in the copy for the next iteration.
            tx_for_signing.vin[i].script_sig = vec![];
        }
        Ok(())
    }
}
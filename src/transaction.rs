// src/transaction.rs

use crate::{block::serde_hash, script, blockchain::Blockchain, wallet::Wallet};
use anyhow::{anyhow, bail, Result};
use bitcoin_hashes::{sha256d, Hash};
use bs58;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Represents a transaction input, which points to a previous transaction's output.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct TxIn {
    #[serde(with = "serde_hash")]
    pub prev_txid: sha256d::Hash,
    pub prev_vout: u32,
    pub script_sig: Vec<u8>,
    pub sequence: u32,
}

/// Represents a transaction output, which specifies an amount and a locking script.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct TxOut {
    pub value: u64,
    pub script_pub_key: Vec<u8>,
}

/// Represents a transaction, which is a collection of inputs and outputs.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Transaction {
    pub version: i32,
    pub vin: Vec<TxIn>,
    pub vout: Vec<TxOut>,
    pub lock_time: u32,
}

impl Transaction {
    /// Calculates the transaction ID by hashing the transaction data.
    pub fn id(&self) -> sha256d::Hash {
        sha256d::Hash::hash(&bincode::serialize(self).unwrap())
    }

    /// Checks if the transaction is a coinbase transaction.
    pub fn is_coinbase(&self) -> bool {
        self.vin.len() == 1 && self.vin[0].prev_txid == sha256d::Hash::all_zeros()
    }

    /// Creates a new coinbase transaction.
    pub fn new_coinbase(coinbase_data: String, address: String, reward: u64, version: i32) -> Self {
        Transaction {
            version,
            vin: vec![TxIn {
                prev_txid: sha256d::Hash::all_zeros(),
                prev_vout: u32::MAX,
                script_sig: coinbase_data.into_bytes(),
                sequence: u32::MAX,
            }],
            vout: vec![TxOut::new(reward, address)],
            lock_time: 0,
        }
    }

    /// Creates a new transaction that spends UTXOs.
    pub fn new_utxo_transaction(
        from_wallet: &Wallet,
        to_address: String,
        amount: u64,
        bc: &mut Blockchain,
    ) -> Result<(Transaction, HashMap<sha256d::Hash, TxOut>)> {
        let fee = bc.consensus_params.fee_per_transaction;
        let (accumulated, unspent_outputs) = bc.find_spendable_outputs(&from_wallet.get_address(), amount + fee)?;

        let mut vin = Vec::new();
        let mut prev_tx_outputs = HashMap::new();

        for (txid, out_idx) in unspent_outputs {
            let prev_tx = bc.get_transaction(&txid)?.ok_or_else(|| anyhow!("Previous tx not found"))?;
            prev_tx_outputs.insert(txid, prev_tx.vout[out_idx as usize].clone());

            let input = TxIn {
                prev_txid: txid,
                prev_vout: out_idx,
                script_sig: vec![],
                sequence: u32::MAX,
            };
            vin.push(input);
        }

        let mut vout = vec![TxOut::new(amount, to_address)];
        if accumulated > amount + fee {
            vout.push(TxOut::new(accumulated - amount - fee, from_wallet.get_address()));
        }

        let mut tx = Transaction {
            version: bc.consensus_params.transaction_version,
            vin,
            vout,
            lock_time: 0,
        };

        from_wallet.sign_transaction(&mut tx, prev_tx_outputs.clone())?;

        Ok((tx, prev_tx_outputs))
    }

    // This function is no longer responsible for cloning and can be simplified or removed
    // if sign_transaction handles all hashing logic. For clarity, we'll have it just hash.
    pub fn sighash(tx_to_sign: &Transaction) -> sha256d::Hash {
        sha256d::Hash::hash(&bincode::serialize(tx_to_sign).unwrap())
    }

    /// Verifies the transaction's signatures and scripts.
    pub fn verify(&self, prev_txs: &HashMap<sha256d::Hash, Transaction>) -> Result<()> {
        if self.is_coinbase() { return Ok(()); }
    
        let mut tx_for_verifying = self.clone();
        for input in &mut tx_for_verifying.vin {
            input.script_sig = vec![];
        }
    
        for (i, vin) in self.vin.iter().enumerate() {
            let prev_tx = prev_txs.get(&vin.prev_txid).ok_or_else(|| anyhow!("Previous tx not found"))?;
            let prev_tx_out = &prev_tx.vout[vin.prev_vout as usize];
            
            let mut temp_tx = tx_for_verifying.clone();
            temp_tx.vin[i].script_sig = prev_tx_out.script_pub_key.clone();
    
            let sighash = Self::sighash(&temp_tx).to_byte_array();
    
            if !script::evaluate(&vin.script_sig, &prev_tx_out.script_pub_key, &sighash) {
                bail!(format!("Script verification failed for input {}", i));
            }
        }
        Ok(())
    }

    /// Creates a burn output, which is an unspendable output used for burning tokens.
    pub fn create_burn_output(amount: u64) -> TxOut {
        TxOut {
            value: amount,
            script_pub_key: vec![0x6a], // OP_RETURN
        }
    }
}

impl TxOut {
    /// Creates a new transaction output with a standard P2PKH script.
    pub fn new(value: u64, address: String) -> Self {
        if address.is_empty() { return TxOut { value, script_pub_key: vec![] }; }
        let pubkey_hash_with_version = match bs58::decode(&address).into_vec() {
            Ok(vec) => vec,
            Err(_) => return TxOut { value, script_pub_key: vec![] },
        };

        if pubkey_hash_with_version.len() < 5 {
             return TxOut { value, script_pub_key: vec![] };
        }
        let pubkey_hash = &pubkey_hash_with_version[1..pubkey_hash_with_version.len() - 4];

        let mut script_pub_key = vec![0x76, 0xa9, 0x14];
        script_pub_key.extend_from_slice(pubkey_hash);
        script_pub_key.extend(&[0x88, 0xac]);

        TxOut { value, script_pub_key }
    }
}
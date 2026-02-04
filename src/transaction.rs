// src/transaction.rs - Secure transaction structure with SIGHASH_ALL and UTXO creation

use crate::{block::serde_hash, script, blockchain::Blockchain, wallet::Wallet};
use anyhow::{anyhow, bail, Result};
use bitcoin_hashes::{sha256d, Hash};
use bs58;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Standard SigHash types to control which parts of the transaction are signed.
/// Currently focused on ALL to ensure full transaction commitment.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigHashType {
    All = 0x01,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct TxIn {
    #[serde(with = "serde_hash")]
    pub prev_txid: sha256d::Hash,
    pub prev_vout: u32,
    pub script_sig: Vec<u8>,
    pub sequence: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct TxOut {
    pub value: u64,
    pub script_pub_key: Vec<u8>,
}

impl TxOut {
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

    pub fn is_burn(&self) -> bool {
        !self.script_pub_key.is_empty() && self.script_pub_key[0] == 0x6a
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Transaction {
    pub version: i32,
    pub vin: Vec<TxIn>,
    pub vout: Vec<TxOut>,
    pub lock_time: u32,
}

impl Transaction {
    pub fn id(&self) -> sha256d::Hash {
        sha256d::Hash::hash(&bincode::serialize(self).unwrap())
    }

    pub fn is_coinbase(&self) -> bool {
        self.vin.len() == 1 && self.vin[0].prev_txid == sha256d::Hash::all_zeros()
    }

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
    /// This function handles UTXO selection, fee calculation, and signing.
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
            let prev_tx = bc.get_transaction(&txid)?.ok_or_else(|| anyhow!("Previous tx {} not found", txid))?;
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

        // Sign the transaction using SIGHASH_ALL to prevent malleability
        from_wallet.sign_transaction(&mut tx, prev_tx_outputs.clone())?;

        Ok((tx, prev_tx_outputs))
    }

    /// Generates the digest for a specific input's signature using SIGHASH_ALL.
    pub fn calculate_sighash(&self, input_index: usize, prev_pubkey_script: &[u8], sighash_type: SigHashType) -> sha256d::Hash {
        let mut tx_copy = self.clone();

        // 1. Clear all scriptSigs
        for input in &mut tx_copy.vin {
            input.script_sig = vec![];
        }

        // 2. Set the scriptSig of the input being signed to the previous output's scriptPubKey
        if input_index < tx_copy.vin.len() {
            tx_copy.vin[input_index].script_sig = prev_pubkey_script.to_vec();
        }

        // 3. Serialize and append the SigHashType
        let mut data = bincode::serialize(&tx_copy).unwrap();
        data.extend_from_slice(&(sighash_type as u32).to_le_bytes());

        sha256d::Hash::hash(&data)
    }

    pub fn verify(&self, prev_txs: &HashMap<sha256d::Hash, Transaction>) -> Result<()> {
        if self.is_coinbase() { return Ok(()); }
    
        for (i, vin) in self.vin.iter().enumerate() {
            let prev_tx = prev_txs.get(&vin.prev_txid).ok_or_else(|| anyhow!("Prev tx {} not found", vin.prev_txid))?;
            let prev_tx_out = &prev_tx.vout[vin.prev_vout as usize];
            
            // Reconstruct the message that was signed using SIGHASH_ALL
            let sighash = self.calculate_sighash(i, &prev_tx_out.script_pub_key, SigHashType::All);
            let digest = sighash.to_byte_array();
    
            if !script::evaluate(&vin.script_sig, &prev_tx_out.script_pub_key, &digest) {
                bail!("Signature verification failed for input {}", i);
            }
        }
        Ok(())
    }

    pub fn create_burn_output(amount: u64) -> TxOut {
        TxOut {
            value: amount,
            script_pub_key: vec![0x6a], // OP_RETURN
        }
    }
}
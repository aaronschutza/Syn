// src/transaction.rs - Robust Hybrid Verification with correct ScriptSig reconstruction

use crate::{block::serde_hash, script, blockchain::Blockchain, wallet::Wallet};
use anyhow::{anyhow, bail, Result};
use bitcoin_hashes::{sha256d, Hash};
use bs58;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use pqcrypto_dilithium::dilithium3::{verify_detached_signature, PublicKey as PqcPublicKey, DetachedSignature as PqcSignature};
use pqcrypto_traits::sign::{PublicKey as PqcPublicKeyTrait, DetachedSignature as PqcDetachedSignatureTrait};

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigHashType { All = 0x01 }

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
        let pubkey_hash_with_version = bs58::decode(&address).into_vec().unwrap_or_default();
        if pubkey_hash_with_version.len() < 5 { return TxOut { value, script_pub_key: vec![] }; }
        let pubkey_hash = &pubkey_hash_with_version[1..pubkey_hash_with_version.len() - 4];
        let mut script_pub_key = vec![0x76, 0xa9, 0x14];
        script_pub_key.extend_from_slice(pubkey_hash);
        script_pub_key.extend(&[0x88, 0xac]);
        TxOut { value, script_pub_key }
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
            let prev_tx = bc.get_transaction(&txid)?.ok_or_else(|| anyhow!("Prev tx missing"))?;
            prev_tx_outputs.insert(txid, prev_tx.vout[out_idx as usize].clone());

            vin.push(TxIn {
                prev_txid: txid,
                prev_vout: out_idx,
                script_sig: vec![],
                sequence: u32::MAX,
            });
        }

        let mut vout = vec![TxOut::new(amount, to_address)];
        if accumulated > amount + fee {
            vout.push(TxOut::new(accumulated - amount - fee, from_wallet.get_address()));
        }

        let mut tx = Transaction {
            version: bc.consensus_params.transaction_version,
            vin, vout, lock_time: 0,
        };

        from_wallet.sign_transaction(&mut tx, prev_tx_outputs.clone())?;
        Ok((tx, prev_tx_outputs))
    }

    /// Creates a transaction that burns tokens to register as a validator stake.
    /// Format: OP_RETURN + "STAKE" + PubKeyHash
    pub fn new_stake_transaction(
        from_wallet: &Wallet,
        amount: u64,
        bc: &mut Blockchain,
    ) -> Result<(Transaction, HashMap<sha256d::Hash, TxOut>)> {
        // The staked amount is effectively "spent" into the contract.
        // We also need to pay the standard network fee.
        let fee = bc.consensus_params.fee_per_transaction;
        let total_needed = amount + fee;
        let (accumulated, unspent_outputs) = bc.find_spendable_outputs(&from_wallet.get_address(), total_needed)?;

        let mut vin = Vec::new();
        let mut prev_tx_outputs = HashMap::new();

        for (txid, out_idx) in unspent_outputs {
            let prev_tx = bc.get_transaction(&txid)?.ok_or_else(|| anyhow!("Prev tx missing"))?;
            prev_tx_outputs.insert(txid, prev_tx.vout[out_idx as usize].clone());

            vin.push(TxIn {
                prev_txid: txid,
                prev_vout: out_idx,
                script_sig: vec![],
                sequence: u32::MAX,
            });
        }

        // Construct the Staking Output
        // OP_RETURN (0x6a) + PUSH(5) + "STAKE" + PUSH(20) + <PubKeyHash>
        let pk_hash = crate::crypto::hash_pubkey(&from_wallet.public_key);
        let mut script_pub_key = vec![0x6a, 0x05];
        script_pub_key.extend_from_slice(b"STAKE");
        script_pub_key.push(0x14); // 20 bytes for RIPEMD160 hash
        script_pub_key.extend_from_slice(pk_hash.as_ref());

        // Value is the amount being staked
        let mut vout = vec![TxOut { value: amount, script_pub_key }];
        
        // Change output
        if accumulated > total_needed {
            vout.push(TxOut::new(accumulated - total_needed, from_wallet.get_address()));
        }

        let mut tx = Transaction {
            version: bc.consensus_params.transaction_version,
            vin, vout, lock_time: 0,
        };

        from_wallet.sign_transaction(&mut tx, prev_tx_outputs.clone())?;
        Ok((tx, prev_tx_outputs))
    }

    pub fn create_burn_output(amount: u64) -> TxOut {
        TxOut { value: amount, script_pub_key: vec![0x6a] }
    }

    pub fn calculate_sighash(&self, input_index: usize, prev_pubkey_script: &[u8], sighash_type: SigHashType) -> sha256d::Hash {
        let mut tx_copy = self.clone();
        for input in &mut tx_copy.vin { input.script_sig = vec![]; }
        if input_index < tx_copy.vin.len() {
            tx_copy.vin[input_index].script_sig = prev_pubkey_script.to_vec();
        }
        let mut data = bincode::serialize(&tx_copy).unwrap();
        data.extend_from_slice(&(sighash_type as u32).to_le_bytes());
        sha256d::Hash::hash(&data)
    }

    pub fn verify_hybrid(&self, prev_txs: &HashMap<sha256d::Hash, Transaction>, pqc_enforced: bool) -> Result<()> {
        if self.is_coinbase() { return Ok(()); }
    
        for (i, vin) in self.vin.iter().enumerate() {
            let prev_tx = prev_txs.get(&vin.prev_txid).ok_or_else(|| anyhow!("Prev tx missing"))?;
            let prev_tx_out = &prev_tx.vout[vin.prev_vout as usize];
            let sighash = self.calculate_sighash(i, &prev_tx_out.script_pub_key, SigHashType::All);
            let digest = sighash.as_ref();

            if vin.script_sig.is_empty() { bail!("Empty signature"); }
            let mut cursor = 0;
            
            // Reconstruct ECDSA Segment
            let ecdsa_sig_len = vin.script_sig[cursor] as usize;
            cursor += 1;
            let ecdsa_sig_end = cursor + ecdsa_sig_len;
            cursor = ecdsa_sig_end;

            let ecdsa_pk_len = vin.script_sig[cursor] as usize;
            cursor += 1;
            let ecdsa_pk_end = cursor + ecdsa_pk_len;
            cursor = ecdsa_pk_end;

            // This slice represents the standard [len][sig][len][pk] part of the witness
            let ecdsa_script = &vin.script_sig[0..cursor];

            let context = script::ScriptContext {
                lock_time: self.lock_time, tx_version: self.version, input_sequence: vin.sequence,
            };
            if !script::evaluate(ecdsa_script, &prev_tx_out.script_pub_key, digest, &context) {
                bail!("ECDSA verification failed for input {}", i);
            }

            // PQC Segment verification
            if pqc_enforced || cursor < vin.script_sig.len() {
                if cursor + 4 > vin.script_sig.len() { bail!("PQC metadata missing"); }
                
                let pqc_sig_len = u32::from_le_bytes(vin.script_sig[cursor..cursor+4].try_into().unwrap()) as usize;
                cursor += 4;
                let pqc_sig_bytes = &vin.script_sig[cursor..cursor + pqc_sig_len];
                cursor += pqc_sig_len;

                let pqc_pk_len = u32::from_le_bytes(vin.script_sig[cursor..cursor+4].try_into().unwrap()) as usize;
                cursor += 4;
                let pqc_pk_bytes = &vin.script_sig[cursor..cursor + pqc_pk_len];

                let sig = PqcSignature::from_bytes(pqc_sig_bytes).map_err(|_| anyhow!("Invalid PQC sig format"))?;
                let pk = PqcPublicKey::from_bytes(pqc_pk_bytes).map_err(|_| anyhow!("Invalid PQC pk format"))?;

                if verify_detached_signature(&sig, digest, &pk).is_err() {
                    bail!("PQC verification failed for input {}", i);
                }
            }
        }
        Ok(())
    }
}
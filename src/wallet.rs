// src/wallet.rs - Full Signing Implementation

use crate::{
    config::NodeConfig,
    crypto::{address_from_pubkey_hash, generate_keypair, hash_pubkey},
    stk_module::StakeInfo,
    transaction::{Transaction, TxOut, SigHashType},
    block::{Beacon, BeaconData},
    cdf::{FinalityVote, Color},
};
use anyhow::{anyhow, Result};
use bitcoin_hashes::{sha256d, Hash};
use secp256k1::{All, Message, PublicKey, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use std::fs;
use pqcrypto_dilithium::dilithium3::{detached_sign, keypair, SecretKey as PqcSecretKey, PublicKey as PqcPublicKey};
use pqcrypto_traits::sign::{SecretKey as PqcSecretKeyTrait, PublicKey as PqcPublicKeyTrait, DetachedSignature};

#[derive(Serialize, Deserialize, Clone, Debug)]
struct WalletData {
    secret_key: [u8; 32],
    pqc_secret_key: Vec<u8>,
    pqc_public_key: Vec<u8>,
    sbtc_balance: u64,
    stake_info: Option<StakeInfo>,
}

pub struct Wallet {
    pub secret_key: SecretKey,
    pub public_key: PublicKey,
    pub pqc_secret_key: PqcSecretKey,
    pub pqc_public_key: PqcPublicKey,
    secp: Secp256k1<All>,
    pub sbtc_balance: u64,
    pub stake_info: Option<StakeInfo>,
}

impl Clone for Wallet {
    fn clone(&self) -> Self {
        Wallet {
            secret_key: self.secret_key.clone(),
            public_key: self.public_key.clone(),
            pqc_secret_key: PqcSecretKey::from_bytes(self.pqc_secret_key.as_bytes()).unwrap(),
            pqc_public_key: PqcPublicKey::from_bytes(self.pqc_public_key.as_bytes()).unwrap(),
            secp: Secp256k1::new(),
            sbtc_balance: self.sbtc_balance,
            stake_info: self.stake_info.clone(),
        }
    }
}

impl Wallet {
    pub fn new() -> Self {
        let secp = Secp256k1::new();
        let (sk, pk) = generate_keypair(&secp);
        let (pqc_pk, pqc_sk) = keypair();
        Wallet {
            secret_key: sk, public_key: pk,
            pqc_secret_key: pqc_sk, pqc_public_key: pqc_pk,
            secp, sbtc_balance: 0, stake_info: None
        }
    }

    pub fn load_from_file(node_config: &NodeConfig) -> Result<Self> {
        let data = fs::read(&node_config.wallet_file)?;
        let decoded: WalletData = bincode::deserialize(&data)?;
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&decoded.secret_key)?;
        let pk = PublicKey::from_secret_key(&secp, &sk);
        let pqc_sk = PqcSecretKey::from_bytes(&decoded.pqc_secret_key).map_err(|_| anyhow!("PQC SK fail"))?;
        let pqc_pk = PqcPublicKey::from_bytes(&decoded.pqc_public_key).map_err(|_| anyhow!("PQC PK fail"))?;
        Ok(Wallet {
            secret_key: sk, public_key: pk,
            pqc_secret_key: pqc_sk, pqc_public_key: pqc_pk,
            secp, sbtc_balance: decoded.sbtc_balance, stake_info: decoded.stake_info
        })
    }

    pub fn save_to_file(&self, node_config: &NodeConfig) -> Result<()> {
        let data = WalletData {
            secret_key: self.secret_key.secret_bytes(),
            pqc_secret_key: self.pqc_secret_key.as_bytes().to_vec(),
            pqc_public_key: self.pqc_public_key.as_bytes().to_vec(),
            sbtc_balance: self.sbtc_balance, stake_info: self.stake_info.clone(),
        };
        fs::write(&node_config.wallet_file, bincode::serialize(&data)?)?;
        Ok(())
    }

    pub fn get_address(&self) -> String { address_from_pubkey_hash(&hash_pubkey(&self.public_key)) }

    pub fn sign_transaction(&self, tx: &mut Transaction, prev_tx_outputs: std::collections::HashMap<sha256d::Hash, TxOut>) -> Result<()> {
        if tx.is_coinbase() { return Ok(()); }

        for i in 0..tx.vin.len() {
            let prev_tx_out = prev_tx_outputs.get(&tx.vin[i].prev_txid).ok_or_else(|| anyhow!("Prev output missing"))?;
            let sighash = tx.calculate_sighash(i, &prev_tx_out.script_pub_key, SigHashType::All);
            let msg_bytes = sighash.as_ref();

            let msg = Message::from_digest_slice(msg_bytes)?;
            let sig = self.secp.sign_ecdsa(&msg, &self.secret_key);
            let mut der_sig = sig.serialize_der().to_vec();
            der_sig.push(SigHashType::All as u8);

            let pqc_sig = detached_sign(msg_bytes, &self.pqc_secret_key);

            let mut hybrid_sig = Vec::new();
            hybrid_sig.push(der_sig.len() as u8);
            hybrid_sig.extend(der_sig);
            let pk_bytes_ecdsa = self.public_key.serialize();
            hybrid_sig.push(pk_bytes_ecdsa.len() as u8);
            hybrid_sig.extend(pk_bytes_ecdsa);

            let sig_bytes = pqc_sig.as_bytes();
            hybrid_sig.extend(&(sig_bytes.len() as u32).to_le_bytes());
            hybrid_sig.extend(sig_bytes);
            let pk_bytes = self.pqc_public_key.as_bytes();
            hybrid_sig.extend(&(pk_bytes.len() as u32).to_le_bytes());
            hybrid_sig.extend(pk_bytes);

            tx.vin[i].script_sig = hybrid_sig;
        }
        Ok(())
    }

    pub fn sign_beacon(&self, data: BeaconData) -> Result<Beacon> {
        let msg_hash = sha256d::Hash::hash(&bincode::serialize(&data)?);
        let msg = Message::from_digest_slice(msg_hash.as_ref())?;
        let sig = self.secp.sign_ecdsa(&msg, &self.secret_key);
        Ok(Beacon {
            public_key: self.public_key.serialize().to_vec(),
            data, signature: sig.serialize_compact().to_vec(),
        })
    }

    pub fn sign_finality_vote(&self, checkpoint_hash: sha256d::Hash, color: Color) -> Result<FinalityVote> {
        let mut msg_bytes = checkpoint_hash.to_byte_array().to_vec();
        msg_bytes.push(color as u8);
        let msg_hash = sha256d::Hash::hash(&msg_bytes);
        let msg = Message::from_digest_slice(msg_hash.as_ref())?;
        let sig = self.secp.sign_ecdsa(&msg, &self.secret_key);
        Ok(FinalityVote {
            voter_public_key: self.public_key.serialize().to_vec(),
            checkpoint_hash, color, signature: sig.serialize_compact().to_vec(),
        })
    }
}
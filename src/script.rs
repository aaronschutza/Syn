// src/script.rs

use bitcoin_hashes::{hash160, Hash};
use secp256k1::{ecdsa::Signature, Message, PublicKey, Secp256k1};
use std::convert::TryInto;

/// Evaluates a combined script (scriptSig and scriptPubKey) to validate a transaction input.
pub fn evaluate(script_sig: &[u8], script_pub_key: &[u8], sighash: &[u8]) -> bool {
    let mut stack: Vec<Vec<u8>> = Vec::new();
    let mut combined_script = script_sig.to_vec();
    combined_script.extend_from_slice(script_pub_key);

    let mut i = 0;
    while i < combined_script.len() {
        let opcode = combined_script[i];
        i += 1;

        match opcode {
            len @ 0x01..=0x4b => {
                let len = len as usize;
                if i + len > combined_script.len() { return false; }
                stack.push(combined_script[i..i + len].to_vec());
                i += len;
            }
            0x76 => { // OP_DUP
                if let Some(top) = stack.last() {
                    stack.push(top.clone());
                } else {
                    return false;
                }
            }
            0xa9 => { // OP_HASH160
                if let Some(top) = stack.pop() {
                    let hash = hash160::Hash::hash(&top);
                    stack.push(hash.to_byte_array().to_vec());
                } else {
                    return false;
                }
            }
            0x88 => { // OP_EQUALVERIFY
                if stack.len() < 2 { return false; }
                let a = stack.pop().unwrap();
                let b = stack.pop().unwrap();
                if a != b {
                    return false;
                }
            }
            0xac => { // OP_CHECKSIG
                if stack.len() < 2 { return false; }
                let pubkey_bytes = stack.pop().unwrap();
                let sig_bytes = stack.pop().unwrap();
                
                let sig = match Signature::from_der(&sig_bytes) {
                    Ok(s) => s,
                    Err(_) => return false,
                };

                let pubkey = match PublicKey::from_slice(&pubkey_bytes) {
                    Ok(pk) => pk,
                    Err(_) => return false,
                };

                // CORRECTED: Use from_digest_slice
                let digest: [u8; 32] = match sighash.try_into() {
                    Ok(d) => d,
                    Err(_) => return false,
                };
                let msg = match Message::from_digest_slice(&digest) {
                    Ok(m) => m,
                    Err(_) => return false,
                };

                let secp = Secp256k1::new();
                if secp.verify_ecdsa(&msg, &sig, &pubkey).is_err() {
                     return false; 
                }
            }
            _ => return false,
        }
    }

    true
}


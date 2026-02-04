// src/script.rs - Security-hardened stack machine for transaction validation

use bitcoin_hashes::{hash160, Hash};
use secp256k1::{ecdsa::Signature, Message, PublicKey, Secp256k1};
use std::convert::TryInto;
use log::debug;

/// Evaluates a combined script (scriptSig and scriptPubKey) to validate a transaction input.
pub fn evaluate(script_sig: &[u8], script_pub_key: &[u8], sighash: &[u8]) -> bool {
    let mut stack: Vec<Vec<u8>> = Vec::new();
    
    // Evaluate scriptSig first, then scriptPubKey
    let mut combined_script = script_sig.to_vec();
    combined_script.extend_from_slice(script_pub_key);

    let mut i = 0;
    while i < combined_script.len() {
        let opcode = combined_script[i];
        i += 1;

        match opcode {
            // Push data (0x01 - 0x4b)
            len @ 0x01..=0x4b => {
                let len = len as usize;
                if i + len > combined_script.len() { return false; }
                stack.push(combined_script[i..i + len].to_vec());
                i += len;
            }
            
            // Push small constants (OP_0, OP_1 - OP_16)
            0x00 => stack.push(vec![]), // OP_0 / OP_FALSE
            val @ 0x51..=0x60 => { // OP_1 (0x51) through OP_16 (0x60)
                let num = (val - 0x50) as i32;
                stack.push(num.to_le_bytes().to_vec());
            }

            // OP_DUP
            0x76 => {
                if let Some(top) = stack.last() {
                    stack.push(top.clone());
                } else { return false; }
            }

            // OP_HASH160
            0xa9 => {
                if let Some(top) = stack.pop() {
                    let hash = hash160::Hash::hash(&top);
                    stack.push(hash.to_byte_array().to_vec());
                } else { return false; }
            }

            // OP_EQUAL / OP_EQUALVERIFY
            0x87 | 0x88 => {
                if stack.len() < 2 { return false; }
                let b = stack.pop().unwrap();
                let a = stack.pop().unwrap();
                let equal = a == b;
                if opcode == 0x88 && !equal { return false; } // OP_EQUALVERIFY
                if opcode == 0x87 {
                    stack.push(if equal { vec![1] } else { vec![] });
                }
            }

            // OP_VERIFY
            0x69 => {
                if let Some(top) = stack.pop() {
                    if !is_truthy(&top) { return false; }
                } else { return false; }
            }

            // OP_ADD / OP_SUB
            0x93 | 0x94 => {
                if stack.len() < 2 { return false; }
                let b_bytes = stack.pop().unwrap();
                let a_bytes = stack.pop().unwrap();
                
                let a = i32::from_le_bytes(pad_to_4(&a_bytes));
                let b = i32::from_le_bytes(pad_to_4(&b_bytes));
                
                let res = if opcode == 0x93 { a + b } else { a - b };
                stack.push(res.to_le_bytes().to_vec());
            }

            // OP_NOT
            0x91 => {
                if let Some(top) = stack.pop() {
                    let val = i32::from_le_bytes(pad_to_4(&top));
                    stack.push(if val == 0 { vec![1] } else { vec![] });
                } else { return false; }
            }

            // OP_CHECKSIG
            0xac => {
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

                let digest: [u8; 32] = match sighash.try_into() {
                    Ok(d) => d,
                    Err(_) => return false,
                };
                let msg = match Message::from_digest_slice(&digest) {
                    Ok(m) => m,
                    Err(_) => return false,
                };

                let secp = Secp256k1::new();
                let valid = secp.verify_ecdsa(&msg, &sig, &pubkey).is_ok();
                stack.push(if valid { vec![1] } else { vec![] });
            }

            0x6a => return false, // OP_RETURN

            _ => {
                debug!("Unsupported opcode: 0x{:02x}", opcode);
                return false;
            }
        }
    }

    // A script is successful if it finishes without error and, 
    // if the stack isn't empty, the top element is truthy.
    match stack.pop() {
        Some(top) => is_truthy(&top),
        None => true, // If stack is empty (e.g. after OP_VERIFY), the script passes.
    }
}

/// Helper to determine truthiness of a stack element (Bitcoin style)
fn is_truthy(bytes: &[u8]) -> bool {
    if bytes.is_empty() { return false; }
    for &b in bytes {
        if b != 0 { return true; }
    }
    false
}

/// Helper to pad byte vectors for i32 conversions (Bitcoin-style)
fn pad_to_4(bytes: &[u8]) -> [u8; 4] {
    let mut out = [0u8; 4];
    let len = bytes.len().min(4);
    out[..len].copy_from_slice(&bytes[..len]);
    out
}
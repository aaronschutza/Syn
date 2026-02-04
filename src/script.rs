// src/script.rs - Production-grade Bitcoin Script interpreter for Synergeia

use bitcoin_hashes::{hash160, sha256, sha256d, Hash};
use secp256k1::{ecdsa::Signature, Message, PublicKey, Secp256k1};
use std::convert::TryInto;
// Removed unused 'log::debug' import to resolve compiler warning

/// Evaluates a combined script (scriptSig and scriptPubKey) to validate a transaction input.
/// Supports conditional logic, stack manipulation, and cryptographic primitives.
pub fn evaluate(script_sig: &[u8], script_pub_key: &[u8], sighash: &[u8]) -> bool {
    let mut stack: Vec<Vec<u8>> = Vec::new();
    // execution_stack tracks IF/ELSE nesting levels
    let mut execution_stack: Vec<bool> = Vec::new();
    
    let mut combined_script = script_sig.to_vec();
    combined_script.extend_from_slice(script_pub_key);

    let mut i = 0;
    while i < combined_script.len() {
        let opcode = combined_script[i];
        i += 1;

        // Current execution state (true if not in a false branch)
        let exec = execution_stack.iter().all(|&e| e);

        match opcode {
            // --- Push Operations (Always run to maintain index i) ---
            len @ 0x01..=0x4b => {
                let len = len as usize;
                if i + len > combined_script.len() { return false; }
                if exec {
                    stack.push(combined_script[i..i + len].to_vec());
                }
                i += len;
            }
            
            // OP_0 to OP_16
            0x00 => if exec { stack.push(vec![]) },
            val @ 0x51..=0x60 => {
                if exec {
                    let num = (val - 0x50) as i32;
                    stack.push(num.to_le_bytes().to_vec());
                }
            }

            // --- Control Flow (Must run even if exec is false) ---
            0x63 => { // OP_IF
                let condition = if exec {
                    stack.pop().map(|v| is_truthy(&v)).unwrap_or(false)
                } else {
                    false
                };
                execution_stack.push(condition);
            }
            0x67 => { // OP_ELSE
                if let Some(e) = execution_stack.last_mut() {
                    *e = !*e;
                } else { return false; }
            }
            0x68 => { // OP_ENDIF
                if execution_stack.pop().is_none() { return false; }
            }

            // --- Opcodes that only run if exec is true ---
            _ if exec => match opcode {
                // Stack Manipulation
                0x75 => { stack.pop(); } // OP_DROP
                0x7c => { // OP_SWAP
                    if stack.len() < 2 { return false; }
                    let len = stack.len();
                    stack.swap(len - 1, len - 2);
                }
                0x78 => { // OP_OVER
                    if stack.len() < 2 { return false; }
                    let item = stack[stack.len() - 2].clone();
                    stack.push(item);
                }
                0x76 => { // OP_DUP
                    if let Some(top) = stack.last() {
                        stack.push(top.clone());
                    } else { return false; }
                }

                // Bitwise / Logic
                0x87 | 0x88 => { // OP_EQUAL / OP_EQUALVERIFY
                    if stack.len() < 2 { return false; }
                    let b = stack.pop().unwrap();
                    let a = stack.pop().unwrap();
                    let equal = a == b;
                    if opcode == 0x88 && !equal { return false; }
                    if opcode == 0x87 {
                        stack.push(if equal { vec![1] } else { vec![] });
                    }
                }
                0x91 => { // OP_NOT
                    if let Some(top) = stack.pop() {
                        let val = i32::from_le_bytes(pad_to_4(&top));
                        stack.push(if val == 0 { vec![1] } else { vec![] });
                    } else { return false; }
                }
                0x69 => { // OP_VERIFY
                    if let Some(top) = stack.pop() {
                        if !is_truthy(&top) { return false; }
                    } else { return false; }
                }

                // Arithmetic & Comparison
                0x93 | 0x94 => { // OP_ADD / OP_SUB
                    if stack.len() < 2 { return false; }
                    let b = i32::from_le_bytes(pad_to_4(&stack.pop().unwrap()));
                    let a = i32::from_le_bytes(pad_to_4(&stack.pop().unwrap()));
                    let res = if opcode == 0x93 { a + b } else { a - b };
                    stack.push(res.to_le_bytes().to_vec());
                }
                0x9f => { // OP_LESSTHAN
                    if stack.len() < 2 { return false; }
                    let b = i32::from_le_bytes(pad_to_4(&stack.pop().unwrap()));
                    let a = i32::from_le_bytes(pad_to_4(&stack.pop().unwrap()));
                    stack.push(if a < b { vec![1] } else { vec![] });
                }
                0xa0 => { // OP_GREATERTHAN
                    if stack.len() < 2 { return false; }
                    let b = i32::from_le_bytes(pad_to_4(&stack.pop().unwrap()));
                    let a = i32::from_le_bytes(pad_to_4(&stack.pop().unwrap()));
                    stack.push(if a > b { vec![1] } else { vec![] });
                }

                // Cryptography
                0xa8 => { // OP_SHA256
                    if let Some(top) = stack.pop() {
                        let hash = sha256::Hash::hash(&top);
                        stack.push(hash.to_byte_array().to_vec());
                    } else { return false; }
                }
                0xa9 => { // OP_HASH160
                    if let Some(top) = stack.pop() {
                        let hash = hash160::Hash::hash(&top);
                        stack.push(hash.to_byte_array().to_vec());
                    } else { return false; }
                }
                0xaa => { // OP_HASH256
                    if let Some(top) = stack.pop() {
                        let hash = sha256d::Hash::hash(&top);
                        stack.push(hash.to_byte_array().to_vec());
                    } else { return false; }
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
                _ => return false,
            }
            _ => { /* Skip opcode if exec is false */ }
        }
    }

    if !execution_stack.is_empty() { return false; } // Missing ENDIF
    
    match stack.pop() {
        Some(top) => is_truthy(&top),
        None => true,
    }
}

fn is_truthy(bytes: &[u8]) -> bool {
    if bytes.is_empty() { return false; }
    for &b in bytes {
        if b != 0 { return true; }
    }
    false
}

fn pad_to_4(bytes: &[u8]) -> [u8; 4] {
    let mut out = [0u8; 4];
    let len = bytes.len().min(4);
    out[..len].copy_from_slice(&bytes[..len]);
    out
}
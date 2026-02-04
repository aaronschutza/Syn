// src/script.rs - Production-grade Bitcoin Script interpreter for Synergeia

use bitcoin_hashes::{hash160, Hash};
use secp256k1::{ecdsa::Signature, Message, PublicKey, Secp256k1};

/// Contextual data required for validating time-locked or sequence-locked transactions.
pub struct ScriptContext {
    pub lock_time: u32,
    pub tx_version: i32,
    pub input_sequence: u32,
}

/// Evaluates a combined script (scriptSig and scriptPubKey) to validate a transaction input.
/// Expanded to support Multi-sig, Time-locks, and Alt-stack management.
pub fn evaluate(
    script_sig: &[u8],
    script_pub_key: &[u8],
    sighash: &[u8],
    context: &ScriptContext,
) -> bool {
    let mut stack: Vec<Vec<u8>> = Vec::new();
    let mut alt_stack: Vec<Vec<u8>> = Vec::new();
    let mut execution_stack: Vec<bool> = Vec::new();
    
    let mut combined_script = script_sig.to_vec();
    combined_script.extend_from_slice(script_pub_key);

    let secp = Secp256k1::new();
    let mut i = 0;

    while i < combined_script.len() {
        let opcode = combined_script[i];
        i += 1;

        // Current execution state (true if not in a false branch)
        let exec = execution_stack.iter().all(|&e| e);

        match opcode {
            // --- Push Operations ---
            len @ 0x01..=0x4b => {
                let len = len as usize;
                if i + len > combined_script.len() { return false; }
                if exec {
                    stack.push(combined_script[i..i + len].to_vec());
                }
                i += len;
            }
            
            // OP_0 (Empty vector)
            0x00 => if exec { stack.push(vec![]) },
            // OP_1 to OP_16
            val @ 0x51..=0x60 => {
                if exec {
                    let num = (val - 0x50) as i32;
                    stack.push(num.to_le_bytes().to_vec());
                }
            }

            // --- Control Flow ---
            0x63 | 0x64 => { // OP_IF / OP_NOTIF
                let condition = if exec {
                    let top = stack.pop().map(|v| is_truthy(&v)).unwrap_or(false);
                    if opcode == 0x63 { top } else { !top }
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
                // Alt Stack Management
                0x6b => { // OP_TOALTSTACK
                    if let Some(top) = stack.pop() { alt_stack.push(top); }
                    else { return false; }
                }
                0x6c => { // OP_FROMALTSTACK
                    if let Some(top) = alt_stack.pop() { stack.push(top); }
                    else { return false; }
                }

                // Stack Manipulation
                0x75 => { stack.pop(); } // OP_DROP
                0x76 => { // OP_DUP
                    if let Some(top) = stack.last() { stack.push(top.clone()); }
                    else { return false; }
                }
                0x7c => { // OP_SWAP
                    let len = stack.len();
                    if len < 2 { return false; }
                    stack.swap(len - 1, len - 2);
                }
                0x78 => { // OP_OVER
                    if stack.len() < 2 { return false; }
                    let item = stack[stack.len() - 2].clone();
                    stack.push(item);
                }

                // Bitwise / Logic
                0x87 | 0x88 => { // OP_EQUAL / OP_EQUALVERIFY
                    if stack.len() < 2 { return false; }
                    let b = stack.pop().unwrap();
                    let a = stack.pop().unwrap();
                    let equal = a == b;
                    if opcode == 0x88 && !equal { return false; }
                    if opcode == 0x87 { stack.push(if equal { vec![1] } else { vec![] }); }
                }
                0x91 => { // OP_NOT
                    if let Some(top) = stack.pop() {
                        stack.push(if is_truthy(&top) { vec![] } else { vec![1] });
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
                    let b = script_get_int(&stack.pop().unwrap());
                    let a = script_get_int(&stack.pop().unwrap());
                    let res = if opcode == 0x93 { a + b } else { a - b };
                    stack.push(res.to_le_bytes().to_vec());
                }
                // FIX: Restore Comparison Opcodes (0x9f: LESSTHAN, 0xa0: GREATERTHAN)
                0x9f | 0xa0 => {
                    if stack.len() < 2 { return false; }
                    let b = script_get_int(&stack.pop().unwrap());
                    let a = script_get_int(&stack.pop().unwrap());
                    let res = if opcode == 0x9f { a < b } else { a > b };
                    stack.push(if res { vec![1] } else { vec![] });
                }

                // Time-locks
                0xb1 => { // OP_CHECKLOCKTIMEVERIFY
                    if let Some(top) = stack.last() {
                        let lock_time_req = script_get_int(top) as u32;
                        if context.lock_time < lock_time_req { return false; }
                    } else { return false; }
                }
                0xb2 => { // OP_CHECKSEQUENCEVERIFY
                    if let Some(top) = stack.last() {
                        let seq_req = script_get_int(top) as u32;
                        if context.input_sequence < seq_req { return false; }
                    } else { return false; }
                }

                // Cryptography
                0xa9 => { // OP_HASH160
                    if let Some(top) = stack.pop() {
                        stack.push(hash160::Hash::hash(&top).to_byte_array().to_vec());
                    } else { return false; }
                }
                0xac => { // OP_CHECKSIG
                    if stack.len() < 2 { return false; }
                    let pubkey_bytes = stack.pop().unwrap();
                    let sig_bytes = stack.pop().unwrap();
                    if !verify_sig(&secp, &sig_bytes, &pubkey_bytes, sighash) { return false; }
                    stack.push(vec![1]);
                }
                0xae => { // OP_CHECKMULTISIG
                    if stack.is_empty() { return false; }
                    let n_pubkeys = script_get_int(&stack.pop().unwrap()) as usize;
                    if stack.len() < n_pubkeys { return false; }
                    let mut pubkeys = Vec::new();
                    for _ in 0..n_pubkeys { pubkeys.push(stack.pop().unwrap()); }
                    
                    let m_sigs = script_get_int(&stack.pop().unwrap()) as usize;
                    if stack.len() < m_sigs { return false; }
                    let mut sigs = Vec::new();
                    for _ in 0..m_sigs { sigs.push(stack.pop().unwrap()); }
                    
                    // Dummy element for BIP-147 / historical bug parity
                    stack.pop();

                    let mut success = 0;
                    let mut k = 0; // Current pubkey index
                    for sig in sigs {
                        while k < pubkeys.len() {
                            if verify_sig(&secp, &sig, &pubkeys[k], sighash) {
                                success += 1;
                                k += 1;
                                break;
                            }
                            k += 1;
                        }
                    }
                    stack.push(if success == m_sigs { vec![1] } else { vec![] });
                }
                _ => return false,
            }
            _ => { /* Skip if branch is false */ }
        }
    }

    if !execution_stack.is_empty() { return false; } 
    stack.pop().map(|v| is_truthy(&v)).unwrap_or(true)
}

fn verify_sig(secp: &Secp256k1<secp256k1::All>, sig_bytes: &[u8], pk_bytes: &[u8], sighash: &[u8]) -> bool {
    if sig_bytes.is_empty() { return false; }
    let sig = match Signature::from_der(sig_bytes) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let pubkey = match PublicKey::from_slice(pk_bytes) {
        Ok(pk) => pk,
        Err(_) => return false,
    };
    let msg = match Message::from_digest_slice(sighash) {
        Ok(m) => m,
        Err(_) => return false,
    };
    secp.verify_ecdsa(&msg, &sig, &pubkey).is_ok()
}

fn is_truthy(bytes: &[u8]) -> bool {
    if bytes.is_empty() { return false; }
    for (i, &b) in bytes.iter().enumerate() {
        if b != 0 {
            if i == bytes.len() - 1 && b == 0x80 { return false; } // Negative zero
            return true;
        }
    }
    false
}

fn script_get_int(bytes: &[u8]) -> i32 {
    let mut out = [0u8; 4];
    let len = bytes.len().min(4);
    out[..len].copy_from_slice(&bytes[..len]);
    i32::from_le_bytes(out)
}
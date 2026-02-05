// src/script.rs - Hardened Script Interpreter with SIGHASH stripping

use bitcoin_hashes::{hash160, sha256, sha256d, ripemd160, Hash};
use secp256k1::{ecdsa::Signature, Message, PublicKey, Secp256k1};

const SECP256K1_ORDER_HALF: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d,
    0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
];

#[derive(Debug, Clone, Copy)]
pub struct ScriptContext {
    pub lock_time: u32,
    pub tx_version: i32,
    pub input_sequence: u32,
}

pub fn evaluate(
    script_sig: &[u8],
    script_pub_key: &[u8],
    sighash: &[u8],
    context: &ScriptContext,
) -> bool {
    let mut stack: Vec<Vec<u8>> = Vec::new();
    let mut alt_stack: Vec<Vec<u8>> = Vec::new();
    let mut execution_stack: Vec<bool> = Vec::new();
    
    const MAX_STACK_SIZE: usize = 1000;
    const MAX_OPS: usize = 201;
    let mut op_count = 0;

    let mut combined_script = script_sig.to_vec();
    combined_script.extend_from_slice(script_pub_key);

    let secp = Secp256k1::new();
    let mut i = 0;

    while i < combined_script.len() {
        if op_count > MAX_OPS { return false; }
        op_count += 1;

        let opcode = combined_script[i];
        i += 1;

        let exec = execution_stack.iter().all(|&e| e);

        match opcode {
            len @ 0x01..=0x4b => {
                let len = len as usize;
                if i + len > combined_script.len() { return false; }
                if exec {
                    if stack.len() >= MAX_STACK_SIZE { return false; }
                    stack.push(combined_script[i..i + len].to_vec());
                }
                i += len;
            }
            0x00 => if exec { stack.push(vec![]) },
            val @ 0x51..=0x60 => {
                if exec {
                    let num = (val - 0x50) as i32;
                    stack.push(num.to_le_bytes().to_vec());
                }
            }
            0x63 | 0x64 => {
                let condition = if exec {
                    let top = stack.pop().map(|v| is_truthy(&v)).unwrap_or(false);
                    if opcode == 0x63 { top } else { !top }
                } else { false };
                execution_stack.push(condition);
            }
            0x67 => if let Some(e) = execution_stack.last_mut() { *e = !*e; } else { return false; }
            0x68 => if execution_stack.pop().is_none() { return false; }
            _ if exec => match opcode {
                0x61 => {}, 
                0x6b => { if let Some(top) = stack.pop() { alt_stack.push(top); } else { return false; } }
                0x6c => { if let Some(top) = alt_stack.pop() { stack.push(top); } else { return false; } }
                0x75 => { stack.pop(); } 
                0x76 => { if let Some(top) = stack.last() { stack.push(top.clone()); } else { return false; } }
                0x77 => { 
                    if stack.len() < 2 { return false; }
                    let v1 = stack[stack.len() - 2].clone();
                    let v2 = stack[stack.len() - 1].clone();
                    stack.push(v1); stack.push(v2);
                }
                0x78 => { if stack.len() < 2 { return false; } let item = stack[stack.len() - 2].clone(); stack.push(item); }
                0x7c => { let len = stack.len(); if len < 2 { return false; } stack.swap(len - 1, len - 2); }
                0x7d => { if stack.len() < 2 { return false; } let item = stack[stack.len() - 1].clone(); stack.insert(stack.len() - 2, item); }
                0x7e => { if stack.len() < 2 { return false; } stack.pop(); stack.pop(); }
                0x83 | 0x84 | 0x85 => {
                    if stack.len() < 2 { return false; }
                    let b = stack.pop().unwrap(); let a = stack.pop().unwrap();
                    if a.len() != b.len() { return false; }
                    let res: Vec<u8> = a.iter().zip(b.iter()).map(|(&x, &y)| match opcode {
                        0x83 => x & y, 0x84 => x | y, _ => x ^ y,
                    }).collect();
                    stack.push(res);
                }
                0x87 | 0x88 => {
                    if stack.len() < 2 { return false; }
                    let b = stack.pop().unwrap(); let a = stack.pop().unwrap();
                    let equal = a == b;
                    if opcode == 0x88 && !equal { return false; }
                    if opcode == 0x87 { stack.push(if equal { vec![1] } else { vec![] }); }
                }
                0x91 => { if let Some(top) = stack.pop() { stack.push(if is_truthy(&top) { vec![] } else { vec![1] }); } else { return false; } }
                0x69 => { if let Some(top) = stack.pop() { if !is_truthy(&top) { return false; } } else { return false; } }
                0x9f | 0xa0 => {
                    if stack.len() < 2 { return false; }
                    let b = script_get_int(&stack.pop().unwrap()); let a = script_get_int(&stack.pop().unwrap());
                    let res = if opcode == 0x9f { a < b } else { a > b };
                    stack.push(if res { vec![1] } else { vec![] });
                }
                0x93 | 0x94 => {
                    if stack.len() < 2 { return false; }
                    let b = script_get_int(&stack.pop().unwrap()); let a = script_get_int(&stack.pop().unwrap());
                    let res = if opcode == 0x93 { a + b } else { a - b };
                    stack.push(res.to_le_bytes().to_vec());
                }
                0xb1 => {
                    if let Some(top) = stack.last() {
                        let lock_time_req = script_get_int(top) as u32;
                        if context.lock_time < lock_time_req { return false; }
                    } else { return false; }
                }
                0xa6 => { if let Some(top) = stack.pop() { stack.push(ripemd160::Hash::hash(&top).to_byte_array().to_vec()); } else { return false; } }
                0xa8 => { if let Some(top) = stack.pop() { stack.push(sha256::Hash::hash(&top).to_byte_array().to_vec()); } else { return false; } }
                0xa9 => { if let Some(top) = stack.pop() { stack.push(hash160::Hash::hash(&top).to_byte_array().to_vec()); } else { return false; } }
                0xaa => { if let Some(top) = stack.pop() { stack.push(sha256d::Hash::hash(&top).to_byte_array().to_vec()); } else { return false; } }
                0xac => {
                    if stack.len() < 2 { return false; }
                    let pubkey_bytes = stack.pop().unwrap();
                    let sig_bytes = stack.pop().unwrap();
                    if !verify_sig_hardened(&secp, &sig_bytes, &pubkey_bytes, sighash) { return false; }
                    stack.push(vec![1]);
                }
                0xae => {
                    if stack.is_empty() { return false; }
                    let n_pubkeys = script_get_int(&stack.pop().unwrap()) as usize;
                    if stack.len() < n_pubkeys { return false; }
                    let mut pubkeys = Vec::new();
                    for _ in 0..n_pubkeys { pubkeys.push(stack.pop().unwrap()); }
                    let m_sigs = script_get_int(&stack.pop().unwrap()) as usize;
                    if stack.len() < m_sigs { return false; }
                    let mut sigs = Vec::new();
                    for _ in 0..m_sigs { sigs.push(stack.pop().unwrap()); }
                    stack.pop(); 
                    let mut success = 0; let mut k = 0; 
                    for sig in sigs {
                        while k < pubkeys.len() {
                            if verify_sig_hardened(&secp, &sig, &pubkeys[k], sighash) { success += 1; k += 1; break; }
                            k += 1;
                        }
                    }
                    stack.push(if success == m_sigs { vec![1] } else { vec![] });
                }
                _ => return false,
            }
            _ => { }
        }
    }
    if !execution_stack.is_empty() { return false; } 
    stack.pop().map(|v| is_truthy(&v)).unwrap_or(true)
}

fn verify_sig_hardened(secp: &Secp256k1<secp256k1::All>, sig_bytes: &[u8], pk_bytes: &[u8], sighash: &[u8]) -> bool {
    if sig_bytes.is_empty() { return false; }
    
    // Synergeia/Bitcoin Script format: the last byte is the SigHash type (e.g. SIGHASH_ALL)
    // The secp256k1 parser expects only the DER sequence.
    let sig_pure = &sig_bytes[..sig_bytes.len() - 1];
    
    let sig = match Signature::from_der(sig_pure) {
        Ok(s) => s,
        Err(_) => { return false; }
    };

    let compact = sig.serialize_compact();
    let s_bytes = &compact[32..64];
    if s_bytes > &SECP256K1_ORDER_HALF[..] { return false; }

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
            if i == bytes.len() - 1 && b == 0x80 { return false; } 
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
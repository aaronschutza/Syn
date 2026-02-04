// src/pos.rs

use crate::{
    block::Block,
    blockchain::Blockchain,
    fixed_point::Fixed,
    transaction::{Transaction, TxOut},
    wallet::Wallet
};
use bitcoin_hashes::{sha256d, Hash};
use secp256k1::{Message, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use std::convert::TryInto;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct StakeInfo {
    pub asset: String,
    pub amount: u64,
}

fn vrf_eval(seed: &[u8], sk: &SecretKey) -> (sha256d::Hash, [u8; 64]) {
    let secp = Secp256k1::new();
    let digest: [u8; 32] = seed.try_into().expect("Seed must be 32 bytes");
    let msg = Message::from_digest_slice(&digest).expect("Failed to create message from digest");
    let sig = secp.sign_ecdsa(&msg, sk);
    let sig_bytes = sig.serialize_compact();
    let vrf_hash = sha256d::Hash::hash(&sig_bytes);
    (vrf_hash, sig_bytes)
}

fn f_delta(delta: u64, f_a: Fixed, psi: u32, gamma: u32) -> Fixed {
    let psi_u64 = psi as u64;
    let gamma_u64 = gamma as u64;

    if delta < psi_u64 {
        Fixed(0)
    } else if delta < gamma_u64 {
        if gamma_u64 - psi_u64 == 0 { return Fixed(0); }
        let numerator = Fixed::from_integer(delta.saturating_sub(psi_u64));
        let denominator = Fixed::from_integer(gamma_u64 - psi_u64);
        f_a * (numerator / denominator)
    } else {
        f_a
    }
}

pub fn is_eligible_to_stake(wallet: &Wallet, bc: &Blockchain, current_slot: u64) -> Option<([u8; 64], u64)> {

    let last_block = match bc.get_block(&bc.tip) {
        Some(b) => b,
        None => return None,
    };

    let parent_slot = last_block.header.time as u64;
    if current_slot <= parent_slot { return None; }
    let delta = current_slot - parent_slot;

    let prev_block_hash = last_block.header.hash();
    let mut seed_data = Vec::new();
    seed_data.extend_from_slice(prev_block_hash.as_ref());
    seed_data.extend_from_slice(&current_slot.to_be_bytes());
    let seed_msg = sha256d::Hash::hash(&seed_data);

    let (y, pi) = vrf_eval(seed_msg.as_ref(), &wallet.secret_key);

    let f_a_pos = bc.ldd_state.f_a_pos;
    
    let f_d = f_delta(
        delta, 
        f_a_pos, 
        bc.ldd_state.current_psi, 
        bc.ldd_state.current_gamma
    );

    let total_stake = Fixed::from_integer(bc.total_staked);
    if total_stake.0 == 0 { return None; }

    let alpha_i = Fixed::from_integer(wallet.stake_info.as_ref().map_or(0, |s| s.amount)) / total_stake;

    let phi = match bc.consensus_params.pos_precision.as_str() {
        "accurate" => alpha_i * f_d,
        "test" => Fixed::from_f64(0.99),
        _ => alpha_i * f_d,
    };

    let mut y_bytes = [0u8; 16];
    y_bytes.copy_from_slice(&y[0..16]);
    let y_u128 = u128::from_be_bytes(y_bytes);
    let y_fixed_normalized = Fixed(y_u128 >> 64);

    if y_fixed_normalized < phi {
        Some((pi, delta))
    } else {
        None
    }
}

pub fn create_pos_block(
    bc: &mut Blockchain,
    wallet: &Wallet,
    vrf_proof: [u8; 64],
    delta: u32,
    timestamp: u32,
) -> Result<Block, String> {
    let coinbase_addr = wallet.get_address();
    let mut transactions = vec![Transaction::new_coinbase("Staked by Synergeia Node".to_string(), coinbase_addr, bc.consensus_params.coinbase_reward, bc.consensus_params.transaction_version)];
    
    // Get mempool transactions
    transactions.extend(bc.get_mempool_txs());

    // --- Proof-of-Burn Implementation ---
    // Calculate total fees
    let mut total_fees = 0;
    for tx in transactions.iter().skip(1) { // Skip coinbase
        let total_in: u64 = tx.vin.iter().map(|vin| {
            bc.get_transaction(&vin.prev_txid)
                .ok().flatten()
                .map_or(0, |prev_tx| prev_tx.vout[vin.prev_vout as usize].value)
        }).sum();
        let total_out: u64 = tx.vout.iter().map(|v| v.value).sum();
        total_fees += total_in.saturating_sub(total_out);
    }

    let burn_amount = (total_fees as f64 * bc.ldd_state.current_burn_rate) as u64;

    if burn_amount > 0 {
        if let Some(coinbase) = transactions.get_mut(0) {
            // Check if reward covers burn, else we might need to burn from wallet balance (simulated here by reducing reward)
            // Ideally, validators burn value they own. Here, we reduce the coinbase reward output and create a burn output.
            if coinbase.vout[0].value > burn_amount {
                coinbase.vout[0].value -= burn_amount;
                coinbase.vout.push(TxOut {
                    value: burn_amount,
                    script_pub_key: vec![0x6a], // OP_RETURN
                });
            } else {
                // If reward < burn (unlikely with block reward), we just consume entire reward? 
                // For safety in this implementation, we just burn what we can from coinbase
                let val = coinbase.vout[0].value;
                coinbase.vout[0].value = 0;
                coinbase.vout.push(TxOut { value: val, script_pub_key: vec![0x6a] });
            }
        }
    }

    let prev_block = bc.get_block(&bc.tip).ok_or("Could not get tip block")?;
    let height = prev_block.height + 1;
    let bits = bc.get_next_work_required(false, delta);

    let mut block = Block::new(timestamp, transactions, bc.tip, bits, height, bc.consensus_params.block_version);
    block.header.vrf_proof = Some(vrf_proof.to_vec());

    Ok(block)
}
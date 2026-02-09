// src/pos.rs - Remediation Step 1: Fixed Snowplow Curve Implementation

use crate::{
    block::Block,
    blockchain::Blockchain,
    fixed_point::Fixed,
    transaction::{Transaction, TxOut},
    wallet::Wallet,
};
use bitcoin_hashes::{sha256d, Hash};
use secp256k1::{Message, Secp256k1, SecretKey};
use std::convert::TryInto;
use log::{debug, info, warn, trace};

fn vrf_eval(seed: &[u8], sk: &SecretKey) -> (sha256d::Hash, [u8; 64]) {
    let secp = Secp256k1::new();
    let digest: [u8; 32] = seed.try_into().expect("Seed must be 32 bytes");
    let msg = Message::from_digest_slice(&digest).expect("Failed to create message from digest");
    let sig = secp.sign_ecdsa(&msg, sk);
    let sig_bytes = sig.serialize_compact();
    let vrf_hash = sha256d::Hash::hash(&sig_bytes);
    (vrf_hash, sig_bytes)
}

// Remediation Step 1: Correct Implementation of Equation (1)
// f(delta) = 0 if delta < psi
// f(delta) = f_a * (delta - psi) / (gamma - psi) if psi <= delta < gamma
// f(delta) = f_b if delta >= gamma
fn f_delta(delta: u64, f_a: Fixed, f_b: Fixed, psi: u32, gamma: u32) -> Fixed {
    if delta < psi as u64 {
        Fixed(0)
    } else if delta < gamma as u64 {
        let den = (gamma - psi) as u64;
        if den == 0 { return Fixed(0); }
        let num = delta.saturating_sub(psi as u64);
        // Linear Interpolation (The Snowplow Ramp)
        f_a * (Fixed::from_integer(num) / Fixed::from_integer(den))
    } else {
        // Recovery Phase: Flatline probability at f_b
        f_b
    }
}

pub fn is_eligible_to_stake(wallet: &Wallet, bc: &Blockchain, current_slot: u64) -> Option<([u8; 64], u64, u64)> {
    let last_block = bc.get_block(&bc.tip)?;
    let parent_slot = last_block.header.time as u64;
    
    // Ensure we are ahead of the tip
    if current_slot <= parent_slot { 
        trace!("PoS: Current slot {} <= Parent slot {}", current_slot, parent_slot);
        return None; 
    }
    
    let delta = current_slot - parent_slot;

    let mut seed_data = Vec::new();
    seed_data.extend_from_slice(last_block.header.hash().as_ref());
    seed_data.extend_from_slice(&current_slot.to_be_bytes());
    let seed_msg = sha256d::Hash::hash(&seed_data);

    let (y, pi) = vrf_eval(seed_msg.as_ref(), &wallet.secret_key);
    
    // Remediation Step 1: Use the corrected hazard function with f_b
    let f_d = f_delta(
        delta, 
        bc.ldd_state.f_a_pos, 
        bc.ldd_state.f_b_pos, 
        bc.ldd_state.current_psi, 
        bc.ldd_state.current_gamma
    );

    // Remediation Step 2: Use the current agreed total stake for the header
    let total_bonded_supply = bc.consensus_engine.staking_module.get_total_bonded_supply() as u64;
    let total_stake = Fixed::from_integer(total_bonded_supply);
    
    if total_stake.0 == 0 { 
        if delta % 10 == 0 { warn!("PoS: Total Network Stake is 0. No one can win."); }
        return None; 
    }
    
    let amount = wallet.stake_info.as_ref().map_or(0, |s| s.amount);
    if amount == 0 {
        if delta % 10 == 0 { 
             debug!("PoS: Local wallet has 0 stake. Ensure stake RPC was called and wallet reloaded.");
        }
        return None;
    }

    let alpha_i = Fixed::from_integer(amount) / total_stake;

    // Use full Phi calculation: 1 - (1-f)^alpha
    // Using deterministic binomial expansion
    let phi = match bc.consensus_params.pos_precision.as_str() {
        "test" => Fixed::from_f64(0.99),
        _ => Fixed::consensus_phi(f_d, alpha_i),
    };

    let mut y_bytes = [0u8; 16];
    y_bytes.copy_from_slice(&y[0..16]);
    
    let normalized_vrf = Fixed(u128::from_be_bytes(y_bytes) >> 64);

    if f_d.0 > 0 {
        info!(
            "PoS Check [Slot {} | Delta {}]: Stake {}/{} (alpha {:.4}) | f_delta {:.6} | Phi {:.6} | VRF {:.6} | Eligible: {}",
            current_slot, delta, amount, total_bonded_supply, alpha_i.to_f64(), 
            f_d.to_f64(), phi.to_f64(), normalized_vrf.to_f64(),
            normalized_vrf < phi
        );
    }

    if normalized_vrf < phi { 
        info!("*** PoS WINNER *** Slot {} | VRF {:.6} < Phi {:.6}", current_slot, normalized_vrf.to_f64(), phi.to_f64());
        // Return total_bonded_supply to be committed to the header
        Some((pi, delta, total_bonded_supply)) 
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
    committed_total_stake: u64, // Remediation Step 2 argument
) -> Result<Block, String> {
    let mut coinbase = Transaction::new_coinbase(
        "PoS Mining".into(), wallet.get_address(), bc.consensus_params.coinbase_reward, bc.consensus_params.transaction_version
    );
    let mut txs = vec![coinbase.clone()]; // Temporary vec to calc fees
    let mempool_txs = bc.get_mempool_txs();
    txs.extend(mempool_txs.clone());
    
    // Calculate required burn based on fees
    // We construct a temporary block to reuse calculate_total_fees logic
    let prev = bc.get_block(&bc.tip).ok_or("Tip missing")?;
    let temp_block = Block::new(timestamp, txs.clone(), bc.tip, 0, prev.height + 1, 1, 0, 0);
    let fees = bc.calculate_total_fees(&temp_block);
    
    let burn_rate_fixed = bc.ldd_state.current_burn_rate;
    // Calculate required burn: fees * burn_rate
    let fees_fixed = Fixed::from_integer(fees);
    // REMOVED: Fixed::from_f64() call on burn_rate_fixed
    let proven_burn = ((fees_fixed * burn_rate_fixed).0 >> 64) as u64;

    if proven_burn > 0 {
        // Add burn output to coinbase
        coinbase.vout.push(TxOut { value: proven_burn, script_pub_key: vec![0x6a] });
        // Deduct from reward? Or is it additional cost?
        // Protocol typically burns FEEs. The miner collects (Fees - Burn).
        // If coinbase value was Reward, we should add (Fees - Burn).
        // Since we don't have fee collection logic in new_coinbase (it just sets value=reward),
        // we implicitly assume the miner takes the rest.
        // However, we MUST include the burn output to pass validation.
    }

    let mut final_txs = vec![coinbase];
    final_txs.extend(mempool_txs);

    let bits = bc.get_next_work_required(false, delta);
    
    // Remediation Step 2: Include committed_total_stake in the block header
    let mut block = Block::new(
        timestamp, 
        final_txs, 
        bc.tip, 
        bits, 
        prev.height + 1, 
        bc.consensus_params.block_version, 
        proven_burn,
        committed_total_stake 
    );
    
    block.header.vrf_proof = Some(vrf_proof.to_vec());
    
    if let Ok(root) = bc.calculate_utxo_root() {
        block.header.utxo_root = root;
    }

    Ok(block)
}
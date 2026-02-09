// src/pos.rs - Deterministic Proof-of-Stake Eligibility with Verbose Debugging

use crate::{
    block::Block,
    blockchain::Blockchain,
    fixed_point::Fixed,
    transaction::Transaction,
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

fn f_delta(delta: u64, f_a: Fixed, psi: u32, gamma: u32) -> Fixed {
    if delta < psi as u64 {
        Fixed(0)
    } else if delta < gamma as u64 {
        let den = (gamma - psi) as u64;
        if den == 0 { return Fixed(0); }
        let num = delta.saturating_sub(psi as u64);
        f_a * (Fixed::from_integer(num) / Fixed::from_integer(den))
    } else {
        f_a
    }
}

pub fn is_eligible_to_stake(wallet: &Wallet, bc: &Blockchain, current_slot: u64) -> Option<([u8; 64], u64)> {
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
    
    let f_d = f_delta(delta, bc.ldd_state.f_a_pos, bc.ldd_state.current_psi, bc.ldd_state.current_gamma);

    let total_bonded_supply = bc.consensus_engine.staking_module.get_total_bonded_supply() as u64;
    let total_stake = Fixed::from_integer(total_bonded_supply);
    
    if total_stake.0 == 0 { 
        // Only warn once per slot/delta to avoid spamming if checking frequently
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

    let phi = match bc.consensus_params.pos_precision.as_str() {
        "test" => Fixed::from_f64(0.99),
        _ => alpha_i * f_d,
    };

    let mut y_bytes = [0u8; 16];
    y_bytes.copy_from_slice(&y[0..16]);
    
    // Fixed point logic: shift right by 64 bits to normalize 128-bit hash to [0,1) in 64.64 fixed point
    let normalized_vrf = Fixed(u128::from_be_bytes(y_bytes) >> 64);

    // DEBUG: Only log if we are past the slot gap (f_d > 0)
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
    let coinbase = Transaction::new_coinbase(
        "PoS Mining".into(), wallet.get_address(), bc.consensus_params.coinbase_reward, bc.consensus_params.transaction_version
    );
    let mut txs = vec![coinbase];
    txs.extend(bc.get_mempool_txs());
    
    // Calculate Burn for PoS
    // In this iteration, we just calculate it from existing OP_RETURNs in mempool txs for now.
    // Ideally, the validator should insert a burn transaction if required by protocol.
    // For now, we assume 0 burn for simplicity in block creation, relying on tests/users to submit fee txs.
    let proven_burn = 0; 

    let prev = bc.get_block(&bc.tip).ok_or("Tip missing")?;
    let bits = bc.get_next_work_required(false, delta);
    
    // Updated Block::new call with proven_burn
    let mut block = Block::new(timestamp, txs, bc.tip, bits, prev.height + 1, bc.consensus_params.block_version, proven_burn);
    block.header.vrf_proof = Some(vrf_proof.to_vec());
    
    if let Ok(root) = bc.calculate_utxo_root() {
        block.header.utxo_root = root;
    }

    Ok(block)
}
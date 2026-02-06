// src/consensus.rs - Mining and Beaconing Loop

use crate::{
    block::{BeaconData, Beacon},
    blockchain::Blockchain, 
    config::NodeConfig, 
    p2p::P2PMessage, 
    transaction::{Transaction, TxOut}, 
    wallet::Wallet,
    crypto::{hash_pubkey, address_from_pubkey_hash},
    cdf::Color,
    pos, // ADDED: Import pos module
};
use anyhow::Result;
use chrono::Utc;
use log::{info, warn, debug}; 
use num_bigint::BigUint;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, mpsc, Mutex};
use secp256k1::PublicKey;

const BEACON_REWARD_PERCENT: u64 = 1; 

fn apply_beacon_rewards(block: &mut crate::block::Block, total_reward: u64, beacons: &[Beacon]) {
    if beacons.is_empty() { return; }
    let total_bounty_pool = (total_reward * BEACON_REWARD_PERCENT) / 100;
    let reward_per_beacon = total_bounty_pool / beacons.len() as u64;
    if let Some(coinbase) = block.transactions.get_mut(0) {
        if coinbase.vout.is_empty() || reward_per_beacon == 0 { return; }
        if coinbase.vout[0].value >= total_bounty_pool {
            coinbase.vout[0].value -= total_bounty_pool;
            for beacon in beacons {
                if let Ok(pk) = PublicKey::from_slice(&beacon.public_key) {
                    let addr = address_from_pubkey_hash(&hash_pubkey(&pk));
                    coinbase.vout.push(TxOut::new(reward_per_beacon, addr));
                }
            }
        }
    }
}

pub async fn start_consensus_loop(
    bc: Arc<Mutex<Blockchain>>,
    mode: String,
    _mine_to_address: Option<String>,
    mut p2p_rx: mpsc::Receiver<P2PMessage>,
    p2p_tx: broadcast::Sender<P2PMessage>,
    node_config: Arc<NodeConfig>,
    mut shutdown_rx: broadcast::Receiver<()>,
) -> Result<()> {
    info!("Starting Synergeia Consensus Engine (Mode: {})", mode);
    let wallet = Wallet::load_from_file(&node_config)?;
    let mut beacon_timer = tokio::time::interval(Duration::from_secs(30));
    let mut cdf_timer = tokio::time::interval(Duration::from_secs(10));
    
    let mut last_slot_log = 0;

    loop {
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_millis(500)) => {
                let mut bc_lock = bc.lock().await;
                
                // --- PoW Logic ---
                if mode == "miner" || mode == "full" {
                    let tip_hash = bc_lock.tip;
                    let last_block = bc_lock.get_block(&tip_hash);
                    let last_block_time = last_block.as_ref().map(|b| b.header.time).unwrap_or(0);
                    let last_height = last_block.as_ref().map(|b| b.height).unwrap_or(0);
                    let mempool_size = bc_lock.mempool.len();
                    
                    let now = Utc::now().timestamp() as u32;
                    let delta = now.saturating_sub(last_block_time);
                    let psi = bc_lock.ldd_state.current_psi;

                    if now > last_slot_log {
                        info!("[SLOT] Time: {} | Height: {} | Delta: {}s / {}s (Psi) | Mempool: {}", 
                            now, last_height, delta, psi, mempool_size);
                        last_slot_log = now;
                    }
                    
                    if delta >= psi {
                        let reward = bc_lock.consensus_params.coinbase_reward;
                        let mempool_txs = bc_lock.get_mempool_txs();
                        let coinbase = Transaction::new_coinbase(
                            "Mined by Synergeia".to_string(),
                            wallet.get_address(),
                            reward,
                            bc_lock.consensus_params.transaction_version
                        );
                        
                        let mut txs = vec![coinbase];
                        txs.extend(mempool_txs);

                        if let Ok(mut block) = bc_lock.create_block_template(txs, 1) {
                            let beacons = block.beacons.clone();
                            apply_beacon_rewards(&mut block, reward, &beacons);
                            let target = bc_lock.get_next_pow_target(delta);
                            for _ in 0..2000 {
                                if BigUint::from_bytes_be(block.header.hash().as_ref()) <= target {
                                    if bc_lock.add_block(block.clone()).is_ok() {
                                        info!("[MINED] Block {} (Hash: {}..) - TxCount: {}", 
                                            block.height, 
                                            block.header.hash().to_string().get(0..8).unwrap_or(""), 
                                            block.transactions.len());
                                        // Broadcast mined block
                                        p2p_tx.send(P2PMessage::NewBlock(Box::new(block))).ok();
                                    }
                                    break;
                                }
                                block.header.nonce += 1;
                            }
                        }
                    }
                }

                // --- PoS Logic (ADDED) ---
                if mode == "staker" || mode == "full" {
                    let now = Utc::now().timestamp() as u64;
                    // Only attempt to stake if we haven't already processed this slot
                    if now as u32 > last_slot_log {
                        // Check if we are eligible to produce a block in this slot
                        if let Some((proof, delta)) = pos::is_eligible_to_stake(&wallet, &bc_lock, now) {
                            debug!("Selected as PoS Leader for slot {}!", now);
                            
                            match pos::create_pos_block(&mut bc_lock, &wallet, proof, delta as u32, now as u32) {
                                Ok(block) => {
                                    if bc_lock.add_block(block.clone()).is_ok() {
                                        info!("[MINED POS] Block {} (Hash: {}..) - Validator: {}", 
                                            block.height, 
                                            block.header.hash().to_string().get(0..8).unwrap_or(""), 
                                            wallet.get_address());
                                        
                                        p2p_tx.send(P2PMessage::NewBlock(Box::new(block))).ok();
                                    }
                                }
                                Err(e) => warn!("Failed to construct PoS block: {}", e),
                            }
                        }
                    }
                }
            }
            _ = beacon_timer.tick() => {
                let mut bc_lock = bc.lock().await;
                let metrics = bc_lock.get_and_reset_metrics();
                if let Ok(b) = wallet.sign_beacon(BeaconData::Time(Utc::now().timestamp() as u64)) { 
                    info!("[BEACON] Broadcasting Time Beacon");
                    p2p_tx.send(P2PMessage::Beacon(b)).ok(); 
                }
                if let Ok(b) = wallet.sign_beacon(BeaconData::Security(metrics.orphan_count, metrics.max_reorg_depth)) { p2p_tx.send(P2PMessage::Beacon(b)).ok(); }
            }
            _ = cdf_timer.tick() => {
                let bc_lock = bc.lock().await;
                if bc_lock.finality_gadget.active && !bc_lock.finality_gadget.finalized {
                    if let Some(target) = bc_lock.finality_gadget.target_checkpoint {
                        let color = match wallet.public_key.serialize()[0] % 3 { 0 => Color::Red, 1 => Color::Green, _ => Color::Blue };
                        if let Ok(vote) = wallet.sign_finality_vote(target, color) { p2p_tx.send(P2PMessage::FinalityVote(vote)).ok(); }
                    }
                }
            }
            Some(msg) = p2p_rx.recv() => {
                match msg {
                    P2PMessage::NewBlock(block) => { 
                        let mut bc_lock = bc.lock().await;
                        // Simple duplicate check to prevent infinite broadcast loops
                        if bc_lock.blocks_tree.contains_key(block.header.hash().as_ref() as &[u8]).unwrap_or(false) {
                            continue;
                        }

                        match bc_lock.add_block(*block.clone()) {
                            Ok(_) => {
                                info!("[PEER] Accepted Block {} (Hash: {}..)", block.height, block.header.hash().to_string().get(0..8).unwrap_or(""));
                                // Rebroadcast accepted blocks to ensure propagation
                                p2p_tx.send(P2PMessage::NewBlock(block)).ok();
                            },
                            Err(e) => {
                                warn!("[REJECT] Block {} Rejected: {}", block.height, e);
                            }
                        }
                    }
                    P2PMessage::Beacon(beacon) => { 
                        let mut bc_lock = bc.lock().await;
                        bc_lock.receive_beacon(beacon).ok(); 
                    }
                    P2PMessage::FinalityVote(vote) => { 
                        let mut bc_lock = bc.lock().await;
                        bc_lock.process_finality_vote(vote); 
                    }
                    // ADDED: Handle NewTransaction messages
                    P2PMessage::NewTransaction(tx) => {
                        let mut bc_lock = bc.lock().await;
                        let txid = tx.id();
                        if !bc_lock.mempool.contains_key(&txid) {
                            // Basic validation could happen here, for now we just insert
                            info!("[MEMPOOL] Received new transaction: {}", txid);
                            bc_lock.mempool.insert(txid, tx.clone());
                            // Gossip to other peers
                            p2p_tx.send(P2PMessage::NewTransaction(tx)).ok();
                        }
                    }
                    _ => {}
                }
            }
            _ = shutdown_rx.recv() => break,
        }
    }
    Ok(())
}
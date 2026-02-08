// src/consensus.rs - Mining and Beaconing Loop with Robust Lock Handling

use crate::{
    block::{BeaconData, Beacon},
    blockchain::Blockchain, 
    config::NodeConfig, 
    p2p::P2PMessage, 
    transaction::{Transaction, TxOut}, 
    wallet::Wallet,
    crypto::{hash_pubkey, address_from_pubkey_hash},
    cdf::Color,
    pos,
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
                // 1. Gather Chain Statistics (Brief Lock)
                let (last_height, delta, psi, _last_block_time, mempool_len) = {
                    let bc_lock = bc.lock().await;
                    let tip_hash = bc_lock.tip;
                    let last_block = bc_lock.get_block(&tip_hash);
                    let l_height = last_block.as_ref().map(|b| b.height).unwrap_or(0);
                    let l_time = last_block.as_ref().map(|b| b.header.time).unwrap_or(0);
                    let now_ts = Utc::now().timestamp() as u32;
                    let d = now_ts.saturating_sub(l_time);
                    let p = bc_lock.ldd_state.current_psi;
                    let m_len = bc_lock.mempool.len();
                    (l_height, d, p, l_time, m_len)
                };

                // Heartbeat Logging for ALL modes (Miner and Staker)
                let now_u32 = Utc::now().timestamp() as u32;
                if now_u32 > last_slot_log {
                    info!("[SLOT] Time: {} | Height: {} | Delta: {}s / {}s (Psi) | Mempool: {}", 
                        now_u32, last_height, delta, psi, mempool_len);
                    last_slot_log = now_u32;
                }

                // 2. PoW Mining Logic
                if mode == "miner" || mode == "full" {
                    if delta >= psi {
                        let mut bc_lock = bc.lock().await;
                        let reward = bc_lock.consensus_params.coinbase_reward;
                        let coinbase = Transaction::new_coinbase(
                            "Mined by Synergeia".to_string(),
                            wallet.get_address(),
                            reward,
                            bc_lock.consensus_params.transaction_version
                        );
                        
                        let mut txs = vec![coinbase];
                        txs.extend(bc_lock.get_mempool_txs());

                        if let Ok(mut block) = bc_lock.create_block_template(txs, 1) {
                            let beacons = block.beacons.clone();
                            apply_beacon_rewards(&mut block, reward, &beacons);
                            let target = bc_lock.get_next_pow_target(delta);
                            // Short PoW attempt
                            for _ in 0..2000 {
                                if BigUint::from_bytes_be(block.header.hash().as_ref()) <= target {
                                    let hash = block.header.hash();
                                    if bc_lock.add_block(block.clone()).is_ok() {
                                        info!("[MINED] Block {} (Hash: {}..) - Broadcasted", 
                                            block.height, 
                                            hash.to_string().get(0..8).unwrap_or(""));
                                        let _ = p2p_tx.send(P2PMessage::NewBlock(Box::new(block)));
                                    }
                                    break;
                                }
                                block.header.nonce += 1;
                            }
                        }
                    }
                }

                // 3. PoS Staking Logic
                if mode == "staker" || mode == "full" {
                    let now_u64 = Utc::now().timestamp() as u64;
                    let mut bc_lock = bc.lock().await;
                    if let Some((proof, delta_pos)) = pos::is_eligible_to_stake(&wallet, &bc_lock, now_u64) {
                        match pos::create_pos_block(&mut bc_lock, &wallet, proof, delta_pos as u32, now_u32) {
                            Ok(block) => {
                                let hash = block.header.hash();
                                let height = block.height;
                                if bc_lock.add_block(block.clone()).is_ok() {
                                    info!("[MINED POS] Block {} (Hash: {}..) - Validator: {}", 
                                        height, 
                                        hash.to_string().get(0..8).unwrap_or(""), 
                                        wallet.get_address());
                                    let _ = p2p_tx.send(P2PMessage::NewBlock(Box::new(block)));
                                }
                            }
                            Err(e) => warn!("Failed to construct PoS block: {}", e),
                        }
                    }
                }
            }
            _ = beacon_timer.tick() => {
                let mut bc_lock = bc.lock().await;
                let metrics = bc_lock.get_and_reset_metrics();
                if let Ok(b) = wallet.sign_beacon(BeaconData::Time(Utc::now().timestamp() as u64)) { 
                    let _ = p2p_tx.send(P2PMessage::Beacon(b)); 
                }
                if let Ok(b) = wallet.sign_beacon(BeaconData::Security(metrics.orphan_count, metrics.max_reorg_depth)) { 
                    let _ = p2p_tx.send(P2PMessage::Beacon(b)); 
                }
            }
            _ = cdf_timer.tick() => {
                let bc_lock = bc.lock().await;
                if bc_lock.finality_gadget.active && !bc_lock.finality_gadget.finalized {
                    if let Some(target) = bc_lock.finality_gadget.target_checkpoint {
                        let color = match wallet.public_key.serialize()[0] % 3 { 0 => Color::Red, 1 => Color::Green, _ => Color::Blue };
                        if let Ok(vote) = wallet.sign_finality_vote(target, color) { 
                            let _ = p2p_tx.send(P2PMessage::FinalityVote(vote)); 
                        }
                    }
                }
            }
            // CRITICAL FIX: The loop was sometimes selecting sleep over receiver. 
            // We prioritize the message receiver to ensure blocks are never dropped.
            Some(msg) = p2p_rx.recv() => {
                match msg {
                    P2PMessage::NewBlock(block) => { 
                        let mut bc_lock = bc.lock().await;
                        let block_hash = block.header.hash();
                        
                        if bc_lock.blocks_tree.contains_key(block_hash.as_ref() as &[u8]).unwrap_or(false) {
                            continue;
                        }
                        
                        let old_work = bc_lock.total_work;
                        let block_height = block.height;

                        match bc_lock.add_block(*block.clone()) {
                            Ok(_) => {
                                // SYNC LOGIC: Relaying blocks that extend total work ensures the entire network catches up.
                                if bc_lock.total_work > old_work {
                                    info!("[PEER] Ingested Block {} (Hash: {}..) - Relaying", block_height, block_hash.to_string().get(0..8).unwrap_or(""));
                                    let _ = p2p_tx.send(P2PMessage::NewBlock(block));
                                } else {
                                    debug!("[PEER] Processed side-chain block {} at height {}", block_hash.to_string().get(0..8).unwrap_or(""), block_height);
                                }
                            },
                            Err(e) => {
                                // If it's an orphan block, add_block returns an error. 
                                // We keep the debug log to see if synchronization is failing due to missing parents.
                                debug!("[SYNC] Block {} rejected: {}", block_height, e);
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
                    P2PMessage::NewTransaction(tx) => {
                        let mut bc_lock = bc.lock().await; 
                        let txid = tx.id();
                        if !bc_lock.mempool.contains_key(&txid) {
                            bc_lock.mempool.insert(txid, tx.clone());
                            let _ = p2p_tx.send(P2PMessage::NewTransaction(tx));
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
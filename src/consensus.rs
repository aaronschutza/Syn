// src/consensus.rs
use crate::{
    block::{Block, BlockHeader, Beacon, BeaconData},
    blockchain::Blockchain, 
    config::NodeConfig, 
    p2p::P2PMessage, 
    transaction::{Transaction, TxOut}, 
    wallet::Wallet,
    pos,
    cdf::Color, 
    crypto::{hash_pubkey, address_from_pubkey_hash},
};
use anyhow::Result;
use bitcoin_hashes::{sha256d, Hash};
use chrono::Utc;
use log::{info, warn, debug};
use num_bigint::BigUint;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, mpsc, Mutex};
use secp256k1::PublicKey;

const BEACON_REWARD_PERCENT: u64 = 1; // 1% of block reward per beacon

/// Helper to distribute rewards to beacon providers in the coinbase transaction.
fn apply_beacon_rewards(
    block: &mut Block, 
    total_reward: u64, 
    beacons: &[Beacon]
) {
    if beacons.is_empty() { return; }

    let reward_per_beacon = total_reward / 100 * BEACON_REWARD_PERCENT;
    let total_beacon_payout = reward_per_beacon * beacons.len() as u64;

    if let Some(coinbase) = block.transactions.get_mut(0) {
        // Assume vout[0] is the miner/staker reward output
        if coinbase.vout.is_empty() { return; }
        
        // Deduct from miner reward (ensure no underflow)
        if coinbase.vout[0].value >= total_beacon_payout {
            coinbase.vout[0].value -= total_beacon_payout;
        } else {
            // Reward too small (e.g. mostly fees burnt or tiny subsidy). 
            // Skip bounties to preserve safety.
            return;
        }

        // Add outputs for beacon providers
        for beacon in beacons {
            if let Ok(pk) = PublicKey::from_slice(&beacon.public_key) {
                let addr = address_from_pubkey_hash(&hash_pubkey(&pk));
                coinbase.vout.push(TxOut::new(reward_per_beacon, addr));
            }
        }
    }
}

pub async fn start_consensus_loop(
    bc: Arc<Mutex<Blockchain>>,
    mode: String,
    mine_to_address: Option<String>,
    mut p2p_rx: mpsc::Receiver<P2PMessage>,
    p2p_tx: broadcast::Sender<P2PMessage>,
    node_config: Arc<NodeConfig>,
    mut shutdown_rx: broadcast::Receiver<()>,
) -> Result<()> {
    info!("Starting consensus loop in {} mode.", mode);
    let wallet = Wallet::load_from_file(&node_config)?;
    let mining_wallet = wallet.clone();
    let staking_wallet = wallet.clone();
    let beacon_wallet = wallet.clone();
    let cdf_wallet = wallet.clone();

    // --- 1. Mining Task (PoW) ---
    let _mining_handle = { 
        let bc = Arc::clone(&bc);
        let mode = mode.clone();
        let p2p_tx = p2p_tx.clone();
        
        tokio::spawn(async move {
            if mode != "miner" && mode != "full" { return; }
            info!("Minining task started.");

            loop {
                tokio::time::sleep(Duration::from_millis(100)).await; 

                // 1. Get Mining Template
                let (original_tip_hash, _last_block_time, block_version, difficulty_bits, height, coinbase_reward, tx_version) = {
                    let bc_lock = bc.lock().await;
                    let tip = bc_lock.tip;
                    let last_block = match bc_lock.get_block(&tip) {
                        Some(b) => b,
                        None => { continue; } 
                    };
                    
                    let current_time = Utc::now().timestamp() as u32;
                    let delta = current_time.saturating_sub(last_block.header.time);
                    let bits = bc_lock.get_next_work_required(true, delta);
                    
                    (
                        tip, 
                        last_block.header.time, 
                        bc_lock.consensus_params.block_version, 
                        bits, 
                        last_block.height + 1,
                        bc_lock.consensus_params.coinbase_reward,
                        bc_lock.consensus_params.transaction_version
                    )
                };

                let addr = mine_to_address.clone().unwrap_or_else(|| mining_wallet.get_address());
                let target = BlockHeader::calculate_target(difficulty_bits);
                let mut nonce: u32 = 0;

                // 2. Mining Inner Loop
                let start_mining = std::time::Instant::now();
                while start_mining.elapsed() < Duration::from_secs(1) {
                    let current_timestamp = Utc::now().timestamp() as u32;
                    
                    // Build Block for Hashing
                    // Note: We perform this INSIDE the loop or logic to ensure the Header matches the Body.
                    let (header, final_txs, beacons) = {
                        let bc_lock = bc.lock().await;
                        if bc_lock.tip != original_tip_hash { break; } 

                        // Peek mempool transactions without clearing
                        let mempool_txs: Vec<Transaction> = bc_lock.mempool.values().cloned().collect();
                        
                        let mut final_txs = vec![Transaction::new_coinbase(
                            "Mined by Synergeia".to_string(), 
                            addr.clone(), 
                            coinbase_reward, 
                            tx_version
                        )];
                        final_txs.extend(mempool_txs.into_iter().filter(|tx| !tx.is_coinbase()));
                        
                        let beacons = bc_lock.beacon_mempool.clone();

                        // Create a temporary block to apply rewards and calc root
                        let mut temp_block = Block::new(current_timestamp, final_txs, original_tip_hash, difficulty_bits, height, block_version);
                        
                        // Apply Beacon Rewards (modifies coinbase in temp_block.transactions)
                        apply_beacon_rewards(&mut temp_block, coinbase_reward, &beacons);
                        
                        // Recompute Merkle Root with modified coinbase
                        let merkle_root = Block::compute_merkle_root(&temp_block.transactions);
                        let utxo_root = bc_lock.calculate_utxo_root().unwrap_or(sha256d::Hash::all_zeros());
                        
                        let header = BlockHeader {
                            version: block_version,
                            prev_blockhash: original_tip_hash,
                            merkle_root,
                            utxo_root,
                            time: current_timestamp,
                            bits: difficulty_bits,
                            nonce,
                            vrf_proof: None,
                        };
                        
                        (header, temp_block.transactions, beacons)
                    };

                    let hash_biguint = BigUint::from_bytes_be(header.hash().as_ref());
                    if hash_biguint <= target {
                        info!("🔨 PoW block found! Hash: {}", header.hash());
                        
                        let mut bc_lock = bc.lock().await;
                        // Construct final block with the found nonce
                        let mut block = Block::new(header.time, final_txs, header.prev_blockhash, header.bits, height, header.version);
                        block.header = header;
                        block.beacons = beacons;
                        
                        // Clear mempools now that block is finalized
                        bc_lock.mempool.clear();
                        bc_lock.beacon_mempool.clear();

                        if let Err(e) = bc_lock.add_block(block.clone()) {
                            warn!("Mined block rejected: {}", e);
                        } else {
                            info!("Broadcasting PoW block {}", block.header.hash());
                            p2p_tx.send(P2PMessage::NewBlock(Box::new(block))).ok();
                        }
                        break; 
                    }
                    
                    nonce = nonce.wrapping_add(1);
                }
            }
        })
    };

    // --- 2. Staking Task (PoS) ---
    let _staking_handle = { 
        let bc = Arc::clone(&bc);
        let wallet = staking_wallet;
        let mode = mode.clone();
        let p2p_tx = p2p_tx.clone();

        tokio::spawn(async move {
            if mode != "staker" && mode != "full" { return; }
            if wallet.stake_info.is_none() { 
                warn!("Staking mode enabled but wallet has no stake info.");
                return; 
            }
            info!("Staking task started.");

            loop {
                tokio::time::sleep(Duration::from_secs(1)).await;

                let (tip_hash, last_block_time, coinbase_reward) = {
                    let bc_lock = bc.lock().await;
                    let last = bc_lock.get_block(&bc_lock.tip);
                    if last.is_none() { continue; }
                    (bc_lock.tip, last.unwrap().header.time, bc_lock.consensus_params.coinbase_reward)
                };

                let current_time = Utc::now().timestamp() as u32;
                
                if current_time <= last_block_time { continue; }

                let bc_lock = bc.lock().await;
                if bc_lock.tip != tip_hash { continue; } 

                if let Some((vrf_proof, delta)) = pos::is_eligible_to_stake(&wallet, &bc_lock, current_time as u64) {
                    info!("✨ Eligible to stake at time {} (delta {})", current_time, delta);
                    
                    drop(bc_lock); 
                    let mut bc_lock = bc.lock().await;
                    
                    match pos::create_pos_block(&mut bc_lock, &wallet, vrf_proof, delta as u32, current_time) {
                        Ok(mut block) => {
                            let beacons = bc_lock.beacon_mempool.clone();
                            
                            // Apply Beacon Rewards
                            apply_beacon_rewards(&mut block, coinbase_reward, &beacons);

                            // Set beacons
                            block.beacons = beacons;
                            
                            // Clear beacon mempool (assuming all included)
                            bc_lock.beacon_mempool.clear();

                            // Recompute Merkle Root (since coinbase changed)
                            block.header.merkle_root = Block::compute_merkle_root(&block.transactions);

                            if let Err(e) = bc_lock.add_block(block.clone()) {
                                warn!("Staked block rejected: {}", e);
                            } else {
                                info!("Broadcasting PoS block {}", block.header.hash());
                                p2p_tx.send(P2PMessage::NewBlock(Box::new(block))).ok();
                            }
                        },
                        Err(e) => warn!("Failed to create PoS block: {}", e),
                    }
                }
            }
        })
    };

    // --- 3. Beacon Generation Task (DCS) ---
    let _beacon_handle = { 
        let bc = Arc::clone(&bc);
        let wallet = beacon_wallet;
        let p2p_tx = p2p_tx.clone();
        
        tokio::spawn(async move {
            let interval = 30; // Default 30s
            loop {
                tokio::time::sleep(Duration::from_secs(interval)).await;
                
                // Collect metrics from Blockchain state
                let (metrics, load, branching, total_stake) = {
                    let mut bc = bc.lock().await;
                    (
                        bc.get_and_reset_metrics(),
                        bc.get_mempool_load(),
                        bc.get_branching_factor(),
                        bc.total_staked
                    )
                };

                // 1. Time Beacon
                let time_data = BeaconData::Time(Utc::now().timestamp() as u64);
                if let Ok(beacon) = wallet.sign_beacon(time_data) {
                    p2p_tx.send(P2PMessage::Beacon(beacon)).ok();
                }

                // 2. Stake Beacon
                let stake_data = BeaconData::Stake(total_stake);
                if let Ok(beacon) = wallet.sign_beacon(stake_data) {
                    p2p_tx.send(P2PMessage::Beacon(beacon)).ok();
                }

                // 3. Load Beacon
                let load_data = BeaconData::Load(load); 
                if let Ok(beacon) = wallet.sign_beacon(load_data) {
                    p2p_tx.send(P2PMessage::Beacon(beacon)).ok();
                }

                // 4. Delay Beacon
                let delay_data = BeaconData::Delay(metrics.last_delay_ms); 
                if let Ok(beacon) = wallet.sign_beacon(delay_data) {
                    p2p_tx.send(P2PMessage::Beacon(beacon)).ok();
                }

                // 5. Security Beacon (Orphans & Reorgs)
                let security_data = BeaconData::Security(metrics.orphan_count, metrics.max_reorg_depth);
                if let Ok(beacon) = wallet.sign_beacon(security_data) {
                    p2p_tx.send(P2PMessage::Beacon(beacon)).ok();
                }

                // 6. Topology Beacon (Branching Factor)
                let topo_data = BeaconData::Topology(branching, 0); // max_orphan_chain_length placeholder
                if let Ok(beacon) = wallet.sign_beacon(topo_data) {
                    p2p_tx.send(P2PMessage::Beacon(beacon)).ok();
                }
            }
        })
    };

    // --- 4. CDF Finality Task ---
    let _cdf_handle = { 
        let bc = Arc::clone(&bc);
        let wallet = cdf_wallet;
        let p2p_tx = p2p_tx.clone();

        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(5)).await;
                
                let vote_opt = {
                    let bc = bc.lock().await;
                    if bc.finality_gadget.active && !bc.finality_gadget.finalized {
                        if let Some(target) = bc.finality_gadget.target_checkpoint {
                            Some((target, Color::Red))
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                };

                if let Some((target, color)) = vote_opt {
                    if let Ok(vote) = wallet.sign_finality_vote(target, color) {
                        info!("Casting CDF Vote for {}", target);
                        p2p_tx.send(P2PMessage::FinalityVote(vote)).ok();
                    }
                }
            }
        })
    };

    // --- Main P2P Event Loop ---
    loop {
        tokio::select! {
            Some(msg) = p2p_rx.recv() => {
                let bc_lock = bc.lock().await; 
                drop(bc_lock); 
                
                let mut bc = bc.lock().await;
                match msg {
                    P2PMessage::NewBlock(block) => {
                        info!("Received new block {} from network.", block.header.hash());
                        if let Err(e) = bc.add_block(*block) {
                            warn!("Failed to add block from peer: {}", e);
                        }
                    }
                    P2PMessage::NewTransaction(tx) => {
                        if bc.verify_transaction(&tx).is_ok() {
                            bc.mempool.insert(tx.id(), tx);
                        }
                    }
                    P2PMessage::Beacon(beacon) => {
                        if let Err(e) = bc.receive_beacon(beacon) {
                            debug!("Beacon error: {}", e);
                        }
                    }
                    P2PMessage::FinalityVote(vote) => {
                        bc.process_finality_vote(vote);
                    }
                    P2PMessage::Version { best_height, .. } => {
                        let (our_height, is_empty) = if bc.tip == sha256d::Hash::all_zeros() {
                            (0, true)
                        } else {
                            (bc.get_block(&bc.tip).map_or(0, |b| b.height), false)
                        };
                        
                        if best_height > our_height || (best_height == our_height && is_empty) {
                            info!("Peer has a better chain. Requesting headers.");
                            p2p_tx.send(P2PMessage::GetHeaders).ok();
                        }
                    }
                    P2PMessage::Headers(headers) => {
                        if headers.len() > bc.headers.len() {
                           p2p_tx.send(P2PMessage::GetBlocks(headers.iter().map(|h| h.hash()).collect())).ok();
                        }
                    }
                    _ => {}
                }
            }
            _ = shutdown_rx.recv() => {
                info!("Consensus loop received shutdown signal.");
                break;
            }
        }
    }
    Ok(())
}
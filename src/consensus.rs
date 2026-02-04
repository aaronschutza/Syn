// src/consensus.rs - Redundancy cleanup and warning resolution

use crate::{
    block::{Block, BlockHeader, Beacon, BeaconData},
    blockchain::Blockchain, 
    config::NodeConfig, 
    p2p::P2PMessage, 
    transaction::{Transaction, TxOut}, 
    wallet::Wallet,
    crypto::{hash_pubkey, address_from_pubkey_hash},
    cdf::Color,
};
use anyhow::Result;
use chrono::Utc;
use log::{info, debug}; // Removed unused 'warn'
use num_bigint::BigUint;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, mpsc, Mutex};
use secp256k1::PublicKey;

const BEACON_REWARD_PERCENT: u64 = 1; 

/// Injects bounty rewards into the block template for all providers who 
/// contributed a valid beacon in this block.
fn apply_beacon_rewards(block: &mut Block, total_reward: u64, beacons: &[Beacon]) {
    if beacons.is_empty() { return; }
    
    // Designated bounty is 1% of the coinbase reward
    let total_bounty_pool = (total_reward * BEACON_REWARD_PERCENT) / 100;
    let reward_per_beacon = total_bounty_pool / beacons.len() as u64;
    
    if let Some(coinbase) = block.transactions.get_mut(0) {
        if coinbase.vout.is_empty() || reward_per_beacon == 0 { return; }
        
        // Subtract total bounty from miner's share
        if coinbase.vout[0].value >= total_bounty_pool {
            coinbase.vout[0].value -= total_bounty_pool;
        } else { return; }

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
    info!("Starting Synergeia Consensus Engine (Mode: {})", mode);
    let wallet = Wallet::load_from_file(&node_config)?;
    let mining_wallet = wallet.clone();
    
    // Heartbeat intervals
    let mut beacon_timer = tokio::time::interval(Duration::from_secs(30));
    let mut cdf_timer = tokio::time::interval(Duration::from_secs(10));

    loop {
        tokio::select! {
            // Block Production (Miner/Staker mode)
            _ = tokio::time::sleep(Duration::from_millis(200)) => {
                if mode == "miner" || mode == "full" {
                    let mut bc_lock = bc.lock().await;
                    let tip_hash = bc_lock.tip;
                    
                    if bc_lock.get_block(&tip_hash).is_some() {
                        // Create block template
                        let reward = bc_lock.consensus_params.coinbase_reward;
                        let addr = mine_to_address.clone().unwrap_or_else(|| mining_wallet.get_address());
                        let txs = vec![Transaction::new_coinbase("Synergistic Block".into(), addr, reward, 1)];
                        
                        if let Ok(mut block) = bc_lock.create_block_template(txs, 1) {
                            // Apply Beacon Bounties
                            let beacons_copy = block.beacons.clone();
                            apply_beacon_rewards(&mut block, reward, &beacons_copy);
                            
                            // Proof-of-Work Attempt (Limited window)
                            let target = BlockHeader::calculate_target(block.header.bits);
                            let start = std::time::Instant::now();
                            while start.elapsed() < Duration::from_millis(100) {
                                if BigUint::from_bytes_be(block.header.hash().as_ref()) <= target {
                                    if bc_lock.add_block(block.clone()).is_ok() {
                                        info!("Mined block at height {}!", block.height);
                                        p2p_tx.send(P2PMessage::NewBlock(Box::new(block))).ok();
                                    }
                                    break;
                                }
                                block.header.nonce += 1;
                            }
                        }
                    }
                }
            }
            
            // DCS Beacon Generation
            _ = beacon_timer.tick() => {
                let mut bc_lock = bc.lock().await;
                let metrics = bc_lock.get_and_reset_metrics();
                
                // Sign and broadcast Time and Security beacons
                if let Ok(b) = wallet.sign_beacon(BeaconData::Time(Utc::now().timestamp() as u64)) {
                    p2p_tx.send(P2PMessage::Beacon(b)).ok();
                }
                if let Ok(b) = wallet.sign_beacon(BeaconData::Security(metrics.orphan_count, metrics.max_reorg_depth)) {
                    p2p_tx.send(P2PMessage::Beacon(b)).ok();
                }
            }

            // Chromo-Dynamic Finality (CDF) Voting
            _ = cdf_timer.tick() => {
                let bc_lock = bc.lock().await;
                if bc_lock.finality_gadget.active && !bc_lock.finality_gadget.finalized {
                    if let Some(target) = bc_lock.finality_gadget.target_checkpoint {
                        // Deterministically assign color based on stake key
                        let color_val = (wallet.public_key.serialize()[0] % 3) as u8;
                        let color = match color_val {
                            0 => Color::Red,
                            1 => Color::Green,
                            _ => Color::Blue,
                        };

                        if let Ok(vote) = wallet.sign_finality_vote(target, color) {
                            debug!("Broadcasting CDF Finality Vote for checkpoint {}", target);
                            p2p_tx.send(P2PMessage::FinalityVote(vote)).ok();
                        }
                    }
                }
            }

            // Message Handling
            Some(msg) = p2p_rx.recv() => {
                let mut bc_lock = bc.lock().await;
                match msg {
                    P2PMessage::NewBlock(block) => { bc_lock.add_block(*block).ok(); }
                    P2PMessage::Beacon(beacon) => { bc_lock.receive_beacon(beacon).ok(); }
                    P2PMessage::FinalityVote(vote) => { bc_lock.process_finality_vote(vote); }
                    _ => {}
                }
            }

            _ = shutdown_rx.recv() => break,
        }
    }
    Ok(())
}
// src/consensus.rs - Fix borrow error and telemetry scaling

use crate::{
    block::{Block, BlockHeader, Beacon, BeaconData},
    blockchain::Blockchain, 
    config::NodeConfig, 
    p2p::P2PMessage, 
    transaction::{Transaction, TxOut}, 
    wallet::Wallet,
    crypto::{hash_pubkey, address_from_pubkey_hash},
};
use anyhow::Result;
use chrono::Utc;
use log::info;
use num_bigint::BigUint;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, mpsc, Mutex};
use secp256k1::PublicKey;

const BEACON_REWARD_PERCENT: u64 = 1; 

fn apply_beacon_rewards(block: &mut Block, total_reward: u64, beacons: &[Beacon]) {
    if beacons.is_empty() { return; }
    let reward_per_beacon = total_reward / 100 * BEACON_REWARD_PERCENT;
    let total_beacon_payout = reward_per_beacon * beacons.len() as u64;
    if let Some(coinbase) = block.transactions.get_mut(0) {
        if coinbase.vout.is_empty() { return; }
        if coinbase.vout[0].value >= total_beacon_payout {
            coinbase.vout[0].value -= total_beacon_payout;
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
    info!("Starting consensus loop in {} mode.", mode);
    let wallet = Wallet::load_from_file(&node_config)?;
    let mining_wallet = wallet.clone();
    let beacon_wallet = wallet.clone();

    loop {
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_millis(100)) => {
                if mode == "miner" || mode == "full" {
                    let mut bc_lock = bc.lock().await;
                    let tip = bc_lock.tip;
                    if let Some(last_block) = bc_lock.get_block(&tip) {
                        let now = Utc::now().timestamp() as u32;
                        let delta = now.saturating_sub(last_block.header.time);
                        let bits = bc_lock.get_next_work_required(true, delta);
                        let reward = bc_lock.consensus_params.coinbase_reward;
                        let addr = mine_to_address.clone().unwrap_or_else(|| mining_wallet.get_address());
                        let target = BlockHeader::calculate_target(bits);
                        
                        let txs = vec![Transaction::new_coinbase("Mined".into(), addr, reward, 1)];
                        if let Ok(mut block) = bc_lock.create_block_template(txs, 1) {
                            // Extract beacons to avoid double-borrow of block
                            let beacons = block.beacons.clone();
                            apply_beacon_rewards(&mut block, reward, &beacons);
                            
                            let mut nonce = 0;
                            let start = std::time::Instant::now();
                            while start.elapsed() < Duration::from_millis(50) {
                                block.header.nonce = nonce;
                                if BigUint::from_bytes_be(block.header.hash().as_ref()) <= target {
                                    if bc_lock.add_block(block.clone()).is_ok() {
                                        p2p_tx.send(P2PMessage::NewBlock(Box::new(block))).ok();
                                    }
                                    break;
                                }
                                nonce += 1;
                            }
                        }
                    }
                }
            }
            
            _ = tokio::time::sleep(Duration::from_secs(30)) => {
                let mut bc_lock = bc.lock().await;
                let metrics = bc_lock.get_and_reset_metrics();
                let load = (bc_lock.get_mempool_load() * 1_000_000.0) as u64;
                let branch = (bc_lock.get_branching_factor() * 1_000_000.0) as u64;
                
                if let Ok(b) = beacon_wallet.sign_beacon(BeaconData::Time(Utc::now().timestamp() as u64)) { p2p_tx.send(P2PMessage::Beacon(b)).ok(); }
                if let Ok(b) = beacon_wallet.sign_beacon(BeaconData::Stake(bc_lock.total_staked)) { p2p_tx.send(P2PMessage::Beacon(b)).ok(); }
                if let Ok(b) = beacon_wallet.sign_beacon(BeaconData::Load(load)) { p2p_tx.send(P2PMessage::Beacon(b)).ok(); }
                if let Ok(b) = beacon_wallet.sign_beacon(BeaconData::Topology(branch, 0)) { p2p_tx.send(P2PMessage::Beacon(b)).ok(); }
                if let Ok(b) = beacon_wallet.sign_beacon(BeaconData::Security(metrics.orphan_count, metrics.max_reorg_depth)) { p2p_tx.send(P2PMessage::Beacon(b)).ok(); }
            }

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
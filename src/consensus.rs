// src/consensus.rs
use crate::{
    block::{Block, BlockHeader}, blockchain::Blockchain, config::NodeConfig, p2p::P2PMessage, transaction::Transaction, wallet::Wallet,
};
use anyhow::Result;
use bitcoin_hashes::{sha256d, Hash};
use chrono::Utc;
use log::{info, warn};
use num_bigint::BigUint;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, mpsc, Mutex};

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

    let mining_handle = {
        let mining_task_bc = Arc::clone(&bc);
        let mining_task_wallet = wallet.clone();
        let mining_task_mode = mode.clone();
        let broadcast_tx_clone = p2p_tx.clone();
        
        tokio::spawn(async move {
            if mining_task_mode != "miner" {
                return;
            }

            loop {
                tokio::time::sleep(Duration::from_secs(1)).await; 

                let (original_tip_hash, last_block_time, block_version) = {
                    let bc_lock = mining_task_bc.lock().await;
                    let tip = bc_lock.tip;
                    let last_block = match bc_lock.get_block(&tip) {
                        Some(b) => b,
                        None => {
                            warn!("Could not get tip block to start mining. Retrying...");
                            continue;
                        }
                    };
                    (tip, last_block.header.time, bc_lock.consensus_params.block_version)
                };

                let addr = mine_to_address.clone().unwrap_or_else(|| mining_task_wallet.get_address());

                let mut nonce: u32 = 0;

                loop {
                    tokio::time::sleep(Duration::from_millis(100)).await;

                    let current_timestamp = Utc::now().timestamp() as u32;
                    let delta = current_timestamp.saturating_sub(last_block_time);

                    let current_tip = mining_task_bc.lock().await.tip;
                    if current_tip != original_tip_hash {
                        info!("New block received from network, abandoning current PoW work.");
                        break;
                    }

                    let bits = {
                        let bc_lock = mining_task_bc.lock().await;
                        bc_lock.get_next_work_required(true, delta)
                    };
                    let target = BlockHeader::calculate_target(bits);
                    
                    let mut header = {
                        let bc_lock = mining_task_bc.lock().await;
                        let txs: Vec<Transaction> = bc_lock.mempool.values().cloned().collect();
                        let merkle_root = Block::compute_merkle_root(&txs);
                        BlockHeader {
                            version: block_version,
                            prev_blockhash: original_tip_hash,
                            merkle_root,
                            utxo_root: bc_lock.calculate_utxo_root().unwrap_or(sha256d::Hash::all_zeros()),
                            time: current_timestamp,
                            bits,
                            nonce,
                            vrf_proof: None,
                        }
                    };

                    const HASHES_PER_SLOT: u32 = 500_000;
                    for _ in 0..HASHES_PER_SLOT {
                        let hash_biguint = BigUint::from_bytes_be(header.hash().as_ref());
                        if hash_biguint <= target {
                            info!("PoW block found! Hash: {}", header.hash());
                            let mut bc_lock = mining_task_bc.lock().await;
                            
                            let height = match bc_lock.get_block(&header.prev_blockhash) {
                                Some(prev_block) => prev_block.height + 1,
                                None => {
                                    warn!("Previous block not found when creating mined block. Abandoning.");
                                    break;
                                }
                            };

                            let mut mempool_txs = bc_lock.get_mempool_txs();
                            mempool_txs.retain(|tx| !tx.is_coinbase());

                            let mut final_txs = vec![Transaction::new_coinbase("Mined by Synergeia".to_string(), addr.clone(), bc_lock.consensus_params.coinbase_reward, bc_lock.consensus_params.transaction_version)];
                            final_txs.extend(mempool_txs);
                            
                            let mut block = Block::new(header.time, final_txs, header.prev_blockhash, header.bits, height, header.version);
                            block.header = header;

                            if let Err(e) = bc_lock.add_block(block.clone()) {
                                warn!("Mined block was invalid and rejected: {}", e);
                            } else {
                                info!("Broadcasting new PoW block {} to peers.", block.header.hash());
                                broadcast_tx_clone.send(P2PMessage::NewBlock(Box::new(block))).ok();
                            }
                            break; 
                        }
                        header.nonce = header.nonce.wrapping_add(1);
                        nonce = header.nonce;
                    }
                }
            }
        })
    };
    
    loop {
        tokio::select! {
            Some(msg) = p2p_rx.recv() => {
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
                    P2PMessage::Version { best_height, .. } => {
                        let (our_height, is_empty) = if bc.tip == sha256d::Hash::all_zeros() {
                            (0, true)
                        } else {
                            (bc.get_block(&bc.tip).map_or(0, |b| b.height), false)
                        };
                        
                        if best_height > our_height || (best_height == our_height && is_empty) {
                            info!("Peer has a better chain (height {} vs our {}). Requesting headers.", best_height, our_height);
                            p2p_tx.send(P2PMessage::GetHeaders).ok();
                        } else {
                            info!("Already synced with peer.");
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
                mining_handle.abort();
                break;
            }
        }
    }
    Ok(())
}

// src/p2p.rs - Optimized Block Propagation (Compact Blocks) and Peer Management

use crate::config::{ConsensusConfig, NodeConfig, P2PConfig};
use crate::{
    blockchain::Blockchain, 
    peer_manager::PeerManager,
    block::{Block, BlockHeader, Beacon},
    cdf::FinalityVote,
};
use anyhow::Result;
use bitcoin_hashes::sha256d; // FIX: Removed unused Hash import
use log::{info, warn, debug, error};
use serde::{Serialize, Deserialize};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream}; // FIX: Added missing opening brace
use tokio::sync::{broadcast, mpsc, Mutex};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum P2PMessage {
    NewBlock(Box<Block>),
    /// Compact Block Announcement: header and short IDs (hashes) of transactions.
    CompactBlockAnnouncement {
        header: BlockHeader,
        txids: Vec<sha256d::Hash>,
    },
    /// Request for specific missing transactions within a compact block.
    BlockTransactionsRequest {
        block_hash: sha256d::Hash,
        indexes: Vec<usize>,
    },
    /// Response providing the requested missing transactions.
    BlockTransactions {
        block_hash: sha256d::Hash,
        transactions: Vec<crate::transaction::Transaction>,
    },
    /// Request for full block data (fallback).
    GetBlockData(sha256d::Hash),
    NewTransaction(crate::transaction::Transaction),
    Beacon(Beacon),
    FinalityVote(FinalityVote),
    Version { version: u32, best_height: u32 },
    GetHeaders,
    Headers(Vec<BlockHeader>),
    GetBlocks(Vec<sha256d::Hash>),
    Veto(sha256d::Hash, Vec<u8>, Vec<u8>),
}

pub async fn start_server(
    blockchain: Arc<Mutex<Blockchain>>,
    to_consensus_tx: mpsc::Sender<P2PMessage>,
    broadcast_tx: broadcast::Sender<P2PMessage>,
    peer_manager: Arc<Mutex<PeerManager>>,
    p2p_config: Arc<P2PConfig>,
    node_config: Arc<NodeConfig>,
    consensus_config: Arc<ConsensusConfig>,
    mut shutdown_rx: broadcast::Receiver<()>,
) -> Result<()> {
    let listener_addr = format!("0.0.0.0:{}", node_config.p2p_port);
    let listener = TcpListener::bind(&listener_addr).await?;
    info!("Synergeia P2P server listening on {}", listener_addr);

    tokio::spawn(start_client(
        blockchain.clone(), to_consensus_tx.clone(), broadcast_tx.clone(),
        peer_manager.clone(), consensus_config.clone(), p2p_config.clone(),
    ));

    loop {
        tokio::select! {
            res = listener.accept() => {
                match res {
                    Ok((socket, addr)) => {
                        if peer_manager.lock().await.is_banned(&addr) {
                            debug!("Rejecting connection from banned peer {}", addr);
                            continue;
                        }
                        info!("Accepted connection from {}", addr);
                        peer_manager.lock().await.on_connect(addr, false);
                        tokio::spawn(handle_connection(
                            socket, addr, blockchain.clone(), to_consensus_tx.clone(),
                            broadcast_tx.subscribe(), peer_manager.clone(), p2p_config.clone(),
                        ));
                    }
                    Err(e) => error!("Listener error: {}", e),
                }
            }
            _ = shutdown_rx.recv() => break,
        }
    }
    Ok(())
}

async fn start_client(
    blockchain: Arc<Mutex<Blockchain>>,
    to_consensus_tx: mpsc::Sender<P2PMessage>,
    broadcast_tx: broadcast::Sender<P2PMessage>,
    peer_manager: Arc<Mutex<PeerManager>>,
    consensus_config: Arc<ConsensusConfig>,
    p2p_config: Arc<P2PConfig>,
) {
    loop {
        let needs_peers = peer_manager.lock().await.needs_outbound();
        if needs_peers {
            for node_addr_str in &consensus_config.bootstrap_nodes {
                if let Ok(node_addr) = node_addr_str.parse::<SocketAddr>() {
                    if peer_manager.lock().await.is_banned(&node_addr) { continue; }
                    if let Ok(socket) = TcpStream::connect(node_addr).await {
                        info!("Connected to bootstrap peer: {}", node_addr);
                        peer_manager.lock().await.on_connect(node_addr, true);
                        tokio::spawn(handle_connection(
                            socket, node_addr, blockchain.clone(), to_consensus_tx.clone(),
                            broadcast_tx.subscribe(), peer_manager.clone(), p2p_config.clone(),
                        ));
                    }
                }
            }
        }
        tokio::time::sleep(std::time::Duration::from_secs(p2p_config.reconnect_delay_secs)).await;
    }
}

async fn handle_connection(
    socket: TcpStream,
    addr: SocketAddr,
    blockchain: Arc<Mutex<Blockchain>>,
    to_consensus_tx: mpsc::Sender<P2PMessage>,
    mut broadcast_rx: broadcast::Receiver<P2PMessage>,
    peer_manager: Arc<Mutex<PeerManager>>,
    p2p_config: Arc<P2PConfig>,
) {
    let (mut reader, mut writer) = tokio::io::split(socket);
    let (peer_tx, mut peer_rx) = mpsc::channel::<P2PMessage>(20);

    // Track pending compact block reconstructions
    let mut pending_compact_blocks: std::collections::HashMap<sha256d::Hash, (BlockHeader, Vec<sha256d::Hash>)> = std::collections::HashMap::new();

    // Initial Version Exchange
    let our_height = blockchain.lock().await.headers.last().map(|h| h.time).unwrap_or(0);
    let version_msg = P2PMessage::Version { version: p2p_config.protocol_version, best_height: our_height as u32 };
    if let Ok(s) = bincode::serialize(&version_msg) {
        let _ = writer.write_all(&(s.len() as u32).to_be_bytes()).await;
        let _ = writer.write_all(&s).await;
    }

    let write_task = tokio::spawn(async move {
        loop {
            let msg_result = tokio::select! {
                res = broadcast_rx.recv() => res.map_err(|_| ()),
                res = peer_rx.recv() => res.ok_or(()),
            };

            match msg_result {
                Ok(msg) => {
                    if let Ok(s) = bincode::serialize(&msg) {
                        let _ = writer.write_all(&(s.len() as u32).to_be_bytes()).await;
                        if writer.write_all(&s).await.is_err() { break; }
                    }
                }
                Err(_) => break,
            }
        }
    });

    let pm_read_clone = peer_manager.clone();
    let bc_read_clone = blockchain.clone();
    let p2p_cfg_read = p2p_config.clone();

    let read_task = tokio::spawn(async move {
        loop {
            let mut size_buf = [0u8; 4];
            if reader.read_exact(&mut size_buf).await.is_err() { break; }
            let size = u32::from_be_bytes(size_buf) as usize;
            if size > p2p_cfg_read.max_message_size {
                pm_read_clone.lock().await.report_misbehavior(addr, 100);
                break;
            }

            let mut buf = vec![0; size];
            if reader.read_exact(&mut buf).await.is_err() { break; }

            if let Ok(msg) = bincode::deserialize::<P2PMessage>(&buf) {
                match msg {
                    P2PMessage::CompactBlockAnnouncement { header, txids } => {
                        let block_hash = header.hash();
                        let mut bc = bc_read_clone.lock().await;
                        
                        if bc.get_block(&block_hash).is_none() {
                            // Attempt reconstruction from local mempool
                            let mut reconstructed_txs = Vec::new();
                            let mut missing_indexes = Vec::new();

                            for (i, txid) in txids.iter().enumerate() {
                                if let Some(tx) = bc.mempool.get(txid) {
                                    reconstructed_txs.push(tx.clone());
                                } else {
                                    missing_indexes.push(i);
                                }
                            }

                            if missing_indexes.is_empty() {
                                debug!("Successfully reconstructed block {} from mempool.", block_hash);
                                // Removed unnecessary mut from block
                                let block = Block {
                                    header, height: 0, // Height will be corrected in add_block
                                    transactions: reconstructed_txs,
                                    synergistic_work: 0, total_work: 0,
                                    beacons: Vec::new(),
                                };
                                if bc.add_block(block).is_ok() {
                                    pm_read_clone.lock().await.reward_peer(&addr, 5);
                                }
                            } else {
                                debug!("Block {} missing {} transactions. Requesting...", block_hash, missing_indexes.len());
                                pending_compact_blocks.insert(block_hash, (header, txids));
                                let _ = peer_tx.send(P2PMessage::BlockTransactionsRequest {
                                    block_hash,
                                    indexes: missing_indexes,
                                }).await;
                            }
                        }
                    }

                    P2PMessage::BlockTransactionsRequest { block_hash, indexes } => {
                        if let Some(block) = bc_read_clone.lock().await.get_block(&block_hash) {
                            let mut response_txs = Vec::new();
                            for idx in indexes {
                                if let Some(tx) = block.transactions.get(idx) {
                                    response_txs.push(tx.clone());
                                }
                            }
                            let _ = peer_tx.send(P2PMessage::BlockTransactions {
                                block_hash,
                                transactions: response_txs,
                            }).await;
                        }
                    }

                    P2PMessage::BlockTransactions { block_hash, transactions } => {
                        if let Some((header, txids)) = pending_compact_blocks.remove(&block_hash) {
                            let mut bc = bc_read_clone.lock().await;
                            let mut full_txs = Vec::new();
                            // Removed unnecessary mut from tx_pool
                            let tx_pool: std::collections::HashMap<sha256d::Hash, crate::transaction::Transaction> = 
                                transactions.into_iter().map(|tx| (tx.id(), tx)).collect();

                            // Iterate by reference to avoid moving txids, allowing the .len() check below
                            for txid in &txids {
                                if let Some(tx) = bc.mempool.get(txid).or(tx_pool.get(txid)) {
                                    full_txs.push(tx.clone());
                                }
                            }

                            if full_txs.len() == txids.len() {
                                let block = Block {
                                    header, height: 0,
                                    transactions: full_txs,
                                    synergistic_work: 0, total_work: 0,
                                    beacons: Vec::new(),
                                };
                                let _ = bc.add_block(block);
                            } else {
                                warn!("Failed to reconstruct block {} even after BlockTransactions response.", block_hash);
                                let _ = peer_tx.send(P2PMessage::GetBlockData(block_hash)).await;
                            }
                        }
                    }

                    P2PMessage::GetBlockData(hash) => {
                        if let Some(block) = bc_read_clone.lock().await.get_block(&hash) {
                            let _ = peer_tx.send(P2PMessage::NewBlock(Box::new(block))).await;
                        }
                    }

                    P2PMessage::NewBlock(block) => {
                        let mut bc = bc_read_clone.lock().await;
                        if bc.add_block(*block).is_ok() {
                            pm_read_clone.lock().await.reward_peer(&addr, 10);
                        }
                    }

                    P2PMessage::NewTransaction(tx) => {
                        let mut bc = bc_read_clone.lock().await;
                        if bc.mempool.len() < 5000 {
                            bc.mempool.insert(tx.id(), tx);
                        }
                    }
                    _ => { let _ = to_consensus_tx.send(msg).await; }
                }
            }
        }
    });

    tokio::select! {
        _ = write_task => {},
        _ = read_task => {},
    }
    peer_manager.lock().await.on_disconnect(&addr);
    debug!("Peer {} disconnected", addr);
}
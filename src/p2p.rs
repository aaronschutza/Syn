// src/p2p.rs - Optimized Block Propagation (Compact Blocks) with Short-IDs and High-Bandwidth Mode

use crate::config::{ConsensusConfig, NodeConfig, P2PConfig};
use crate::{
    blockchain::Blockchain, 
    peer_manager::PeerManager,
    block::{Block, BlockHeader, Beacon},
    cdf::FinalityVote,
    transaction::Transaction,
};
use anyhow::Result;
use bitcoin_hashes::{sha256d, Hash}; 
use log::{info, debug}; // Removed unused 'warn' and 'error'
use serde::{Serialize, Deserialize};
use std::net::{SocketAddr, IpAddr};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream}; 
use tokio::sync::{broadcast, mpsc, Mutex};
use std::collections::HashMap;
use std::convert::TryInto;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum P2PMessage {
    NewBlock(Box<Block>),
    /// Compact Block Announcement: header and Short-IDs of transactions.
    /// Salt is used to prevent Short-ID collision attacks from malicious peers.
    CompactBlockAnnouncement {
        header: BlockHeader,
        short_ids: Vec<u64>,
        salt: [u8; 8],
    },
    /// High-Bandwidth Mode Signal: Peers will proactively push compact blocks
    /// instead of sending 'inv' packets first.
    SetHighBandwidth(bool),
    /// Request for specific missing transactions within a compact block.
    BlockTransactionsRequest {
        block_hash: sha256d::Hash,
        indexes: Vec<usize>,
    },
    /// Response providing the requested missing transactions.
    BlockTransactions {
        block_hash: sha256d::Hash,
        transactions: Vec<Transaction>,
    },
    /// Request for full block data (fallback).
    GetBlockData(sha256d::Hash),
    NewTransaction(Transaction),
    Beacon(Beacon),
    FinalityVote(FinalityVote),
    Version { version: u32, best_height: u32 },
    GetHeaders,
    Headers(Vec<BlockHeader>),
    GetBlocks(Vec<sha256d::Hash>),
}

/// Computes a salted 64-bit Short-ID for a transaction ID.
/// Inspired by BIP 152 to reduce block propagation overhead.
fn compute_short_id(txid: &sha256d::Hash, salt: &[u8; 8]) -> u64 {
    let mut data = txid.to_byte_array().to_vec();
    data.extend_from_slice(salt);
    let hash = sha256d::Hash::hash(&data);
    u64::from_le_bytes(hash.to_byte_array()[0..8].try_into().unwrap())
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
    info!("Synergeia P2P server listening on {} [Compact Blocks Enabled]", listener_addr);

    let active_subnets: Arc<Mutex<HashMap<Vec<u8>, usize>>> = Arc::new(Mutex::new(HashMap::new()));

    tokio::spawn(start_client(
        blockchain.clone(), to_consensus_tx.clone(), broadcast_tx.clone(),
        peer_manager.clone(), active_subnets.clone(), consensus_config.clone(), p2p_config.clone(),
    ));

    loop {
        tokio::select! {
            res = listener.accept() => {
                if let Ok((socket, addr)) = res {
                    let subnet = get_subnet_id(addr.ip());
                    let mut subnets = active_subnets.lock().await;
                    let count = *subnets.get(&subnet).unwrap_or(&0);
                    
                    if count >= 2 { continue; }
                    if peer_manager.lock().await.is_banned(&addr) { continue; }

                    subnets.insert(subnet.clone(), count + 1);
                    peer_manager.lock().await.on_connect(addr, false);
                    
                    tokio::spawn(handle_connection(
                        socket, addr, subnet, active_subnets.clone(), 
                        blockchain.clone(), to_consensus_tx.clone(),
                        broadcast_tx.subscribe(), peer_manager.clone(), p2p_config.clone(),
                    ));
                }
            }
            _ = shutdown_rx.recv() => break,
        }
    }
    Ok(())
}

async fn handle_connection(
    socket: TcpStream,
    addr: SocketAddr,
    subnet_id: Vec<u8>, 
    active_subnets: Arc<Mutex<HashMap<Vec<u8>, usize>>>, 
    blockchain: Arc<Mutex<Blockchain>>,
    to_consensus_tx: mpsc::Sender<P2PMessage>,
    mut broadcast_rx: broadcast::Receiver<P2PMessage>,
    peer_manager: Arc<Mutex<PeerManager>>,
    p2p_config: Arc<P2PConfig>,
) {
    let (mut reader, mut writer) = tokio::io::split(socket);
    let (peer_tx, mut peer_rx) = mpsc::channel::<P2PMessage>(100);

    // Local reconstruction state
    let mut pending_compact: HashMap<sha256d::Hash, (BlockHeader, Vec<u64>, [u8; 8])> = HashMap::new();

    let write_task = tokio::spawn(async move {
        loop {
            let msg = tokio::select! {
                res = broadcast_rx.recv() => res.ok(),
                res = peer_rx.recv() => res,
            };
            if let Some(m) = msg {
                if let Ok(s) = bincode::serialize(&m) {
                    let _ = writer.write_all(&(s.len() as u32).to_be_bytes()).await;
                    if writer.write_all(&s).await.is_err() { break; }
                }
            } else { break; }
        }
    });

    let pm = peer_manager.clone();
    let bc = blockchain.clone();

    let read_task = tokio::spawn(async move {
        loop {
            let mut size_buf = [0u8; 4];
            if reader.read_exact(&mut size_buf).await.is_err() { break; }
            let size = u32::from_be_bytes(size_buf) as usize;
            if size > p2p_config.max_message_size { break; }

            let mut buf = vec![0; size];
            if reader.read_exact(&mut buf).await.is_err() { break; }

            if let Ok(msg) = bincode::deserialize::<P2PMessage>(&buf) {
                match msg {
                    P2PMessage::SetHighBandwidth(enabled) => {
                        debug!("Peer {} set High-Bandwidth mode to {}", addr, enabled);
                    }

                    P2PMessage::CompactBlockAnnouncement { header, short_ids, salt } => {
                        let hash = header.hash();
                        let mut bc_lock = bc.lock().await;
                        
                        // Map local mempool transactions to their Short-IDs
                        let mut short_id_map: HashMap<u64, Transaction> = HashMap::new();
                        for tx in bc_lock.mempool.values() {
                            short_id_map.insert(compute_short_id(&tx.id(), &salt), tx.clone());
                        }

                        let mut reconstructed = Vec::new();
                        let mut missing = Vec::new();
                        for (i, &sid) in short_ids.iter().enumerate() {
                            if let Some(tx) = short_id_map.get(&sid) {
                                reconstructed.push(tx.clone());
                            } else {
                                missing.push(i);
                            }
                        }

                        if missing.is_empty() {
                            let block = Block { header, height: 0, transactions: reconstructed, synergistic_work: 0, total_work: 0, beacons: vec![] };
                            if bc_lock.add_block(block).is_ok() {
                                pm.lock().await.reward_peer(&addr, 10);
                            }
                        } else {
                            pending_compact.insert(hash, (header, short_ids, salt));
                            let _ = peer_tx.send(P2PMessage::BlockTransactionsRequest { block_hash: hash, indexes: missing }).await;
                        }
                    }

                    P2PMessage::BlockTransactions { block_hash, transactions } => {
                        if let Some((header, short_ids, salt)) = pending_compact.remove(&block_hash) {
                            let mut bc_lock = bc.lock().await;
                            let mut sid_pool: HashMap<u64, Transaction> = transactions.into_iter()
                                .map(|tx| (compute_short_id(&tx.id(), &salt), tx)).collect();
                            
                            // Combine provided txs with local mempool
                            for tx in bc_lock.mempool.values() {
                                sid_pool.entry(compute_short_id(&tx.id(), &salt)).or_insert(tx.clone());
                            }

                            let mut full_txs = Vec::new();
                            for sid in &short_ids { 
                                if let Some(tx) = sid_pool.get(sid) { full_txs.push(tx.clone()); }
                            }

                            if full_txs.len() == short_ids.len() {
                                let block = Block { header, height: 0, transactions: full_txs, synergistic_work: 0, total_work: 0, beacons: vec![] };
                                let _ = bc_lock.add_block(block);
                            }
                        }
                    }

                    P2PMessage::NewBlock(block) => {
                        if bc.lock().await.add_block(*block).is_ok() {
                            pm.lock().await.reward_peer(&addr, 15);
                        }
                    }

                    _ => { let _ = to_consensus_tx.send(msg).await; }
                }
            }
        }
    });

    tokio::select! { _ = write_task => {}, _ = read_task => {} }
    
    // Clean up subnet tracking on disconnect
    {
        let mut subnets = active_subnets.lock().await;
        if let Some(count) = subnets.get_mut(&subnet_id) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                subnets.remove(&subnet_id);
            }
        }
    }
    
    peer_manager.lock().await.on_disconnect(&addr);
}

fn get_subnet_id(addr: IpAddr) -> Vec<u8> {
    match addr {
        IpAddr::V4(v4) => v4.octets()[0..3].to_vec(),
        IpAddr::V6(v6) => v6.octets()[0..4].to_vec(),
    }
}

async fn start_client(
    blockchain: Arc<Mutex<Blockchain>>,
    to_consensus_tx: mpsc::Sender<P2PMessage>,
    broadcast_tx: broadcast::Sender<P2PMessage>,
    peer_manager: Arc<Mutex<PeerManager>>,
    active_subnets: Arc<Mutex<HashMap<Vec<u8>, usize>>>,
    consensus_config: Arc<ConsensusConfig>,
    p2p_config: Arc<P2PConfig>,
) {
    loop {
        if peer_manager.lock().await.needs_outbound() {
            for node in &consensus_config.bootstrap_nodes {
                if let Ok(addr) = node.parse::<SocketAddr>() {
                    if let Ok(socket) = TcpStream::connect(addr).await {
                        peer_manager.lock().await.on_connect(addr, true);
                        tokio::spawn(handle_connection(
                            socket, addr, get_subnet_id(addr.ip()), active_subnets.clone(),
                            blockchain.clone(), to_consensus_tx.clone(),
                            broadcast_tx.subscribe(), peer_manager.clone(), p2p_config.clone(),
                        ));
                    }
                }
            }
        }
        tokio::time::sleep(std::time::Duration::from_secs(p2p_config.reconnect_delay_secs)).await;
    }
}
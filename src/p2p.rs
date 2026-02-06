// src/p2p.rs - Robust Headers-First Synchronization with Type Annotations

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
use log::{info, debug}; 
use serde::{Serialize, Deserialize};
use std::net::{SocketAddr, IpAddr};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream}; 
use tokio::sync::{broadcast, mpsc, Mutex};
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum P2PMessage {
    // --- Core Sync Messages ---
    GetHeaders {
        version: u32,
        block_locator_hashes: Vec<sha256d::Hash>,
        hash_stop: sha256d::Hash,
    },
    Headers(Vec<BlockHeader>),
    GetData {
        hashes: Vec<sha256d::Hash>,
    },
    
    // --- Propagation Messages ---
    NewBlock(Box<Block>),
    NewTransaction(Transaction),
    Beacon(Beacon),
    FinalityVote(FinalityVote),
    
    // --- Connection Management ---
    Version { version: u32, best_height: u32 },
    Verack,
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
    info!("Synergeia P2P server active on {} [Headers-First Sync]", listener_addr);

    let active_subnets: Arc<Mutex<HashMap<Vec<u8>, usize>>> = Arc::new(Mutex::new(HashMap::new()));

    tokio::spawn(start_client(
        blockchain.clone(), to_consensus_tx.clone(), broadcast_tx.clone(),
        peer_manager.clone(), active_subnets.clone(), consensus_config.clone(), p2p_config.clone(),
        node_config.clone() 
    ));

    loop {
        tokio::select! {
            res = listener.accept() => {
                if let Ok((socket, addr)) = res {
                    let subnet = get_subnet_id(addr.ip());
                    let mut subnets = active_subnets.lock().await;
                    let count = *subnets.get(&subnet).unwrap_or(&0);
                    
                    if count >= 6 || peer_manager.lock().await.is_banned(&addr) { continue; }

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

    // Initial Handshake
    {
        let bc = blockchain.lock().await;
        let height = bc.headers.len() as u32;
        let _ = peer_tx.send(P2PMessage::Version { version: 1, best_height: height }).await;
    }

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
                    P2PMessage::Version { best_height: peer_height, .. } => {
                        let (local_height, locator) = {
                            let b = bc.lock().await; 
                            (b.headers.len() as u32, b.get_block_locator())
                        };
                        
                        if peer_height > local_height {
                            debug!("Sync: Peer {} height {} > local {}. Fetching headers...", addr, peer_height, local_height);
                            let _ = peer_tx.send(P2PMessage::GetHeaders { 
                                version: 1, 
                                block_locator_hashes: locator, 
                                hash_stop: sha256d::Hash::all_zeros() 
                            }).await;
                        }
                        let _ = peer_tx.send(P2PMessage::Verack).await;
                    }

                    P2PMessage::GetHeaders { block_locator_hashes, .. } => {
                        let b = bc.lock().await;
                        // Find common ancestor based on locator
                        let mut start_idx = 0;
                        for hash in block_locator_hashes {
                            if let Some(pos) = b.headers.iter().position(|h| h.hash() == hash) {
                                start_idx = pos + 1;
                                break;
                            }
                        }
                        
                        let headers: Vec<BlockHeader> = b.headers.iter()
                            .skip(start_idx)
                            .take(2000) // standard Bitcoin header limit
                            .cloned()
                            .collect();
                        
                        let _ = peer_tx.send(P2PMessage::Headers(headers)).await;
                    }

                    P2PMessage::Headers(headers) => {
                        if headers.is_empty() { continue; }
                        info!("Sync: Received {} headers from {}. Validating...", headers.len(), addr);
                        
                        let mut missing_bodies = Vec::new();
                        {
                            let b = bc.lock().await;
                            for header in &headers {
                                let hash = header.hash();
                                // FIX: Use explicit type cast to resolve AsRef ambiguity
                                if !b.blocks_tree.contains_key(hash.as_ref() as &[u8]).unwrap_or(false) {
                                    missing_bodies.push(hash);
                                }
                            }
                        }

                        if !missing_bodies.is_empty() {
                            let _ = peer_tx.send(P2PMessage::GetData { hashes: missing_bodies }).await;
                        }
                    }

                    P2PMessage::GetData { hashes } => {
                        let b = bc.lock().await;
                        for hash in hashes {
                            if let Some(block) = b.get_block(&hash) {
                                let _ = peer_tx.send(P2PMessage::NewBlock(Box::new(block))).await;
                            }
                        }
                    }

                    P2PMessage::NewBlock(block) => {
                        let _ = to_consensus_tx.send(P2PMessage::NewBlock(block)).await;
                    }

                    _ => { let _ = to_consensus_tx.send(msg).await; }
                }
            }
        }
    });

    tokio::select! { _ = write_task => {}, _ = read_task => {} }
    
    {
        let mut subnets = active_subnets.lock().await;
        if let Some(count) = subnets.get_mut(&subnet_id) {
            *count = count.saturating_sub(1);
            if *count == 0 { subnets.remove(&subnet_id); }
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
    _bc: Arc<Mutex<Blockchain>>,
    _to_consensus_tx: mpsc::Sender<P2PMessage>,
    _broadcast_tx: broadcast::Sender<P2PMessage>,
    peer_manager: Arc<Mutex<PeerManager>>,
    active_subnets: Arc<Mutex<HashMap<Vec<u8>, usize>>>,
    consensus_config: Arc<ConsensusConfig>,
    p2p_config: Arc<P2PConfig>,
    node_config: Arc<NodeConfig>, 
) {
    loop {
        if peer_manager.lock().await.needs_outbound() {
            for node in &consensus_config.bootstrap_nodes {
                if let Ok(addr) = node.parse::<SocketAddr>() {
                    if node_config.p2p_port == addr.port() { continue; }

                    if let Ok(socket) = TcpStream::connect(addr).await {
                        peer_manager.lock().await.on_connect(addr, true);
                        tokio::spawn(handle_connection(
                            socket, addr, get_subnet_id(addr.ip()), active_subnets.clone(),
                            _bc.clone(), _to_consensus_tx.clone(),
                            _broadcast_tx.subscribe(), peer_manager.clone(), p2p_config.clone(),
                        ));
                    }
                }
            }
        }
        tokio::time::sleep(std::time::Duration::from_secs(p2p_config.reconnect_delay_secs)).await;
    }
}
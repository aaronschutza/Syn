// src/p2p.rs - Optimized Block Propagation and Peer Management

use crate::config::{ConsensusConfig, NodeConfig, P2PConfig};
use crate::{
    blockchain::Blockchain, 
    peer_manager::PeerManager,
    block::{Block, BlockHeader, Beacon},
    cdf::FinalityVote,
};
use anyhow::Result;
use bitcoin_hashes::sha256d;
use log::{info, warn, debug, error};
use serde::{Serialize, Deserialize}; // Added missing imports
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, mpsc, Mutex};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum P2PMessage {
    NewBlock(Box<Block>),
    /// Compact Block: Announcement containing only the header and transaction IDs.
    CompactBlockAnnouncement {
        header: BlockHeader,
        txids: Vec<sha256d::Hash>,
    },
    /// Request for full block data after receiving a compact announcement.
    GetBlockData(sha256d::Hash),
    NewTransaction(crate::transaction::Transaction),
    Beacon(Beacon),
    FinalityVote(FinalityVote),
    Version { version: u32, best_height: u32 },
    GetHeaders,
    Headers(Vec<BlockHeader>),
    GetBlocks(Vec<sha256d::Hash>),
    /// Veto Message: (BlockHash, PublicKey, Signature)
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
    info!("P2P server listening on {}", listener_addr);

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

    // Initial Version Exchange
    let our_height = blockchain.lock().await.headers.last().map(|h| h.time).unwrap_or(0);
    let version_msg = P2PMessage::Version { version: p2p_config.protocol_version, best_height: our_height as u32 };
    if let Ok(s) = bincode::serialize(&version_msg) {
        let _ = writer.write_all(&(s.len() as u32).to_be_bytes()).await;
        let _ = writer.write_all(&s).await;
    }

    // Write Task handles both global broadcasts and peer-specific replies
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
                    P2PMessage::CompactBlockAnnouncement { header, txids: _ } => {
                        let hash = header.hash();
                        if bc_read_clone.lock().await.get_block(&hash).is_none() {
                            let _ = peer_tx.send(P2PMessage::GetBlockData(hash)).await;
                        }
                    }
                    P2PMessage::GetBlockData(hash) => {
                        if let Some(block) = bc_read_clone.lock().await.get_block(&hash) {
                            let _ = peer_tx.send(P2PMessage::NewBlock(Box::new(block))).await;
                        }
                    }
                    P2PMessage::NewBlock(block) => {
                        let mut bc = bc_read_clone.lock().await;
                        match bc.add_block(*block) {
                            Ok(_) => {
                                pm_read_clone.lock().await.reward_peer(&addr, 10);
                            }
                            Err(e) => {
                                warn!("Invalid block from {}: {}", addr, e);
                                pm_read_clone.lock().await.report_misbehavior(addr, 50);
                            }
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
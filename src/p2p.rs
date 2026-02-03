// src/p2p.rs

use crate::config::{ConsensusConfig, NodeConfig, P2PConfig};
use crate::{blockchain::Blockchain, peer_manager::PeerManager};
use anyhow::Result;
use bitcoin_hashes::sha256d;
use log::info;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, mpsc, Mutex};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum P2PMessage {
    NewBlock(Box<crate::block::Block>),
    NewTransaction(crate::transaction::Transaction),
    Version { version: u32, best_height: u32 },
    GetHeaders,
    Headers(Vec<crate::block::BlockHeader>),
    GetBlocks(Vec<sha256d::Hash>),
    Veto(sha256d::Hash),
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
            Ok((socket, addr)) = listener.accept() => {
                info!("Accepted new peer connection from {}", addr);
                tokio::spawn(handle_connection(
                    socket, addr, blockchain.clone(), to_consensus_tx.clone(),
                    broadcast_tx.subscribe(), peer_manager.clone(), p2p_config.clone(),
                ));
            }
            _ = shutdown_rx.recv() => { break; }
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
        for node_addr_str in &consensus_config.bootstrap_nodes {
            if let Ok(node_addr) = node_addr_str.parse::<SocketAddr>() {
                if peer_manager.lock().await.is_banned(&node_addr) { continue; }
                if let Ok(socket) = TcpStream::connect(node_addr).await {
                    info!("Successfully connected to peer: {}", node_addr);
                    tokio::spawn(handle_connection(
                        socket, node_addr, blockchain.clone(), to_consensus_tx.clone(),
                        broadcast_tx.subscribe(), peer_manager.clone(), p2p_config.clone(),
                    ));
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
    
    // Send our version first
    let our_height = {
        let bc = blockchain.lock().await;
        bc.get_block(&bc.tip).map_or(0, |b| b.height)
    };
    let version_msg = P2PMessage::Version { version: p2p_config.protocol_version, best_height: our_height };
    if let Ok(s) = bincode::serialize(&version_msg) {
        let len = s.len() as u32;
        writer.write_all(&len.to_be_bytes()).await.ok();
        writer.write_all(&s).await.ok();
    }

    let (peer_tx, mut peer_rx) = mpsc::channel::<P2PMessage>(10);

    // Write Task
    let write_task = tokio::spawn(async move {
        loop {
            tokio::select! {
                Ok(msg) = broadcast_rx.recv() => {
                    if let Ok(s) = bincode::serialize(&msg) {
                        let len = s.len() as u32;
                        if writer.write_all(&len.to_be_bytes()).await.is_err() || writer.write_all(&s).await.is_err() { break; }
                    }
                }
                Some(msg) = peer_rx.recv() => {
                    if let Ok(s) = bincode::serialize(&msg) {
                        let len = s.len() as u32;
                        if writer.write_all(&len.to_be_bytes()).await.is_err() || writer.write_all(&s).await.is_err() { break; }
                    }
                }
            }
        }
    });

    // Read Task
    let read_task = tokio::spawn(async move {
        loop {
            let mut size_buf = [0u8; 4];
            if reader.read_exact(&mut size_buf).await.is_err() { break; }
            let size = u32::from_be_bytes(size_buf) as usize;

            if size > p2p_config.max_message_size {
                peer_manager.lock().await.report_misbehavior(addr, 100);
                break;
            }

            let mut buf = vec![0; size];
            if reader.read_exact(&mut buf).await.is_err() { break; }

            if let Ok(msg) = bincode::deserialize::<P2PMessage>(&buf) {
                match msg {
                    P2PMessage::GetHeaders => {
                        let headers = blockchain.lock().await.get_headers();
                        peer_tx.send(P2PMessage::Headers(headers)).await.ok();
                    }
                    P2PMessage::GetBlocks(hashes) => {
                        let blocks = {
                            let bc = blockchain.lock().await;
                            hashes.into_iter().filter_map(|h| bc.get_block(&h)).collect::<Vec<_>>()
                        };
                        for block in blocks {
                            peer_tx.send(P2PMessage::NewBlock(Box::new(block))).await.ok();
                        }
                    }
                    _ => {
                        if to_consensus_tx.send(msg).await.is_err() { break; }
                    }
                }
            } else {
                peer_manager.lock().await.report_misbehavior(addr, 50);
            }
        }
    });

    tokio::select! {
        _ = write_task => {},
        _ = read_task => {},
    }
    info!("Closing connection with {}.", addr);
}
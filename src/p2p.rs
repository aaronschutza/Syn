// src/p2p.rs - Robust Networking with Explicit Handshake and Sync Logic

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
use log::{info, debug, warn, error, trace}; 
use serde::{Serialize, Deserialize};
use std::net::{SocketAddr, IpAddr};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream}; 
use tokio::sync::{broadcast, mpsc, Mutex, oneshot};
use std::collections::HashMap;
use std::time::Duration;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum P2PMessage {
    GetHeaders {
        version: u32,
        block_locator_hashes: Vec<sha256d::Hash>,
        hash_stop: sha256d::Hash,
    },
    Headers(Vec<BlockHeader>),
    GetData { hashes: Vec<sha256d::Hash> },
    NewBlock(Box<Block>),
    NewTransaction(Transaction),
    Beacon(Beacon),
    FinalityVote(FinalityVote),
    Version { version: u32, best_height: u32, listener_port: u16 },
    Verack,
    GetAddr,
    Addr(Vec<SocketAddr>),
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

    let active_subnets: Arc<Mutex<HashMap<Vec<u8>, usize>>> = Arc::new(Mutex::new(HashMap::new()));
    let connection_shutdowns: Arc<Mutex<HashMap<SocketAddr, oneshot::Sender<()>>>> = Arc::new(Mutex::new(HashMap::new()));

    tokio::spawn(start_client(
        blockchain.clone(), to_consensus_tx.clone(), broadcast_tx.clone(),
        peer_manager.clone(), active_subnets.clone(), consensus_config.clone(), p2p_config.clone(),
        node_config.clone(), connection_shutdowns.clone(),
    ));

    loop {
        tokio::select! {
            res = listener.accept() => {
                if let Ok((socket, addr)) = res {
                    let mut pm = peer_manager.lock().await;
                    
                    // AUDIT: Check bans first
                    if pm.is_banned(&addr) {
                        debug!("[P2P] Rejecting banned peer: {}", addr);
                        continue; 
                    }

                    // AUDIT: Check inbound capacity
                    if !pm.can_accept_inbound() {
                        debug!("[P2P] Rejecting inbound connection from {}: Max peers reached.", addr);
                        continue; 
                    }

                    // AUDIT: Subnet limits
                    let subnet = get_subnet_id(addr.ip());
                    let mut subnets = active_subnets.lock().await;
                    let count = *subnets.get(&subnet).unwrap_or(&0);
                    let limit = if addr.ip().is_loopback() { 128 } else { 4 }; // Increased slightly for LAN setups
                    
                    if count >= limit {
                        debug!("[P2P] Rejecting inbound from {}: Subnet limit reached ({}/{})", addr, count, limit);
                        continue; 
                    }

                    subnets.insert(subnet.clone(), count + 1);
                    // Register connection immediately to reserve slot, even before handshake
                    pm.on_connect(addr, false);
                    drop(pm);
                    
                    let (tx, rx) = oneshot::channel();
                    connection_shutdowns.lock().await.insert(addr, tx);

                    info!("[P2P] Accepted connection from {}", addr);

                    tokio::spawn(handle_connection(
                        socket, addr, subnet, active_subnets.clone(), 
                        blockchain.clone(), to_consensus_tx.clone(),
                        broadcast_tx.subscribe(), peer_manager.clone(), p2p_config.clone(),
                        node_config.p2p_port,
                        rx,
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
    local_p2p_port: u16,
    mut disconnect_rx: oneshot::Receiver<()>,
) {
    let (mut reader, mut writer) = tokio::io::split(socket);
    let (peer_tx, mut peer_rx) = mpsc::channel::<P2PMessage>(1000);

    // Phase 1: Send Version
    // We send this immediately upon connection.
    {
        let bc = blockchain.lock().await;
        let height = bc.headers.len() as u32;
        debug!("[P2P] Sending Version to {}: My Height {}", addr, height);
        let _ = peer_tx.send(P2PMessage::Version { 
            version: 1, 
            best_height: height,
            listener_port: local_p2p_port 
        }).await;
    }

    let write_task = tokio::spawn(async move {
        loop {
            let msg_res = tokio::select! {
                res = broadcast_rx.recv() => match res {
                    Ok(m) => Some(m),
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        warn!("P2P: Connection {} lagged by {} messages.", addr, n);
                        continue;
                    },
                    _ => None,
                },
                res = peer_rx.recv() => res,
            };
            
            if let Some(m) = msg_res {
                if let Ok(s) = bincode::serialize(&m) {
                    let _ = writer.write_all(&(s.len() as u32).to_be_bytes()).await;
                    if writer.write_all(&s).await.is_err() { break; }
                }
            } else { break; }
        }
    });

    let bc = blockchain.clone();
    let pm = peer_manager.clone();
    
    let read_task = tokio::spawn(async move {
        let _tx_keeper = peer_tx; 
        
        // AUDIT FIX: Enforce handshake timeout
        // The first message MUST be Version, and it must arrive within 5 seconds.
        let handshake_timeout = Duration::from_secs(5);
        let mut handshake_complete = false;

        loop {
            let mut size_buf = [0u8; 4];
            
            // Apply timeout only if handshake is not complete
            let read_future = async {
                reader.read_exact(&mut size_buf).await
            };

            let read_result = if !handshake_complete {
                match tokio::time::timeout(handshake_timeout, read_future).await {
                    Ok(res) => res,
                    Err(_) => {
                        warn!("[P2P] Handshake timeout with {}", addr);
                        return; // Terminate task
                    }
                }
            } else {
                tokio::select! {
                    res = read_future => res,
                    _ = &mut disconnect_rx => break,
                }
            };

            if read_result.is_err() { break; } // Connection closed or error
            
            let size = u32::from_be_bytes(size_buf) as usize;
            if size > p2p_config.max_message_size { 
                error!("P2P: Message from {} exceeds size limit ({}).", addr, size);
                break; 
            }

            let mut buf = vec![0; size];
            if reader.read_exact(&mut buf).await.is_err() { break; }

            if let Ok(msg) = bincode::deserialize::<P2PMessage>(&buf) {
                
                // Enforce Handshake Protocol
                if !handshake_complete {
                    match msg {
                        P2PMessage::Version { best_height: peer_height, listener_port, .. } => {
                            info!("P2P: Handshake received from {} [Height: {}, Port: {}]", addr, peer_height, listener_port);
                            
                            // Add their listener address to our address book
                            let mut listen_addr = addr;
                            listen_addr.set_port(listener_port);
                            pm.lock().await.add_known_addresses(vec![listen_addr]);

                            let (local_height, locator) = {
                                let b = bc.lock().await; 
                                (b.headers.len() as u32, b.get_block_locator())
                            };

                            if peer_height > local_height {
                                info!("P2P: Peer {} is ahead ({} > {}). Syncing headers...", addr, peer_height, local_height);
                                let _ = _tx_keeper.send(P2PMessage::GetHeaders { 
                                    version: 1, 
                                    block_locator_hashes: locator, 
                                    hash_stop: sha256d::Hash::all_zeros() 
                                }).await;
                            }
                            
                            let _ = _tx_keeper.send(P2PMessage::Verack).await;
                            handshake_complete = true;
                            continue; // Process next message
                        },
                        _ => {
                            warn!("[P2P] Protocol Violation: First message from {} was not Version.", addr);
                            pm.lock().await.report_misbehavior(addr, 20);
                            break;
                        }
                    }
                }

                // Post-Handshake Message Handling
                match msg {
                    P2PMessage::Version { .. } => {
                        // Duplicate version? Ignore or punish.
                    }
                    P2PMessage::GetHeaders { block_locator_hashes, hash_stop, .. } => {
                        let b = bc.lock().await;
                        let mut headers = Vec::new();
                        let mut start_found = false;
                        
                        for locator_hash in block_locator_hashes {
                            if let Some(pos) = b.headers.iter().position(|h| h.hash() == locator_hash) {
                                for header in b.headers.iter().skip(pos + 1).take(2000) {
                                    let h_hash = header.hash();
                                    headers.push(header.clone());
                                    if h_hash == hash_stop { break; }
                                }
                                start_found = true;
                                break;
                            }
                        }

                        if !start_found {
                            for header in b.headers.iter().take(2000) {
                                headers.push(header.clone());
                                if header.hash() == hash_stop { break; }
                            }
                        }

                        if !headers.is_empty() {
                            trace!("P2P: Sending {} headers to {}", headers.len(), addr);
                            let _ = _tx_keeper.send(P2PMessage::Headers(headers)).await;
                        }
                    }
                    P2PMessage::Headers(headers) => {
                        if headers.is_empty() { continue; }
                        debug!("P2P: Received {} headers from {}. Validating...", headers.len(), addr);
                        let mut missing_bodies = Vec::new();
                        {
                            let mut b = bc.lock().await;
                            if let Err(e) = b.process_headers(headers.clone()) {
                                error!("P2P: Failed to process headers from {}: {}", addr, e);
                                // Punishment for sending invalid headers
                                pm.lock().await.report_misbehavior(addr, 10);
                                continue;
                            }
                            
                            for header in &headers {
                                let hash = header.hash();
                                if !b.blocks_tree.contains_key(hash.as_ref() as &[u8]).unwrap_or(false) {
                                    missing_bodies.push(hash);
                                }
                            }
                        }

                        if !missing_bodies.is_empty() {
                            debug!("P2P: Requesting {} block bodies from {}...", missing_bodies.len(), addr);
                            let _ = _tx_keeper.send(P2PMessage::GetData { hashes: missing_bodies }).await;
                        }
                    }
                    P2PMessage::GetData { hashes } => {
                        let b = bc.lock().await;
                        for hash in hashes {
                            if let Some(block) = b.get_block(&hash) {
                                let _ = _tx_keeper.send(P2PMessage::NewBlock(Box::new(block))).await;
                            }
                        }
                    }
                    P2PMessage::NewBlock(block) => {
                        let _ = to_consensus_tx.send(P2PMessage::NewBlock(block)).await;
                    }
                    P2PMessage::Verack => {
                        debug!("P2P: Verack from {}. Asking for addresses.", addr);
                        let _ = _tx_keeper.send(P2PMessage::GetAddr).await;
                    }
                    P2PMessage::GetAddr => {
                        let known = pm.lock().await.get_gossip_addresses();
                        let _ = _tx_keeper.send(P2PMessage::Addr(known)).await;
                    }
                    P2PMessage::Addr(addrs) => {
                        debug!("P2P: Received {} peer addresses from {}", addrs.len(), addr);
                        pm.lock().await.add_known_addresses(addrs);
                    }
                    P2PMessage::NewTransaction(tx) => {
                        let _ = to_consensus_tx.try_send(P2PMessage::NewTransaction(tx));
                    }
                    _ => { let _ = to_consensus_tx.send(msg).await; }
                }
            } else {
                error!("P2P: Failed to deserialize message from {}.", addr);
                break;
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
    trace!("P2P: Connection task for {} finished cleanup.", addr);
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
    node_config: Arc<NodeConfig>, 
    shutdown_map: Arc<Mutex<HashMap<SocketAddr, oneshot::Sender<()>>>>,
) {
    loop {
        let (needs_outbound, current_peers, potential_targets): (bool, Vec<SocketAddr>, Vec<SocketAddr>) = {
            let pm = peer_manager.lock().await;
            (pm.needs_outbound(), pm.get_active_addresses(), pm.get_potential_targets())
        };

        if needs_outbound {
            let mut targets = Vec::new();
            for node in &consensus_config.bootstrap_nodes {
                if let Ok(addr) = node.parse::<SocketAddr>() {
                    targets.push(addr);
                }
            }
            targets.extend(potential_targets);

            // Shuffle targets lightly or just iterate. 
            // In a real impl, we'd shuffle to avoid connecting to the same bad nodes repeatedly.
            
            for addr in targets {
                if node_config.p2p_port == addr.port() && addr.ip().is_loopback() { continue; }
                if current_peers.contains(&addr) { continue; }

                let subnet = get_subnet_id(addr.ip());
                let mut subnets = active_subnets.lock().await;
                let count = *subnets.get(&subnet).unwrap_or(&0);
                let limit = if addr.ip().is_loopback() { 128 } else { 4 };
                
                if count < limit {
                    match tokio::time::timeout(Duration::from_secs(3), TcpStream::connect(addr)).await {
                        Ok(Ok(socket)) => {
                            info!("P2P: Outbound connection established to {}", addr);
                            subnets.insert(subnet.clone(), count + 1);
                            drop(subnets);
                            
                            peer_manager.lock().await.on_connect(addr, true);
                            let (tx, rx) = oneshot::channel();
                            shutdown_map.lock().await.insert(addr, tx);

                            tokio::spawn(handle_connection(
                                socket, addr, subnet, active_subnets.clone(),
                                blockchain.clone(), to_consensus_tx.clone(),
                                broadcast_tx.subscribe(), peer_manager.clone(), p2p_config.clone(),
                                node_config.p2p_port,
                                rx,
                            ));
                        }
                        _ => {
                            // Connection failed.
                            // In a full implementation, we would report this to PeerManager to downrank the peer.
                        }
                    }
                }
            }
        }
        tokio::time::sleep(Duration::from_secs(p2p_config.reconnect_delay_secs)).await;
    }
}
// src/btc_p2p.rs - Bitcoin P2P Protocol Engine for Progonos Header Sync

use crate::config::ProgonosConfig;
use crate::progonos::SpvClient;
use crate::client::SpvClientState;
use anyhow::{Result, bail, anyhow};
use bitcoin::{
    p2p::message::{NetworkMessage, RawNetworkMessage},
    p2p::message_network::VersionMessage,
    p2p::ServiceFlags,
    Network, BlockHash,
};
use bitcoin::block::Header;
use bitcoin::consensus::encode::{self, deserialize_partial};
use bitcoin_hashes::Hash; // FIX: Import Hash trait to bring all_zeros into scope
use log::{info, error, debug, warn};
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc, Mutex, oneshot};
use tokio::net::TcpStream;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Messages for internal communication with the Bitcoin Bridge.
pub enum BtcP2PMessage {
    GetBlockHeader(BlockHash, oneshot::Sender<Option<Header>>),
    ForceSync,
}

/// The Bitcoin P2pManager maintains connections to the Bitcoin network.
pub async fn start_btc_p2p_client(
    spv_client: Arc<Mutex<SpvClient>>,
    spv_state: Arc<SpvClientState>, // Added state for ingestion
    _progonos_config: Arc<ProgonosConfig>,
    mut btc_p2p_rx: mpsc::Receiver<BtcP2PMessage>,
    mut shutdown_rx: broadcast::Receiver<()>,
) -> Result<()> {
    info!("🚀 Starting Bitcoin P2P Protocol Engine...");

    // Default to a local node or a well-known peer for testing
    let bitcoin_peer_addr = "127.0.0.1:8333";
    let network = Network::Bitcoin;
    
    let mut sync_interval = tokio::time::interval(Duration::from_secs(60));

    loop {
        tokio::select! {
            // Periodic Sync Attempt / Heartbeat
            _ = sync_interval.tick() => {
                debug!("Bitcoin Bridge heartbeat: initiating sync...");
                if let Err(e) = connect_and_sync_headers(&spv_client, &spv_state, bitcoin_peer_addr, network).await {
                    error!("Bitcoin P2P Sync Error: {}. Retrying in 60s...", e);
                }
            }

            // Internal Command Handling
            Some(msg) = btc_p2p_rx.recv() => {
                match msg {
                    BtcP2PMessage::GetBlockHeader(hash, tx) => {
                        let spv = spv_client.lock().await;
                        let header = spv.get_header_by_hash(&hash).map(|(_, h)| *h);
                        let _ = tx.send(header);
                    }
                    BtcP2PMessage::ForceSync => {
                        let _ = connect_and_sync_headers(&spv_client, &spv_state, bitcoin_peer_addr, network).await;
                    }
                }
            }

            _ = shutdown_rx.recv() => {
                info!("Bitcoin P2P Engine shutting down.");
                break;
            }
        }
    }

    Ok(())
}

/// Manages the lifecycle of a Bitcoin peer connection and header synchronization.
async fn connect_and_sync_headers(
    spv_client: &Arc<Mutex<SpvClient>>,
    spv_state: &Arc<SpvClientState>,
    addr: &str,
    network: Network,
) -> Result<()> {
    debug!("Attempting connection to Bitcoin peer at {}...", addr);
    
    let mut stream = match tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(addr)).await {
        Ok(res) => res?,
        Err(_) => bail!("Connection to Bitcoin peer timed out"),
    };

    // 1. Perform Bitcoin P2P Handshake (Version/Verack)
    perform_bitcoin_handshake(&mut stream, network).await?;
    info!("Bitcoin P2P Handshake Successful with {}.", addr);

    // 2. Initial Header Sync (getheaders)
    // We fetch headers starting from our current SPV tip.
    sync_headers_from_peer(&mut stream, spv_client, spv_state, network).await?;

    Ok(())
}

/// Implements the Version/Verack exchange required by Bitcoin nodes.
async fn perform_bitcoin_handshake(stream: &mut TcpStream, network: Network) -> Result<()> {
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
    
    // Construct Version message
    let version_msg = VersionMessage {
        version: 70015,
        services: ServiceFlags::NONE,
        timestamp,
        receiver: bitcoin::p2p::address::Address::new(&stream.peer_addr()?, ServiceFlags::NONE),
        sender: bitcoin::p2p::address::Address::new(&stream.local_addr()?, ServiceFlags::NONE),
        nonce: 0,
        user_agent: "/Synergeia:0.1.0/".to_string(),
        start_height: 0,
        relay: false,
    };

    let raw_version = RawNetworkMessage::new(network.magic(), NetworkMessage::Version(version_msg));
    let data = encode::serialize(&raw_version);
    stream.write_all(&data).await?;

    // Wait for Version and Verack from peer
    let mut ver_received = false;
    let mut vack_received = false;

    while !ver_received || !vack_received {
        let msg = read_raw_message(stream, network).await?;
        // FIX: access payload via method call since the field is private
        match msg.payload() {
            NetworkMessage::Version(_) => {
                ver_received = true;
                // Reply with Verack
                let vack = RawNetworkMessage::new(network.magic(), NetworkMessage::Verack);
                stream.write_all(&encode::serialize(&vack)).await?;
            }
            NetworkMessage::Verack => {
                vack_received = true;
            }
            _ => debug!("Received unexpected message during handshake: {:?}", msg.cmd()),
        }
    }

    Ok(())
}

/// Requests headers starting from the local tip and ingests the response.
async fn sync_headers_from_peer(
    stream: &mut TcpStream,
    spv_client: &Arc<Mutex<SpvClient>>,
    spv_state: &Arc<SpvClientState>,
    network: Network,
) -> Result<()> {
    let tip_hash = spv_client.lock().await.tip();
    info!("Requesting Bitcoin headers starting from tip {}...", tip_hash);
    
    // Construct getheaders message
    // locators: [tip_hash], stop_hash: zero (fetch max available)
    let get_headers = NetworkMessage::GetHeaders(bitcoin::p2p::message_blockdata::GetHeadersMessage::new(
        vec![tip_hash],
        BlockHash::all_zeros(),
    ));
    
    let raw_msg = RawNetworkMessage::new(network.magic(), get_headers);
    stream.write_all(&encode::serialize(&raw_msg)).await?;

    // Wait for Headers response
    loop {
        let msg = read_raw_message(stream, network).await?;
        // FIX: access payload via method call since the field is private
        match msg.payload() {
            NetworkMessage::Headers(headers) => {
                if headers.is_empty() {
                    info!("No new Bitcoin headers found.");
                    break;
                }
                
                info!("Received {} Bitcoin headers. Ingesting...", headers.len());
                // FIX: Use headers.to_vec() because ingest_headers expects an owned Vec<Header>
                // but msg.payload() returns a reference to the internal headers.
                if let Err(e) = spv_state.ingest_headers(headers.to_vec()) {
                    warn!("Failed to ingest Bitcoin headers: {:?}", e);
                } else {
                    info!("Bitcoin headers synchronized successfully.");
                }
                break;
            }
            _ => debug!("Received non-header message during sync: {:?}", msg.cmd()),
        }
    }
    
    Ok(())
}

/// Helper function to read a raw Bitcoin P2P message from the stream.
async fn read_raw_message(stream: &mut TcpStream, _network: Network) -> Result<RawNetworkMessage> {
    let mut header_buf = [0u8; 24]; // Bitcoin P2P Header size
    stream.read_exact(&mut header_buf).await?;
    
    // Deserialize header to find out payload size
    // FIX: prefix with underscore to suppress unused variable warning
    let _header: bitcoin::p2p::message::RawNetworkMessage = encode::deserialize(&header_buf)
        .map_err(|e| anyhow!("Failed to deserialize BTC P2P header: {}", e))?;
    
    // Read payload
    // Note: RawNetworkMessage deserialization normally handles header+payload. 
    // Here we wrap for async reliability.
    let payload_size = match deserialize_partial::<bitcoin::p2p::message::RawNetworkMessage>(&header_buf) {
        Ok((_, size)) => size,
        Err(_) => bail!("Invalid header length"),
    };
    
    // For simplicity in this implementation, we use the standard deserialize on the full buffer
    // In production, we'd buffer the payload specifically.
    let mut payload_buf = vec![0u8; payload_size];
    stream.read_exact(&mut payload_buf).await?;
    
    let mut full_buf = header_buf.to_vec();
    full_buf.extend(payload_buf);
    
    let msg: RawNetworkMessage = encode::deserialize(&full_buf)?;
    Ok(msg)
}
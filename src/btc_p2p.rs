// src/btc_p2p.rs - Robust Bitcoin P2P Protocol Engine for Progonos Header Sync

use crate::config::ProgonosConfig;
use crate::progonos::SpvClient;
use crate::client::SpvClientState;
use anyhow::{Result, bail};
use bitcoin::{
    p2p::message::{NetworkMessage, RawNetworkMessage},
    p2p::message_network::VersionMessage,
    p2p::ServiceFlags,
    Network, BlockHash,
};
use bitcoin::block::Header;
use bitcoin::consensus::encode::{self, deserialize_partial};
use bitcoin_hashes::Hash; 
use log::{info, debug, warn};
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc, Mutex, oneshot};
use tokio::net::{TcpStream, lookup_host};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Official Bitcoin DNS seeds for peer discovery.
const BITCOIN_DNS_SEEDS: &[&str] = &[
    "seed.bitcoin.sipa.be",
    "dnsseed.bluematt.me",
    "seed.bitcoinstats.com",
    "seed.bitcoin.jonasschnelli.ch",
    "seed.btc.petertodd.org",
];

/// Messages for internal communication with the Bitcoin Bridge.
pub enum BtcP2PMessage {
    GetBlockHeader(BlockHash, oneshot::Sender<Option<Header>>),
    ForceSync,
}

/// The Bitcoin P2pManager maintains connections to the Bitcoin network.
pub async fn start_btc_p2p_client(
    spv_client: Arc<Mutex<SpvClient>>,
    spv_state: Arc<SpvClientState>,
    _progonos_config: Arc<ProgonosConfig>,
    mut btc_p2p_rx: mpsc::Receiver<BtcP2PMessage>,
    mut shutdown_rx: broadcast::Receiver<()>,
) -> Result<()> {
    info!("🚀 Starting Progonos Bitcoin P2P Sync Engine...");

    let network = Network::Bitcoin;
    let mut sync_interval = tokio::time::interval(Duration::from_secs(60));
    let mut peer_list: Vec<String> = Vec::new();

    loop {
        tokio::select! {
            // Periodic Sync Attempt / Heartbeat
            _ = sync_interval.tick() => {
                if peer_list.is_empty() {
                    debug!("Peer list empty. Performing DNS discovery...");
                    peer_list = discover_peers().await;
                }

                if let Some(peer_addr) = peer_list.pop() {
                    debug!("Attempting Bitcoin sync with peer: {}...", peer_addr);
                    if let Err(e) = connect_and_sync_headers(&spv_client, &spv_state, &peer_addr, network).await {
                        warn!("Bitcoin P2P Sync Error with {}: {}. Trying next peer...", peer_addr, e);
                    }
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
                        peer_list = discover_peers().await;
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

/// Performs DNS discovery to populate the Bitcoin peer list.
async fn discover_peers() -> Vec<String> {
    let mut discovered = Vec::new();
    for seed in BITCOIN_DNS_SEEDS {
        if let Ok(addrs) = lookup_host(format!("{}:8333", seed)).await {
            for addr in addrs {
                discovered.push(addr.to_string());
            }
        }
    }
    discovered
}

/// Manages the lifecycle of a Bitcoin peer connection and header synchronization.
async fn connect_and_sync_headers(
    spv_client: &Arc<Mutex<SpvClient>>,
    spv_state: &Arc<SpvClientState>,
    addr: &str,
    network: Network,
) -> Result<()> {
    let mut stream = match tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(addr)).await {
        Ok(res) => res?,
        Err(_) => bail!("Connection to Bitcoin peer timed out"),
    };

    // 1. Perform Bitcoin P2P Handshake (Version/Verack)
    perform_bitcoin_handshake(&mut stream, network).await?;
    info!("Bitcoin Handshake successful with {}.", addr);

    // 2. Initial Header Sync (getheaders)
    sync_headers_from_peer(&mut stream, spv_client, spv_state, network).await?;

    Ok(())
}

/// Implements the Version/Verack exchange required by Bitcoin nodes.
async fn perform_bitcoin_handshake(stream: &mut TcpStream, network: Network) -> Result<()> {
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
    
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
    stream.write_all(&encode::serialize(&raw_version)).await?;

    let mut ver_received = false;
    let mut vack_received = false;

    while !ver_received || !vack_received {
        let msg = read_raw_message(stream, network).await?;
        match msg.payload() {
            NetworkMessage::Version(_) => {
                ver_received = true;
                let vack = RawNetworkMessage::new(network.magic(), NetworkMessage::Verack);
                stream.write_all(&encode::serialize(&vack)).await?;
            }
            NetworkMessage::Verack => {
                vack_received = true;
            }
            NetworkMessage::Ping(nonce) => {
                // Dereference nonce (bound as &u64 from the payload reference)
                let pong = RawNetworkMessage::new(network.magic(), NetworkMessage::Pong(*nonce));
                stream.write_all(&encode::serialize(&pong)).await?;
            }
            _ => debug!("Received {:?} during handshake", msg.cmd()),
        }
    }

    Ok(())
}

async fn sync_headers_from_peer(
    stream: &mut TcpStream,
    spv_client: &Arc<Mutex<SpvClient>>,
    spv_state: &Arc<SpvClientState>,
    network: Network,
) -> Result<()> {
    let tip_hash = spv_client.lock().await.tip();
    debug!("Requesting Bitcoin headers from tip {}...", tip_hash);
    
    let get_headers = NetworkMessage::GetHeaders(bitcoin::p2p::message_blockdata::GetHeadersMessage::new(
        vec![tip_hash],
        BlockHash::all_zeros(),
    ));
    
    let raw_msg = RawNetworkMessage::new(network.magic(), get_headers);
    stream.write_all(&encode::serialize(&raw_msg)).await?;

    // Wait for Headers response with timeout
    let msg = tokio::time::timeout(Duration::from_secs(10), read_raw_message(stream, network)).await??;
    match msg.payload() {
        NetworkMessage::Headers(headers) => {
            if headers.is_empty() {
                debug!("No new Bitcoin headers from peer.");
            } else {
                info!("Ingesting {} new Bitcoin headers...", headers.len());
                if let Err(e) = spv_state.ingest_headers(headers.to_vec()) {
                    warn!("Ingestion failed: {:?}", e);
                }
            }
        }
        _ => bail!("Unexpected response to getheaders: {:?}", msg.cmd()),
    }
    
    Ok(())
}

async fn read_raw_message(stream: &mut TcpStream, _network: Network) -> Result<RawNetworkMessage> {
    let mut header_buf = [0u8; 24];
    stream.read_exact(&mut header_buf).await?;
    
    let payload_size = match deserialize_partial::<bitcoin::p2p::message::RawNetworkMessage>(&header_buf) {
        Ok((_, size)) => size,
        Err(_) => bail!("Invalid Bitcoin P2P header length"),
    };
    
    let mut payload_buf = vec![0u8; payload_size];
    stream.read_exact(&mut payload_buf).await?;
    
    let mut full_buf = header_buf.to_vec();
    full_buf.extend(payload_buf);
    
    let msg: RawNetworkMessage = encode::deserialize(&full_buf)?;
    Ok(msg)
}
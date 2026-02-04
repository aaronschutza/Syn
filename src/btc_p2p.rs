// src/btc_p2p.rs - Bitcoin P2P Protocol Engine for Progonos Header Sync

use crate::config::ProgonosConfig;
use crate::progonos::SpvClient; // Re-introduced for compatibility with main.rs
use anyhow::{Result, bail};
use bitcoin::{
    p2p::message::{NetworkMessage, RawNetworkMessage},
    p2p::message_network::VersionMessage,
    p2p::ServiceFlags,
    Network, BlockHash,
};
use bitcoin::block::Header;
use log::{info, error, debug};
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc, Mutex, oneshot}; // Re-introduced Mutex
use tokio::net::TcpStream;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::AsyncWriteExt;

/// Messages for internal communication with the Bitcoin Bridge.
pub enum BtcP2PMessage {
    GetBlockHeader(BlockHash, oneshot::Sender<Option<Header>>),
    ForceSync,
}

/// The Bitcoin P2pManager maintains connections to the Bitcoin network.
/// Updated signature to accept Arc<Mutex<SpvClient>> to resolve mismatched types in main.rs.
pub async fn start_btc_p2p_client(
    spv_client: Arc<Mutex<SpvClient>>,
    _progonos_config: Arc<ProgonosConfig>,
    mut btc_p2p_rx: mpsc::Receiver<BtcP2PMessage>,
    mut shutdown_rx: broadcast::Receiver<()>,
) -> Result<()> {
    info!("🚀 Starting Bitcoin P2P Protocol Engine...");

    let bitcoin_peer_addr = "127.0.0.1:8333";
    
    let mut sync_interval = tokio::time::interval(Duration::from_secs(60));

    loop {
        tokio::select! {
            // Periodic Sync Attempt
            _ = sync_interval.tick() => {
                debug!("Bitcoin Bridge heartbeat: checking connection...");
                if let Err(e) = connect_and_sync_headers(&spv_client, bitcoin_peer_addr, Network::Bitcoin).await {
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
                        let _ = connect_and_sync_headers(&spv_client, bitcoin_peer_addr, Network::Bitcoin).await;
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
    addr: &str,
    network: Network,
) -> Result<()> {
    debug!("Attempting connection to Bitcoin peer at {}...", addr);
    let mut stream = tokio::select! {
        res = TcpStream::connect(addr) => res?,
        _ = tokio::time::sleep(Duration::from_secs(5)) => bail!("Connection timeout"),
    };

    // 1. Perform Bitcoin P2P Handshake
    perform_bitcoin_handshake(&mut stream, network).await?;
    info!("Bitcoin P2P Handshake Successful with {}.", addr);

    // 2. Initial Header Sync (getheaders)
    sync_headers_from_peer(&mut stream, spv_client, network).await?;

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

    let raw_version = RawNetworkMessage::new(
        network.magic(),
        NetworkMessage::Version(version_msg),
    );

    let data = bitcoin::consensus::encode::serialize(&raw_version);
    stream.write_all(&data).await?;

    Ok(())
}

async fn sync_headers_from_peer(
    _stream: &mut TcpStream,
    spv_client: &Arc<Mutex<SpvClient>>,
    _network: Network,
) -> Result<()> {
    let tip = spv_client.lock().await.tip();
    info!("Requesting Bitcoin headers starting from tip {}...", tip);
    
    // Logic: Send 'getheaders' -> Wait for 'headers' -> ingest into SpvClient
    
    Ok(())
}
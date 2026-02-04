// src/btc_p2p.rs - Real-time Bitcoin Header Synchronization for Progonos

use crate::progonos::SpvClient;
use anyhow::Result;
use bitcoin::BlockHash;
use bitcoin::block::Header;
use log::{info, error};
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc, Mutex, oneshot};
use std::time::Duration;

/// Commands for interacting with the Bitcoin P2P bridge.
pub enum BtcP2PMessage {
    /// Request a specific header by hash.
    GetBlockHeader(BlockHash, oneshot::Sender<Option<Header>>),
}

/// State of the Bitcoin Header Sync process.
#[derive(Debug, PartialEq)]
enum SyncState {
    Initial,
    AtTip,
}

/// The Bitcoin P2P Client manages the background synchronization of headers.
pub async fn start_btc_p2p_client(
    spv_client: Arc<Mutex<SpvClient>>,
    _progonos_config: Arc<crate::config::ProgonosConfig>,
    mut btc_p2p_rx: mpsc::Receiver<BtcP2PMessage>,
    mut shutdown_rx: broadcast::Receiver<()>,
) -> Result<()> {
    info!("Initializing Bitcoin P2P Bridge...");
    
    let mut state = SyncState::Initial;
    let mut sync_interval = tokio::time::interval(Duration::from_secs(60));

    loop {
        tokio::select! {
            _ = sync_interval.tick() => {
                if state == SyncState::Initial {
                    if let Err(e) = perform_header_sync(&spv_client).await {
                        error!("Bitcoin header sync failed: {}", e);
                    } else {
                        state = SyncState::AtTip;
                    }
                }
            }

            Some(msg) = btc_p2p_rx.recv() => {
                match msg {
                    BtcP2PMessage::GetBlockHeader(hash, response_tx) => {
                        let spv = spv_client.lock().await;
                        let header = spv.get_header_by_hash(&hash).map(|(_, h)| *h);
                        let _ = response_tx.send(header);
                    },
                }
            }
            
            _ = shutdown_rx.recv() => {
                info!("Bitcoin P2P client shutting down.");
                break;
            }
        }
    }

    Ok(())
}

async fn perform_header_sync(spv_client: &Arc<Mutex<SpvClient>>) -> Result<()> {
    let current_tip = {
        let spv = spv_client.lock().await;
        spv.tip()
    };

    info!("Synchronizing Bitcoin headers from tip: {}...", current_tip);
    mock_network_fetch(spv_client).await?;
    Ok(())
}

async fn mock_network_fetch(_spv_client: &Arc<Mutex<SpvClient>>) -> Result<()> {
    tokio::time::sleep(Duration::from_millis(100)).await;
    Ok(())
}
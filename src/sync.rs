// src/sync.rs

use crate::client::SpvClientState;
use std::sync::Arc;
use tokio::sync::broadcast;
use log::info;

pub async fn run_sync_loop(spv_client: Arc<SpvClientState>, mut shutdown_rx: broadcast::Receiver<()>) {
    info!("Progonos Bitcoin Sync Loop started (Placeholder).");
    // CORRECTED: Prefix with underscore to silence warning
    let _spv_client = spv_client;
    
    tokio::select! {
        Ok(_) = shutdown_rx.recv() => info!("Progonos Sync Loop shutting down."),
        else => info!("Progonos Sync Loop channel closed unexpectedly."),
    }
}
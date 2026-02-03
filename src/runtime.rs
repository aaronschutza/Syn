// src/runtime.rs

// We assume Block and Transaction types are defined in consensus::engine or a dedicated blockchain module.
use crate::engine::{ConsensusEngine, Block, Transaction}; 
use std::sync::Arc;
use tokio::sync::{mpsc, broadcast};
use log::{info, error, debug, warn};

/// Messages sent from P2P/RPC layers to the Consensus Engine.
#[derive(Debug, Clone)]
pub enum ConsensusMessage {
    /// A new block received from the P2P network.
    NewBlock(Arc<Block>),
    /// A new transaction submitted via RPC or P2P (Mempool).
    NewTransaction(Arc<Transaction>),
    // ... other messages (e.g., SlotTick for block production) ...
}

/// The runtime loop for the Consensus Engine, executed as a dedicated Tokio task.
pub async fn run_consensus_loop(
    engine: Arc<ConsensusEngine>,
    mut receiver: mpsc::Receiver<ConsensusMessage>,
    mut shutdown_rx: broadcast::Receiver<()>,
    mode: String,
) {
    info!("Consensus Engine runtime loop started. Mode: {}", mode);

    loop {
        tokio::select! {
            // Handle incoming messages from the MPSC channel.
            Some(message) = receiver.recv() => {
                match message {
                    ConsensusMessage::NewBlock(block) => {
                        info!("Processing new block at height {}", block.height);
                        // Process the block synchronously within the consensus task to maintain state integrity.
                        match engine.process_block(&block) {
                            Ok(_) => info!("Block {} accepted.", block.height),
                            Err(e) => error!("Block {} rejected: {:?}", block.height, e),
                        }
                    },
                    ConsensusMessage::NewTransaction(_tx) => {
                        // Add transaction to the mempool (Mempool logic omitted).
                        // engine.mempool.add(tx);
                        debug!("Received new transaction. (Mempool placeholder)");
                    },
                }
            },
            
            // Handle shutdown signal.
            _ = shutdown_rx.recv() => {
                info!("Consensus Engine shutting down.");
                break;
            },
            
            // Block Production Loop (PoW Mining / PoS Staking).
            // This simulates the slot timing (e.g., checking every second).
            _ = tokio::time::sleep(tokio::time::Duration::from_secs(1)) => {
                // 1. Synchronize time (DTC - Section 5.1).
                // 2. Determine the current slot and time since last block (delta).
                // 3. If mode includes 'miner' or 'staker', attempt block production.
                // Example: engine.attempt_block_production(&mode);
            }
        }
    }

    warn!("Consensus Engine runtime loop terminated.");
}
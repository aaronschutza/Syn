// src/runtime.rs - Fixed imports and Arc method calling

use crate::engine::{ConsensusEngine}; 
// Corrected imports: Block and Transaction are defined in their own modules
use crate::block::Block;
use crate::transaction::Transaction;
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
}

/// The runtime loop for the Consensus Engine.
pub async fn run_consensus_loop(
    engine: Arc<ConsensusEngine>,
    mut receiver: mpsc::Receiver<ConsensusMessage>,
    mut shutdown_rx: broadcast::Receiver<()>,
    mode: String,
) {
    info!("Consensus Engine runtime loop started. Mode: {}", mode);

    loop {
        tokio::select! {
            Some(message) = receiver.recv() => {
                match message {
                    ConsensusMessage::NewBlock(block) => {
                        info!("Processing new block at height {}", block.height);
                        // Fixed E0599: engine is an Arc, but we can call process_block directly 
                        // because it takes &self and ConsensusEngine is the inner type.
                        match engine.process_block(&block) {
                            Ok(_) => info!("Block {} accepted.", block.height),
                            Err(e) => error!("Block {} rejected: {:?}", block.height, e),
                        }
                    },
                    ConsensusMessage::NewTransaction(_tx) => {
                        debug!("Received new transaction for mempool.");
                    },
                }
            },
            
            _ = shutdown_rx.recv() => {
                info!("Consensus Engine shutting down.");
                break;
            },
            
            _ = tokio::time::sleep(tokio::time::Duration::from_secs(1)) => {
                // Logic for slot-based block production checks...
            }
        }
    }

    warn!("Consensus Engine runtime loop terminated.");
}
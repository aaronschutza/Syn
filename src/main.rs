// src/main.rs - Integrated CLI and Node Entry point

pub mod block;
pub mod blockchain;
pub mod btc_p2p;
pub mod cli;
pub mod config;
pub mod consensus;
pub mod crypto;
pub mod dcs;
pub mod burst;
pub mod cdf;
pub mod fixed_point;
pub mod governance;
pub mod p2p;
pub mod params;
pub mod peer_manager;
pub mod pos;
pub mod progonos;
pub mod rpc;
pub mod script;
pub mod stk_module; 
pub mod transaction;
pub mod wallet;
pub mod engine;
pub mod gov_module;
pub mod spv;
pub mod storage;
pub mod client;
pub mod difficulty;
pub mod sync;
pub mod runtime;

use anyhow::Result;
use clap::Parser;
use cli::{Cli, Commands};
use log::info;
use p2p::P2PMessage;
use btc_p2p::BtcP2PMessage;
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc, Mutex};
use crate::params::{ParamManager, ConsensusParams};
use crate::stk_module::{StakingModule, BankModule};
use crate::gov_module::GovernanceModule;
use crate::storage::{GovernanceStore, HeaderStore};
use crate::difficulty::DynamicDifficultyManager;
use crate::engine::ConsensusEngine;
use crate::client::SpvClientState;

const CHANNEL_CAPACITY: usize = 100;

#[tokio::main]
async fn main() -> Result<()> {
    // FIX: Force logger to use Stdout to prevent PowerShell NativeCommandError artifacts
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .target(env_logger::Target::Stdout) 
        .init();

    let cli = Cli::parse();
    
    // Load config globally based on CLI flag
    let loaded_config = config::load(&cli.config)?;

    match cli.command {
        Commands::CreateWallet => {
            let wallet = wallet::Wallet::new();
            wallet.save_to_file(&loaded_config.node)?;
            println!("New wallet created and saved to {}", loaded_config.node.wallet_file);
            println!("Address: {}", wallet.get_address());
        }
        Commands::StartNode { mode, mine_to_address } => {
            // --- Engine Dependencies Initialization ---
            let param_manager = Arc::new(ParamManager::new());
            let bank_module = Arc::new(BankModule {}); 
            let staking_module = Arc::new(StakingModule::new(bank_module));
            let db_for_gov = Arc::new(sled::open(&cli.data_dir)?);
            let governance_store = GovernanceStore::new(db_for_gov.clone());
            let governance_module = Arc::new(GovernanceModule::new(param_manager.clone(), staking_module.clone(), governance_store));
            let difficulty_manager = Arc::new(DynamicDifficultyManager::new(param_manager.clone()));

            let consensus_engine = ConsensusEngine::new(
                param_manager.clone(),
                staking_module.clone(),
                governance_module.clone(),
                difficulty_manager.clone(),
                ConsensusParams::new(),
            );

            // --- Configuration Params ---
            let fee_params = Arc::new(loaded_config.fees.clone());
            let governance_params = Arc::new(loaded_config.governance.clone());
            let db_config = Arc::new(loaded_config.database.clone());
            
            let mut node_conf = loaded_config.node.clone();
            node_conf.db_path = cli.data_dir.clone();
            let node_config = Arc::new(node_conf);

            let p2p_config = Arc::new(loaded_config.p2p.clone());
            let progonos_config = Arc::new(loaded_config.progonos.clone());
            let consensus_params = Arc::new(loaded_config.consensus.clone());

            // --- SPV State Initialization ---
            let header_store = HeaderStore::new(db_for_gov.clone());
            let spv_state = Arc::new(SpvClientState::new(header_store));
            let spv_client = Arc::new(Mutex::new(progonos::SpvClient::new(&progonos_config)));

            // --- Blockchain Initialization ---
            let bc = Arc::new(Mutex::new(blockchain::Blockchain::new_with_db(
                db_for_gov.clone(),
                consensus_params.clone(),
                fee_params,
                governance_params.clone(),
                progonos_config.clone(),
                spv_state.clone(),
                db_config,
                consensus_engine, 
            )?));

            let peer_manager = Arc::new(Mutex::new(peer_manager::PeerManager::new(p2p_config.clone())));
            let (p2p_tx, _p2p_rx) = mpsc::channel::<P2PMessage>(CHANNEL_CAPACITY);
            let (broadcast_tx, _) = broadcast::channel::<P2PMessage>(CHANNEL_CAPACITY);
            let (_btc_p2p_tx, btc_p2p_rx) = mpsc::channel::<BtcP2PMessage>(CHANNEL_CAPACITY);
            let (to_consensus_tx, consensus_rx) = mpsc::channel(CHANNEL_CAPACITY);
            let (shutdown_tx, _) = broadcast::channel(1);

            let consensus_handle = tokio::spawn(consensus::start_consensus_loop(
                bc.clone(),
                mode,
                mine_to_address,
                consensus_rx,
                broadcast_tx.clone(),
                node_config.clone(),
                shutdown_tx.subscribe(),
            ));

            let p2p_handle = tokio::spawn(p2p::start_server(
                bc.clone(),
                to_consensus_tx.clone(),
                broadcast_tx.clone(),
                peer_manager,
                p2p_config.clone(),
                node_config.clone(),
                consensus_params.clone(),
                shutdown_tx.subscribe(),
            ));
            
            let rpc_handle = tokio::spawn(rpc::start_rpc_server(
                bc.clone(),
                spv_client.clone(),
                p2p_tx,
                governance_params.clone(),
                progonos_config.clone(),
                node_config.clone(),
                node_config.rpc_port,
                shutdown_tx.subscribe(),
            ));
            
            let btc_p2p_handle = tokio::spawn(btc_p2p::start_btc_p2p_client(
                spv_client.clone(),
                spv_state,
                progonos_config.clone(),
                btc_p2p_rx,
                shutdown_tx.subscribe(),
            ));

            tokio::select! {
                _ = tokio::signal::ctrl_c() => {
                    info!("Shutdown signal received.");
                    shutdown_tx.send(()).ok();
                }
                res = consensus_handle => res??,
                res = p2p_handle => res??,
                res = rpc_handle => res??,
                res = btc_p2p_handle => res??,
            }
        }
        _ => {
            rpc::client::handle_cli_command(cli.command, &loaded_config).await?;
        }
    }

    Ok(())
}
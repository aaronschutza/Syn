// src/config.rs

use anyhow::Result;
use serde::Deserialize;

/// The main configuration struct for the Synergeia node.
#[derive(Clone, Deserialize, Debug)]
pub struct Config {
    pub node: NodeConfig,
    pub p2p: P2PConfig,
    pub consensus: ConsensusConfig,
    pub fees: FeeConfig,
    pub governance: GovernanceConfig,
    pub database: DatabaseConfig,
    pub progonos: ProgonosConfig,
}

/// Node-specific configuration.
#[derive(Clone, Deserialize, Debug)]
pub struct NodeConfig {
    pub rpc_port: u16,
    pub rpc_host: String,
    pub p2p_port: u16,
    pub db_path: String,
    pub wallet_file: String,
    pub rpc_auth_token: Option<String>,
}

/// P2P-specific configuration.
#[derive(Clone, Deserialize, Debug)]
pub struct P2PConfig {
    pub max_message_size: usize,
    pub initial_score: i32,
    pub ban_threshold: i32,
    pub ban_duration_secs: u64,
    pub reconnect_delay_secs: u64,
    pub protocol_version: u32,
}

/// Consensus-specific configuration.
#[derive(Clone, Deserialize, Debug)]
pub struct ConsensusConfig {
    pub target_block_time: u64,
    pub adjustment_window: usize,
    pub psi_slot_gap: u32,
    pub gamma_recovery_threshold: u32,
    pub mempool_threshold: usize,
    pub witnessing_period: u64,
    pub pos_precision: String,
    pub fee_per_transaction: u64,
    pub coinbase_maturity: u32,
    pub coinbase_reward: u64,
    pub max_target_bits: u32,
    pub genesis_timestamp: u32,
    pub genesis_bits: u32,
    pub genesis_coinbase_data: String,
    pub genesis_address: String,
    pub block_version: i32,
    pub transaction_version: i32,
    pub total_supply: u64,
    pub nakamoto_target_block_time: u64,
    pub bootstrap_pos_block_threshold: u32,
    pub beacon_target_multiplier: u32,
    pub bootstrap_nodes: Vec<String>,
}

/// Database-specific configuration.
#[derive(Clone, Deserialize, Debug, Default)]
pub struct DatabaseConfig {
    pub blocks_tree: String,
    pub utxo_tree: String,
    pub tip_key: String,
    pub total_work_key: String,
    pub tx_index_tree: String,
}

/// Fee-specific configuration.
#[derive(Clone, Deserialize, Debug, Default)]
pub struct FeeConfig {
    pub target_staking_ratio: f64,
    pub min_burn_rate: f64,
    pub max_burn_rate: f64,
}

/// Governance-specific configuration.
#[derive(Clone, Deserialize, Debug, Default)]
pub struct GovernanceConfig {
    pub proposal_duration_blocks: u32,
    pub vote_threshold_percent: u64,
}

#[derive(Clone, Deserialize, Debug)]
pub struct ProgonosConfig {
    pub btc_confirmations: u32,
    pub btc_genesis_header: String,
}

/// Loads the configuration from the `synergeia.toml` file.
pub fn load(filename: &str) -> Result<Config> {
    let builder = config::Config::builder().add_source(config::File::with_name(filename));

    let cfg: Config = builder.build()?.try_deserialize()?;
    Ok(cfg)
}

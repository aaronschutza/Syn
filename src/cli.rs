// src/cli.rs - Global configuration and command definition

use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(author = "Proof-of-Consensus LLC", version = "0.1.0 (Kratos)", about = "Synergeia Node (Hybrid PoW/PoS)", long_about = None)]
pub struct Cli {
    /// Path to the configuration file.
    #[arg(long, global = true, default_value = "synergeia.toml")]
    pub config: String,

    /// Path to the database directory.
    #[arg(long, global = true, default_value = "./data_kratos")]
    pub data_dir: String,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Starts the Synergeia full node.
    StartNode {
        /// Sets the operating mode (e.g., miner, staker, full).
        #[arg(long, default_value = "full")]
        mode: String,
        
        /// Optional address to mine PoW rewards to.
        #[arg(long)]
        mine_to_address: Option<String>,
    },
    
    // --- Client Commands (Interact via RPC) ---
    /// Create a new wallet and address.
    CreateWallet,
    /// Check the balance of an address.
    GetBalance {
        #[arg(long)]
        address: String,
    },
    /// Send a transaction to another address.
    Send {
        #[arg(long)]
        to: String,
        #[arg(long)]
        amount: u64,
    },
    /// Get information about the current state of the blockchain.
    PrintChain,
    /// Simulate a Bitcoin deposit to mint SBTC via Progonos.
    DepositBtc,
    /// Initiate a withdrawal of SBTC to a Bitcoin address.
    WithdrawSbtc {
        #[arg(long)]
        btc_address: String,
        #[arg(long)]
        amount: u64,
    },
    /// Dispense testnet funds from a node to a specified address.
    Faucet {
        #[arg(long)]
        address: String,
        #[arg(long)]
        amount: u64,
    },
    /// Stake a specified amount of an asset.
    Stake {
        #[arg(long)]
        asset: String,
        #[arg(long)]
        amount: u64,
    },
}
// src/rpc.rs - Fixed syntax, filter arguments, and allowed unauthed print_chain

use crate::{
    blockchain::Blockchain, 
    config::{GovernanceConfig, NodeConfig, ProgonosConfig}, 
    governance::{Proposal, ProposalPayload}, 
    p2p::P2PMessage, 
    progonos, 
    transaction::{Transaction, TxIn, TxOut}, 
    wallet::{self, Wallet}, 
    stk_module::StakeInfo,
};
use anyhow::Result;
use bitcoin::{Address, BlockHash, Txid};
use log::{info, warn};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::{broadcast, Mutex};
use warp::{http::StatusCode, Filter, Rejection, Reply};
use bitcoin_hashes::{sha256d, Hash};


/// The structure of a JSON-RPC request.
#[derive(Serialize, Deserialize, Debug)]
pub struct RpcRequest {
    jsonrpc: String,
    method: String,
    params: Vec<serde_json::Value>,
    id: serde_json::Value,
}

/// The structure of a successful JSON-RPC response.
#[derive(Serialize, Deserialize, Debug)]
pub struct RpcResponse {
    jsonrpc: String,
    result: serde_json::Value,
    id: serde_json::Value,
}

/// The structure of a JSON-RPC error response.
#[derive(Serialize, Deserialize, Debug)]
pub struct RpcError {
    jsonrpc: String,
    error: serde_json::Value,
    id: serde_json::Value,
}

type RpcResult = std::result::Result<Box<dyn Reply>, Rejection>;

#[derive(Debug)]
struct Unauthorized;
impl warp::reject::Reject for Unauthorized {}

async fn handle_rejection(err: Rejection) -> std::result::Result<impl Reply, Rejection> {
    let code;
    let message;
    let id = json!(-1);

    if err.is_not_found() {
        code = StatusCode::NOT_FOUND;
        message = "NOT_FOUND";
    } else if err.find::<Unauthorized>().is_some() {
        code = StatusCode::UNAUTHORIZED;
        message = "UNAUTHORIZED";
    } else {
        eprintln!("unhandled rejection: {:?}", err);
        code = StatusCode::INTERNAL_SERVER_ERROR;
        message = "INTERNAL_SERVER_ERROR";
    }

    let json = warp::reply::json(&RpcError {
        jsonrpc: "2.0".to_string(),
        error: json!({"code": code.as_u16(), "message": message}),
        id,
    });

    Ok(warp::reply::with_status(json, code))
}


async fn handle_request(
    req: RpcRequest,
    blockchain: Arc<Mutex<Blockchain>>,
    spv_client: Arc<Mutex<progonos::SpvClient>>,
    p2p_tx: broadcast::Sender<P2PMessage>, // CHANGED: mpsc -> broadcast
    governance_config: Arc<GovernanceConfig>,
    progonos_config: Arc<ProgonosConfig>,
    node_config: Arc<NodeConfig>,
    auth_header: Option<String>,
) -> RpcResult {
    let id = req.id.clone();
    
    // Auth Check logic
    // We allow 'print_chain' and 'get_block' without auth for testnet visibility
    let is_public_method = match req.method.as_str() {
        "print_chain" | "get_block" | "get_transaction" | "get_mempool_info" => true,
        _ => false,
    };

    if !is_public_method {
        if let Some(required_token) = &node_config.rpc_auth_token {
            let expected = format!("Bearer {}", required_token);
            if auth_header.as_ref() != Some(&expected) {
                return Err(warp::reject::custom(Unauthorized));
            }
        }
    }

    match req.method.as_str() {
        "get_balance" => get_balance(req, blockchain).await,
        "send" => send(req, blockchain, p2p_tx, node_config).await,
        "print_chain" => print_chain(req, blockchain).await,
        "get_block" => get_block(req, blockchain).await,
        "get_transaction" => get_transaction(req, blockchain).await,
        "get_mempool_info" => get_mempool_info(req, blockchain).await,
        "initiate_withdrawal" => initiate_withdrawal(req, blockchain, p2p_tx, node_config, progonos_config).await, // Passed p2p_tx
        "submit_deposit_proof" => submit_deposit_proof(req, blockchain, spv_client, p2p_tx, node_config, progonos_config).await, // Passed p2p_tx
        "create_proposal" => create_proposal(req, blockchain, node_config, governance_config).await,
        "list_proposals" => list_proposals(req, blockchain).await,
        "vote" => vote(req, blockchain, node_config).await,
        "faucet" => faucet_coins(req, blockchain, p2p_tx).await, // Passed p2p_tx
        "stake" => rpc_stake(req, blockchain, node_config).await,
        _ => Ok(Box::new(warp::reply::json(&RpcError {
            jsonrpc: "2.0".to_string(),
            error: json!({"code": -32601, "message": "Method not found"}),
            id,
        }))),
    }
}

async fn rpc_stake(req: RpcRequest, blockchain: Arc<Mutex<Blockchain>>, node_config: Arc<NodeConfig>) -> RpcResult {
    if req.params.len() != 2 {
        return create_error_reply(req.id, -32602, "Invalid params: expected [asset, amount]");
    }
    let asset = req.params[0].as_str().unwrap_or("SYN").to_string();
    let amount = match req.params[1].as_u64() {
        Some(n) => n,
        None => return create_error_reply(req.id, -32602, "Amount must be integer"),
    };

    // 1. Update Wallet File (so pos.rs knows we are staking)
    let mut wallet = match Wallet::load_from_file(&node_config) {
        Ok(w) => w,
        Err(e) => return create_error_reply(req.id, -1, &format!("Wallet load error: {}", e)),
    };
    
    wallet.stake_info = Some(StakeInfo { asset, amount });
    if let Err(e) = wallet.save_to_file(&node_config) {
        return create_error_reply(req.id, -1, &format!("Wallet save error: {}", e));
    }

    // 2. Update Chain State (so eligibility math works)
    let bc = blockchain.lock().await;
    match bc.consensus_engine.staking_module.process_stake(wallet.get_address(), amount as u128) {
        Ok(_) => {
            info!("Stake registered: {} SYN for {}", amount, wallet.get_address());
            Ok(Box::new(warp::reply::json(&RpcResponse {
                jsonrpc: "2.0".to_string(),
                result: json!(format!("Stake of {} SYN processed and wallet updated.", amount)),
                id: req.id,
            })))
        },
        Err(e) => create_error_reply(req.id, -1, &format!("Staking failed: {}", e)),
    }
}

async fn faucet_coins(req: RpcRequest, blockchain: Arc<Mutex<Blockchain>>, p2p_tx: broadcast::Sender<P2PMessage>) -> RpcResult {
    if req.params.len() != 2 {
        return create_error_reply(req.id, -32602, "Invalid params: expected [address, amount]");
    }
    let to_address = match req.params[0].as_str() {
        Some(s) => s.to_string(),
        None => return create_error_reply(req.id, -32602, "Invalid params: address must be a string"),
    };
    let amount = match req.params[1].as_u64() {
        Some(n) => n,
        None => return create_error_reply(req.id, -32602, "Invalid params: amount must be a positive integer"),
    };

    let mut bc_lock = blockchain.lock().await;

    if bc_lock.mempool.len() >= bc_lock.consensus_params.mempool_threshold {
         return create_error_reply(req.id, -32001, "Mempool full. Cannot process faucet request.");
    }
    
    let is_coinbase_pending = bc_lock.mempool.values().any(|tx| tx.is_coinbase());
    if is_coinbase_pending {
        return create_error_reply(req.id, -32002, "Another coin-creating transaction is already pending. Please wait for the next block.");
    }
    
    let faucet_tx = Transaction {
        version: bc_lock.consensus_params.transaction_version,
        vin: vec![TxIn {
            prev_txid: sha256d::Hash::all_zeros(),
            prev_vout: u32::MAX,
            script_sig: b"faucet".to_vec(),
            sequence: u32::MAX,
        }],
        vout: vec![TxOut::new(amount, to_address.clone())],
        lock_time: 0,
    };
    let txid = faucet_tx.id();
    
    bc_lock.mempool.insert(txid, faucet_tx.clone());
    
    // GOSSIP THE FAUCET TX
    if p2p_tx.send(P2PMessage::NewTransaction(faucet_tx)).is_err() {
        warn!("Failed to broadcast faucet transaction");
    }

    info!("Faucet dispensed {} coins to {}. TXID: {}", amount, to_address, txid);

    Ok(Box::new(warp::reply::json(&RpcResponse {
        jsonrpc: "2.0".to_string(),
        result: json!(txid.to_string()),
        id: req.id,
    })))
}


fn create_error_reply(id: serde_json::Value, code: i32, message: &str) -> RpcResult {
    Ok(Box::new(warp::reply::json(&RpcError {
        jsonrpc: "2.0".to_string(),
        error: json!({"code": code, "message": message}),
        id,
    })))
}

async fn get_balance(req: RpcRequest, blockchain: Arc<Mutex<Blockchain>>) -> RpcResult {
    if req.params.len() != 1 {
        return create_error_reply(req.id, -32602, "Invalid params: expected [address]");
    }
    let address = match req.params[0].as_str() {
        Some(s) => s.to_string(),
        None => return create_error_reply(req.id, -32602, "Invalid params: address must be a string"),
    };

    let bc_lock = blockchain.lock().await;
    let balance = match bc_lock.find_spendable_outputs(&address, 0) {
        Ok((bal, _)) => bal,
        Err(_) => 0,
    };

    Ok(Box::new(warp::reply::json(&RpcResponse {
        jsonrpc: "2.0".to_string(),
        result: json!(balance),
        id: req.id,
    })))
}

async fn send(req: RpcRequest, blockchain: Arc<Mutex<Blockchain>>, p2p_tx: broadcast::Sender<P2PMessage>, node_config: Arc<NodeConfig>) -> RpcResult {
    if req.params.len() != 2 {
        return create_error_reply(req.id, -32602, "Invalid params: expected [to_address, amount]");
    }
    let to_address = match req.params[0].as_str() {
        Some(s) => s.to_string(),
        None => return create_error_reply(req.id, -32602, "Invalid params: to_address must be a string"),
    };
    let amount = match req.params[1].as_u64() {
        Some(n) => n,
        None => return create_error_reply(req.id, -32602, "Invalid params: amount must be a positive integer"),
    };

    let wallet = match wallet::Wallet::load_from_file(&node_config) {
        Ok(w) => w,
        Err(e) => return create_error_reply(req.id, -1, &format!("Failed to load wallet: {}", e)),
    };

    let mut bc_lock = blockchain.lock().await;

    match Transaction::new_utxo_transaction(&wallet, to_address, amount, &mut bc_lock) {
        Ok((tx, _)) => {
            let txid = tx.id();
            bc_lock.mempool.insert(txid, tx.clone());
            
            // Broadcast::send returns the number of receivers, or error if channel closed.
            // We ignore the count.
            if p2p_tx.send(P2PMessage::NewTransaction(tx)).is_err() {
                 warn!("Failed to broadcast transaction to P2P network");
                 return create_error_reply(req.id, -1, "Failed to broadcast transaction to P2P network");
            }
            Ok(Box::new(warp::reply::json(&RpcResponse {
                jsonrpc: "2.0".to_string(),
                result: json!(txid.to_string()),
                id: req.id,
            })))
        }
        Err(e) => create_error_reply(req.id, -1, &e.to_string()),
    }
}

async fn print_chain(req: RpcRequest, blockchain: Arc<Mutex<Blockchain>>) -> RpcResult {
    let bc_lock = blockchain.lock().await;
    let tip_hash = bc_lock.tip;
    let tip_block = bc_lock.get_block(&tip_hash);
    let height = tip_block.map_or(0, |b| b.height);
    let tip_hash_str = tip_hash.to_string();

    let chain_info = json!({
        "height": height,
        "tip": tip_hash_str,
    });

    Ok(Box::new(warp::reply::json(&RpcResponse {
        jsonrpc: "2.0".to_string(),
        result: chain_info,
        id: req.id,
    })))
}

async fn get_block(req: RpcRequest, blockchain: Arc<Mutex<Blockchain>>) -> RpcResult {
    let hash_str = req.params.get(0).and_then(|v| v.as_str()).unwrap_or_default();
    let hash = match sha256d::Hash::from_str(hash_str) {
        Ok(h) => h,
        Err(_) => return create_error_reply(req.id, -32602, "Invalid block hash"),
    };
    let bc_lock = blockchain.lock().await;
    let block = bc_lock.get_block(&hash);
     Ok(Box::new(warp::reply::json(&RpcResponse {
        jsonrpc: "2.0".to_string(),
        result: json!(block),
        id: req.id,
    })))
}

async fn get_transaction(req: RpcRequest, blockchain: Arc<Mutex<Blockchain>>) -> RpcResult {
    let txid_str = req.params.get(0).and_then(|v| v.as_str()).unwrap_or_default();
    let txid = match sha256d::Hash::from_str(txid_str) {
        Ok(h) => h,
        Err(_) => return create_error_reply(req.id, -32602, "Invalid transaction ID"),
    };
    let bc_lock = blockchain.lock().await;
    let tx = match bc_lock.get_transaction(&txid) {
        Ok(t) => t,
        Err(e) => return create_error_reply(req.id, -1, &e.to_string()),
    };
    Ok(Box::new(warp::reply::json(&RpcResponse {
        jsonrpc: "2.0".to_string(),
        result: json!(tx),
        id: req.id,
    })))
}

async fn get_mempool_info(req: RpcRequest, blockchain: Arc<Mutex<Blockchain>>) -> RpcResult {
    let bc_lock = blockchain.lock().await;
    let mempool_txids: Vec<_> = bc_lock.mempool.keys().collect();
    Ok(Box::new(warp::reply::json(&RpcResponse {
        jsonrpc: "2.0".to_string(),
        result: json!({
            "tx_count": mempool_txids.len(),
            "txids": mempool_txids
        }),
        id: req.id,
    })))
}

async fn initiate_withdrawal(req: RpcRequest, blockchain: Arc<Mutex<Blockchain>>, p2p_tx: broadcast::Sender<P2PMessage>, node_config: Arc<NodeConfig>, _progonos_config: Arc<ProgonosConfig>) -> RpcResult {
    let btc_address_str = req.params.get(0).and_then(|v| v.as_str()).unwrap_or_default();
    let amount = req.params.get(1).and_then(|v| v.as_u64()).unwrap_or_default();

    if Address::from_str(btc_address_str).is_err() {
        return create_error_reply(req.id, -32602, "Invalid Bitcoin address");
    };

    let mut bc_lock = blockchain.lock().await;
    let _wallet = wallet::Wallet::load_from_file(&node_config).unwrap();

    let burn_output = Transaction::create_burn_output(amount);
    let burn_tx = Transaction {
        version: bc_lock.consensus_params.transaction_version,
        vin: vec![],
        vout: vec![burn_output],
        lock_time: 0,
    };
    let txid = burn_tx.id();
    bc_lock.mempool.insert(txid, burn_tx.clone());

    // GOSSIP
    if p2p_tx.send(P2PMessage::NewTransaction(burn_tx)).is_err() {
        warn!("Failed to broadcast withdrawal transaction");
    }

    info!("Withdrawal initiated. Burn transaction {} broadcast.", txid);
    Ok(Box::new(warp::reply::json(&RpcResponse {
        jsonrpc: "2.0".to_string(),
        result: json!({
            "message": "Withdrawal initiated. Burn transaction created. Please wait for confirmation before generating the PSBT.",
            "burn_txid": txid.to_string(),
        }),
        id: req.id,
    })))
}


async fn submit_deposit_proof(req: RpcRequest, blockchain: Arc<Mutex<Blockchain>>, spv_client: Arc<Mutex<progonos::SpvClient>>, p2p_tx: broadcast::Sender<P2PMessage>, node_config: Arc<NodeConfig>, progonos_config: Arc<ProgonosConfig>) -> RpcResult {
    let btc_txid_str = req.params.get(0).and_then(|v| v.as_str()).unwrap_or_default();
    let btc_block_hash_str = req.params.get(1).and_then(|v| v.as_str()).unwrap_or_default();
    let merkle_proof_str = req.params.get(2).and_then(|v| v.as_str()).unwrap_or_default();
    let amount = req.params.get(3).and_then(|v| v.as_u64()).unwrap_or(0);

    let btc_txid = match Txid::from_str(btc_txid_str) {
        Ok(txid) => txid,
        Err(_) => return create_error_reply(req.id, -32602, "Invalid Bitcoin transaction ID format"),
    };
    let btc_block_hash = match BlockHash::from_str(btc_block_hash_str) {
        Ok(hash) => hash,
        Err(_) => return create_error_reply(req.id, -32602, "Invalid Bitcoin block hash format"),
    };
    let merkle_proof = match hex::decode(merkle_proof_str) {
        Ok(proof) => proof,
        Err(_) => return create_error_reply(req.id, -32602, "Invalid Merkle proof format; must be hex-encoded"),
    };

    let mut bc = blockchain.lock().await;
    let spv = spv_client.lock().await;

    let proof = progonos::DepositProof { btc_txid, btc_block_hash, merkle_proof };
    
    let wallet = match wallet::Wallet::load_from_file(&node_config) {
        Ok(w) => w,
        Err(e) => return create_error_reply(req.id, -1, &format!("Failed to load wallet: {}", e)),
    };
    let mint_to_address = wallet.get_address();

    match progonos::verify_and_mint_sbtc(&mut bc, &spv, proof, mint_to_address, amount, &progonos_config).await {
        Ok(mint_tx) => {
            // GOSSIP MINT TX
            if p2p_tx.send(P2PMessage::NewTransaction(mint_tx)).is_err() {
                warn!("Failed to broadcast mint transaction");
            }
            
            Ok(Box::new(warp::reply::json(&RpcResponse {
                jsonrpc: "2.0".to_string(),
                result: json!("sBTC minting transaction created and sent to mempool."),
                id: req.id,
            })))
        },
        Err(e) => create_error_reply(req.id, -1, &e.to_string()),
    }
}

async fn create_proposal(req: RpcRequest, blockchain: Arc<Mutex<Blockchain>>, node_config: Arc<NodeConfig>, governance_config: Arc<GovernanceConfig>) -> RpcResult {
    let title = req.params.get(0).and_then(|v| v.as_str()).unwrap_or_default().to_string();
    let description = req.params.get(1).and_then(|v| v.as_str()).unwrap_or_default().to_string();
    let wallet = wallet::Wallet::load_from_file(&node_config).unwrap();

    let mut bc_lock = blockchain.lock().await;
    let tip_hash = bc_lock.tip;
    let current_height = bc_lock.get_block(&tip_hash).map_or(0, |b| b.height);

    let proposal_id = bc_lock.governance.create_proposal(
        wallet.get_address(), title, description, current_height, ProposalPayload::None, &governance_config);

    Ok(Box::new(warp::reply::json(&RpcResponse {
        jsonrpc: "2.0".to_string(),
        result: json!({ "message": "Proposal created successfully", "proposal_id": proposal_id }),
        id: req.id,
    })))
}

async fn list_proposals(req: RpcRequest, blockchain: Arc<Mutex<Blockchain>>) -> RpcResult {
    let bc_lock = blockchain.lock().await;
    let proposals: Vec<&Proposal> = bc_lock.governance.proposals.values().collect();
    Ok(Box::new(warp::reply::json(&RpcResponse {
        jsonrpc: "2.0".to_string(),
        result: json!(proposals),
        id: req.id,
    })))
}

async fn vote(req: RpcRequest, blockchain: Arc<Mutex<Blockchain>>, node_config: Arc<NodeConfig>) -> RpcResult {
    let proposal_id = req.params.get(0).and_then(|v| v.as_u64()).unwrap_or_default();
    let in_favor = req.params.get(1).and_then(|v| v.as_bool()).unwrap_or_default();
    let wallet = wallet::Wallet::load_from_file(&node_config).unwrap();
    let stake = wallet.stake_info.map_or(0, |s| s.amount as u64);

    let mut bc_lock = blockchain.lock().await;
    match bc_lock.governance.cast_vote(proposal_id, stake, in_favor) {
        Ok(_) => Ok(Box::new(warp::reply::json(&RpcResponse {
            jsonrpc: "2.0".to_string(),
            result: json!({ "message": "Vote cast successfully" }),
            id: req.id,
        }))),
        Err(e) => create_error_reply(req.id, -1, &e),
    }
}

pub async fn start_rpc_server(
    blockchain: Arc<Mutex<Blockchain>>,
    spv_client: Arc<Mutex<progonos::SpvClient>>,
    p2p_tx: broadcast::Sender<P2PMessage>, // CHANGED: mpsc -> broadcast
    governance_config: Arc<GovernanceConfig>,
    progonos_config: Arc<ProgonosConfig>,
    node_config: Arc<NodeConfig>,
    port: u16,
    mut shutdown_rx: broadcast::Receiver<()>,
) -> Result<()> {
    let blockchain_filter = warp::any().map(move || blockchain.clone());
    let spv_client_filter = warp::any().map(move || spv_client.clone());
    let p2p_tx_filter = warp::any().map(move || p2p_tx.clone());
    let governance_config_filter = warp::any().map(move || governance_config.clone());
    let progonos_config_filter = warp::any().map(move || progonos_config.clone());
    
    // Auth filter now just extracts the header if present, handle_request does the logic
    let auth_filter = warp::header::optional("authorization");
    
    let node_config_clone = node_config.clone();
    let node_config_filter = warp::any().map(move || node_config_clone.clone());

    let rpc = warp::post()
        .and(warp::body::json())
        .and(blockchain_filter)
        .and(spv_client_filter)
        .and(p2p_tx_filter)
        .and(governance_config_filter)
        .and(progonos_config_filter)
        .and(node_config_filter)
        .and(auth_filter)
        .and_then(|req, bc, spv, p2p, gov, prog, node, auth| async move {
            handle_request(req, bc, spv, p2p, gov, prog, node, auth).await
        })
        .recover(handle_rejection);

    let addr = (node_config.rpc_host.parse::<std::net::IpAddr>()?, port);
    let server = warp::serve(rpc);
    let (_, server_fut) = server.bind_with_graceful_shutdown(addr, async move {
        shutdown_rx.recv().await.ok();
        info!("RPC server shutting down.");
    });

    info!("RPC server listening on port {}", port);
    server_fut.await;
    Ok(())
}

pub mod client {
    use anyhow::Result;
    use serde_json::json;
    use crate::config::Config;
    use super::{RpcRequest, RpcResponse, RpcError};
    use crate::cli::Commands;
    use reqwest;

    pub async fn handle_cli_command(command: Commands, config: &Config) -> Result<()> {
        match command {
            Commands::GetBalance { address } => {
                let balance = get_balance(&address, config).await?;
                println!("Balance for {}: {}", address, balance);
            }
            Commands::Send { to, amount } => {
                let txid = send_transaction(&to, amount as u64, config).await?;
                println!("Transaction sent. TXID: {}", txid);
            }
            Commands::PrintChain => {
                let chain_info = print_chain(config).await?;
                println!("{}", serde_json::to_string_pretty(&chain_info)?);
            }
            Commands::Faucet { address, amount } => {
                let txid = request_faucet_coins(config, &address, amount).await?;
                println!("Faucet dispensed coins. TXID: {}", txid);
            }
            Commands::Stake { asset, amount } => {
                let res = stake_asset(config, &asset, amount).await?;
                println!("{}", res);
            }
            Commands::DepositBtc => {
                 println!("This command is a placeholder.");
            }
            Commands::WithdrawSbtc{ btc_address, amount } => {
                let response = initiate_withdrawal(&btc_address, amount as u64, config).await?;
                println!("{}", serde_json::to_string_pretty(&response)?);
            }
            _ => {
                println!("This command is not handled by the RPC client.");
            }
        }
        Ok(())
    }

    async fn call_rpc(method: &str, params: Vec<serde_json::Value>, config: &Config) -> Result<serde_json::Value> {
        let client = reqwest::Client::new();
        let req = RpcRequest {
            jsonrpc: "2.0".to_string(),
            method: method.to_string(),
            params,
            id: json!(1),
        };

        let mut request_builder = client.post(format!("http://{}:{}", config.node.rpc_host, config.node.rpc_port));

        if let Some(token) = &config.node.rpc_auth_token {
            request_builder = request_builder.header("Authorization", format!("Bearer {}", token));
        }
        
        let response = request_builder.json(&req).send().await?;

        let text = response.text().await?;
        if let Ok(err) = serde_json::from_str::<RpcError>(&text) {
                anyhow::bail!("RPC Error: {}", err.error);
        }

        let res: RpcResponse = serde_json::from_str(&text)?;

        Ok(res.result)
    }

    pub async fn request_faucet_coins(config: &Config, address: &str, amount: u64) -> Result<String> {
        let params = vec![json!(address), json!(amount)];
        let result = call_rpc("faucet", params, config).await?;
        Ok(result.as_str().unwrap_or("").to_string())
    }

    pub async fn stake_asset(config: &Config, asset: &str, amount: u64) -> Result<String> {
        let params = vec![json!(asset), json!(amount)];
        let result = call_rpc("stake", params, config).await?;
        Ok(result.as_str().unwrap_or("").to_string())
    }

    pub async fn get_balance(address: &str, config: &Config) -> Result<u64> {
        let params = vec![json!(address)];
        let result = call_rpc("get_balance", params, config).await?;
        Ok(result.as_u64().unwrap_or(0))
    }

    pub async fn print_chain(config: &Config) -> Result<serde_json::Value> {
        call_rpc("print_chain", vec![], config).await
    }

    pub async fn send_transaction(to: &str, amount: u64, config: &Config) -> Result<String> {
        let params = vec![json!(to), json!(amount)];
        let result = call_rpc("send", params, config).await?;
        Ok(result.as_str().unwrap_or("").to_string())
    }

    pub async fn initiate_withdrawal(btc_address: &str, amount: u64, config: &Config) -> Result<serde_json::Value> {
        let params = vec![json!(btc_address), json!(amount)];
        let result = call_rpc("initiate_withdrawal", params, config).await?;
        Ok(result)
    }
}
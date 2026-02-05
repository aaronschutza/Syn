// src/tests/integration_tests.rs - Updated to fix imports and remove unused dependencies

#[cfg(test)]
mod tests {
    use crate::{
        block::BlockHeader,
        blockchain::{self},
        config::{self, NodeConfig, GovernanceConfig},
        transaction::Transaction,
        wallet,
        engine::ConsensusEngine,
        params::{ParamManager, ConsensusParams},
        stk_module::{StakingModule, BankModule},
        gov_module::GovernanceModule,
        storage::{GovernanceStore, HeaderStore},
        difficulty::DynamicDifficultyManager,
        client::SpvClientState,
    };
    use anyhow::Result;
    use bitcoin_hashes::{sha256d, Hash};
    use num_bigint::BigUint;
    use std::sync::Arc;
    use tokio::sync::Mutex;
    use crate::fixed_point::Fixed;

    const DB_PATH: &str = "test_db_";
    const WALLET_FILE: &str = "test_wallet_";

    fn setup_test_env(test_name: &str) -> (Arc<Mutex<blockchain::Blockchain>>, wallet::Wallet, NodeConfig, GovernanceConfig) {
        let db_path = format!("{}{}", DB_PATH, test_name);
        let wallet_file = format!("{}{}", WALLET_FILE, test_name);

        let _ = std::fs::remove_dir_all(&db_path);
        let _ = std::fs::remove_file(&wallet_file);
        let config = config::load("synergeia.toml").unwrap();
        let governance_config_clone = config.governance.clone();
        
        let mut consensus_config_val = config.consensus.clone();
        consensus_config_val.coinbase_maturity = 1;
        consensus_config_val.pos_precision = "test".to_string();
        let consensus_config = Arc::new(consensus_config_val);
        
        let fee_config = Arc::new(config.fees.clone());
        let db_config = Arc::new(config.database.clone());
        let progonos_config = Arc::new(config.progonos.clone());
        
        let db = Arc::new(sled::open(&db_path).unwrap());

        let param_manager = Arc::new(ParamManager::new());
        let bank_module = Arc::new(BankModule {});
        let staking_module = Arc::new(StakingModule::new(bank_module));
        
        let governance_store = GovernanceStore::new(db.clone()); 
        let governance_module = Arc::new(GovernanceModule::new(param_manager.clone(), staking_module.clone(), governance_store));
        let difficulty_manager = Arc::new(DynamicDifficultyManager::new(param_manager.clone()));
        
        let header_store = HeaderStore::new(db.clone());
        let spv_state = Arc::new(SpvClientState::new(header_store));

        let consensus_engine = ConsensusEngine::new(
            param_manager.clone(),
            staking_module.clone(),
            governance_module.clone(),
            difficulty_manager.clone(),
            ConsensusParams::new(),
        );

        let bc_arc = Arc::new(Mutex::new(
            blockchain::Blockchain::new_with_db(
                db, 
                consensus_config, 
                fee_config, 
                Arc::new(governance_config_clone.clone()), 
                progonos_config,
                spv_state,
                db_config, 
                consensus_engine
            ).unwrap(),
        ));
        
        let wallet = {
            let wallet = wallet::Wallet::new();
            let node_config_inner = NodeConfig {
                rpc_port: 0,
                rpc_host: "127.0.0.1".to_string(),
                p2p_port: 0,
                db_path: db_path.clone(),
                wallet_file: wallet_file.clone(),
                rpc_auth_token: None,
            };
            wallet.save_to_file(&node_config_inner).unwrap();
            wallet
        };

        let node_config = NodeConfig {
            rpc_port: 0,
            rpc_host: "127.0.0.1".to_string(),
            p2p_port: 0,
            db_path,
            wallet_file,
            rpc_auth_token: None,
        };

        (bc_arc, wallet, node_config, governance_config_clone)
    }

    async fn cleanup_test_env(node_config: NodeConfig) {
        let _ = std::fs::remove_dir_all(&node_config.db_path);
        let _ = std::fs::remove_file(&node_config.wallet_file);
    }

    fn mine_next_block_sync(bc: &mut blockchain::Blockchain, mine_to_address: String) -> Result<()> {
        let txs = bc.get_mempool_txs();
        let mut final_txs = vec![Transaction::new_coinbase(
            "Mined for Test".to_string(),
            mine_to_address.clone(),
            bc.consensus_params.coinbase_reward,
            bc.consensus_params.transaction_version,
        )];
        final_txs.extend(txs);
        let block_version = bc.consensus_params.block_version;
        let tip_hash = bc.tip;

        let mut block = bc.create_block_template(final_txs, block_version)?;

        let target = BlockHeader::calculate_target(block.header.bits);
        while {
            let hash_biguint = BigUint::from_bytes_be(block.header.hash().as_ref());
            hash_biguint > target
        } {
            if bc.tip != tip_hash {
                anyhow::bail!("Aborting mining due to new block from network.");
            }
            block.header.nonce = block.header.nonce.wrapping_add(1);
        }

        bc.add_block(block)?;
        Ok(())
    }

    async fn mine_next_block(bc_arc: Arc<Mutex<blockchain::Blockchain>>, mine_to_address: String) -> Result<()> {
        let mut bc_lock = bc_arc.lock().await;
        mine_next_block_sync(&mut bc_lock, mine_to_address)
    }

    #[tokio::test]
    async fn test_0_node_startup_and_genesis() {
        let test_name = "0";
        let (bc_arc, _wallet, node_config, _g) = setup_test_env(test_name);
        
        {
            let bc_lock = bc_arc.lock().await;
            assert_ne!(bc_lock.tip, sha256d::Hash::all_zeros(), "Blockchain tip should not be zero hash after initialization.");
            let genesis_block = bc_lock.get_block(&bc_lock.tip).unwrap();
            assert_eq!(genesis_block.height, 0, "Genesis block height should be 0.");
        }

        cleanup_test_env(node_config).await;
    }
    
    #[tokio::test]
    async fn test_3_mixed_pow_pos_chain_and_ldd() -> Result<()> {
        let test_name = "3";
        let (bc_arc, miner_wallet, node_config, _g) = setup_test_env(test_name);

        {
            let mut bc_lock = bc_arc.lock().await;
            bc_lock.ldd_state.f_a_pow = Fixed::from_f64(0.8);
            bc_lock.ldd_state.f_a_pos = Fixed::from_f64(0.8);
        }
        
        mine_next_block(bc_arc.clone(), miner_wallet.get_address()).await?;
        cleanup_test_env(node_config).await;
        Ok(())
    }
}
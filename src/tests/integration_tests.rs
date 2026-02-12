// src/tests/integration_tests.rs - Updated to match Block::new schema

#[cfg(test)]
mod tests {
    use crate::{
        block::{Block, BlockHeader},
        blockchain::{self},
        config::{self, NodeConfig, GovernanceConfig},
        pos::{self}, 
        transaction::Transaction,
        wallet,
        engine::ConsensusEngine,
        params::{ParamManager, ConsensusParams},
        stk_module::{StakingModule, BankModule, StakeInfo}, 
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
        
        let mut governance_config_clone = config.governance.clone();
        governance_config_clone.proposal_duration_blocks = 5;
        
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
        let tip_hash = bc.tip;
        let prev_block = bc.get_block(&tip_hash).unwrap();
        
        let min_delta = bc.ldd_state.current_psi + 1;
        let target_time = prev_block.header.time + min_delta;
        
        let txs = bc.get_mempool_txs();
        let mut final_txs = vec![Transaction::new_coinbase(
            "Mined for Test".to_string(),
            mine_to_address.clone(),
            bc.consensus_params.coinbase_reward,
            bc.consensus_params.transaction_version,
        )];
        final_txs.extend(txs);
        
        let bits = bc.get_next_work_required(true, min_delta);

        // Updated Block::new call
        let mut block = Block::new(
            target_time, 
            final_txs, 
            tip_hash, 
            bits, 
            prev_block.height + 1, 
            bc.consensus_params.block_version,
            0, // proven_burn
            bc.total_staked // committed_total_stake
        );
        
        block.header.utxo_root = bc.calculate_utxo_root()?;

        let target = BlockHeader::calculate_target(block.header.bits);
        
        let mut attempts = 0;
        while {
            let hash_biguint = BigUint::from_bytes_be(block.header.hash().as_ref());
            hash_biguint > target
        } {
            if bc.tip != tip_hash {
                anyhow::bail!("Aborting mining due to new block from network.");
            }
            block.header.nonce = block.header.nonce.wrapping_add(1);
            attempts += 1;
            if attempts > 1_000_000 {
                anyhow::bail!("Mining timed out - difficulty too high?");
            }
        }

        bc.add_block(block)?;
        Ok(())
    }

    async fn mine_next_block(bc_arc: Arc<Mutex<blockchain::Blockchain>>, mine_to_address: String) -> Result<()> {
        let mut bc_lock = bc_arc.lock().await;
        mine_next_block_sync(&mut bc_lock, mine_to_address)
    }

    async fn get_balance(bc_arc: Arc<Mutex<blockchain::Blockchain>>, address: &str) -> u64 {
        let bc_lock = bc_arc.lock().await;
        bc_lock.find_spendable_outputs(address, 0).map(|(bal, _)| bal).unwrap_or(0)
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
    async fn test_1_faucet_minting_and_maturity() -> Result<()> {
        let test_name = "1";
        let (bc_arc, wallet, node_config, _g) = setup_test_env(test_name);
        let address = wallet.get_address();

        mine_next_block(bc_arc.clone(), address.clone()).await?;

        let initial_balance = get_balance(bc_arc.clone(), &address).await;
        let coinbase_reward = bc_arc.lock().await.consensus_params.coinbase_reward;
        assert_eq!(initial_balance, coinbase_reward, "Balance should equal one coinbase reward after mining one block.");
        
        for i in 0..10 {
            mine_next_block(bc_arc.clone(), format!("miner-{}", i)).await?;
        }
        
        mine_next_block(bc_arc.clone(), address.clone()).await?;
        mine_next_block(bc_arc.clone(), "maturing_block".to_string()).await?;
        let final_balance = get_balance(bc_arc.clone(), &address).await;
        let expected_balance = coinbase_reward;

        assert_eq!(final_balance, expected_balance, "Balance should include all matured coinbase rewards.");
        
        cleanup_test_env(node_config).await;
        Ok(())
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

        let stake_amount = 100000;
        let staker_wallet = {
            let mut w = wallet::Wallet::new();
            w.stake_info = Some(StakeInfo { asset: "SYN".to_string(), amount: stake_amount });
            w
        };
        let staker_address = staker_wallet.get_address();
        let miner_address = miner_wallet.get_address();

        mine_next_block(bc_arc.clone(), miner_address.clone()).await?;

        {
            let mut bc_lock = bc_arc.lock().await;
            let (tx, _) = Transaction::new_utxo_transaction(&miner_wallet, staker_address.clone(), stake_amount, &mut bc_lock)
                .expect("Failed to create transaction to fund staker");
            bc_lock.mempool.insert(tx.id(), tx);
        }
        mine_next_block(bc_arc.clone(), miner_address.clone()).await?;

        {
            let mut bc_lock = bc_arc.lock().await;
            bc_lock.total_staked = stake_amount;
            bc_lock.consensus_engine.staking_module.process_stake(staker_address.clone(), stake_amount as u128).unwrap();
        }

        let mut pow_blocks_produced = 0;
        let mut pos_blocks_produced = 0;

        for block_num in 0..20 {
            let (last_block_time, tip_hash, version, consensus_params_clone) = {
                let bc_lock = bc_arc.lock().await;
                let last_block = bc_lock.get_block(&bc_lock.tip).unwrap();
                (
                    last_block.header.time,
                    bc_lock.tip,
                    bc_lock.consensus_params.block_version,
                    bc_lock.consensus_params.clone(),
                )
            };
            
            let staker_wallet_clone = staker_wallet.clone();
            let bc_arc_clone_pos = bc_arc.clone();
            let pos_task: tokio::task::JoinHandle<Result<(Block, bool)>> = tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                
                let mut current_time = last_block_time + 1;
                loop {
                    {
                        let mut bc_lock = bc_arc_clone_pos.lock().await;
                        if tip_hash != bc_lock.tip {
                            anyhow::bail!("New block found, restarting PoS");
                        }
                        // Updated to capture committed_total_stake
                        if let Some((pi, delta_actual, total_stake)) = pos::is_eligible_to_stake(&staker_wallet_clone, &bc_lock, current_time as u64) {
                            let block = pos::create_pos_block(&mut bc_lock, &staker_wallet_clone, pi, delta_actual as u32, current_time, total_stake).unwrap();
                            return Ok((block, false));
                        }
                    }
                    current_time += 1;
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            });

            let miner_address_clone = miner_address.clone();
            let bc_arc_clone_pow = bc_arc.clone();
            let pow_task: tokio::task::JoinHandle<Result<(Block, bool)>> = tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                if tip_hash != bc_arc_clone_pow.lock().await.tip {
                    anyhow::bail!("New block found, restarting PoW");
                }
                
                let bits = 0x207fffff;
                let target = BlockHeader::calculate_target(bits);

                let (transactions, utxo_root, total_stake) = {
                    let bc_lock = bc_arc_clone_pow.lock().await;
                    let coinbase = Transaction::new_coinbase("Mined for Test".to_string(), miner_address_clone.clone(), consensus_params_clone.coinbase_reward, consensus_params_clone.transaction_version);
                    (vec![coinbase], bc_lock.calculate_utxo_root().unwrap_or(sha256d::Hash::all_zeros()), bc_lock.total_staked)
                };

                let merkle_root = Block::compute_merkle_root(&transactions);
                let current_time = { bc_arc_clone_pow.lock().await.get_block(&tip_hash).unwrap().header.time + 1 };

                let mut header = BlockHeader { 
                    version, 
                    prev_blockhash: tip_hash, 
                    merkle_root, 
                    utxo_root, 
                    time: current_time, 
                    bits, 
                    nonce: 0, 
                    vrf_proof: None,
                    proven_burn: 0,
                    committed_total_stake: total_stake, // Updated
                };

                while BigUint::from_bytes_be(header.hash().as_ref()) > target {
                    header.nonce = header.nonce.wrapping_add(1);
                    if header.nonce % 1000 == 0 {
                        tokio::task::yield_now().await;
                    }
                }

                let height = { 
                    let bc_lock = bc_arc_clone_pow.lock().await;
                    bc_lock.get_block(&tip_hash).unwrap().height + 1
                };
                
                let mut block = Block::new(
                    header.time, 
                    transactions, 
                    header.prev_blockhash, 
                    header.bits, 
                    height, 
                    header.version, 
                    0, 
                    total_stake // Updated
                );
                block.header = header;
                return Ok((block, true));
            });


            let (next_block, is_pow): (Block, bool) = tokio::select! {
                res = pos_task => res.unwrap().unwrap(),
                res = pow_task => res.unwrap().unwrap(),
            };

            {
                let mut bc_lock = bc_arc.lock().await;
                let block_time = next_block.header.time;
                bc_lock.add_block(next_block)?;

                if is_pow {
                    pow_blocks_produced += 1;
                    println!("Block {} (PoW) produced at time {}", block_num + 3, block_time);
                } else {
                    pos_blocks_produced += 1;
                    println!("Block {} (PoS) produced at time {}", block_num + 3, block_time);
                }
            }
        }

        assert!(pow_blocks_produced > 0, "Should have produced at least one PoW block.");
        assert!(pos_blocks_produced > 0, "Should have produced at least one PoS block.");

        cleanup_test_env(node_config).await;
        Ok(())
    }
}
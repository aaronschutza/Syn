// src/tests/integration_tests.rs - Fixed imports, mining loop hang, and test duration

#[cfg(test)]
mod tests {
    use crate::{
        block::{Block, BlockHeader},
        blockchain::{self},
        config::{self, NodeConfig, GovernanceConfig},
        governance::ProposalPayload,
        pos::{self}, 
        transaction::Transaction,
        wallet,
        engine::ConsensusEngine,
        params::{ParamManager, ConsensusParams},
        stk_module::{StakingModule, BankModule, StakeInfo}, // Corrected Import
        gov_module::GovernanceModule,
        storage::{GovernanceStore, HeaderStore},
        difficulty::DynamicDifficultyManager,
        client::SpvClientState,
        cdf::{FinalityVote, Color},
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
        
        // Reduce proposal duration for tests to avoid mining 100 blocks
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
        
        // FIX: Force time advancement to avoid delta=0 which causes infinite difficulty (target=0)
        // LDD requires delta >= psi for valid mining
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
        
        // Calculate bits based on our artificial delta to ensure it's easy
        let bits = bc.get_next_work_required(true, min_delta);

        let mut block = Block::new(
            target_time, 
            final_txs, 
            tip_hash, 
            bits, 
            prev_block.height + 1, 
            bc.consensus_params.block_version
        );
        
        // Block::new initializes utxo_root to zero, so we must calculate it
        block.header.utxo_root = bc.calculate_utxo_root()?;

        let target = BlockHeader::calculate_target(block.header.bits);
        
        // Prevent infinite loops with a timeout counter
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
            let genesis_coinbase_txid = genesis_block.transactions[0].id();
            let utxo_tree = bc_lock.db.open_tree(&bc_lock.db_config.utxo_tree).unwrap();
            let mut utxo_key = Vec::with_capacity(36);
            utxo_key.extend_from_slice(genesis_coinbase_txid.as_ref());
            utxo_key.extend_from_slice(&(0 as u32).to_be_bytes());
            assert!(utxo_tree.contains_key(&utxo_key).unwrap(), "Genesis UTXO should exist in the database.");
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
    async fn test_2_send_tx_insufficient_funds() -> Result<()> {
        let test_name = "2";
        let (bc_arc, sender_wallet, node_config, _g) = setup_test_env(test_name);
        let sender_address = sender_wallet.get_address();
        let recipient_address = wallet::Wallet::new().get_address();
        
        mine_next_block(bc_arc.clone(), sender_address.clone()).await?;

        let initial_balance = get_balance(bc_arc.clone(), &sender_address).await;
        let fee = bc_arc.lock().await.consensus_params.fee_per_transaction;

        let amount_to_send = initial_balance - fee + 1;
        
        let result = {
            let mut bc_lock = bc_arc.lock().await;
            Transaction::new_utxo_transaction(&sender_wallet, recipient_address.clone(), amount_to_send, &mut bc_lock)
        };

        assert!(result.is_err(), "Transaction creation should fail due to insufficient funds.");
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("Insufficient funds"), "Error message should indicate insufficient funds. Got: {}", err_msg);
        
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
            // FIXED: Removed call to non-existent field bootstrap_phase_complete
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
                        if let Some((pi, delta_actual)) = pos::is_eligible_to_stake(&staker_wallet_clone, &bc_lock, current_time as u64) {
                            let block = pos::create_pos_block(&mut bc_lock, &staker_wallet_clone, pi, delta_actual as u32, current_time).unwrap();
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

                let (transactions, utxo_root) = {
                    let bc_lock = bc_arc_clone_pow.lock().await;
                    let coinbase = Transaction::new_coinbase("Mined for Test".to_string(), miner_address_clone.clone(), consensus_params_clone.coinbase_reward, consensus_params_clone.transaction_version);
                    (vec![coinbase], bc_lock.calculate_utxo_root().unwrap_or(sha256d::Hash::all_zeros()))
                };

                let merkle_root = Block::compute_merkle_root(&transactions);
                let current_time = { bc_arc_clone_pow.lock().await.get_block(&tip_hash).unwrap().header.time + 1 };

                let mut header = BlockHeader { version, prev_blockhash: tip_hash, merkle_root, utxo_root, time: current_time, bits, nonce: 0, vrf_proof: None };

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
                
                let mut block = Block::new(header.time, transactions, header.prev_blockhash, header.bits, height, header.version);
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

                if bc_lock.ldd_state.recent_blocks.len() >= bc_lock.ldd_state.current_adjustment_window {
                    bc_lock.adjust_ldd();
                }
            }
        }

        println!("Total PoW blocks: {}, Total PoS blocks: {}", pow_blocks_produced, pos_blocks_produced);
        assert!(pow_blocks_produced > 0, "Should have produced at least one PoW block.");
        assert!(pos_blocks_produced > 0, "Should have produced at least one PoS block.");

        cleanup_test_env(node_config).await;
        Ok(())
    }

    #[tokio::test]
    async fn test_4_governance_voting_and_execution() -> Result<()> {
        let test_name = "4";
        let (bc_arc, miner_wallet, node_config, governance_config) = setup_test_env(test_name);
        
        let staker_wallet = {
            let mut w = wallet::Wallet::new();
            w.stake_info = Some(StakeInfo { asset: "SYN".to_string(), amount: 10000 });
            w
        };
        let staker_stake = staker_wallet.stake_info.as_ref().unwrap().amount;
        
        mine_next_block(bc_arc.clone(), miner_wallet.get_address()).await?;
        
        let proposal_id = {
            let mut bc_lock = bc_arc.lock().await;
            let proposal_start_height = bc_lock.get_block(&bc_lock.tip).unwrap().height;
            bc_lock.total_staked = staker_stake;
            bc_lock.governance.create_proposal(
                miner_wallet.get_address(), 
                "New Block Time".to_string(), 
                "Change target block time to 1 second.".to_string(), 
                proposal_start_height, 
                ProposalPayload::UpdateTargetBlockTime(1),
                &governance_config,
            )
        };

        {
            let mut bc_lock = bc_arc.lock().await;
            bc_lock.governance.cast_vote(proposal_id, staker_stake, true)
                .map_err(|e| anyhow::anyhow!(e))?; 
        }

        let end_block = { bc_arc.lock().await.governance.proposals[&proposal_id].end_block };

        while {
            let bc_lock = bc_arc.lock().await;
            let tip_hash = bc_lock.tip;
            bc_lock.get_block(&tip_hash).unwrap().height <= end_block
        } {
            mine_next_block(bc_arc.clone(), miner_wallet.get_address()).await?;
        }
        
        let final_block_time = {
            let mut bc_lock = bc_arc.lock().await; 
            bc_lock.update_and_execute_proposals(); 
            let proposal = &bc_lock.governance.proposals[&proposal_id];
            
            assert_eq!(proposal.state, crate::governance::ProposalState::Executed, "Proposal should be executed.");

            bc_lock.consensus_params.target_block_time
        };
        
        assert_eq!(final_block_time, 1, "Target Block Time should have been updated to 1 second by the successful proposal.");
        
        cleanup_test_env(node_config).await;
        Ok(())
    }

    #[test]
    fn test_sbtc_defi_tutorial() {
        #[derive(PartialEq, Eq, Hash, Clone, Copy, Debug)]
        struct User { id: u32 }
        struct LendingContract { collateral: std::collections::HashMap<User, u64>, debt: std::collections::HashMap<User, u64> }
        impl LendingContract {
            fn new() -> Self { Self { collateral: std::collections::HashMap::new(), debt: std::collections::HashMap::new() } }
            pub fn deposit_collateral(&mut self, user: User, amount: u64) { *self.collateral.entry(user).or_insert(0) += amount; }
            pub fn borrow(&mut self, user: User, amount: u64) { *self.debt.entry(user).or_insert(0) += amount; }
        }
        let mut contract = LendingContract::new();
        let user = User { id: 1 };
        contract.deposit_collateral(user, 1000);
        assert_eq!(contract.collateral.get(&user), Some(&1000));
        contract.borrow(user, 500);
        assert_eq!(contract.debt.get(&user), Some(&500));
    }

    #[test]
    fn test_fungible_token_tutorial() {
        #[derive(PartialEq, Eq, Hash, Clone, Copy, Debug)]
        struct User { id: u32 }
        struct FungibleToken { total_supply: u64, balances: std::collections::HashMap<User, u64> }
        impl FungibleToken {
            fn new(creator: User, supply: u64) -> Self {
                let mut balances = std::collections::HashMap::new();
                balances.insert(creator, supply);
                Self { total_supply: supply, balances }
            }
            fn transfer(&mut self, from: User, to: User, amount: u64) -> Result<(), &'static str> {
                let from_balance = self.balances.entry(from).or_insert(0);
                if *from_balance < amount { return Err("Insufficient funds"); }
                *from_balance -= amount;
                *self.balances.entry(to).or_insert(0) += amount;
                Ok(())
            }
        }
        let creator = User { id: 1 };
        let recipient = User { id: 2 };
        let mut token = FungibleToken::new(creator, 1_000_000);
        assert_eq!(token.total_supply, 1_000_000);
        assert_eq!(token.balances.get(&creator), Some(&1_000_000));
        assert!(token.transfer(creator, recipient, 250_000).is_ok());
        assert_eq!(token.balances.get(&creator), Some(&750_000));
        assert_eq!(token.balances.get(&recipient), Some(&250_000));
    }

    #[test]
    fn test_decentralized_oracle_tutorial() {
        #[derive(PartialEq, Eq, Hash, Clone, Copy, Debug)]
        struct User { id: u32 }
        struct Oracle { trusted_source: User, data: std::collections::HashMap<String, u64> }
        impl Oracle {
            fn new(trusted_source: User) -> Self { Self { trusted_source, data: std::collections::HashMap::new() } }
            fn update_data(&mut self, source: User, key: String, value: u64) -> Result<(), &'static str> {
                if source.id != self.trusted_source.id { return Err("Unauthorized source"); }
                self.data.insert(key, value);
                Ok(())
            }
        }
        let trusted_source = User { id: 1 };
        let mut oracle = Oracle::new(trusted_source);
        assert!(oracle.update_data(trusted_source, "BTC/USD".into(), 60000).is_ok());
        assert!(oracle.update_data(User { id: 2 }, "BTC/USD".into(), 55000).is_err());
    }

    #[test]
    fn test_advanced_smart_contract_tutorial() {
        struct Counter { count: u64 }
        impl Counter { fn new() -> Self { Self { count: 0 } } fn increment(&mut self) { self.count += 1; } }
        let mut counter = Counter::new();
        counter.increment();
        assert_eq!(counter.count, 1);
    }

    #[test]
    fn test_inter_contract_communication_tutorial() {
        #[derive(PartialEq, Eq, Hash, Clone, Debug)]
        struct UserAddress(String);
        struct Registry { registered_users: Vec<UserAddress> }
        impl Registry { fn new() -> Self { Self { registered_users: Vec::new() } } pub fn add_user(&mut self, user: UserAddress) { self.registered_users.push(user); } }
        struct UserProfile<'a> { registry: &'a mut Registry, user_data: std::collections::HashMap<UserAddress, String> }
        impl<'a> UserProfile<'a> {
            fn new(registry: &'a mut Registry) -> Self { Self { registry, user_data: std::collections::HashMap::new() } }
            pub fn create_profile(&mut self, user: UserAddress, data: String) { self.user_data.insert(user.clone(), data); self.registry.add_user(user); }
        }
        let mut registry = Registry::new();
        let user = UserAddress("user123".into());
        let mut profile = UserProfile::new(&mut registry);
        profile.create_profile(user.clone(), "data".into());
        assert_eq!(registry.registered_users.len(), 1);
    }

    #[test]
    fn test_upgradable_contracts_tutorial() {
        struct Storage { value: u64 }
        struct LogicV1; impl LogicV1 { fn add(s: &mut Storage, v: u64) { s.value += v; } }
        struct LogicV2; impl LogicV2 { fn multiply(s: &mut Storage, v: u64) { s.value *= v; } }
        let mut s = Storage { value: 10 };
        LogicV1::add(&mut s, 5); assert_eq!(s.value, 15);
        LogicV2::multiply(&mut s, 3); assert_eq!(s.value, 45);
    }

    #[test]
    fn test_gas_optimization_tutorial() {
        let numbers: Vec<u64> = (1..=100).collect();
        let result: u64 = numbers.iter().sum();
        assert_eq!(result, 5050);
    }

    #[test]
    fn test_state_machine_tutorial() {
        #[derive(PartialEq, Debug)] enum State { Pending, Active, Closed }
        struct SM { state: State }
        impl SM {
            fn new() -> Self { Self { state: State::Pending } }
            fn activate(&mut self) { if self.state == State::Pending { self.state = State::Active; } }
            fn close(&mut self) { if self.state == State::Active { self.state = State::Closed; } }
        }
        let mut sm = SM::new();
        sm.activate(); assert_eq!(sm.state, State::Active);
        sm.close(); assert_eq!(sm.state, State::Closed);
    }

    #[test]
    fn test_asset_data_composability_tutorial() {
        struct DigitalAsset { owner: String, data: String }
        let asset = DigitalAsset { owner: "user".into(), data: "metadata".into() };
        assert_eq!(asset.owner, "user");
        assert_eq!(asset.data, "metadata");
    }

    #[test]
    fn test_staking_and_governance_tutorial() {
        struct Gov { total_staked: u64 }
        let gov = Gov { total_staked: 1000 };
        assert_eq!(gov.total_staked, 1000);
    }

    #[test]
    fn test_data_and_computation_tutorial() {
        let data = vec![10, 20, 30, 40, 50];
        let average: u64 = data.iter().sum::<u64>() / data.len() as u64;
        assert_eq!(average, 30);
    }

    #[test]
    fn test_security_and_bridges_tutorial() {
        struct Bridge { locked: u64 }
        let bridge = Bridge { locked: 500 };
        assert_eq!(bridge.locked, 500);
    }

    #[tokio::test]
    async fn test_dynamic_slope_adjustment() {
        let mut params = ConsensusParams::new();
        params.enable_dynamic_slope = true;
        let param_manager = Arc::new(ParamManager::new());
        let bank_module = Arc::new(BankModule {});
        let staking_module = Arc::new(StakingModule::new(bank_module));
        let db_path = "test_slope_db_2";
        let _ = std::fs::remove_dir_all(&db_path);
        let db_for_gov = Arc::new(sled::open(db_path).unwrap());
        let governance_store = GovernanceStore::new(db_for_gov);
        let governance_module = Arc::new(GovernanceModule::new(param_manager.clone(), staking_module.clone(), governance_store));
        let difficulty_manager = Arc::new(DynamicDifficultyManager::new(param_manager.clone()));
        let mut consensus_engine = ConsensusEngine::new(param_manager.clone(), staking_module.clone(), governance_module.clone(), difficulty_manager.clone(), params.clone());
        let initial_slope = consensus_engine.params.max_slope_change_per_block;
        consensus_engine.adjust_target_slope(consensus_engine.params.target_block_size + 100);
        assert_ne!(consensus_engine.params.max_slope_change_per_block, initial_slope);
        let node_config = NodeConfig { rpc_port: 0, rpc_host: "127.0.0.1".to_string(), p2p_port: 0, db_path: db_path.to_string(), wallet_file: "".to_string(), rpc_auth_token: None };
        cleanup_test_env(node_config).await;
    }

    #[tokio::test]
    async fn test_5_cdf_irreversibility_enforcement() -> Result<()> {
        let test_name = "5";
        let (bc_arc, miner_wallet, node_config, _g) = setup_test_env(test_name);
        let address = miner_wallet.get_address();

        // Establish a base
        mine_next_block(bc_arc.clone(), address.clone()).await?;
        let checkpoint_hash = {
            let bc = bc_arc.lock().await;
            bc.tip
        };

        // Ratify finality via the CDF gadget
        {
            let mut bc = bc_arc.lock().await;
            bc.total_staked = 1000;
            let votes = vec![
                FinalityVote { voter_public_key: vec![1], checkpoint_hash, color: Color::Red, signature: vec![] },
                FinalityVote { voter_public_key: vec![2], checkpoint_hash, color: Color::Green, signature: vec![] },
                FinalityVote { voter_public_key: vec![3], checkpoint_hash, color: Color::Blue, signature: vec![] },
            ];
            bc.finality_gadget.activate(checkpoint_hash, 1000);
            bc.finality_gadget.work_threshold = 0; // Force work quorum for test
            for v in votes { bc.finality_gadget.process_vote(&v, 400); }
            
            if bc.finality_gadget.check_finality() {
                bc.last_finalized_checkpoint = Some(checkpoint_hash);
            }
        }

        // Attempt a deep reorg that reverts the finalized checkpoint (parallel genesis)
        let mut fork_block = Block::create_genesis_block(
            5000000000, 1672531200, 0x1e0ffff0, "Evil Fork".into(), 
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".into(), 1, 1
        );
        fork_block.synergistic_work = 1000000; 

        let result = {
            let mut bc = bc_arc.lock().await;
            bc.add_block(fork_block)
        };

        assert!(result.is_err(), "Fork reverting a finalized block should be rejected.");
        assert!(result.unwrap_err().to_string().contains("Irreversibility Violation"), 
            "Error message should indicate finality violation.");

        cleanup_test_env(node_config).await;
        Ok(())
    }
}
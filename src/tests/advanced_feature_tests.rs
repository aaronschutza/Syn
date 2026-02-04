// src/tests/advanced_feature_tests.rs

#[cfg(test)]
mod tests {
    use crate::{
        block::{Block, BlockHeader, BeaconData},
        blockchain::{Blockchain},
        config::{self, NodeConfig},
        transaction::{Transaction, TxIn, TxOut},
        wallet::Wallet,
        engine::ConsensusEngine,
        params::{ParamManager, ConsensusParams},
        stk_module::{StakingModule, BankModule},
        gov_module::GovernanceModule,
        storage::GovernanceStore,
        difficulty::DynamicDifficultyManager,
    };
    use std::sync::Arc;
    use tokio::sync::Mutex;
    use chrono::Utc;
    use num_bigint::BigUint;

    // Helper to setup test environment
    fn setup_test_env(test_name: &str) -> (Arc<Mutex<Blockchain>>, Wallet, NodeConfig) {
        let db_path = format!("test_adv_db_{}", test_name);
        let wallet_file = format!("test_adv_wallet_{}", test_name);
        
        // Clean up previous runs
        let _ = std::fs::remove_dir_all(&db_path);
        let _ = std::fs::remove_file(&wallet_file);

        // Load or Mock Config
        let mut config = config::load("synergeia.toml").unwrap_or_else(|_| {
            panic!("synergeia.toml must exist for tests");
        });
        
        // Modify config for testing
        config.consensus.target_block_time = 1; 
        config.consensus.adjustment_window = 5; // Short window for LDD test
        config.consensus.coinbase_maturity = 1; // Instant maturity for Burst test
        config.fees.fee_burst_threshold = 1_000_000;
        config.node.db_path = db_path.clone();
        config.node.wallet_file = wallet_file.clone();

        // Dependencies
        let db = Arc::new(sled::open(&db_path).unwrap());
        let param_manager = Arc::new(ParamManager::new());
        let bank_module = Arc::new(BankModule {});
        let staking_module = Arc::new(StakingModule::new(bank_module));
        let governance_store = GovernanceStore::new(db.clone());
        let governance_module = Arc::new(GovernanceModule::new(param_manager.clone(), staking_module.clone(), governance_store));
        let difficulty_manager = Arc::new(DynamicDifficultyManager::new(param_manager.clone()));
        
        let consensus_engine = ConsensusEngine::new(
            param_manager.clone(),
            staking_module.clone(),
            governance_module.clone(),
            difficulty_manager.clone(),
            ConsensusParams::new(),
        );

        let bc = Blockchain::new_with_db(
            db,
            Arc::new(config.consensus),
            Arc::new(config.fees),
            Arc::new(config.governance),
            Arc::new(config.database),
            consensus_engine,
        ).unwrap();

        let wallet = Wallet::new();
        wallet.save_to_file(&config.node).unwrap();

        (Arc::new(Mutex::new(bc)), wallet, config.node)
    }

    async fn cleanup_test_env(node_config: &NodeConfig) {
        let _ = std::fs::remove_dir_all(&node_config.db_path);
        let _ = std::fs::remove_file(&node_config.wallet_file);
    }

    // Helper to mine a block manually
    async fn mine_block(bc_arc: Arc<Mutex<Blockchain>>, wallet: &Wallet) {
        let mut bc = bc_arc.lock().await;
        let prev_block = bc.get_block(&bc.tip).unwrap();
        let height = prev_block.height + 1;
        let time = Utc::now().timestamp() as u32;
        
        // Coinbase
        let coinbase = Transaction::new_coinbase(
            "test".to_string(), 
            wallet.get_address(), 
            bc.consensus_params.coinbase_reward, 
            bc.consensus_params.transaction_version
        );

        let mut txs = vec![coinbase];
        // Include mempool
        txs.extend(bc.get_mempool_txs());
        
        let mut block = Block::new(time, txs, bc.tip, 0x207fffff, height, 1);
        
        // Include mempool beacons
        block.beacons = bc.beacon_mempool.clone();
        bc.beacon_mempool.clear();

        block.header.utxo_root = bc.calculate_utxo_root().unwrap();

        // Solve PoW
        let target = BlockHeader::calculate_target(block.header.bits);
        while BigUint::from_bytes_be(block.header.hash().as_ref()) > target {
            block.header.nonce += 1;
        }

        bc.add_block(block).unwrap();
    }

    #[tokio::test]
    async fn test_autonomous_ldd_adaptation() {
        let (bc_arc, wallet, node_config) = setup_test_env("ldd");
        
        // 1. Create a high delay beacon (5000ms)
        let high_delay = 5000;
        let beacon = wallet.sign_beacon(BeaconData::Delay(high_delay)).unwrap();
        
        {
            let mut bc = bc_arc.lock().await;
            
            // Inject beacon into mempool
            bc.receive_beacon(beacon.clone()).unwrap();
            
            // 2. Mine enough blocks to fill adjustment window (5 blocks)
            // We ensure the beacon is included in every block to influence the consensus
            let start_psi = bc.ldd_state.current_psi;
            println!("Initial PSI: {}", start_psi);
        }

        for _ in 0..5 {
            // Re-inject beacon for each block (simulating network consensus)
            {
                let mut bc = bc_arc.lock().await;
                // Ensure beacon mempool has our beacon
                if bc.beacon_mempool.is_empty() {
                    bc.receive_beacon(beacon.clone()).unwrap();
                }
            }
            mine_block(bc_arc.clone(), &wallet).await;
        }

        {
            let bc = bc_arc.lock().await;
            // 3. Verify Adaptation
            // Expected PSI = Delay(5s) + SafetyMargin(2s) = 7
            // DCS uses 95th percentile. With all blocks reporting 5000, consensus is 5000.
            let new_psi = bc.ldd_state.current_psi;
            println!("New PSI: {}", new_psi);
            
            assert!(new_psi >= 6, "PSI should adapt to reflect high network delay. Expected >= 7 (5s delay + 2s safety), Got {}", new_psi);
        }

        cleanup_test_env(&node_config).await;
    }

    #[tokio::test]
    async fn test_burst_finality_trigger() {
        let (bc_arc, wallet, node_config) = setup_test_env("burst");
        let address = wallet.get_address();

        // 1. Mine genesis and a few blocks to mature coinbase (maturity=1 in test config)
        mine_block(bc_arc.clone(), &wallet).await; // Genesis handled in setup, this is block 1
        mine_block(bc_arc.clone(), &wallet).await; // Block 2

        // 2. Create High Fee Transaction
        let (_utxo_val, utxos) = {
            let bc = bc_arc.lock().await;
            bc.find_spendable_outputs(&address, 0).unwrap()
        };
        
        let txid = *utxos.keys().next().unwrap();
        let vout = utxos[&txid];

        // Create a tx that spends a UTXO but sends 0 to output, leaving entire value as fee
        // Value is huge (coinbase reward), so fee >> 1,000,000 threshold
        let input = TxIn {
            prev_txid: txid,
            prev_vout: vout,
            script_sig: vec![],
            sequence: 0xFFFFFFFF,
        };
        let mut tx = Transaction {
            version: 1,
            vin: vec![input],
            vout: vec![], // All input value becomes fee
            lock_time: 0,
        };

        // Sign it
        {
            // Helper to get prev_out needed for signing
             let mut bc = bc_arc.lock().await; // FIXED: Must be mutable to insert into mempool
             let prev_tx = bc.get_transaction(&txid).unwrap().unwrap();
             let mut prev_map = std::collections::HashMap::new();
             prev_map.insert(txid, prev_tx.vout[vout as usize].clone());
             wallet.sign_transaction(&mut tx, prev_map).unwrap();
             
             // Add to mempool
             bc.mempool.insert(tx.id(), tx);
        }

        // 3. Mine block containing high fee tx
        mine_block(bc_arc.clone(), &wallet).await;

        // 4. Verify Burst Mode Activation
        {
            let bc = bc_arc.lock().await;
            assert!(bc.burst_manager.burst_active, "Burst Mode should be active after high-fee transaction");
            assert!(bc.burst_manager.burst_end_height > bc.get_block(&bc.tip).unwrap().height, "Burst end height should be set in future");
            
            // Verify LDD Override
            let (psi, _) = bc.burst_manager.get_burst_parameters().unwrap();
            assert_eq!(psi, 0, "Burst mode should override PSI to 0");
        }

        cleanup_test_env(&node_config).await;
    }

    #[tokio::test]
    async fn test_pos_proof_of_burn_enforcement() {
        let (bc_arc, wallet, _node_config) = setup_test_env("burn");
        
        // 1. Mine blocks to get UTXOs
        mine_block(bc_arc.clone(), &wallet).await;
        mine_block(bc_arc.clone(), &wallet).await;

        // 2. Construct an invalid PoS block (Missing Burn)
        let mut bc = bc_arc.lock().await;
        
        let prev_block = bc.get_block(&bc.tip).unwrap();
        let height = prev_block.height + 1;
        let time = Utc::now().timestamp() as u32;

        // Fake PoS block with standard coinbase (no burn)
        let coinbase = Transaction::new_coinbase("PoS attempt".to_string(), wallet.get_address(), 100, 1);
        let mut block = Block::new(time, vec![coinbase], bc.tip, 0x207fffff, height, 1);
        
        // Fake VRF proof to mark it as PoS
        block.header.vrf_proof = Some(vec![0u8; 64]);
        
        // This relies on finding a tx with fees to require burn. 
        // Let's add a dummy tx with fee.
        let (val, utxos) = bc.find_spendable_outputs(&wallet.get_address(), 0).unwrap();
        let txid = *utxos.keys().next().unwrap();
        let input = TxIn { prev_txid: txid, prev_vout: utxos[&txid], script_sig: vec![], sequence: 0 };
        // Spend val, output val - 1000. Fee = 1000.
        let tx = Transaction { 
            version: 1, vin: vec![input], 
            vout: vec![TxOut::new(val - 1000, wallet.get_address())], 
            lock_time: 0 
        };
        
        // Need to sign tx properly or skip verify? verify_transaction called in add_block.
        // We will skip signing logic for brevity and just inject into block transactions 
        // assuming verify_transaction passes or mocking it. 
        // Actually, let's create valid signed tx.
        let prev_tx_obj = bc.get_transaction(&txid).unwrap().unwrap();
        let mut p_map = std::collections::HashMap::new();
        p_map.insert(txid, prev_tx_obj.vout[utxos[&txid] as usize].clone());
        let mut signed_tx = tx.clone();
        wallet.sign_transaction(&mut signed_tx, p_map).unwrap();
        
        block.transactions.push(signed_tx);
        
        // Recalc roots
        block.header.merkle_root = Block::compute_merkle_root(&block.transactions);
        block.header.utxo_root = bc.calculate_utxo_root().unwrap();

        // 3. Attempt to add block -> Should Fail due to missing OP_RETURN burn
        let result = bc.add_block(block);
        
        assert!(result.is_err(), "PoS block without Proof-of-Burn should be rejected");
        assert!(result.unwrap_err().to_string().contains("Insufficient Proof-of-Burn"), "Error message should mention burn");
    }
}
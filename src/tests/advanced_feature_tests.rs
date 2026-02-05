// src/tests/advanced_feature_tests.rs

#[cfg(test)]
mod tests {
    use crate::{
        block::{Block, BlockHeader, BeaconData, Beacon},
        blockchain::{Blockchain},
        config::{self, NodeConfig},
        transaction::{Transaction, TxIn, TxOut},
        wallet::Wallet,
        engine::ConsensusEngine,
        params::{ParamManager, ConsensusParams},
        stk_module::{StakingModule, BankModule},
        gov_module::GovernanceModule,
        storage::{GovernanceStore, HeaderStore},
        difficulty::DynamicDifficultyManager,
        crypto::{hash_pubkey, address_from_pubkey_hash},
        client::SpvClientState,
    };
    use std::sync::Arc;
    use tokio::sync::Mutex;
    use chrono::Utc;
    use num_bigint::BigUint;
    use secp256k1::PublicKey;
    use log::info;

    fn setup_test_env(test_name: &str) -> (Arc<Mutex<Blockchain>>, Wallet, NodeConfig) {
        let db_path = format!("test_adv_db_{}", test_name);
        let wallet_file = format!("test_adv_wallet_{}", test_name);
        
        let _ = std::fs::remove_dir_all(&db_path);
        let _ = std::fs::remove_file(&wallet_file);

        let mut config = config::load("synergeia.toml").unwrap();
        
        config.consensus.target_block_time = 1; 
        config.consensus.adjustment_window = 5; 
        config.consensus.coinbase_maturity = 1; 
        config.fees.fee_burst_threshold = 1_000_000;
        config.node.db_path = db_path.clone();
        config.node.wallet_file = wallet_file.clone();

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

        let bc = Blockchain::new_with_db(
            db,
            Arc::new(config.consensus),
            Arc::new(config.fees),
            Arc::new(config.governance),
            Arc::new(config.progonos),
            spv_state,
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

    fn apply_test_bounties(coinbase: &mut Transaction, reward: u64, beacons: &[Beacon]) {
        if beacons.is_empty() { return; }
        let pool = (reward * 1) / 100;
        let per_beacon = pool / beacons.len() as u64;
        
        if per_beacon > 0 {
            coinbase.vout[0].value -= per_beacon * beacons.len() as u64;
            for beacon in beacons {
                if let Ok(pk) = PublicKey::from_slice(&beacon.public_key) {
                    let addr = address_from_pubkey_hash(&hash_pubkey(&pk));
                    coinbase.vout.push(TxOut::new(per_beacon, addr));
                }
            }
        }
    }

    async fn mine_block(bc_arc: Arc<Mutex<Blockchain>>, wallet: &Wallet) {
        let mut bc = bc_arc.lock().await;
        let height = bc.headers.len() as u32;
        let time = Utc::now().timestamp() as u32;
        
        let reward = bc.consensus_params.coinbase_reward;
        let mut coinbase = Transaction::new_coinbase(
            "test".to_string(), 
            wallet.get_address(), 
            reward, 
            bc.consensus_params.transaction_version
        );

        let mut txs = vec![];
        txs.extend(bc.get_mempool_txs());
        
        let beacons = bc.beacon_mempool.clone();
        bc.beacon_mempool.clear();
        apply_test_bounties(&mut coinbase, reward, &beacons);
        
        let mut final_txs = vec![coinbase];
        final_txs.extend(txs);

        let mut block = Block::new(time, final_txs, bc.tip, 0x207fffff, height, 1);
        block.beacons = beacons;
        block.header.utxo_root = bc.calculate_utxo_root().unwrap();

        let target = BlockHeader::calculate_target(block.header.bits);
        while BigUint::from_bytes_be(block.header.hash().as_ref()) > target {
            block.header.nonce += 1;
        }

        bc.add_block(block).unwrap();
    }

    #[tokio::test]
    async fn test_autonomous_ldd_adaptation() {
        let (bc_arc, wallet, node_config) = setup_test_env("ldd");
        
        let high_delay = 5000;
        let beacon = wallet.sign_beacon(BeaconData::Delay(high_delay)).unwrap();
        
        for _ in 0..5 {
            {
                let mut bc = bc_arc.lock().await;
                bc.receive_beacon(beacon.clone()).unwrap();
            }
            mine_block(bc_arc.clone(), &wallet).await;
        }

        {
            let bc = bc_arc.lock().await;
            let new_psi = bc.ldd_state.current_psi;
            assert!(new_psi >= 6, "PSI should adapt to high delay. Got {}", new_psi);
        }

        cleanup_test_env(&node_config).await;
    }

    #[tokio::test]
    async fn test_burst_finality_trigger() {
        let (bc_arc, wallet, node_config) = setup_test_env("burst");
        let address = wallet.get_address();

        mine_block(bc_arc.clone(), &wallet).await; 
        mine_block(bc_arc.clone(), &wallet).await;

        let (_utxo_val, utxos) = {
            let bc = bc_arc.lock().await;
            bc.find_spendable_outputs(&address, 0).unwrap()
        };
        
        let txid = *utxos.keys().next().unwrap();
        let vout = utxos[&txid];

        let mut tx = Transaction {
            version: 1,
            vin: vec![TxIn { prev_txid: txid, prev_vout: vout, script_sig: vec![], sequence: 0xFFFFFFFF }],
            vout: vec![], 
            lock_time: 0,
        };

        {
             let mut bc = bc_arc.lock().await;
             let prev_tx = bc.get_transaction(&txid).unwrap().unwrap();
             let mut prev_map = std::collections::HashMap::new();
             prev_map.insert(txid, prev_tx.vout[vout as usize].clone());
             wallet.sign_transaction(&mut tx, prev_map).unwrap();
             bc.mempool.insert(tx.id(), tx);
        }

        mine_block(bc_arc.clone(), &wallet).await;

        {
            let bc = bc_arc.lock().await;
            assert!(bc.burst_manager.burst_active);
        }

        cleanup_test_env(&node_config).await;
    }

    #[tokio::test]
    async fn test_pos_proof_of_burn_enforcement() {
        let (bc_arc, wallet, node_config) = setup_test_env("burn");
        
        mine_block(bc_arc.clone(), &wallet).await;
        mine_block(bc_arc.clone(), &wallet).await;

        let (val, txid, vout, prev_tx_out) = {
            let bc = bc_arc.lock().await;
            let (val, utxos) = bc.find_spendable_outputs(&wallet.get_address(), 1000).unwrap();
            let txid = *utxos.keys().next().unwrap();
            let vout = utxos[&txid];
            let prev_tx_obj = bc.get_transaction(&txid).unwrap().unwrap();
            (val, txid, vout, prev_tx_obj.vout[vout as usize].clone())
        };

        let mut fee_tx = Transaction { 
            version: 1, 
            vin: vec![TxIn { prev_txid: txid, prev_vout: vout, script_sig: vec![], sequence: 0 }], 
            vout: vec![TxOut::new(val - 1000, wallet.get_address())], 
            lock_time: 0 
        };
        
        let mut p_map = std::collections::HashMap::new();
        p_map.insert(txid, prev_tx_out);
        wallet.sign_transaction(&mut fee_tx, p_map).unwrap();

        let mut bc = bc_arc.lock().await;
        let prev_block = bc.get_block(&bc.tip).unwrap();

        let coinbase = Transaction::new_coinbase("PoS Mining".to_string(), wallet.get_address(), bc.consensus_params.coinbase_reward, 1);
        let mut block = Block::new(Utc::now().timestamp() as u32, vec![coinbase, fee_tx], bc.tip, 0x207fffff, prev_block.height + 1, 1);
        block.header.vrf_proof = Some(vec![0u8; 64]);
        block.header.utxo_root = bc.calculate_utxo_root().unwrap();

        let result = bc.add_block(block);
        
        assert!(result.is_err(), "PoS block without Proof-of-Burn output should be rejected");
        assert!(result.unwrap_err().to_string().contains("Insufficient Proof-of-Burn"));

        cleanup_test_env(&node_config).await;
    }

    #[tokio::test]
    async fn test_economic_immune_response() {
        let (bc_arc, wallet, node_config) = setup_test_env("immune");
        
        let threat_beacon = wallet.sign_beacon(BeaconData::Security(2, 5)).unwrap();
        
        {
            let bc = bc_arc.lock().await;
            info!("Initial burn rate: {}", bc.ldd_state.current_burn_rate);
        }

        for _ in 0..5 {
            {
                let mut bc = bc_arc.lock().await;
                bc.receive_beacon(threat_beacon.clone()).unwrap();
            }
            mine_block(bc_arc.clone(), &wallet).await;
        }

        {
            let bc = bc_arc.lock().await;
            let new_burn = bc.ldd_state.current_burn_rate;
            let initial_base = bc.fee_params.min_burn_rate;
            
            info!("Hardened burn rate: {}", new_burn);
            assert!(new_burn > initial_base, "Burn rate should increase in response to security threat");
            assert!(bc.ldd_state.current_adjustment_window < 240, "Adjustment window should compress to increase reactivity");
        }

        cleanup_test_env(&node_config).await;
    }
}
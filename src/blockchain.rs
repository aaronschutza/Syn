// src/blockchain.rs - Feature-complete Burst Finality realized via CDF gadget

use crate::{
    block::{Block, BlockHeader, Beacon},
    config::{ConsensusConfig, DatabaseConfig, FeeConfig, GovernanceConfig},
    dcs::DecentralizedConsensusService,
    burst::BurstFinalityManager,
    cdf::{FinalityGadget, FinalityVote}, 
    fixed_point::Fixed,
    governance::{Governance, ProposalState, ProposalPayload},
    transaction::{Transaction, TxOut},
    engine::ConsensusEngine,
    crypto::{hash_pubkey, address_from_pubkey_hash},
};
use anyhow::{anyhow, bail, Result};
use bitcoin_hashes::{sha256d, Hash};
use chrono::Utc;
use log::info;
use num_traits::{ToPrimitive, Zero};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use secp256k1::PublicKey;
use sled::Batch;

#[allow(dead_code)]
const VETO_THRESHOLD_PERCENT: u64 = 51;
const MAX_BEACONS_PER_BLOCK: usize = 16;
const P_FALLBACK: f64 = 0.001; 
const MAX_TX_CACHE_SIZE: usize = 10000;

/// Tree Names for persistent indexing
const ADDR_UTXO_TREE: &str = "addr_utxo_index";
const METADATA_TREE: &str = "chain_metadata";

#[derive(Clone, Debug)]
pub struct LddState {
    pub f_a_pow: Fixed,
    pub f_a_pos: Fixed,
    pub recent_blocks: Vec<(u32, bool)>,
    pub current_psi: u32,
    pub current_gamma: u32,
    pub current_target_block_time: u64,
    pub current_adjustment_window: usize,
    pub current_burn_rate: f64,
    pub current_kappa: f64,
    pub beacon_bounty_bps: u64, 
}

impl Default for LddState {
    fn default() -> Self {
        Self {
            f_a_pow: Fixed::from_f64(0.05),
            f_a_pos: Fixed::from_f64(0.05),
            recent_blocks: Vec::new(),
            current_psi: 2,  
            current_gamma: 20, 
            current_target_block_time: 15,
            current_adjustment_window: 100, 
            current_burn_rate: 0.1,
            current_kappa: 0.1,
            beacon_bounty_bps: 100,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct LocalMetrics {
    pub orphan_count: u32,
    pub max_reorg_depth: u32,
    pub last_delay_ms: u32,
    pub beacon_providers: HashSet<Vec<u8>>,
}

#[derive(Debug, Default)]
pub struct VetoManager {
    pub votes: HashMap<sha256d::Hash, HashSet<Vec<u8>>>,
    pub weight: HashMap<sha256d::Hash, u64>,
    pub blacklisted_blocks: HashSet<sha256d::Hash>,
}

pub struct Blockchain {
    pub db: Arc<sled::Db>,
    pub blocks_tree: sled::Tree,
    pub utxo_tree: sled::Tree,
    pub addr_utxo_tree: sled::Tree, 
    pub tx_index_tree: sled::Tree,
    pub meta_tree: sled::Tree,

    pub tip: sha256d::Hash,
    pub total_work: u64,
    pub mempool: HashMap<sha256d::Hash, Transaction>,
    pub beacon_mempool: Vec<Beacon>,
    pub ldd_state: LddState,
    pub consensus_params: Arc<ConsensusConfig>,
    pub fee_params: Arc<FeeConfig>,
    pub governance_params: Arc<GovernanceConfig>,
    pub total_staked: u64,
    pub governance: Governance,
    pub db_config: Arc<DatabaseConfig>,
    pub headers: Vec<BlockHeader>,
    pub tx_cache: HashMap<sha256d::Hash, Transaction>,
    pub pos_block_count: u32,
    pub bootstrap_phase_complete: bool,
    pub last_pow_block_hash: sha256d::Hash,
    pub consensus_engine: ConsensusEngine,
    pub dcs: DecentralizedConsensusService,
    pub burst_manager: BurstFinalityManager,
    pub finality_gadget: FinalityGadget,
    pub metrics: LocalMetrics,
    pub veto_manager: VetoManager,
}

impl Blockchain {
    pub fn new_with_db(
        db: Arc<sled::Db>,
        consensus_params: Arc<ConsensusConfig>,
        fee_params: Arc<FeeConfig>,
        governance_params: Arc<GovernanceConfig>,
        db_config: Arc<DatabaseConfig>,
        consensus_engine: ConsensusEngine,
    ) -> Result<Self> {
        let blocks_tree = db.open_tree(&db_config.blocks_tree)?;
        let utxo_tree = db.open_tree(&db_config.utxo_tree)?;
        let addr_utxo_tree = db.open_tree(ADDR_UTXO_TREE)?;
        let tx_index_tree = db.open_tree(&db_config.tx_index_tree)?;
        let meta_tree = db.open_tree(METADATA_TREE)?;

        let mut ldd_state = LddState::default();
        ldd_state.current_psi = consensus_params.psi_slot_gap;
        ldd_state.current_gamma = consensus_params.gamma_recovery_threshold;
        ldd_state.current_target_block_time = consensus_params.target_block_time;
        ldd_state.current_adjustment_window = consensus_params.adjustment_window;
        ldd_state.current_burn_rate = fee_params.min_burn_rate;

        let mut bc = Blockchain {
            db,
            blocks_tree,
            utxo_tree,
            addr_utxo_tree,
            tx_index_tree,
            meta_tree,
            tip: sha256d::Hash::all_zeros(),
            total_work: 0,
            mempool: HashMap::new(),
            beacon_mempool: Vec::new(),
            ldd_state,
            consensus_params,
            fee_params: fee_params.clone(), // FIX: Clone here to allow later use
            governance_params,
            total_staked: 0,
            governance: Governance::new(),
            db_config,
            headers: Vec::new(),
            tx_cache: HashMap::new(),
            pos_block_count: 0,
            bootstrap_phase_complete: false,
            last_pow_block_hash: sha256d::Hash::all_zeros(),
            consensus_engine,
            dcs: DecentralizedConsensusService::new(),
            burst_manager: BurstFinalityManager::new(fee_params.k_burst, fee_params.fee_burst_threshold), 
            finality_gadget: FinalityGadget::new(),
            metrics: LocalMetrics::default(),
            veto_manager: VetoManager::default(),
        };

        if bc.blocks_tree.is_empty() {
            let mut genesis = Block::create_genesis_block(
                bc.consensus_params.coinbase_reward,
                bc.consensus_params.genesis_timestamp,
                bc.consensus_params.genesis_bits,
                bc.consensus_params.genesis_coinbase_data.clone(),
                bc.consensus_params.genesis_address.clone(),
                bc.consensus_params.block_version,
                bc.consensus_params.transaction_version,
            );
            let genesis_hash = genesis.header.hash();
            bc.calculate_synergistic_work(&mut genesis);
            genesis.total_work = genesis.synergistic_work;
            bc.blocks_tree.insert(genesis_hash.as_ref() as &[u8], bincode::serialize(&genesis)?)?;
            bc.blocks_tree.insert(bc.db_config.tip_key.as_str(), genesis_hash.as_ref() as &[u8])?;
            bc.tip = genesis_hash;
            bc.total_work = genesis.total_work;
            bc.headers.push(genesis.header.clone());
            bc.update_utxo_set(&genesis)?;
        } else {
            let tip_bytes = bc.blocks_tree.get(&bc.db_config.tip_key)?.ok_or_else(|| anyhow!("Tip missing"))?;
            bc.tip = sha256d::Hash::from_slice(&tip_bytes)?;
            
            if let Some(work_bytes) = bc.blocks_tree.get(&bc.db_config.total_work_key)? {
                let mut arr = [0u8; 8];
                arr.copy_from_slice(&work_bytes);
                bc.total_work = u64::from_be_bytes(arr);
            }

            if let Some(h_bytes) = bc.blocks_tree.get("headers")? {
                bc.headers = bincode::deserialize(&h_bytes)?;
            }
        }
        Ok(bc)
    }

    pub fn calculate_utxo_root(&self) -> Result<sha256d::Hash> {
        if let Some(root_bytes) = self.meta_tree.get("utxo_rolling_root")? {
            return Ok(sha256d::Hash::from_slice(&root_bytes)?);
        }
        Ok(sha256d::Hash::all_zeros())
    }

    pub fn update_utxo_set(&mut self, block: &Block) -> Result<()> {
        let mut utxo_batch = Batch::default();
        let mut index_batch = Batch::default();
        let mut addr_index_batch = Batch::default();
        
        let mut rolling_root = self.calculate_utxo_root()?;

        for tx in &block.transactions {
            let txid = tx.id();
            
            if !tx.is_coinbase() {
                for vin in &tx.vin {
                    let mut utxo_key = Vec::with_capacity(36);
                    utxo_key.extend_from_slice(vin.prev_txid.as_ref());
                    utxo_key.extend_from_slice(&vin.prev_vout.to_be_bytes());
                    
                    if let Some(val) = self.utxo_tree.get(&utxo_key)? {
                        rolling_root = xor_hashes(rolling_root, sha256d::Hash::hash(&val));
                        let tx_out: TxOut = bincode::deserialize(&val)?;
                        if !tx_out.script_pub_key.is_empty() {
                            let mut addr_key = tx_out.script_pub_key.clone();
                            addr_key.extend_from_slice(&utxo_key);
                            addr_index_batch.remove(addr_key);
                        }
                        utxo_batch.remove(utxo_key);
                    }
                }
            }

            index_batch.insert(txid.as_ref() as &[u8], block.header.hash().as_ref() as &[u8]);
            
            for (i, vout) in tx.vout.iter().enumerate() {
                let mut utxo_key = txid.to_byte_array().to_vec();
                utxo_key.extend(&(i as u32).to_be_bytes());
                let val = bincode::serialize(vout)?;
                rolling_root = xor_hashes(rolling_root, sha256d::Hash::hash(&val));
                utxo_batch.insert(utxo_key.clone(), val);

                if !vout.script_pub_key.is_empty() {
                    let mut addr_key = vout.script_pub_key.clone();
                    addr_key.extend_from_slice(&utxo_key);
                    addr_index_batch.insert(addr_key, &[]);
                }
            }

            if self.tx_cache.len() >= MAX_TX_CACHE_SIZE { self.tx_cache.clear(); }
            self.tx_cache.insert(txid, tx.clone());
        }

        self.utxo_tree.apply_batch(utxo_batch)?;
        self.tx_index_tree.apply_batch(index_batch)?;
        self.addr_utxo_tree.apply_batch(addr_index_batch)?;
        self.meta_tree.insert("utxo_rolling_root", rolling_root.as_ref() as &[u8])?;

        Ok(())
    }

    pub fn find_spendable_outputs(&self, address: &str, amount_needed: u64) -> Result<(u64, HashMap<sha256d::Hash, u32>)> {
        let mut unspent_outputs = HashMap::new();
        let mut accumulated_value = 0;
        let script_pub_key = TxOut::new(0, address.to_string()).script_pub_key;
        if script_pub_key.is_empty() { return Ok((0, HashMap::new())); }

        for item in self.addr_utxo_tree.scan_prefix(&script_pub_key) {
            let (addr_key, _) = item?;
            let utxo_key = &addr_key[script_pub_key.len()..];
            if let Some(val) = self.utxo_tree.get(utxo_key)? {
                let tx_out: TxOut = bincode::deserialize(&val)?;
                let txid = sha256d::Hash::from_slice(&utxo_key[0..32])?;
                let vout = u32::from_be_bytes(utxo_key[32..36].try_into()?);
                accumulated_value += tx_out.value;
                unspent_outputs.insert(txid, vout);
                if amount_needed > 0 && accumulated_value >= amount_needed { break; }
            }
        }

        if amount_needed > 0 && accumulated_value < amount_needed { bail!("Insufficient funds"); }
        Ok((accumulated_value, unspent_outputs))
    }

    pub fn calculate_total_fees(&self, block: &Block) -> u64 {
        block.transactions.iter()
            .filter(|tx| !tx.is_coinbase())
            .map(|tx| {
                let total_in: u64 = tx.vin.iter().map(|vin| {
                    self.get_transaction(&vin.prev_txid)
                        .ok().flatten()
                        .map_or(0, |prev_tx| prev_tx.vout[vin.prev_vout as usize].value)
                }).sum();
                let total_out: u64 = tx.vout.iter().map(|v| v.value).sum();
                total_in.saturating_sub(total_out)
            })
            .sum()
    }

    pub fn calculate_synergistic_work(&self, block: &mut Block) {
        let is_pow = block.header.vrf_proof.is_none();
        if is_pow {
            let easiest = BlockHeader::calculate_target(0x207fffff);
            let target = BlockHeader::calculate_target(block.header.bits);
            block.synergistic_work = if target.is_zero() { 1 } else { (&easiest / &target).to_u64().unwrap_or(1) };
        } else {
            let block_reward = self.consensus_params.coinbase_reward;
            let total_fees = self.calculate_total_fees(block);
            let economic_value = Fixed::from_integer(block_reward + total_fees);
            let alpha = Fixed::from_f64(0.4); 
            let pos_commitment = alpha * economic_value;
            block.synergistic_work = (pos_commitment.0 / (1 << 64)) as u64;
        }
    }

    pub fn create_block_template(&mut self, transactions: Vec<Transaction>, version: i32) -> Result<Block> {
        let prev = self.get_block(&self.tip).ok_or(anyhow!("Tip missing"))?;
        let now = Utc::now().timestamp() as u32;
        let delta = now.saturating_sub(prev.header.time);
        let bits = self.get_next_work_required(true, delta);
        let mut block = Block::new(now, transactions, self.tip, bits, prev.height + 1, version);
        block.beacons = self.beacon_mempool.clone();
        block.beacons.truncate(MAX_BEACONS_PER_BLOCK);
        block.header.utxo_root = self.calculate_utxo_root()?;
        Ok(block)
    }

    pub fn receive_beacon(&mut self, beacon: Beacon) -> Result<()> {
        if self.beacon_mempool.len() < 1000 { self.beacon_mempool.push(beacon); }
        Ok(())
    }

    pub fn process_finality_vote(&mut self, vote: FinalityVote) {
        if let Ok(pk) = PublicKey::from_slice(&vote.voter_public_key) {
            let addr = address_from_pubkey_hash(&hash_pubkey(&pk));
            let stake = self.consensus_engine.staking_module.get_voting_power(&addr);
            if stake > 0 { self.finality_gadget.process_vote(&vote, stake as u64); }
        }
    }

    /// Primary block ingestion logic.
    pub fn add_block(&mut self, mut block: Block) -> Result<()> {
        let hash = block.header.hash();
        
        // 1. Basic Validations
        if self.veto_manager.blacklisted_blocks.contains(&hash) { bail!("Vetoed block"); }
        
        // 2. CDF Checkpoint Protection (Section 13.6)
        if self.finality_gadget.finalized {
            if let Some(cp) = self.finality_gadget.target_checkpoint {
                if let Some(cp_block) = self.get_block(&cp) {
                    if block.height <= cp_block.height && hash != cp {
                        bail!("Finality Violation: Attempt to reorganize below CDF checkpoint {}", cp);
                    }
                }
            }
        }

        let is_pow = block.header.vrf_proof.is_none();
        let fees = self.calculate_total_fees(&block);

        // 3. PoS Proof-of-Burn Enforcement
        if !is_pow {
            let required = (fees as f64 * self.ldd_state.current_burn_rate) as u64;
            let burned = block.transactions.get(0).map_or(0, |tx| {
                tx.vout.iter().filter(|o| o.script_pub_key == vec![0x6a]).map(|o| o.value).sum::<u64>()
            });
            if burned < required { bail!("Insufficient Proof-of-Burn commitment for PoS block."); }
        }

        let prev = self.get_block(&block.header.prev_blockhash).ok_or(anyhow!("Parent block missing"))?;
        self.calculate_synergistic_work(&mut block);
        block.total_work = prev.total_work + block.synergistic_work;

        self.blocks_tree.insert(hash.as_ref() as &[u8], bincode::serialize(&block)?)?;

        // 4. Fork Choice & State Updates
        if block.total_work > self.total_work {
            self.tip = hash;
            self.total_work = block.total_work;
            self.headers.push(block.header.clone()); // Maintain headers vector
            self.update_utxo_set(&block)?;
            self.dcs.process_beacons(&block.beacons);
            
            // --- Burst Finality & CDF Integration ---
            if self.burst_manager.check_and_activate(&block, fees) {
                info!("🔥 BURST TRIGGERED BY FEES: Realizing via CDF Gadget for Block {}", hash);
                self.finality_gadget.activate(hash, self.total_staked);
            }
            
            if self.finality_gadget.active && !self.finality_gadget.finalized {
                if is_pow {
                    self.finality_gadget.process_pow_block(&hash);
                }
                if self.finality_gadget.check_finality() {
                    info!("✅ CHROMO-DYNAMIC FINALITY REACHED for checkpoint block {}", hash);
                }
            }

            self.burst_manager.update_state(block.height);

            // 5. Autonomous Adaptation (LDD Control Loop)
            self.ldd_state.recent_blocks.push((block.header.time, is_pow));
            if self.ldd_state.recent_blocks.len() >= self.ldd_state.current_adjustment_window {
                self.adjust_ldd();
            }

            self.update_and_execute_proposals();
            self.blocks_tree.insert(self.db_config.tip_key.as_str(), hash.as_ref() as &[u8])?;
            self.blocks_tree.insert(&self.db_config.total_work_key, &self.total_work.to_be_bytes() as &[u8])?;
        }
        Ok(())
    }

    pub fn get_block(&self, hash: &sha256d::Hash) -> Option<Block> {
        self.blocks_tree.get(hash.as_ref() as &[u8]).ok()?.map(|b| bincode::deserialize(&b).unwrap())
    }

    pub fn get_transaction(&self, txid: &sha256d::Hash) -> Result<Option<Transaction>> {
        if let Some(bh) = self.tx_index_tree.get(txid.as_ref() as &[u8])? {
            let block_hash = sha256d::Hash::from_slice(&bh)?;
            if let Some(block) = self.get_block(&block_hash) {
                return Ok(block.transactions.iter().find(|t| t.id() == *txid).cloned());
            }
        }
        Ok(None)
    }

    pub fn get_mempool_txs(&mut self) -> Vec<Transaction> {
        let txs = self.mempool.values().cloned().collect();
        self.mempool.clear();
        txs
    }

    pub fn get_and_reset_metrics(&mut self) -> LocalMetrics {
        let m = self.metrics.clone();
        self.metrics.orphan_count = 0;
        self.metrics.max_reorg_depth = 0;
        self.metrics.beacon_providers.clear();
        m
    }

    pub fn get_next_work_required(&self, _pow: bool, _delta: u32) -> u32 {
        0x207fffff 
    }

    pub fn adjust_ldd(&mut self) {
        let consensus_values = self.dcs.calculate_consensus();
        let consensus_delay_sec = (consensus_values.consensus_delay as f64 / 1000.0).ceil() as u32;
        let safety_margin = 2; 
        let psi_new = consensus_delay_sec + safety_margin;
        let floor = psi_new + safety_margin; 
        let mu_max = self.consensus_params.target_block_time as u32;
        let mu_target = mu_max.saturating_sub(((mu_max.saturating_sub(floor)) as f64 * consensus_values.consensus_load) as u32).max(floor);

        self.ldd_state.current_psi = psi_new;
        self.ldd_state.current_target_block_time = mu_target as u64;

        let delta_mu = (mu_target as f64 - psi_new as f64).max(1.0);
        let m_req = std::f64::consts::PI / (2.0 * delta_mu * delta_mu);
        let xi_optimal = ((-2.0 * P_FALLBACK.ln()) / m_req).sqrt().round() as u32;
        self.ldd_state.current_gamma = psi_new + xi_optimal;

        let beta_base = self.fee_params.min_burn_rate;
        let k_sec = 0.5; 
        self.ldd_state.current_burn_rate = (beta_base + k_sec * consensus_values.security_threat_level).min(self.fee_params.max_burn_rate);
        
        let n_base = 240.0;
        let n_min = 5.0;
        self.ldd_state.current_adjustment_window = ((n_base - n_min) * (1.0 - consensus_values.security_threat_level) + n_min).round() as usize;

        let (pow_blocks, pos_blocks) = self.ldd_state.recent_blocks.iter().fold((0.0, 0.0), |(pow, pos), &(_, is_pow)| {
            if is_pow { (pow + 1.0, pos) } else { (pow, pos + 1.0) }
        });
        let total_blocks = pow_blocks + pos_blocks;
        let proportion_error = if total_blocks > 0.0 { (pow_blocks / total_blocks) - 0.5 } else { 0.0 };

        let kappa_base = 0.1;
        let kappa_gain = 0.2;
        let current_kappa = kappa_base + kappa_gain * (0.0_f64.max(-proportion_error));

        let new_f_a_pow = self.ldd_state.f_a_pow.to_f64() * (1.0 - current_kappa * proportion_error);
        let new_f_a_pos = self.ldd_state.f_a_pos.to_f64() * (1.0 + current_kappa * proportion_error);

        self.ldd_state.f_a_pow = Fixed::from_f64(new_f_a_pow.max(0.01));
        self.ldd_state.f_a_pos = Fixed::from_f64(new_f_a_pos.max(0.01));

        self.ldd_state.recent_blocks.clear();
        self.dcs.reset_interval();
    }

    pub fn update_and_execute_proposals(&mut self) {
        let current_height = self.headers.len() as u32; 
        let proposals_clone = self.governance.proposals.clone();
        for proposal in proposals_clone.values() {
            if proposal.state == ProposalState::Active && current_height > proposal.end_block as u32 {
                let total_votes = proposal.votes_for + proposal.votes_against;
                if total_votes > 0 && (proposal.votes_for * 100 > self.governance_params.vote_threshold_percent * total_votes) {
                    let current_proposal = self.governance.proposals.get_mut(&proposal.id).unwrap();
                    current_proposal.state = ProposalState::Executed;
                    match &proposal.payload {
                        ProposalPayload::UpdateTargetBlockTime(new_time) => {
                            Arc::make_mut(&mut self.consensus_params).target_block_time = *new_time;
                        }
                        _ => {}
                    }
                } else {
                    self.governance.proposals.get_mut(&proposal.id).unwrap().state = ProposalState::Failed;
                }
            }
        }
    }

    #[allow(dead_code)]
    fn validate_beacon_bounties(&self, block: &Block) -> Result<()> {
        let coinbase = block.transactions.get(0).ok_or(anyhow!("Missing coinbase"))?;
        let pool = (self.consensus_params.coinbase_reward * 1) / 100;
        let per_beacon = pool / block.beacons.len() as u64;
        if per_beacon == 0 { return Ok(()); }

        for beacon in &block.beacons {
            let pk = PublicKey::from_slice(&beacon.public_key)?;
            let addr = address_from_pubkey_hash(&hash_pubkey(&pk));
            
            let found = coinbase.vout.iter().any(|out| {
                out.value == per_beacon && 
                out.script_pub_key == TxOut::new(0, addr.clone()).script_pub_key
            });
            if !found { bail!("Invalid Coinbase: Missing bounty payment for provider {}", addr); }
        }
        Ok(())
    }
}

fn xor_hashes(h1: sha256d::Hash, h2: sha256d::Hash) -> sha256d::Hash {
    let mut b1 = h1.to_byte_array();
    let b2 = h2.to_byte_array();
    for i in 0..32 { b1[i] ^= b2[i]; }
    sha256d::Hash::from_byte_array(b1)
}
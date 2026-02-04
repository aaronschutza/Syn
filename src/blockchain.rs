// src/blockchain.rs

use crate::{
    block::{Block, BlockHeader, Beacon, BeaconData},
    config::{ConsensusConfig, DatabaseConfig, FeeConfig, GovernanceConfig},
    dcs::DecentralizedConsensusService,
    burst::BurstFinalityManager,
    cdf::{FinalityGadget, FinalityVote}, 
    fixed_point::Fixed,
    governance::{Governance, ProposalState, ProposalPayload},
    transaction::{Transaction, TxOut},
    engine::ConsensusEngine,
    params::MAX_BLOCK_SIZE,
};
use anyhow::{anyhow, bail, Result};
use bitcoin_hashes::{sha256d, Hash, HashEngine};
use chrono::Utc;
use log::{info, warn};
use num_bigint::BigUint;
use num_traits::{FromPrimitive, ToPrimitive, Zero};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use secp256k1::{Secp256k1, PublicKey, Message, ecdsa::Signature};

/// Represents the dynamic state of the LDD system.
#[derive(Clone, Debug)]
pub struct LddState {
    pub f_a_pow: Fixed,
    pub f_a_pos: Fixed,
    /// History of (timestamp, is_pow) for the current adjustment window.
    pub recent_blocks: Vec<(u32, bool)>,
    
    // --- Autonomous Parameters (Whitepaper Section 10.12) ---
    pub current_psi: u32,
    pub current_gamma: u32,
    pub current_target_block_time: u64,
    pub current_adjustment_window: usize,
    pub current_burn_rate: f64,
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
        }
    }
}

/// Local metrics for beacon generation (Whitepaper Section 15.2 & 15.5)
#[derive(Clone, Debug, Default)]
pub struct LocalMetrics {
    pub orphan_count: u32,
    pub max_reorg_depth: u32,
    pub last_delay_ms: u32,
}

/// Manages VETO votes against blocks (Whitepaper Section 9.1 & 9.11)
#[derive(Debug, Default)]
pub struct VetoManager {
    /// Maps BlockHash -> Set of Voter Public Keys (to prevent double voting)
    pub votes: HashMap<sha256d::Hash, HashSet<Vec<u8>>>,
    /// Maps BlockHash -> Accumulated Stake Weight of Vetoes
    pub weight: HashMap<sha256d::Hash, u64>,
}

pub struct Blockchain {
    pub db: Arc<sled::Db>,
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
    /// Headers of the canonical chain.
    pub headers: Vec<BlockHeader>,
    pub tx_cache: HashMap<sha256d::Hash, Transaction>,
    pub pos_block_count: u32,
    pub bootstrap_phase_complete: bool,
    pub last_pow_block_hash: sha256d::Hash,
    pub consensus_engine: ConsensusEngine,
    
    // --- Decentralized Consensus Service ---
    pub dcs: DecentralizedConsensusService,
    // --- Burst Finality Manager ---
    pub burst_manager: BurstFinalityManager,
    // --- CDF Finality Gadget ---
    pub finality_gadget: FinalityGadget,
    
    // --- Local Metrics ---
    pub metrics: LocalMetrics,

    // --- Veto Manager ---
    pub veto_manager: VetoManager,
}

impl Blockchain {
    pub fn new(
        db_path: &str,
        consensus_params: Arc<ConsensusConfig>,
        fee_params: Arc<FeeConfig>,
        governance_params: Arc<GovernanceConfig>,
        db_config: Arc<DatabaseConfig>,
        consensus_engine: ConsensusEngine,
    ) -> Result<Self> {
        let db = Arc::new(sled::open(db_path)?);
        Self::new_with_db(db, consensus_params, fee_params, governance_params, db_config, consensus_engine)
    }

    pub fn new_with_db(
        db: Arc<sled::Db>,
        consensus_params: Arc<ConsensusConfig>,
        fee_params: Arc<FeeConfig>,
        governance_params: Arc<GovernanceConfig>,
        db_config: Arc<DatabaseConfig>,
        consensus_engine: ConsensusEngine,
    ) -> Result<Self> {
        let blocks_tree = db.open_tree(&db_config.blocks_tree)?;
        let state_tree = db.open_tree("state")?;

        let mut ldd_state = LddState::default();
        ldd_state.current_psi = consensus_params.psi_slot_gap;
        ldd_state.current_gamma = consensus_params.gamma_recovery_threshold;
        ldd_state.current_target_block_time = consensus_params.target_block_time;
        ldd_state.current_adjustment_window = consensus_params.adjustment_window;
        ldd_state.current_burn_rate = fee_params.min_burn_rate;

        let mut bc = Blockchain {
            db,
            tip: sha256d::Hash::all_zeros(),
            total_work: 0,
            mempool: HashMap::new(),
            beacon_mempool: Vec::new(),
            ldd_state,
            consensus_params: consensus_params.clone(),
            fee_params,
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
            burst_manager: BurstFinalityManager::new(24, 1_000_000), 
            finality_gadget: FinalityGadget::new(),
            metrics: LocalMetrics::default(),
            veto_manager: VetoManager::default(),
        };

        if blocks_tree.is_empty() {
            info!("No existing blockchain found. Creating genesis block.");
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
            blocks_tree.insert(genesis_hash.as_ref() as &[u8], bincode::serialize(&genesis)?)?;
            blocks_tree.insert(bc.db_config.tip_key.as_str(), genesis_hash.as_ref() as &[u8])?;
            blocks_tree.insert(&bc.db_config.total_work_key, &genesis.total_work.to_be_bytes() as &[u8])?;
            bc.tip = genesis_hash;
            bc.total_work = genesis.total_work;
            bc.headers.push(genesis.header.clone());
            bc.last_pow_block_hash = genesis_hash;
            blocks_tree.insert("headers", bincode::serialize(&bc.headers)?)?;
            bc.update_utxo_set(&genesis)?;
            blocks_tree.flush()?;

        } else {
            info!("Loading existing blockchain from database.");
            let tip_bytes = blocks_tree.get(&bc.db_config.tip_key)?.ok_or_else(|| anyhow!("Failed to read tip from db"))?;
            bc.tip = Hash::from_slice(&tip_bytes)?;
            let total_work_bytes = blocks_tree.get(&bc.db_config.total_work_key)?.unwrap_or_else(|| 0u64.to_be_bytes().to_vec().into());
            bc.total_work = u64::from_be_bytes(total_work_bytes.as_ref().try_into().unwrap_or([0; 8]));
            let headers_bytes = blocks_tree.get("headers")?.unwrap_or_else(|| bincode::serialize(&Vec::<BlockHeader>::new()).unwrap().into());
            bc.headers = bincode::deserialize(&headers_bytes)?;
            let pos_count_bytes = state_tree.get("pos_block_count")?.unwrap_or_else(|| 0u32.to_be_bytes().to_vec().into());
            bc.pos_block_count = u32::from_be_bytes(pos_count_bytes.as_ref().try_into().unwrap_or([0; 4]));
            let bootstrap_bytes = state_tree.get("bootstrap_phase_complete")?.unwrap_or_else(|| bincode::serialize(&false).unwrap().into());
            bc.bootstrap_phase_complete = bincode::deserialize(&bootstrap_bytes)?;
        }

        Ok(bc)
    }

    // ... (find_spendable_outputs, get_confirmations, calculate_utxo_root, calculate_total_fees, calculate_synergistic_work, create_block_template remain unchanged) ...
    pub fn find_spendable_outputs(&self, address: &str, amount_needed: u64) -> Result<(u64, HashMap<sha256d::Hash, u32>)> {
        let mut unspent_outputs = HashMap::new();
        let mut accumulated_value = 0;
        let utxo_tree = self.db.open_tree(&self.db_config.utxo_tree)?;
        let script_pub_key_to_find = TxOut::new(0, address.to_string()).script_pub_key;

        for item in utxo_tree.iter() {
            let (key, value) = item?;
            let tx_out: TxOut = bincode::deserialize(&value)?;

            if tx_out.script_pub_key == script_pub_key_to_find {
                if key.len() != 36 { continue; }
                let txid = sha256d::Hash::from_slice(&key[0..32])?;

                let tx = match self.get_transaction(&txid) {
                    Ok(Some(tx)) => tx,
                    _ => {
                        warn!("Could not find transaction for UTXO with txid: {}", txid);
                        continue;
                    }
                };

                if tx.is_coinbase() {
                    let confirmations = self.get_confirmations(&txid).unwrap_or(0);
                    if confirmations < self.consensus_params.coinbase_maturity {
                        continue;
                    }
                }

                let vout = u32::from_be_bytes(key[32..36].try_into()?);
                accumulated_value += tx_out.value;
                unspent_outputs.insert(txid, vout);

                if amount_needed > 0 && accumulated_value >= amount_needed {
                    break;
                }
            }
        }

        if amount_needed > 0 && accumulated_value < amount_needed {
            bail!("Insufficient funds. Needed {}, found {}", amount_needed, accumulated_value);
        }
        Ok((accumulated_value, unspent_outputs))
    }
    
    pub fn get_confirmations(&self, txid: &sha256d::Hash) -> Result<u32> {
        let tx_index_tree = self.db.open_tree(&self.db_config.tx_index_tree)?;
        if let Some(block_hash_bytes) = tx_index_tree.get::<&[u8]>(txid.as_ref())? {
            let block_hash = sha256d::Hash::from_slice(&block_hash_bytes)?;
            if let Some(block) = self.get_block(&block_hash) {
                let tip_height = self.get_block(&self.tip).map_or(0, |b| b.height);
                return Ok(tip_height.saturating_sub(block.height) + 1);
            }
        }
        Ok(0)
    }

    pub fn calculate_utxo_root(&self) -> Result<sha256d::Hash> {
        let utxo_tree = self.db.open_tree(&self.db_config.utxo_tree)?;
        if utxo_tree.is_empty() { return Ok(sha256d::Hash::all_zeros()); }

        let mut utxo_hashes = Vec::new();
        for key_res in utxo_tree.iter().keys() {
            utxo_hashes.push(sha256d::Hash::hash(&key_res?));
        }
        utxo_hashes.sort();

        if utxo_hashes.is_empty() { return Ok(sha256d::Hash::all_zeros()); }
        if utxo_hashes.len() % 2 == 1 {
            if let Some(last) = utxo_hashes.last().cloned() { utxo_hashes.push(last); }
        }

        while utxo_hashes.len() > 1 {
            let mut next_level = vec![];
            for chunk in utxo_hashes.chunks(2) {
                let mut engine = sha256d::Hash::engine();
                engine.input(&chunk[0][..]);
                engine.input(&chunk[1][..]);
                next_level.push(sha256d::Hash::from_engine(engine));
            }
            utxo_hashes = next_level;
            if utxo_hashes.len() % 2 == 1 && utxo_hashes.len() > 1 {
                if let Some(last) = utxo_hashes.last().cloned() { utxo_hashes.push(last); }
            }
        }

        Ok(utxo_hashes.pop().unwrap_or_else(sha256d::Hash::all_zeros))
    }

    // Helper to calculate total transaction fees in a block
    fn calculate_total_fees(&self, block: &Block) -> u64 {
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

    fn calculate_synergistic_work(&self, block: &mut Block) {
        let is_pow = block.header.vrf_proof.is_none();
        let mut work = 0;

        if is_pow {
            let easiest_target = BlockHeader::calculate_target(0x207fffff);
            let block_target = BlockHeader::calculate_target(block.header.bits);
            if !block_target.is_zero() {
                if let Some(w) = (&easiest_target / &block_target).to_u64() {
                    work += w.max(1);
                } else {
                    work += 1;
                }
            } else {
                work += 1;
            }
        } else {
            let block_reward = self.consensus_params.coinbase_reward;
            let total_fees = self.calculate_total_fees(block);
            let total_staked_fixed = Fixed::from_integer(self.total_staked);
            let alpha = if total_staked_fixed.0 > 0 {
                Fixed::from_integer(1)
            } else {
                Fixed(0)
            };
            let economic_value = Fixed::from_integer(block_reward + total_fees);
            let pos_commitment = alpha * economic_value;
            work += (pos_commitment.0 / (1 << 64)) as u64;
        }

        block.synergistic_work = work;
    }

    pub fn create_block_template(&mut self, transactions: Vec<Transaction>, block_version: i32) -> Result<Block> {
        let prev_block = self.get_block(&self.tip).ok_or_else(|| anyhow!("Could not get tip block to mine on"))?;
        let height = prev_block.height + 1;
        let delta = (Utc::now().timestamp() as u32).saturating_sub(prev_block.header.time);
        
        let bits = if !self.bootstrap_phase_complete {
            info!("[Bootstrap] Forcing minimum difficulty for fast initial blocks.");
            0x207fffff
        } else {
            self.get_next_work_required(true, delta)
        };
        let mut block = Block::new(Utc::now().timestamp() as u32, transactions, self.tip, bits, height, block_version);
        block.beacons = self.beacon_mempool.clone();
        self.beacon_mempool.clear();
        block.header.utxo_root = self.calculate_utxo_root()?;
        Ok(block)
    }

    pub fn receive_beacon(&mut self, beacon: Beacon) -> Result<()> {
        let secp = Secp256k1::new();
        let pubkey = PublicKey::from_slice(&beacon.public_key)?;
        let msg_hash = sha256d::Hash::hash(&bincode::serialize(&beacon.data)?);
        let message = Message::from_digest_slice(msg_hash.as_ref())?;
        let signature = Signature::from_compact(&beacon.signature)?;
        
        secp.verify_ecdsa(&message, &signature, &pubkey)
            .map_err(|_| anyhow!("Invalid beacon signature"))?;

        if self.beacon_mempool.len() < 1000 {
            if !self.beacon_mempool.contains(&beacon) {
                self.beacon_mempool.push(beacon);
            }
        }
        Ok(())
    }

    // --- VETO Logic ---
    // Whitepaper Section 9.1 & 9.11: Non-slashing economic deterrent.
    // If a block is VETOed by > 50% of stake, it effectively forfeits its reward.
    // In longest-chain terms, we treat it as INVALID to force a reorg.
    
    pub fn process_veto(&mut self, block_hash: sha256d::Hash, public_key: Vec<u8>, signature: Vec<u8>, stake_weight: u64) -> Result<()> {
        // 1. Verify Signature on VETO message
        // Veto Message = "VETO" + block_hash
        let mut msg_bytes = b"VETO".to_vec();
        msg_bytes.extend_from_slice(block_hash.as_ref());
        let msg_hash = sha256d::Hash::hash(&msg_bytes);
        
        let secp = Secp256k1::new();
        let pk = PublicKey::from_slice(&public_key)?;
        let msg = Message::from_digest_slice(msg_hash.as_ref())?;
        let sig = Signature::from_compact(&signature)?;
        
        secp.verify_ecdsa(&msg, &sig, &pk).map_err(|_| anyhow!("Invalid VETO signature"))?;

        // 2. Aggregate Vote
        let voters = self.veto_manager.votes.entry(block_hash).or_insert_with(HashSet::new);
        if voters.insert(public_key.clone()) {
            let current_weight = self.veto_manager.weight.entry(block_hash).or_insert(0);
            *current_weight += stake_weight;
            
            info!("Received VETO for block {} from stake {}. Total Weight: {}/{}", block_hash, stake_weight, *current_weight, self.total_staked);

            // 3. Check Threshold ( > 50% of total stake)
            if *current_weight > (self.total_staked / 2) {
                warn!("🚨 BLOCK {} HAS BEEN VETOED BY STAKE MAJORITY! 🚨", block_hash);
                // In a full impl, we would prune this block and all its descendants.
                // For this prototype, we just log it as a critical event. 
                // Actual reorganization would happen because honest nodes would stop building on it.
            }
        }

        Ok(())
    }

    pub fn process_finality_vote(&mut self, vote: FinalityVote) {
        let secp = Secp256k1::new();
        if let Ok(pubkey) = PublicKey::from_slice(&vote.voter_public_key) {
            let mut msg_bytes = vote.checkpoint_hash.to_byte_array().to_vec();
            msg_bytes.push(vote.color as u8);
            let msg_hash = sha256d::Hash::hash(&msg_bytes);
            
            if let Ok(message) = Message::from_digest_slice(msg_hash.as_ref()) {
                if let Ok(signature) = Signature::from_compact(&vote.signature) {
                    if secp.verify_ecdsa(&message, &signature, &pubkey).is_ok() {
                        let stake = 1000; 
                        self.finality_gadget.process_vote(&vote, stake);
                        
                        if self.finality_gadget.check_finality() {
                             info!("✨✨✨ CDF FINALITY ACHIEVED via Vote Aggregation ✨✨✨");
                        }
                    } else {
                        warn!("Invalid signature on FinalityVote");
                    }
                }
            }
        }
    }

    pub fn add_block(&mut self, mut block: Block) -> Result<()> {
        let block_hash = block.header.hash();
        if self.get_block(&block_hash).is_some() {
             info!("Ignoring known block {}", block_hash);
             return Ok(());
        }

        // --- Veto Check ---
        // If a block has already been vetoed (e.g. propagated header before body), reject it.
        if let Some(weight) = self.veto_manager.weight.get(&block_hash) {
            if *weight > (self.total_staked / 2) {
                bail!("Block {} rejected due to active VETO.", block_hash);
            }
        }

        // Calculate Network Delay (Whitepaper 15.2)
        let now = Utc::now().timestamp() as u32;
        // Avoid negative delay if clocks drift
        let delay = now.saturating_sub(block.header.time);
        self.metrics.last_delay_ms = delay * 1000;

        if block.header.prev_blockhash == sha256d::Hash::all_zeros() {
            bail!("Genesis block should be handled by Blockchain::new");
        }
        
        for tx in &block.transactions {
            self.verify_transaction(tx)?;
        }

        let is_pow = block.header.vrf_proof.is_none();

        if !is_pow {
            let total_fees = self.calculate_total_fees(&block);
            let current_burn_rate = self.ldd_state.current_burn_rate; 
            let required_burn = (total_fees as f64 * current_burn_rate) as u64;

            let mut burned_amount = 0;
            if let Some(coinbase) = block.transactions.get(0) {
                for out in &coinbase.vout {
                    if out.is_burn() {
                        burned_amount += out.value;
                    }
                }
            }

            if burned_amount < required_burn {
                warn!("Invalid PoS Block: Insufficient Proof-of-Burn. Required: {}, Found: {}", required_burn, burned_amount);
                bail!("Invalid PoS Block: Insufficient Proof-of-Burn");
            }
        }

        info!("[Validation] Starting validation for block {} at height {}", block_hash, block.height);
        
        // --- Persistence Logic ---
        // We now persist valid blocks even if they don't immediately extend the tip, 
        // to support reorgs and accurate topology measurement.
        let prev_block = match self.get_block(&block.header.prev_blockhash) {
            Some(b) => b,
            None => {
                bail!("[Validation] FAILED: Previous block {} not found.", block.header.prev_blockhash);
            }
        };

        if is_pow {
            self.last_pow_block_hash = block.header.hash();
        }
        self.calculate_synergistic_work(&mut block);
        let new_total_work = prev_block.total_work + block.synergistic_work;
        block.total_work = new_total_work;
        
        // --- Burst Finality Trigger Check ---
        let total_fees = self.calculate_total_fees(&block);
        if self.burst_manager.check_and_activate(&block, total_fees) {
            self.finality_gadget.activate(block_hash, self.total_staked);
        }
        self.burst_manager.update_state(block.height);

        // --- CDF Processing ---
        if is_pow && self.finality_gadget.active && !self.finality_gadget.finalized {
            self.finality_gadget.process_pow_block(&block_hash);
            if self.finality_gadget.check_finality() {
                info!("✨✨✨ CDF FINALITY ACHIEVED for Checkpoint {} ✨✨✨", self.finality_gadget.target_checkpoint.unwrap());
            }
        }

        // --- Store Block (Sidechain or Main) ---
        let blocks_tree = self.db.open_tree(&self.db_config.blocks_tree)?;
        blocks_tree.insert(block_hash.as_ref() as &[u8], bincode::serialize(&block)?)?;

        if new_total_work > self.total_work {
            // New Tip / Reorg
            info!("[Validation] PASSED: New total work {} is greater than current tip's work {}.", new_total_work, self.total_work);
            
            // Calculate Reorg Depth
            if prev_block.header.hash() != self.tip {
                // Simplified: Previous tip height - Common Ancestor height
                // Since we don't track full tree efficiently in memory, we approximate reorg depth
                // as difference in height between old tip and new block, if heights are close.
                // A better check requires traversing back.
                // For metrics, we count this event.
                let old_tip_height = self.headers.last().map(|h| self.get_block(&h.hash()).unwrap().height).unwrap_or(0);
                // Rough estimate for metric beacon
                let depth = old_tip_height.saturating_sub(prev_block.height) + 1;
                self.metrics.max_reorg_depth = self.metrics.max_reorg_depth.max(depth);
            }

            self.tip = block_hash;
            self.total_work = new_total_work;
            
            // Rebuild headers chain in memory (Simplified for prototype)
            // Real impl would handle reorg of self.headers properly
            self.headers.push(block.header.clone());
            
            blocks_tree.insert(self.db_config.tip_key.as_str(), block_hash.as_ref() as &[u8])?;
            blocks_tree.insert(&self.db_config.total_work_key, &new_total_work.to_be_bytes() as &[u8])?;
            blocks_tree.insert("headers", bincode::serialize(&self.headers)?)?;
            
            self.update_utxo_set(&block)?;
            self.apply_clock_adjustment(&block);
            self.update_and_execute_proposals();
            self.dcs.process_beacons(&block.beacons);

            if !self.bootstrap_phase_complete {
                if block.header.vrf_proof.is_some() {
                    self.pos_block_count += 1;
                    if self.pos_block_count >= self.consensus_params.bootstrap_pos_block_threshold {
                        self.bootstrap_phase_complete = true;
                        info!("[Validation] ✅ Bootstrap phase complete! Transitioning to permanent recovery behavior.");
                    }
                }
                let state_tree = self.db.open_tree("state")?;
                state_tree.insert("pos_block_count", &self.pos_block_count.to_be_bytes() as &[u8])?;
                state_tree.insert("bootstrap_phase_complete", bincode::serialize(&self.bootstrap_phase_complete)?)?;
            }

            self.ldd_state.recent_blocks.push((block.header.time, is_pow));
            
            if self.ldd_state.recent_blocks.len() >= self.ldd_state.current_adjustment_window { 
                self.adjust_ldd(); 
                self.dcs.reset_interval();
            }
            blocks_tree.flush()?;
            self.db.flush()?;
            info!("[Validation] Block successfully added and persisted as TIP.");
        } else {
            // Orphan / Sidechain block
            self.metrics.orphan_count += 1;
            info!("[Validation] Block {} accepted as sidechain/orphan (Work {} <= Tip {}).", block_hash, new_total_work, self.total_work);
        }

        let block_size = block.get_size();
        self.consensus_engine.adjust_target_slope(block_size);
        
        Ok(())
    }

    pub fn add_header(&mut self, header: BlockHeader) -> Result<()> {
        let prev_header = self.headers.last().ok_or_else(|| anyhow!("No headers in chain"))?;
        if header.prev_blockhash != prev_header.hash() {
            bail!("Header does not connect to the previous one");
        }
        self.headers.push(header);
        let blocks_tree = self.db.open_tree(&self.db_config.blocks_tree)?;
        blocks_tree.insert("headers", bincode::serialize(&self.headers)?)?;
        Ok(())
    }

    pub fn get_headers(&self) -> Vec<BlockHeader> {
        self.headers.clone()
    }
    
    pub fn get_next_work_required(&self, is_pow: bool, delta: u32) -> u32 {
        let f_a = if is_pow { self.ldd_state.f_a_pow } else { self.ldd_state.f_a_pos };
        
        if let Some((psi_override, _target_override)) = self.burst_manager.get_burst_parameters() {
            return Self::get_next_work_required_dynamic(is_pow, delta, f_a, 
                psi_override, 
                psi_override + 5, 
                self.consensus_params.clone());
        }

        Self::get_next_work_required_dynamic(is_pow, delta, f_a, 
            self.ldd_state.current_psi, 
            self.ldd_state.current_gamma, 
            self.consensus_params.clone())
    }

    pub fn get_next_work_required_dynamic(_is_pow: bool, delta: u32, f_a: Fixed, psi: u32, gamma: u32, consensus_params: Arc<ConsensusConfig>) -> u32 {
        if delta < psi {
            return consensus_params.max_target_bits;
        }
        if psi >= gamma {
            warn!("Configuration error: psi ({}) must be less than gamma ({}).", psi, gamma);
            return consensus_params.max_target_bits;
        }
    
        let f_delta = if delta < gamma {
            if gamma - psi == 0 { return consensus_params.max_target_bits; }
            let num = Fixed::from_integer(delta.saturating_sub(psi).into());
            let den = Fixed::from_integer((gamma - psi).into());
            f_a * (num / den)
        } else {
            f_a
        };
    
        if f_delta.0 == 0 { return consensus_params.max_target_bits; }
    
        let max_target = BlockHeader::calculate_target(consensus_params.max_target_bits);
        let work_f64 = (Fixed::from_integer(1) / f_delta).to_f64();
        let work_biguint = BigUint::from_f64(work_f64).unwrap_or_else(|| BigUint::from(1u32));
    
        if work_biguint.is_zero() {
            return consensus_params.max_target_bits;
        }
    
        let mut target_biguint = &max_target / work_biguint;
        if target_biguint.is_zero() {
            target_biguint = BigUint::from(1u32);
        }
    
        let mut target_bytes = target_biguint.to_bytes_be();
        if target_biguint > max_target { target_bytes = max_target.to_bytes_be(); }
        if target_bytes.is_empty() { return consensus_params.max_target_bits; }
    
        let mut mantissa_bytes = [0u8; 3];
        let start = if target_bytes.len() > 3 { target_bytes.len() - 3 } else { 0 };
        let slice = &target_bytes[start..];
        mantissa_bytes[(3 - slice.len())..].copy_from_slice(slice);
        let mantissa = u32::from_be_bytes([0, mantissa_bytes[0], mantissa_bytes[1], mantissa_bytes[2]]);
        let exponent = target_bytes.len() as u32;
        (exponent << 24) | mantissa
    }

    pub fn adjust_ldd(&mut self) {
        let window_size = self.ldd_state.recent_blocks.len();
        if window_size < self.ldd_state.current_adjustment_window {
            return;
        }

        let consensus_values = self.dcs.calculate_consensus();
        let consensus_delay_ms = consensus_values.consensus_delay; 
        let consensus_load = consensus_values.consensus_load;      
        let consensus_threat = consensus_values.consensus_threat_level;
        let chain_health = consensus_values.chain_health_score;

        let consensus_delay_sec = (consensus_delay_ms as f64 / 1000.0).ceil() as u32;

        let safety_margin = 2; 
        let psi_new = consensus_delay_sec + safety_margin;
        
        let floor = psi_new + safety_margin; 
        let mu_max = self.consensus_params.target_block_time as u32;
        
        let target_reduction = ((mu_max.saturating_sub(floor)) as f64 * consensus_load) as u32;
        let mut mu_target = mu_max.saturating_sub(target_reduction);
        if mu_target < floor { mu_target = floor; }

        self.ldd_state.current_psi = psi_new;
        self.ldd_state.current_target_block_time = mu_target as u64;
        
        let window_duration = self.consensus_params.gamma_recovery_threshold.saturating_sub(self.consensus_params.psi_slot_gap);
        self.ldd_state.current_gamma = psi_new + window_duration;

        // Adaptive Security & Monetary Policy
        let n_base = 240.0;
        let n_min = 5.0;
        let n_new = ((n_base - n_min) * (1.0 - consensus_threat) + n_min).round() as usize;
        self.ldd_state.current_adjustment_window = n_new;

        let beta_base = self.fee_params.min_burn_rate;
        let beta_max = self.fee_params.max_burn_rate;
        let kappa_sec = 0.5; 
        let beta_new = (beta_base + kappa_sec * consensus_threat).min(beta_max);
        self.ldd_state.current_burn_rate = beta_new;

        let fee_base = 1_000_000.0; 
        let kappa_topo = 2.0;
        let fee_burst_new = (fee_base * (1.0 + kappa_topo * chain_health)) as u64;
        self.burst_manager.fee_burst_threshold = fee_burst_new;

        info!(
            "LDD Autonomy: Threat={:.2}, Health={:.2} -> N={}, Burn={:.4}, BurstFee={}", 
            consensus_threat, chain_health, n_new, beta_new, fee_burst_new
        );

        let (pow_blocks, pos_blocks) = self.ldd_state.recent_blocks.iter().fold((0.0, 0.0), |(pow, pos), &(_, is_pow)| {
            if is_pow { (pow + 1.0, pos) } else { (pow, pos + 1.0) }
        });
        let total_blocks = pow_blocks + pos_blocks;

        let first_block_time = self.ldd_state.recent_blocks[0].0;
        let last_block_time = self.ldd_state.recent_blocks.last().unwrap().0;
        
        let observed_avg_time = if window_size > 1 {
            (last_block_time - first_block_time) as f64 / (window_size - 1) as f64
        } else {
            mu_target as f64
        };

        let time_error = observed_avg_time - mu_target as f64;
        let proportion_error = if total_blocks > 0.0 { (pow_blocks / total_blocks) - 0.5 } else { 0.0 };

        let kappa_time = 0.02;
        let kappa_prop = 0.1;

        let time_adjustment = 1.0 - kappa_time * time_error;
        let pow_prop_adjustment = 1.0 - kappa_prop * proportion_error;
        let pos_prop_adjustment = 1.0 + kappa_prop * proportion_error;

        let new_f_a_pow = self.ldd_state.f_a_pow.to_f64() * time_adjustment * pow_prop_adjustment;
        let new_f_a_pos = self.ldd_state.f_a_pos.to_f64() * time_adjustment * pos_prop_adjustment;

        self.ldd_state.f_a_pow = Fixed::from_f64(new_f_a_pow.max(0.01));
        self.ldd_state.f_a_pos = Fixed::from_f64(new_f_a_pos.max(0.01));

        info!(
            "LDD Amplitudes Updated: Observed avg time: {:.2}s (Target {}s). P(PoW): {:.2}. New f_a_pow: {:.4}, New f_a_pos: {:.4}",
            observed_avg_time, mu_target,
            if total_blocks > 0.0 { pow_blocks / total_blocks } else { 0.5 },
            self.ldd_state.f_a_pow.to_f64(),
            self.ldd_state.f_a_pos.to_f64()
        );

        self.ldd_state.recent_blocks.clear();
    }
    
    fn apply_clock_adjustment(&self, block: &Block) {
        if block.beacons.is_empty() {
            return;
        }
        let mut differences: Vec<i64> = block.beacons.iter()
            .filter_map(|beacon| {
                if let BeaconData::Time(timestamp) = beacon.data {
                    Some(timestamp as i64 - block.header.time as i64)
                } else {
                    None
                }
            })
            .collect();
        differences.sort_unstable();
        if differences.is_empty() { return; }
        let median_diff = if differences.len() % 2 == 1 {
            differences[differences.len() / 2]
        } else {
            (differences[differences.len() / 2 - 1] + differences[differences.len() / 2]) / 2
        };
        info!("DTC: Calculated median time shift of {} seconds.", median_diff);
    }


    fn update_utxo_set(&self, block: &Block) -> Result<()> {
        let utxo_tree = self.db.open_tree(&self.db_config.utxo_tree)?;
        let tx_index_tree = self.db.open_tree(&self.db_config.tx_index_tree)?;
        for tx in &block.transactions {
            let txid = tx.id();
            if !tx.is_coinbase() {
                for vin in &tx.vin {
                    let mut utxo_key = Vec::with_capacity(36);
                    utxo_key.extend_from_slice(vin.prev_txid.as_ref());
                    utxo_key.extend_from_slice(&vin.prev_vout.to_be_bytes());
                    utxo_tree.remove(&utxo_key)?;
                }
            }
            let value1: &[u8] = txid.as_ref();
            let bh = &block.header.hash();
            let value2: &[u8] = bh.as_ref();
            tx_index_tree.insert(value1, value2)?;
            for (i, vout) in tx.vout.iter().enumerate() {
                let mut utxo_key = Vec::with_capacity(36);
                utxo_key.extend_from_slice(txid.as_ref());
                utxo_key.extend_from_slice(&(i as u32).to_be_bytes());
                let serialized_vout = bincode::serialize(vout)?;
                utxo_tree.insert(&utxo_key, serialized_vout)?;
            }
        }
        Ok(())
    }

    pub fn get_block(&self, hash: &sha256d::Hash) -> Option<Block> {
        if let Ok(tree) = self.db.open_tree(&self.db_config.blocks_tree) {
            if let Ok(Some(bytes)) = tree.get(hash.as_ref() as &[u8]) {
                return bincode::deserialize(&bytes).ok();
            }
        }
        None
    }

    pub fn get_transaction(&self, txid: &sha256d::Hash) -> Result<Option<Transaction>> {
        let tx_index_tree = self.db.open_tree(&self.db_config.tx_index_tree)?;
        if let Some(block_hash_bytes) = tx_index_tree.get::<&[u8]>(txid.as_ref())? {
            let block_hash = sha256d::Hash::from_slice(&block_hash_bytes)?;
            if let Some(block) = self.get_block(&block_hash) {
                for tx in &block.transactions {
                    if tx.id() == *txid {
                        return Ok(Some(tx.clone()));
                    }
                }
            }
        }
        Ok(None)
    }
    
    pub fn iter(&self) -> BlockchainIterator<'_> {
        BlockchainIterator { current_hash: self.tip, blockchain: self }
    }

    pub fn get_mempool_txs(&mut self) -> Vec<Transaction> {
        let txs = self.mempool.values().cloned().collect();
        self.mempool.clear();
        txs
    }

    pub fn verify_transaction(&mut self, tx: &Transaction) -> Result<()> {
        if tx.is_coinbase() {
            return Ok(());
        }
    
        let mut prev_txs = HashMap::new();
        for vin in &tx.vin {
            let prev_tx = self.get_transaction(&vin.prev_txid)?.ok_or_else(|| anyhow!("Previous tx not found in blockchain for input of tx {}", tx.id()))?;
            prev_txs.insert(vin.prev_txid, prev_tx);
        }
        tx.verify(&prev_txs)
    }    

    pub fn update_and_execute_proposals(&mut self) {
        let current_height = self.get_block(&self.tip).map_or(0, |b| b.height);
        let proposals_clone = self.governance.proposals.clone();
        for proposal in proposals_clone.values() {
            if proposal.state == ProposalState::Active && current_height > proposal.end_block {
                let total_votes = proposal.votes_for + proposal.votes_against;
                if total_votes > 0 && (proposal.votes_for * 100 > self.governance_params.vote_threshold_percent * total_votes) {

                    let current_proposal = self.governance.proposals.get_mut(&proposal.id).unwrap();
                    current_proposal.state = ProposalState::Succeeded;
                    info!("✅ Governance Proposal {} Succeeded!", proposal.id);

                    match &proposal.payload {
                        ProposalPayload::UpdateTargetBlockTime(new_time) => {
                            info!("EXECUTION: Updating target block time to {}", new_time);
                            Arc::make_mut(&mut self.consensus_params).target_block_time = *new_time;
                        }
                        ProposalPayload::UpdateFeeBurnRate(new_rate) => {
                            info!("EXECUTION: Updating fee burn rate to {}", new_rate);
                            Arc::make_mut(&mut self.fee_params).min_burn_rate = *new_rate;
                        }
                        ProposalPayload::None => {}
                    }
                    current_proposal.state = ProposalState::Executed;

                } else {
                    let current_proposal = self.governance.proposals.get_mut(&proposal.id).unwrap();
                    current_proposal.state = ProposalState::Failed;
                    info!("❌ Governance Proposal {} Failed.", proposal.id);
                }
            }
        }
    }

    // --- Metrics for Beacon Generation ---
    pub fn get_and_reset_metrics(&mut self) -> LocalMetrics {
        let m = self.metrics.clone();
        // Reset counters for next interval
        self.metrics.orphan_count = 0;
        self.metrics.max_reorg_depth = 0;
        // Keep last delay as is, it's a point measurement
        m
    }

    pub fn get_mempool_load(&self) -> f64 {
        // Estimate load based on mempool bytes vs max block size
        // Simplified: mempool count / arbitrary large number
        // Real: sum bytes of all txs in mempool
        let current_bytes: usize = self.mempool.values().map(|tx| bincode::serialize(tx).unwrap().len()).sum();
        (current_bytes as f64 / MAX_BLOCK_SIZE as f64).min(1.0)
    }

    pub fn get_branching_factor(&self) -> f64 {
        // Simplified: Orphan count / (Reorg depth + 1)
        // A high orphan count with low reorg depth means many competing tips -> high branching
        if self.metrics.orphan_count == 0 { return 1.0; }
        1.0 + (self.metrics.orphan_count as f64)
    }
}

pub struct BlockchainIterator<'a> {
    current_hash: sha256d::Hash,
    blockchain: &'a Blockchain,
}

impl<'a> Iterator for BlockchainIterator<'a> {
    type Item = Block;
    fn next(&mut self) -> Option<Self::Item> {
        if self.current_hash == sha256d::Hash::all_zeros() { return None; }
        let current_block = self.blockchain.get_block(&self.current_hash)?;
        self.current_hash = current_block.header.prev_blockhash;
        Some(current_block)
    }
}
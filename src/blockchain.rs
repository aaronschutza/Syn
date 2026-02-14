// src/blockchain.rs - Reorg Logic Audit & Fixes

use crate::{
    block::{Block, BlockHeader, Beacon},
    config::{ConsensusConfig, DatabaseConfig, FeeConfig, GovernanceConfig, ProgonosConfig},
    dcs::{DecentralizedConsensusService, ConsensusOracle}, 
    burst::BurstFinalityManager,
    cdf::{FinalityGadget, FinalityVote}, 
    fixed_point::Fixed,
    governance::{Governance, ProposalState, ProposalPayload},
    transaction::{Transaction, TxOut}, 
    engine::ConsensusEngine,
    crypto::{hash_pubkey, address_from_pubkey_hash},
    spv::{self, DepositProofRequest},
    client::SpvClientState,
    difficulty::calculate_next_difficulty, 
    units::{LddParams, SlotDuration, Probability},
    weight::SynergisticWeight, 
};
use anyhow::{anyhow, bail, Result};
use bitcoin_hashes::{sha256d, Hash, hash160};
use chrono::Utc;
use num_bigint::BigUint;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use secp256k1::PublicKey;
use sled::Batch;
use serde::{Serialize, Deserialize};
use log::{info, warn, error}; // Added error
use std::cmp;

const MAX_BEACONS_PER_BLOCK: usize = 16;
const MAX_UTXO_CACHE_SIZE: usize = 100000;
const MAX_ORPHAN_BLOCKS: usize = 512;
const BEACON_BOUNTY_POOL_PERCENT: u64 = 1;
const PQC_ENFORCEMENT_HEIGHT: u32 = 100_000;

lazy_static::lazy_static! {
    static ref MUHASH_PRIME: BigUint = BigUint::parse_bytes(b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF", 16).unwrap();
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct UtxoEntry {
    pub output: TxOut,
    pub height: u32,
    pub is_coinbase: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct HeaderMetadata {
    pub height: u32,
    pub total_work: u64,
    pub synergistic_work: u64,
}

#[derive(Clone, Debug, Default)]
pub struct LocalMetrics {
    pub orphan_count: u32,
    pub max_reorg_depth: u32,
    pub beacon_providers: HashSet<Vec<u8>>,
}

#[derive(Debug, Default)]
pub struct VetoManager {
    pub votes: HashMap<sha256d::Hash, HashSet<Vec<u8>>>,
    pub weight: HashMap<sha256d::Hash, u64>,
    pub blacklisted_blocks: HashSet<sha256d::Hash>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LddState {
    pub f_a_pow: Fixed,
    pub f_a_pos: Fixed,
    pub f_b_pow: Fixed, 
    pub f_b_pos: Fixed, 
    pub recent_blocks: Vec<(u32, bool)>,
    pub current_psi: u32,
    pub current_gamma: u32,
    pub current_target_block_time: u64,
    pub current_adjustment_window: usize,
    pub next_adjustment_height: u32,
    pub current_burn_rate: Fixed,
    pub current_kappa: Fixed,
}

impl Default for LddState {
    fn default() -> Self {
        Self {
            f_a_pow: Fixed::from_f64(0.01), 
            f_a_pos: Fixed::from_f64(0.5), 
            f_b_pow: Fixed::from_f64(0.01),
            f_b_pos: Fixed::from_f64(0.5),
            recent_blocks: Vec::new(),
            current_psi: 3,
            current_gamma: 30,
            current_target_block_time: 15,
            current_adjustment_window: 5,
            next_adjustment_height: 5,
            current_burn_rate: Fixed::from_f64(0.1),
            current_kappa: Fixed::from_f64(0.1),
        }
    }
}

/// A pure state encapsulation representing the variables derived 
/// exclusively from block history at a specific hash.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockState {
    pub ldd: LddState,
    pub dcs: DecentralizedConsensusService,
}

pub struct Blockchain {
    pub db: Arc<sled::Db>,
    pub blocks_tree: sled::Tree,
    pub headers_tree: sled::Tree,
    pub header_meta_tree: sled::Tree,
    pub utxo_tree: sled::Tree,
    pub addr_utxo_tree: sled::Tree, 
    pub tx_index_tree: sled::Tree,
    pub btc_txid_tree: sled::Tree, 
    pub meta_tree: sled::Tree,
    pub tip: sha256d::Hash,
    pub total_work: u64,
    pub best_header_tip: sha256d::Hash,
    pub best_header_work: u64,
    pub mempool: HashMap<sha256d::Hash, Transaction>,
    pub beacon_mempool: Vec<Beacon>,
    pub ldd_state: LddState,
    pub consensus_params: Arc<ConsensusConfig>,
    pub fee_params: Arc<FeeConfig>,
    pub governance_params: Arc<GovernanceConfig>,
    pub progonos_config: Arc<ProgonosConfig>,
    pub spv_state: Arc<SpvClientState>,
    pub total_staked: u64,
    pub governance: Governance,
    pub db_config: Arc<DatabaseConfig>,
    pub headers: Vec<BlockHeader>,
    pub utxo_cache: HashMap<(sha256d::Hash, u32), UtxoEntry>,
    pub orphan_blocks: HashMap<sha256d::Hash, Block>,
    pub last_pow_block_hash: sha256d::Hash,
    pub consensus_engine: ConsensusEngine,
    pub dcs: DecentralizedConsensusService,
    pub burst_manager: BurstFinalityManager,
    pub finality_gadget: FinalityGadget,
    pub last_finalized_checkpoint: Option<sha256d::Hash>,
    pub metrics: LocalMetrics,
    pub veto_manager: VetoManager,
}

impl Blockchain {
    pub fn new_with_db(
        db: Arc<sled::Db>,
        consensus_params: Arc<ConsensusConfig>,
        fee_params: Arc<FeeConfig>,
        governance_params: Arc<GovernanceConfig>,
        progonos_config: Arc<ProgonosConfig>,
        spv_state: Arc<SpvClientState>,
        db_config: Arc<DatabaseConfig>,
        consensus_engine: ConsensusEngine,
    ) -> Result<Self> {
        let blocks_tree = db.open_tree(&db_config.blocks_tree)?;
        let headers_tree = db.open_tree("headers_tree")?;
        let header_meta_tree = db.open_tree("header_metadata")?;
        let utxo_tree = db.open_tree(&db_config.utxo_tree)?;
        let addr_utxo_tree = db.open_tree("addr_utxo_index")?;
        let tx_index_tree = db.open_tree(&db_config.tx_index_tree)?;
        let btc_txid_tree = db.open_tree("progonos_used_btc_txids")?;
        let meta_tree = db.open_tree("chain_metadata")?;

        let mut bc = Blockchain {
            db, blocks_tree, headers_tree, header_meta_tree, utxo_tree, addr_utxo_tree, tx_index_tree, btc_txid_tree, meta_tree,
            tip: sha256d::Hash::all_zeros(),
            total_work: 0,
            best_header_tip: sha256d::Hash::all_zeros(),
            best_header_work: 0,
            mempool: HashMap::new(), beacon_mempool: Vec::new(),
            ldd_state: LddState::default(), consensus_params, fee_params: fee_params.clone(),
            governance_params, progonos_config, spv_state, total_staked: 0, governance: Governance::new(),
            db_config, headers: Vec::new(),
            utxo_cache: HashMap::with_capacity(MAX_UTXO_CACHE_SIZE),
            orphan_blocks: HashMap::new(),
            last_pow_block_hash: sha256d::Hash::all_zeros(),
            consensus_engine, 
            dcs: DecentralizedConsensusService::new(),
            burst_manager: BurstFinalityManager::new(fee_params.k_burst, fee_params.fee_burst_threshold), 
            finality_gadget: FinalityGadget::new(), last_finalized_checkpoint: None,
            metrics: LocalMetrics::default(),
            veto_manager: VetoManager::default(),
        };

        if bc.blocks_tree.is_empty() {
            let mut genesis = Block::create_genesis_block(
                bc.consensus_params.coinbase_reward, bc.consensus_params.genesis_timestamp,
                bc.consensus_params.genesis_bits, bc.consensus_params.genesis_coinbase_data.clone(),
                bc.consensus_params.genesis_address.clone(), bc.consensus_params.block_version,
                bc.consensus_params.transaction_version,
            );
            
            let mut ldd = LddState::default();
            ldd.current_target_block_time = bc.consensus_params.target_block_time;
            ldd.current_burn_rate = Fixed::from_f64(bc.fee_params.min_burn_rate);
            let dcs = DecentralizedConsensusService::new();
            
            let block_state = BlockState { ldd: ldd.clone(), dcs: dcs.clone() };
            bc.ldd_state = ldd;
            bc.dcs = dcs;
            
            bc.calculate_synergistic_work(&mut genesis, &bc.ldd_state);
            genesis.total_work = genesis.synergistic_work;
            let genesis_hash = genesis.header.hash();
            
            let mut key = b"state_".to_vec();
            key.extend_from_slice(genesis_hash.as_ref());
            bc.meta_tree.insert(key, bincode::serialize(&block_state)?)?;

            bc.headers_tree.insert(genesis_hash.as_ref() as &[u8], bincode::serialize(&genesis.header)?)?;
            let meta = HeaderMetadata { height: 0, total_work: genesis.total_work, synergistic_work: genesis.synergistic_work };
            bc.header_meta_tree.insert(genesis_hash.as_ref() as &[u8], bincode::serialize(&meta)?)?;

            bc.blocks_tree.insert(genesis_hash.as_ref() as &[u8], bincode::serialize(&genesis)?)?;
            bc.blocks_tree.insert(bc.db_config.tip_key.as_str(), genesis_hash.as_ref() as &[u8])?;
            bc.tip = genesis_hash; bc.total_work = genesis.total_work;
            bc.best_header_tip = genesis_hash; bc.best_header_work = genesis.total_work;
            bc.headers.push(genesis.header.clone());
            bc.meta_tree.insert("utxo_muhash_root", BigUint::from(1u32).to_bytes_be().as_slice())?;
            bc.update_utxo_set(&genesis)?;
        } else {
            let tip_bytes = bc.blocks_tree.get(&bc.db_config.tip_key)?.ok_or_else(|| anyhow!("Tip missing"))?;
            bc.tip = sha256d::Hash::from_slice(&tip_bytes)?;
            if let Some(work_bytes) = bc.blocks_tree.get(&bc.db_config.total_work_key)? {
                let mut arr = [0u8; 8]; arr.copy_from_slice(&work_bytes); bc.total_work = u64::from_be_bytes(arr);
            }
            
            if let Some(state_bytes) = bc.meta_tree.get({
                let mut k = b"state_".to_vec();
                k.extend_from_slice(bc.tip.as_ref());
                k
            })? {
                let state: BlockState = bincode::deserialize(&state_bytes)?;
                bc.ldd_state = state.ldd;
                bc.dcs = state.dcs;
            } else {
                warn!("BlockState not found for tip. Node state sync incomplete.");
            }
            
            let mut curr = bc.tip;
            let mut headers_rev = Vec::new();
            while curr != sha256d::Hash::all_zeros() {
                if let Some(h_bytes) = bc.headers_tree.get(curr.as_ref() as &[u8])? {
                    let header: BlockHeader = bincode::deserialize(&h_bytes)?;
                    headers_rev.push(header.clone());
                    curr = header.prev_blockhash;
                } else { break; }
            }
            bc.headers = headers_rev.into_iter().rev().collect();
            
            let mut best_tip = bc.tip;
            let mut best_work = bc.total_work;
            for item in bc.header_meta_tree.iter() {
                let (hash_bytes, meta_bytes) = item?;
                let meta: HeaderMetadata = bincode::deserialize(&meta_bytes)?;
                if meta.total_work > best_work {
                    best_work = meta.total_work;
                    best_tip = sha256d::Hash::from_slice(&hash_bytes)?;
                }
            }
            bc.best_header_tip = best_tip;
            bc.best_header_work = best_work;
        }
        
        bc.sync_staking_totals();
        Ok(bc)
    }

    pub fn chain_height(&self) -> u32 {
        self.headers.len().saturating_sub(1) as u32
    }

    pub fn is_syncing(&self) -> bool {
        let current_height = self.chain_height();
        if let Some(best_meta_bytes) = self.header_meta_tree.get(self.best_header_tip.as_ref() as &[u8]).ok().flatten() {
            if let Ok(best_meta) = bincode::deserialize::<HeaderMetadata>(&best_meta_bytes) {
                return best_meta.height > current_height.saturating_add(5);
            }
        }
        false
    }

    pub fn validate_header(&self, header: &BlockHeader) -> Result<u64> {
        let prev_hash = header.prev_blockhash;
        if prev_hash == sha256d::Hash::all_zeros() { return Ok(1); }

        // Fetch to ensure parent header actually exists in our tree.
        let _prev_meta_bytes = self.header_meta_tree.get(prev_hash.as_ref() as &[u8])?
            .ok_or_else(|| anyhow!("Header parent missing: {}", prev_hash))?;

        if header.vrf_proof.is_none() {
            let hash_val = BigUint::from_bytes_be(header.hash().as_ref());
            let target = BlockHeader::calculate_target(header.bits);
            
            // Header-only sync cannot strictly validate exact dynamic difficulty targets due to missing block bodies,
            // so we fallback to verifying it matches the intrinsic bits claim for SPV filtering.
            if hash_val > target { bail!("Invalid PoW in header"); }

            let burn_rate = Probability::from_num(self.fee_params.min_burn_rate);
            return Ok(header.calculate_synergistic_weight(burn_rate));
        } else {
            let burn_rate = Probability::from_num(self.fee_params.min_burn_rate);
            return Ok(header.calculate_synergistic_weight(burn_rate));
        }
    }

    pub fn process_headers(&mut self, headers: Vec<BlockHeader>) -> Result<()> {
        for header in headers {
            let hash = header.hash();
            if self.headers_tree.contains_key(hash.as_ref() as &[u8])? { continue; }

            let synergistic_work = self.validate_header(&header)?;
            let prev_hash = header.prev_blockhash;
            
            let total_work = if prev_hash == sha256d::Hash::all_zeros() {
                synergistic_work
            } else {
                let prev_meta_bytes = self.header_meta_tree.get(prev_hash.as_ref() as &[u8])?
                    .ok_or_else(|| anyhow!("Sync fail: orphaned header"))?;
                let prev_meta: HeaderMetadata = bincode::deserialize(&prev_meta_bytes)?;
                prev_meta.total_work + synergistic_work
            };

            let height = if prev_hash == sha256d::Hash::all_zeros() { 0 } else {
                let prev_meta_bytes = self.header_meta_tree.get(prev_hash.as_ref() as &[u8])?.unwrap();
                let prev_meta: HeaderMetadata = bincode::deserialize(&prev_meta_bytes)?;
                prev_meta.height + 1
            };

            let meta = HeaderMetadata { height, total_work, synergistic_work };
            self.headers_tree.insert(hash.as_ref() as &[u8], bincode::serialize(&header)?)?;
            self.header_meta_tree.insert(hash.as_ref() as &[u8], bincode::serialize(&meta)?)?;

            if total_work > self.best_header_work {
                self.best_header_tip = hash;
                self.best_header_work = total_work;
                info!("Sync: Best header tip updated to height {}: {}", height, hash);
            }
        }
        Ok(())
    }

    pub fn sync_staking_totals(&mut self) {
        let actual_bonded = self.consensus_engine.staking_module.get_total_bonded_supply();
        self.total_staked = actual_bonded as u64;
        
        self.consensus_engine.difficulty_manager.set_state_from_bits(
            self.ldd_state.f_a_pow.to_bits(),
            self.ldd_state.f_a_pos.to_bits(),
            self.ldd_state.current_psi,
            self.ldd_state.current_gamma,
        );
        
        info!("[CONSENSUS] sync_staking_totals: Total Bonded Supply = {} tokens. Engine state synchronized.", self.total_staked);
    }

    pub fn update_utxo_set(&mut self, block: &Block) -> Result<()> {
        let mut utxo_batch = Batch::default();
        let mut addr_batch = Batch::default();
        let mut index_batch = Batch::default();
        let mut btc_tx_batch = Batch::default();
        let mut rolling_muhash = self.get_muhash_root()?;
        let pqc_enforced = block.height >= PQC_ENFORCEMENT_HEIGHT;

        // FIX: Intra-block UTXO tracking. Key -> Serialized UtxoEntry
        // IMPORTANT: We must store deserialized values or at least track existence efficiently
        // to prevent parsing repeatedly. For simplicity in validation, we just store serialized bytes.
        let mut intra_block_utxos: HashMap<Vec<u8>, Vec<u8>> = HashMap::new();
        
        // Track consumed intra-block UTXOs to prevent double-spending within the same block.
        // We use the utxo_key (txid + vout) as the identifier.
        let mut intra_block_spent: HashSet<Vec<u8>> = HashSet::new();
        
        // Track consumed DB-based UTXOs to prevent double-spending within the same block
        // (e.g. two txs in the same block trying to spend the same old UTXO).
        let mut db_spent_in_block: HashSet<Vec<u8>> = HashSet::new();

        let skip_verify = if let Some(finalized_hash) = self.last_finalized_checkpoint {
            if let Some(f_meta_bytes) = self.header_meta_tree.get(finalized_hash.as_ref() as &[u8]).ok().flatten() {
                if let Ok(f_meta) = bincode::deserialize::<HeaderMetadata>(&f_meta_bytes) {
                    block.height < f_meta.height.saturating_sub(6)
                } else { false }
            } else { false }
        } else { false };

        for (tx_idx, tx) in block.transactions.iter().enumerate() {
            let txid = tx.id();
            
            // --- 1. Validation Logic ---
            if !tx.is_coinbase() && !skip_verify {
                let is_bridge_mint = tx.vin.len() == 1 && tx.vin[0].prev_txid == sha256d::Hash::all_zeros() && tx.vin[0].script_sig.starts_with(b"{");

                if is_bridge_mint {
                    self.validate_progonos_mint(tx, &mut btc_tx_batch)?;
                } else {
                    let mut prev_txs = HashMap::new();
                    // We need to fetch previous transactions to verify scripts.
                    // NOTE: verify_hybrid needs the *full* prev tx, which might be in this block or in DB.
                    // Current verify_hybrid implementation relies on a map we pass in.
                    
                    for vin in &tx.vin {
                        // Check if parent is in this block (intra-block dependency)
                        // We can scan the blocks' transaction list processed *so far*
                        let intra_parent = block.transactions[0..tx_idx].iter().find(|t| t.id() == vin.prev_txid);
                        
                        if let Some(parent) = intra_parent {
                             prev_txs.insert(vin.prev_txid, parent.clone());
                        } else {
                             // Check DB
                             let prev_tx = self.get_transaction(&vin.prev_txid)?.ok_or_else(|| anyhow!("Input tx missing: {}", vin.prev_txid))?;
                             prev_txs.insert(vin.prev_txid, prev_tx);
                        }
                    }
                    
                    if let Err(e) = tx.verify_hybrid(&prev_txs, pqc_enforced) {
                         error!("[CONSENSUS] Tx {} failed hybrid verification: {}", txid, e);
                         bail!("Tx verification failed: {}", e);
                    }
                }
            }

            // --- 2. Input Processing (Spending) ---
            if !tx.is_coinbase() && !tx.vin.is_empty() {
                for (vin_idx, vin) in tx.vin.iter().enumerate() {
                    if vin.prev_txid == sha256d::Hash::all_zeros() { continue; } 
                    let mut utxo_key = Vec::with_capacity(36);
                    utxo_key.extend_from_slice(vin.prev_txid.as_ref());
                    utxo_key.extend_from_slice(&vin.prev_vout.to_be_bytes());

                    // A. Check Intra-block UTXOs first
                    if intra_block_utxos.contains_key(&utxo_key) {
                        if intra_block_spent.contains(&utxo_key) {
                            error!("[CONSENSUS] Double spend in block {} at tx {} input {}. Key (Intra): {:02x?}", block.header.hash(), txid, vin_idx, utxo_key);
                            bail!("Double spend detected within block (intra)");
                        }
                        
                        // Mark spent
                        intra_block_spent.insert(utxo_key.clone());
                        
                        // Get value for MuHash update
                        let val = intra_block_utxos.get(&utxo_key).unwrap();
                        let entry_hash = BigUint::from_bytes_be(sha256d::Hash::hash(val).as_ref());
                        rolling_muhash = self.muhash_div(rolling_muhash, entry_hash);

                        // Since it was created AND spent in the same block, it's transient.
                        // We remove it from the map so it doesn't get written to DB later.
                        intra_block_utxos.remove(&utxo_key);
                        
                        // It might have been added to the batch in the previous iteration of this loop.
                        // We must ensure it is NOT in the final batch insert.
                        utxo_batch.remove(utxo_key.as_slice());
                        
                    } 
                    // B. Check Database
                    else if let Some(val) = self.utxo_tree.get(&utxo_key)? {
                         if db_spent_in_block.contains(&utxo_key) {
                            error!("[CONSENSUS] Double spend in block {} at tx {} input {}. Key (DB): {:02x?}", block.header.hash(), txid, vin_idx, utxo_key);
                            bail!("Double spend detected within block (db)");
                         }
                         db_spent_in_block.insert(utxo_key.clone());
                         
                        let entry_hash = BigUint::from_bytes_be(sha256d::Hash::hash(&val).as_ref());
                        rolling_muhash = self.muhash_div(rolling_muhash, entry_hash);
                        
                        self.utxo_cache.remove(&(vin.prev_txid, vin.prev_vout));
                        utxo_batch.remove(utxo_key.as_slice());
                        
                        // Handle Address Index
                        let entry: UtxoEntry = bincode::deserialize(&val)?;
                        if !entry.output.script_pub_key.is_empty() {
                            let mut addr_key = entry.output.script_pub_key;
                            addr_key.extend_from_slice(&utxo_key);
                            addr_batch.remove(addr_key);
                        }
                    } else { 
                        error!("[CONSENSUS] UTXO missing for tx {} input {}. PrevOut: {}:{}", txid, vin_idx, vin.prev_txid, vin.prev_vout);
                        bail!("UTXO missing in tx {}. Input: {}:{}", txid, vin.prev_txid, vin.prev_vout); 
                    }
                }
            }

            // --- 3. Output Processing (Creation) ---
            for (i, vout) in tx.vout.iter().enumerate() {
                // Staking logic check
                if vout.script_pub_key.len() >= 27 && vout.script_pub_key[0] == 0x6a && vout.script_pub_key[1] == 0x05 && &vout.script_pub_key[2..7] == b"STAKE" {
                    let pubkey_hash_bytes = &vout.script_pub_key[8..28];
                    let pk_hash = hash160::Hash::from_slice(pubkey_hash_bytes)?;
                    let address = address_from_pubkey_hash(&pk_hash);
                    
                    info!("[STAKING] Detected on-chain stake for address {}: {} SYN", address, vout.value);
                    if let Err(e) = self.consensus_engine.staking_module.process_stake(address, vout.value as u128) {
                        warn!("Failed to process stake: {}", e);
                    }
                }

                let entry = UtxoEntry { output: vout.clone(), height: block.height, is_coinbase: tx.is_coinbase() };
                let mut utxo_key = Vec::with_capacity(36);
                utxo_key.extend_from_slice(txid.as_ref());
                utxo_key.extend_from_slice(&(i as u32).to_be_bytes());
                
                let serialized = bincode::serialize(&entry)?;
                let entry_hash = BigUint::from_bytes_be(sha256d::Hash::hash(&serialized).as_ref());
                rolling_muhash = self.muhash_mul(rolling_muhash, entry_hash);
                
                // Add to intra-block tracking so subsequent txs in this block can spend it
                intra_block_utxos.insert(utxo_key.clone(), serialized.clone());
                
                // Queue for DB insertion
                utxo_batch.insert(utxo_key.clone(), serialized);
                
                if self.utxo_cache.len() < MAX_UTXO_CACHE_SIZE { self.utxo_cache.insert((txid, i as u32), entry); }
                if !vout.script_pub_key.is_empty() {
                    let mut addr_key = vout.script_pub_key.clone(); addr_key.extend_from_slice(&utxo_key); addr_batch.insert(addr_key, &[]);
                }
            }
            
            // Index the transaction location
            index_batch.insert(txid.as_ref() as &[u8], block.header.hash().as_ref() as &[u8]);
        }
        
        self.utxo_tree.apply_batch(utxo_batch)?; 
        self.addr_utxo_tree.apply_batch(addr_batch)?; 
        self.tx_index_tree.apply_batch(index_batch)?;
        self.btc_txid_tree.apply_batch(btc_tx_batch)?; 
        self.meta_tree.insert("utxo_muhash_root", rolling_muhash.to_bytes_be().as_slice())?;
        Ok(())
    }

    fn validate_progonos_mint(&self, tx: &Transaction, btc_tx_batch: &mut Batch) -> Result<()> {
        let binding = tx.vin.get(0).map(|v| v.script_sig.clone()).unwrap_or_default();
        let proof_json = String::from_utf8_lossy(&binding);
        let request: DepositProofRequest = serde_json::from_str(&proof_json)
            .map_err(|_| anyhow!("Invalid Progonos Proof Metadata"))?;

        if self.btc_txid_tree.contains_key(request.expected_txid.as_bytes())? {
            bail!("Double-Mint Attempt: Bitcoin TXID {} already used.", request.expected_txid);
        }

        let btc_header = spv::verify_deposit_proof(request.clone(), &self.spv_state)
            .map_err(|e| anyhow!("SPV Verification Failed: {}", e))?;

        let btc_block_hash = btc_header.block_hash();
        let stored_header = self.spv_state.get_stored_header(&btc_block_hash)
            .map_err(|_| anyhow!("Bitcoin block not found in synchronized chain"))?;
        
        let btc_tip_hash = self.spv_state.get_tip_hash().map_err(|e| anyhow!("BTC SPV Storage error: {:?}", e))?;
        let btc_tip_header = self.spv_state.get_stored_header(&btc_tip_hash)?;

        let depth = btc_tip_header.height.saturating_sub(stored_header.height) + 1;
        if depth < self.progonos_config.btc_confirmations {
            bail!("Progonos Bridge: Insufficient confirmations. Have {}, Require {}", depth, self.progonos_config.btc_confirmations);
        }

        btc_tx_batch.insert(request.expected_txid.as_bytes(), &[]);
        log::info!("Progonos Bridge: Validated Mint for BTC TXID {}", request.expected_txid);
        Ok(())
    }

    fn get_muhash_root(&self) -> Result<BigUint> {
        match self.meta_tree.get("utxo_muhash_root")? {
            Some(bytes) => Ok(BigUint::from_bytes_be(&bytes)),
            None => Ok(BigUint::from(1u32)),
        }
    }

    fn muhash_mul(&self, a: BigUint, b: BigUint) -> BigUint { (a * b) % &*MUHASH_PRIME }
    fn muhash_div(&self, a: BigUint, b: BigUint) -> BigUint {
        let inv = b.modpow(&(&*MUHASH_PRIME - BigUint::from(2u32)), &*MUHASH_PRIME);
        (a * inv) % &*MUHASH_PRIME
    }

    pub fn calculate_utxo_root(&self) -> Result<sha256d::Hash> {
        let root = self.get_muhash_root()?;
        let mut bytes = root.to_bytes_be();
        if bytes.len() > 32 { bytes = bytes[bytes.len()-32..].to_vec(); }
        else if bytes.len() < 32 { let mut tmp = vec![0u8; 32-bytes.len()]; tmp.extend(bytes); bytes = tmp; }
        Ok(sha256d::Hash::from_slice(&bytes)?)
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
                let entry: UtxoEntry = bincode::deserialize(&val)?;
                let txid = sha256d::Hash::from_slice(&utxo_key[0..32])?;
                let vout = u32::from_be_bytes(utxo_key[32..36].try_into()?);
                accumulated_value += entry.output.value; unspent_outputs.insert(txid, vout);
                if amount_needed > 0 && accumulated_value >= amount_needed { break; }
            }
        }
        if amount_needed > 0 && accumulated_value < amount_needed { bail!("Insufficient funds"); }
        Ok((accumulated_value, unspent_outputs))
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

    pub fn calculate_total_fees(&self, block: &Block) -> u64 {
        block.transactions.iter().filter(|tx| !tx.is_coinbase()).map(|tx| {
            let mut total_in = 0;
            for vin in &tx.vin { if let Ok(Some(prev_tx)) = self.get_transaction(&vin.prev_txid) { total_in += prev_tx.vout[vin.prev_vout as usize].value; } }
            let total_out: u64 = tx.vout.iter().map(|v| v.value).sum();
            total_in.saturating_sub(total_out)
        }).sum()
    }

    pub fn calculate_synergistic_work(&self, block: &mut Block, ldd: &LddState) {
        let burn_rate = Probability::from_num(ldd.current_burn_rate.to_f64());
        block.synergistic_work = block.header.calculate_synergistic_weight(burn_rate);
    }

    pub fn get_and_reset_metrics(&mut self) -> LocalMetrics {
        let m = self.metrics.clone();
        self.metrics.orphan_count = 0; self.metrics.max_reorg_depth = 0; self.metrics.beacon_providers.clear();
        m
    }

    pub fn receive_beacon(&mut self, beacon: Beacon) -> Result<()> {
        self.metrics.beacon_providers.insert(beacon.public_key.clone());
        if self.beacon_mempool.len() < 1000 { self.beacon_mempool.push(beacon); }
        Ok(())
    }

    pub fn process_finality_vote(&mut self, vote: FinalityVote) {
        if let Ok(pk) = PublicKey::from_slice(&vote.voter_public_key) {
            let addr = address_from_pubkey_hash(&hash_pubkey(&pk));
            let stake = self.consensus_engine.staking_module.get_voting_power(&addr);
            if stake > 0 { 
                self.finality_gadget.process_vote(&vote, stake as u64); 
                if self.finality_gadget.check_finality() {
                    let finalized_hash = self.finality_gadget.target_checkpoint.unwrap();
                    log::info!("🛡️ CDF FINALITY RATIFIED: Block {} is now IRREVERSIBLE.", finalized_hash);
                    self.last_finalized_checkpoint = Some(finalized_hash);
                }
            }
        }
    }

    pub fn adjust_ldd_pure(&self, ldd_state: &mut LddState, dcs: &mut DecentralizedConsensusService) {
        let total_window_blocks = ldd_state.recent_blocks.len();
        if total_window_blocks < 2 { return; }

        let n_pow = ldd_state.recent_blocks.iter().filter(|(_, is_pow)| *is_pow).count();
        let n_pos = total_window_blocks.saturating_sub(n_pow);

        let start_time = ldd_state.recent_blocks.first().unwrap().0;
        let end_time = ldd_state.recent_blocks.last().unwrap().0;
        let duration = end_time.saturating_sub(start_time);
        
        let observed_mu = if total_window_blocks > 1 {
            SlotDuration((duration as u64) / (total_window_blocks as u64 - 1))
        } else {
            SlotDuration(15)
        };

        let network_state = dcs.get_consensus_state();
        let target_mu = SlotDuration(self.consensus_params.target_block_time);

        let current_params = LddParams {
            psi: SlotDuration(ldd_state.current_psi as u64),
            gamma: SlotDuration(ldd_state.current_gamma as u64),
            f_a_pow: Probability::from_bits(ldd_state.f_a_pow.to_bits()),
            f_a_pos: Probability::from_bits(ldd_state.f_a_pos.to_bits()),
        };

        let new_params = calculate_next_difficulty(
            &current_params,
            network_state,
            target_mu,
            observed_mu,
            n_pos,
            total_window_blocks
        );

        ldd_state.current_psi = new_params.psi.0 as u32;
        ldd_state.current_gamma = new_params.gamma.0 as u32;
        ldd_state.f_a_pow = Fixed::from_bits(new_params.f_a_pow.to_bits());
        ldd_state.f_a_pos = Fixed::from_bits(new_params.f_a_pos.to_bits());

        let t_fallback = self.consensus_params.nakamoto_target_block_time;
        let t_fallback_fixed = Fixed::from_integer(t_fallback);
        let b_total = if t_fallback_fixed.0 > 0 {
            Fixed::one() / t_fallback_fixed
        } else {
            Fixed::from_integer(0) 
        };

        let sum_a = ldd_state.f_a_pow + ldd_state.f_a_pos;
        
        if sum_a.0 > 0 {
            let ratio_pow = ldd_state.f_a_pow / sum_a;
            let f_b_pow_target = b_total * ratio_pow;
            
            let ratio_pos = ldd_state.f_a_pos / sum_a;
            let f_b_pos_target = b_total * ratio_pos;

            ldd_state.f_b_pow = cmp::min(f_b_pow_target, ldd_state.f_a_pow);
            ldd_state.f_b_pos = cmp::min(f_b_pos_target, ldd_state.f_a_pos);
        }

        ldd_state.recent_blocks.clear();
        dcs.reset_interval(); 
    }

    pub fn get_pow_target_from_state(&self, ldd: &LddState, delta: u32) -> BigUint {
        let hazard = self.calculate_hazard_from_state(ldd, delta, ldd.f_a_pow, ldd.f_b_pow);
        let max_target = BigUint::from(1u32) << 256;
        (BigUint::from(hazard.0) * max_target) >> 64
    }

    pub fn get_work_required_from_state(&self, ldd: &LddState, pow: bool, delta: u32) -> u32 {
        let hazard = if pow {
            self.calculate_hazard_from_state(ldd, delta, ldd.f_a_pow, ldd.f_b_pow)
        } else {
            self.calculate_hazard_from_state(ldd, delta, ldd.f_a_pos, ldd.f_b_pos)
        };

        if pow {
            let max_target = BigUint::from(1u32) << 256;
            let target: BigUint = (BigUint::from(hazard.0) * max_target) >> 64;
            let mut bytes = target.to_bytes_be();
            if bytes.is_empty() { return 0x1d00ffff; }
            let mut exponent = bytes.len() as u32;
            if bytes[0] > 0x7f {
                exponent += 1;
                bytes.insert(0, 0x00);
            }
            let mut mantissa = 0u32;
            for i in 0..3 {
                if i < bytes.len() { mantissa = (mantissa << 8) | bytes[i] as u32; }
                else { mantissa <<= 8; }
            }
            (exponent << 24) | mantissa
        } else { 0x207fffff }
    }

    fn calculate_hazard_from_state(&self, ldd: &LddState, delta: u32, f_a: Fixed, f_b: Fixed) -> Fixed {
        let psi = ldd.current_psi;
        let gamma = ldd.current_gamma;

        if delta < psi {
            Fixed(0)
        } else if delta < gamma {
            let num = Fixed::from_integer((delta - psi) as u64);
            let den = Fixed::from_integer((gamma - psi) as u64);
            if den.0 == 0 { f_b } else { f_a * (num / den) }
        } else {
            f_b 
        }
    }

    pub fn get_next_pow_target(&self, delta: u32) -> BigUint {
        self.get_pow_target_from_state(&self.ldd_state, delta)
    }

    pub fn get_next_work_required(&self, pow: bool, delta: u32) -> u32 {
        self.get_work_required_from_state(&self.ldd_state, pow, delta)
    }

    pub fn get_mempool_txs(&mut self) -> Vec<Transaction> { 
        // 1. Snapshot and Topological Sort
        // We preserve the topological sort to ensure parents are processed before children.
        let source_txs: Vec<Transaction> = self.mempool.values().cloned().collect();
        let mut tx_map: HashMap<sha256d::Hash, Transaction> = HashMap::new();
        for tx in &source_txs {
            tx_map.insert(tx.id(), tx.clone());
        }

        let mut visited = HashSet::new();
        let mut sorted = Vec::with_capacity(source_txs.len());
        let mut stack = Vec::new();

        for root_tx in &source_txs {
            if visited.contains(&root_tx.id()) { continue; }
            stack.push((root_tx.id(), 0));
            
            while let Some((tx_id, state)) = stack.pop() {
                if state == 1 {
                     if let Some(tx) = tx_map.get(&tx_id) {
                        if visited.insert(tx_id) {
                            sorted.push(tx.clone());
                        }
                     }
                     continue;
                }
                if visited.contains(&tx_id) { continue; }
                stack.push((tx_id, 1));
                if let Some(tx) = tx_map.get(&tx_id) {
                     for vin in &tx.vin {
                         if tx_map.contains_key(&vin.prev_txid) && !visited.contains(&vin.prev_txid) {
                             stack.push((vin.prev_txid, 0));
                         }
                     }
                }
            }
        }
        
        // 2. Conflict Resolution & Validity Check
        // We now iterate through the sorted list and greedily select transactions.
        // If a transaction spends an input that was ALREADY spent by a previous transaction
        // in this specific selection, we skip it.
        
        let mut final_txs = Vec::with_capacity(sorted.len());
        let mut inputs_spent_in_block: HashSet<(sha256d::Hash, u32)> = HashSet::new();
        // We also track outputs created in this block to allow chaining (unconfirmed parents)
        let mut outputs_created_in_block: HashSet<(sha256d::Hash, u32)> = HashSet::new();

        for tx in sorted {
            let txid = tx.id();
            let mut is_conflict = false;
            let mut inputs_to_spend = Vec::new();

            // Check inputs
            if !tx.is_coinbase() {
                for vin in &tx.vin {
                    let input_key = (vin.prev_txid, vin.prev_vout);
                    
                    // CHECK A: Is this input already spent by a higher-priority tx in this block?
                    if inputs_spent_in_block.contains(&input_key) {
                        is_conflict = true;
                        break;
                    }

                    // CHECK B: Does the UTXO exist?
                    // It must either be in the main UTXO set OR be created by a parent in this block.
                    let in_chain = self.utxo_tree.contains_key(&{
                        let mut k = Vec::new();
                        k.extend_from_slice(vin.prev_txid.as_ref());
                        k.extend_from_slice(&vin.prev_vout.to_be_bytes());
                        k
                    }).unwrap_or(false);

                    let in_mempool_chain = outputs_created_in_block.contains(&input_key);

                    if !in_chain && !in_mempool_chain {
                        // Input is invalid (already spent in chain or never existed).
                        // We skip this tx. Ideally, we should also purge it from mempool.
                        is_conflict = true; 
                        break;
                    }

                    inputs_to_spend.push(input_key);
                }
            }

            if !is_conflict {
                // Transaction is valid for this block context
                final_txs.push(tx.clone());
                
                // Mark inputs as spent
                for input in inputs_to_spend {
                    inputs_spent_in_block.insert(input);
                }

                // Register outputs for child transactions
                for (i, _) in tx.vout.iter().enumerate() {
                    outputs_created_in_block.insert((txid, i as u32));
                }
            } else {
                // Optional: Purge invalid transaction from mempool to free memory
                // self.mempool.remove(&txid);
                // debug!("Dropped conflicting/invalid tx from block template: {}", txid);
            }
        }
        
        final_txs
    }

    pub fn create_block_template(&mut self, mut transactions: Vec<Transaction>, version: i32) -> Result<Block> {
        let prev = self.get_block(&self.tip).ok_or(anyhow!("Tip missing"))?;
        let now = Utc::now().timestamp() as u32;
        let delta = now.saturating_sub(prev.header.time);
        let bits = self.get_next_work_required(true, delta);
        
        let total_reward = self.consensus_params.coinbase_reward;
        let total_bounty_pool = (total_reward * BEACON_BOUNTY_POOL_PERCENT) / 100;
        let beacons = self.beacon_mempool.clone();
        let beacons_to_include = if beacons.len() > MAX_BEACONS_PER_BLOCK { &beacons[0..MAX_BEACONS_PER_BLOCK] } else { &beacons };

        if !beacons_to_include.is_empty() {
            let reward_per_beacon = total_bounty_pool / beacons_to_include.len() as u64;
            if reward_per_beacon > 0 {
                if let Some(coinbase) = transactions.get_mut(0) {
                    if !coinbase.vout.is_empty() && coinbase.vout[0].value >= total_bounty_pool {
                        coinbase.vout[0].value -= total_bounty_pool;
                        for beacon in beacons_to_include {
                            if let Ok(pk) = PublicKey::from_slice(&beacon.public_key) {
                                let addr = address_from_pubkey_hash(&hash_pubkey(&pk));
                                coinbase.vout.push(TxOut::new(reward_per_beacon, addr));
                            }
                        }
                    }
                }
            }
        }
        
        let committed_total_stake = self.total_staked;

        let mut block = Block::new(now, transactions, self.tip, bits, prev.height + 1, version, 0, committed_total_stake);
        block.beacons = beacons_to_include.to_vec();
        block.header.utxo_root = self.calculate_utxo_root()?;
        Ok(block)
    }

    fn verify_dcs_metadata_with_state(&self, block: &Block, dcs: &DecentralizedConsensusService) -> Result<()> {
        if block.header.vrf_proof.is_some() { return Ok(()); }
        let consensus_values = dcs.calculate_consensus();
        if consensus_values.median_total_stake > 0 && self.total_staked > 0 {
            let deviation = (self.total_staked as i128 - consensus_values.median_total_stake as i128).abs();
            if deviation > (consensus_values.median_total_stake as i128 / 10) { bail!("DCS Stake Violation."); }
        }
        if consensus_values.median_time > 0 {
            let time_drift = (block.header.time as i64 - consensus_values.median_time as i64).abs();
            if time_drift > 600 { bail!("DTC Time Violation."); }
        }
        Ok(())
    }

    pub fn add_block(&mut self, mut block: Block) -> Result<()> {
        let hash = block.header.hash();
        if self.blocks_tree.contains_key(hash.as_ref() as &[u8])? { return Ok(()); }
        
        if self.veto_manager.blacklisted_blocks.contains(&hash) { 
            bail!("Rejection: Block {} has been vetoed.", hash); 
        }

        let prev_hash = block.header.prev_blockhash;
        let is_parallel_genesis = prev_hash == sha256d::Hash::all_zeros();

        if !is_parallel_genesis {
            let mut parent_state_key = b"state_".to_vec();
            parent_state_key.extend_from_slice(prev_hash.as_ref());
            
            if !self.meta_tree.contains_key(&parent_state_key)? {
                if self.orphan_blocks.len() < MAX_ORPHAN_BLOCKS {
                    self.orphan_blocks.insert(hash, block);
                    return Ok(());
                } else { 
                    bail!("Orphan buffer full"); 
                }
            }
        }

        let mut block_state = if is_parallel_genesis {
            let mut ldd = LddState::default();
            ldd.current_target_block_time = self.consensus_params.target_block_time;
            ldd.current_burn_rate = Fixed::from_f64(self.fee_params.min_burn_rate);
            BlockState { ldd, dcs: DecentralizedConsensusService::new() }
        } else {
            let prev_state_bytes = self.meta_tree.get({
                let mut k = b"state_".to_vec();
                k.extend_from_slice(prev_hash.as_ref());
                k
            })?.ok_or_else(|| anyhow!("Previous block state missing for block {}", hash))?;
            bincode::deserialize(&prev_state_bytes)?
        };

        if let Err(e) = self.verify_dcs_metadata_with_state(&block, &block_state.dcs) { bail!("DCS telemetry failed: {}", e); }

        let is_pow = block.header.vrf_proof.is_none();
        let fees = self.calculate_total_fees(&block);

        if !is_parallel_genesis {
            let prev_header_bytes = self.headers_tree.get(prev_hash.as_ref() as &[u8])?.unwrap();
            let prev_header: BlockHeader = bincode::deserialize(&prev_header_bytes)?;
            let delta = block.header.time.saturating_sub(prev_header.time);
            
            if block.height > 64 {
                if is_pow {
                    let target = self.get_pow_target_from_state(&block_state.ldd, delta);
                    if BigUint::from_bytes_be(hash.as_ref()) > target {
                        bail!("Rejection: Block {} does not meet PoW target for delta {}s", hash, delta);
                    }
                    
                    let expected_bits = self.get_work_required_from_state(&block_state.ldd, true, delta);
                    if block.header.bits != expected_bits {
                        bail!("Rejection: Block {} claimed bits {} but expected {}", hash, block.header.bits, expected_bits);
                    }
                } else {
                    let vrf_proof = block.header.vrf_proof.as_ref().ok_or_else(|| anyhow!("PoS block missing VRF"))?;
                    let vrf_hash = sha256d::Hash::hash(vrf_proof);
                    
                    let validator_addr = block.transactions.first()
                        .and_then(|tx| tx.vout.first())
                        .map(|out| {
                            if out.script_pub_key.len() >= 25 {
                                let pkh = &out.script_pub_key[3..23];
                                address_from_pubkey_hash(&hash160::Hash::from_slice(pkh).unwrap())
                            } else { "".to_string() }
                        }).unwrap_or_default();

                    let committed_stake = block.header.committed_total_stake;
                    
                    if !self.consensus_engine.check_pos_eligibility_with_state(&block_state.ldd, &validator_addr, delta, vrf_hash.as_ref(), committed_stake) {
                        bail!("Rejection: Validator {} not eligible for PoS block at delta {}s", validator_addr, delta);
                    }
                }
            }
        }

        // REMEDIATION: CAUSALITY FIX
        // We MUST calculate synergistic_work using the state *before* we potentially adjust it for the next epoch.
        // This ensures the weight of Block N is derived from the difficulty parameters active at Height N.
        
        self.calculate_synergistic_work(&mut block, &block_state.ldd);

        // Advance block_state for the *next* block generation
        block_state.dcs.process_beacons(&block.beacons);
        block_state.ldd.recent_blocks.push((block.header.time, is_pow));
        
        if block.height >= block_state.ldd.next_adjustment_height {
            self.adjust_ldd_pure(&mut block_state.ldd, &mut block_state.dcs);
            block_state.ldd.next_adjustment_height = block.height + block_state.ldd.current_adjustment_window as u32;
        }

        // Save block_state to DB
        let mut key = b"state_".to_vec();
        key.extend_from_slice(hash.as_ref());
        self.meta_tree.insert(key, bincode::serialize(&block_state)?)?;

        // Calculate Total Work using Previous Meta
        let total_work = if is_parallel_genesis {
            block.synergistic_work
        } else {
            let prev_meta_bytes = self.header_meta_tree.get(block.header.prev_blockhash.as_ref() as &[u8])?.unwrap();
            let prev_meta: HeaderMetadata = bincode::deserialize(&prev_meta_bytes)?;
            prev_meta.total_work + block.synergistic_work
        };
        block.total_work = total_work;

        let meta = HeaderMetadata { height: block.height, total_work: block.total_work, synergistic_work: block.synergistic_work };
        self.headers_tree.insert(hash.as_ref() as &[u8], bincode::serialize(&block.header)?)?;
        self.header_meta_tree.insert(hash.as_ref() as &[u8], bincode::serialize(&meta)?)?;

        if !is_pow {
            let fees_fixed = Fixed::from_integer(fees);
            let burn_rate_fixed = block_state.ldd.current_burn_rate;
            let required_burn = ((fees_fixed * burn_rate_fixed).0 >> 64) as u64;
            let claimed_burn = block.header.proven_burn;
            
            if claimed_burn < required_burn {
                 bail!("Insufficient Burn Claim in Header: {} < Required {}", claimed_burn, required_burn);
            }

            let actual_burned = block.transactions.get(0).map_or(0, |tx| {
                tx.vout.iter().filter(|o| o.script_pub_key == vec![0x6a]).map(|o| o.value).sum::<u64>()
            });
            
            if actual_burned < claimed_burn {
                bail!("Invalid Proof-of-Burn: Header claims {}, Block burned {}", claimed_burn, actual_burned);
            }
        }

        if is_parallel_genesis && self.last_finalized_checkpoint.is_some() {
            bail!("Irreversibility Violation: Fork reverts finalized genesis.");
        }

        let type_label = if is_pow { "PoW" } else { "PoS" };
        info!("[CONSENSUS] Adopting {} block {} at height {}.", type_label, hash, block.height);

        self.blocks_tree.insert(hash.as_ref() as &[u8], bincode::serialize(&block)?)?;
        
        let current_height = self.chain_height();
        
        // REORG RULE 1: Reject lower block height (User Requirement)
        // We reject blocks that are historically deep compared to our tip.
        if block.height < current_height {
            info!("[CONSENSUS] Ignoring block {} at height {} (Behind tip {})", hash, block.height, current_height);
            return Ok(());
        }

        // REORG RULE 2: Strict ASW Superiority (Tie-Breaker / Main Rule)
        // We switch if:
        // 1. It is a reorg that has STRICTLY more work.
        // 2. It is a direct extension of our current tip (Liveness).
        
        let is_extension = block.header.prev_blockhash == self.tip;
        
        if is_extension || block.total_work > self.total_work {
            if !is_extension && !is_parallel_genesis { 
                self.handle_reorganization(hash)?; 
            } else { 
                self.tip = hash; 
                self.update_utxo_set(&block)?;
                self.headers.push(block.header.clone());
                
                self.ldd_state = block_state.ldd;
                self.dcs = block_state.dcs;
            }
            
            self.sync_staking_totals();
            for tx in &block.transactions { self.mempool.remove(&tx.id()); }
            self.total_work = block.total_work;
            
            if self.burst_manager.check_and_activate(&block, fees) { self.finality_gadget.activate(hash, self.total_staked); }
            self.burst_manager.update_state(block.height);

            self.update_and_execute_proposals();
            self.blocks_tree.insert(self.db_config.tip_key.as_str(), hash.as_ref() as &[u8])?;
            self.process_orphans(hash);
        }
        Ok(())
    }

    fn process_orphans(&mut self, parent_hash: sha256d::Hash) {
        let children: Vec<sha256d::Hash> = self.orphan_blocks.iter()
            .filter(|(_, b)| b.header.prev_blockhash == parent_hash)
            .map(|(h, _)| *h).collect();
        for child_hash in children {
            if let Some(child_block) = self.orphan_blocks.remove(&child_hash) {
                let _ = self.add_block(child_block);
            }
        }
    }

    pub fn handle_reorganization(&mut self, new_block_hash: sha256d::Hash) -> Result<()> {
        let ancestor = self.find_common_ancestor(self.tip, new_block_hash)?;
        if let Some(finalized) = self.last_finalized_checkpoint {
            if !self.is_block_in_path(finalized, new_block_hash)? { bail!("Irreversibility Violation"); }
        }

        let mut curr = self.tip;
        while curr != ancestor {
            let block = self.get_block(&curr).ok_or(anyhow!("Block missing"))?;
            self.rollback_utxo_set(&block)?;
            curr = block.header.prev_blockhash;
        }

        let mut path = Vec::new();
        let mut curr = new_block_hash;
        while curr != ancestor {
            let block = self.get_block(&curr).ok_or(anyhow!("Block missing"))?;
            path.push(block);
            curr = path.last().unwrap().header.prev_blockhash;
        }

        for block in path.into_iter().rev() { self.update_utxo_set(&block)?; }

        self.tip = new_block_hash;
        
        let state_bytes = self.meta_tree.get({
            let mut k = b"state_".to_vec();
            k.extend_from_slice(new_block_hash.as_ref());
            k
        })?.ok_or_else(|| anyhow!("State missing for new tip {}", new_block_hash))?;
        let new_state: BlockState = bincode::deserialize(&state_bytes)?;
        self.ldd_state = new_state.ldd;
        self.dcs = new_state.dcs;

        if let Some(idx) = self.headers.iter().position(|h| h.hash() == ancestor) {
            self.headers.truncate(idx + 1);
            let mut to_append = Vec::new();
            let mut cursor = self.tip;
            while cursor != ancestor {
                if let Some(h_bytes) = self.headers_tree.get(cursor.as_ref() as &[u8])? {
                    let h: BlockHeader = bincode::deserialize(&h_bytes)?;
                    to_append.push(h.clone());
                    cursor = h.prev_blockhash;
                } else { break; }
            }
            self.headers.extend(to_append.into_iter().rev());
        }
        Ok(())
    }

    fn is_block_in_path(&self, target: sha256d::Hash, tip: sha256d::Hash) -> Result<bool> {
        let mut curr = tip;
        while curr != sha256d::Hash::all_zeros() {
            if curr == target { return Ok(true); }
            if let Some(h_bytes) = self.headers_tree.get(curr.as_ref() as &[u8])? {
                let h: BlockHeader = bincode::deserialize(&h_bytes)?;
                curr = h.prev_blockhash;
            } else { break; }
        }
        Ok(false)
    }

    fn rollback_utxo_set(&mut self, block: &Block) -> Result<()> {
        let mut rolling_muhash = self.get_muhash_root()?;
        for tx in block.transactions.iter().rev() {
            for vout in tx.vout.iter() {
                if vout.script_pub_key.len() >= 27 && vout.script_pub_key[0] == 0x6a && vout.script_pub_key[1] == 0x05 && &vout.script_pub_key[2..7] == b"STAKE" {
                    let pubkey_hash_bytes = &vout.script_pub_key[8..28];
                    if let Ok(pk_hash) = hash160::Hash::from_slice(pubkey_hash_bytes) {
                        let address = address_from_pubkey_hash(&pk_hash);
                        info!("[ROLLBACK] Reducing stake for address {}: {} SYN", address, vout.value);
                        let _ = self.consensus_engine.staking_module.reduce_stake(&address, vout.value as u128);
                    }
                }
            }

            let txid = tx.id();
            for (i, _) in tx.vout.iter().enumerate() {
                let mut utxo_key = Vec::with_capacity(36);
                utxo_key.extend_from_slice(txid.as_ref());
                utxo_key.extend_from_slice(&(i as u32).to_be_bytes());
                if let Some(val) = self.utxo_tree.get(&utxo_key)? {
                    rolling_muhash = self.muhash_div(rolling_muhash, BigUint::from_bytes_be(sha256d::Hash::hash(&val).as_ref()));
                    self.utxo_cache.remove(&(txid, i as u32));
                    self.utxo_tree.remove(utxo_key)?;
                }
            }
            if !tx.is_coinbase() {
                for vin in &tx.vin {
                    if let Ok(Some(prev_tx)) = self.get_transaction(&vin.prev_txid) {
                        let out = &prev_tx.vout[vin.prev_vout as usize];
                        let entry = UtxoEntry { output: out.clone(), height: 0, is_coinbase: false };
                        let val = bincode::serialize(&entry)?;
                        rolling_muhash = self.muhash_mul(rolling_muhash, BigUint::from_bytes_be(sha256d::Hash::hash(&val).as_ref()));
                        let mut k = Vec::with_capacity(36);
                        k.extend_from_slice(vin.prev_txid.as_ref());
                        k.extend_from_slice(&vin.prev_vout.to_be_bytes());
                        self.utxo_tree.insert(k, val)?;
                    }
                }
            }
        }
        self.meta_tree.insert("utxo_muhash_root", rolling_muhash.to_bytes_be().as_slice())?;
        Ok(())
    }

    fn find_common_ancestor(&self, hash1: sha256d::Hash, hash2: sha256d::Hash) -> Result<sha256d::Hash> {
        let mut path = HashSet::new();
        let mut curr = hash1;
        while curr != sha256d::Hash::all_zeros() {
            path.insert(curr);
            if let Some(h_bytes) = self.headers_tree.get(curr.as_ref() as &[u8])? {
                curr = bincode::deserialize::<BlockHeader>(&h_bytes)?.prev_blockhash;
            } else { break; }
        }
        curr = hash2;
        while curr != sha256d::Hash::all_zeros() {
            if path.contains(&curr) { return Ok(curr); }
            if let Some(h_bytes) = self.headers_tree.get(curr.as_ref() as &[u8])? {
                curr = bincode::deserialize::<BlockHeader>(&h_bytes)?.prev_blockhash;
            } else { break; }
        }
        bail!("No common ancestor")
    }

    pub fn get_block_locator(&self) -> Vec<sha256d::Hash> {
        let mut locator = Vec::new();
        let mut step = 1;
        let mut index = self.headers.len() as i32 - 1;
        while index >= 0 {
            locator.push(self.headers[index as usize].hash());
            if index == 0 { break; }
            index -= step;
            if locator.len() > 10 { step *= 2; }
        }
        if let Some(gen) = self.headers.first() {
            let h = gen.hash();
            if locator.last() != Some(&h) { locator.push(h); }
        }
        locator
    }

    pub fn update_and_execute_proposals(&mut self) {
        let height = self.headers.len() as u32; 
        let proposals = self.governance.proposals.clone();
        for p in proposals.values() {
            if p.state == ProposalState::Active && height > p.end_block {
                let total = p.votes_for + p.votes_against;
                if total > 0 && (p.votes_for * 100 > self.governance_params.vote_threshold_percent * total) {
                    if let Some(cp) = self.governance.proposals.get_mut(&p.id) {
                        cp.state = ProposalState::Executed;
                        if let ProposalPayload::UpdateTargetBlockTime(new_time) = p.payload {
                            Arc::make_mut(&mut self.consensus_params).target_block_time = new_time;
                        }
                    }
                } else if let Some(cp) = self.governance.proposals.get_mut(&p.id) { cp.state = ProposalState::Failed; }
            }
        }
    }
}
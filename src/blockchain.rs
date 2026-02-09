// src/blockchain.rs - Remediation Step 4: Operational Reset and Validation

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
};
use anyhow::{anyhow, bail, Result};
use bitcoin_hashes::{sha256d, Hash, hash160};
use chrono::Utc;
use num_traits::{ToPrimitive, Zero};
use num_bigint::BigUint;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use secp256k1::PublicKey;
use sled::Batch;
use serde::{Serialize, Deserialize};
use log::{info, warn};

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

#[derive(Clone, Debug)]
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
    // CHANGED: Use Fixed for deterministic state
    pub current_burn_rate: Fixed,
    pub current_kappa: Fixed,
}

impl Default for LddState {
    fn default() -> Self {
        // Remediation Step 4: Operational Reset Safety Parameters
        Self {
            f_a_pow: Fixed::from_f64(0.05), // Reset Amplitude
            f_a_pos: Fixed::from_f64(0.05), // Reset Amplitude
            f_b_pow: Fixed::from_f64(0.005),
            f_b_pos: Fixed::from_f64(0.005),
            recent_blocks: Vec::new(),
            current_psi: 5,   // Reset Slot Gap
            current_gamma: 50, // Reset Recovery Threshold
            current_target_block_time: 15,
            current_adjustment_window: 10,
            next_adjustment_height: 10,
            current_burn_rate: Fixed::from_f64(0.1),
            current_kappa: Fixed::from_f64(0.1),
        }
    }
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

        let mut ldd_state = LddState::default();
        // Override with config only if config is more conservative, otherwise respect the safety patch
        ldd_state.current_target_block_time = consensus_params.target_block_time;
        // CHANGED: Use Fixed conversion for state
        ldd_state.current_burn_rate = Fixed::from_f64(fee_params.min_burn_rate);

        let mut bc = Blockchain {
            db, blocks_tree, headers_tree, header_meta_tree, utxo_tree, addr_utxo_tree, tx_index_tree, btc_txid_tree, meta_tree,
            tip: sha256d::Hash::all_zeros(),
            total_work: 0,
            best_header_tip: sha256d::Hash::all_zeros(),
            best_header_work: 0,
            mempool: HashMap::new(), beacon_mempool: Vec::new(),
            ldd_state, consensus_params, fee_params: fee_params.clone(),
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
            bc.calculate_synergistic_work(&mut genesis);
            genesis.total_work = genesis.synergistic_work;
            let genesis_hash = genesis.header.hash();
            
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

            if let Some(height_bytes) = bc.meta_tree.get("next_adjustment_height")? {
                let mut arr = [0u8; 4]; arr.copy_from_slice(&height_bytes);
                bc.ldd_state.next_adjustment_height = u32::from_be_bytes(arr);
            }
        }
        
        bc.sync_staking_totals();
        Ok(bc)
    }

    pub fn is_syncing(&self) -> bool {
        let current_height = self.headers.len() as u32;
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

        let _prev_meta_bytes = self.header_meta_tree.get(prev_hash.as_ref() as &[u8])?
            .ok_or_else(|| anyhow!("Header parent missing: {}", prev_hash))?;
        let prev_header_bytes = self.headers_tree.get(prev_hash.as_ref() as &[u8])?.unwrap();
        let prev_header: BlockHeader = bincode::deserialize(&prev_header_bytes)?;

        let delta = header.time.saturating_sub(prev_header.time);
        
        let height = self.headers.len() as u32;
        if height > 64 && delta < self.ldd_state.current_psi {
            bail!("Protocol Violation: Block found before Slot Gap elapsed (Delta: {}s, Psi: {}s)", delta, self.ldd_state.current_psi);
        }

        if header.vrf_proof.is_none() {
            let hash_val = BigUint::from_bytes_be(header.hash().as_ref());
            let ldd_target = self.get_next_pow_target(delta);
            
            if height > 64 && hash_val > ldd_target {
                 bail!("Rejection: Block {} does not meet PoW target for delta {}s", header.hash(), delta);
            }

            let target = BlockHeader::calculate_target(header.bits);
            if hash_val > target { bail!("Invalid PoW in header"); }

            let easiest = BlockHeader::calculate_target(0x207fffff);
            let easiest_val = if easiest.is_zero() { BigUint::from(1u32) } else { easiest.clone() };
            let target_val = if target.is_zero() { BigUint::from(1u32) } else { target };
            return Ok((easiest_val / target_val).to_u64().unwrap_or(1));
        } else {
            let pow_target_bits = self.consensus_params.max_target_bits;
            let easiest = BlockHeader::calculate_target(0x207fffff);
            let target = BlockHeader::calculate_target(pow_target_bits);
            let easiest_val = if easiest.is_zero() { BigUint::from(1u32) } else { easiest.clone() };
            let target_val = if target.is_zero() { BigUint::from(1u32) } else { target };
            return Ok((easiest_val / target_val).to_u64().unwrap_or(1));
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
        
        // CHANGED: Use set_state_from_bits to avoid float
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

        let skip_verify = if let Some(finalized_hash) = self.last_finalized_checkpoint {
            if let Some(f_meta_bytes) = self.header_meta_tree.get(finalized_hash.as_ref() as &[u8]).ok().flatten() {
                if let Ok(f_meta) = bincode::deserialize::<HeaderMetadata>(&f_meta_bytes) {
                    block.height < f_meta.height.saturating_sub(6)
                } else { false }
            } else { false }
        } else { false };

        for tx in &block.transactions {
            let mut prev_txs = HashMap::new();
            if !tx.is_coinbase() && !skip_verify {
                let is_bridge_mint = tx.vin.len() == 1 && tx.vin[0].prev_txid == sha256d::Hash::all_zeros() && tx.vin[0].script_sig.starts_with(b"{");

                if is_bridge_mint {
                    self.validate_progonos_mint(tx, &mut btc_tx_batch)?;
                } else {
                    for vin in &tx.vin {
                        let prev_tx = self.get_transaction(&vin.prev_txid)?.ok_or_else(|| anyhow!("Input tx missing"))?;
                        prev_txs.insert(vin.prev_txid, prev_tx);
                    }
                    tx.verify_hybrid(&prev_txs, pqc_enforced)?;
                }
            }

            let txid = tx.id();
            if !tx.is_coinbase() && !tx.vin.is_empty() {
                for vin in &tx.vin {
                    if vin.prev_txid == sha256d::Hash::all_zeros() { continue; } 
                    let mut utxo_key = Vec::with_capacity(36);
                    utxo_key.extend_from_slice(vin.prev_txid.as_ref());
                    utxo_key.extend_from_slice(&vin.prev_vout.to_be_bytes());
                    if let Some(val) = self.utxo_tree.get(&utxo_key)? {
                        let entry_hash = BigUint::from_bytes_be(sha256d::Hash::hash(&val).as_ref());
                        rolling_muhash = self.muhash_div(rolling_muhash, entry_hash);
                        self.utxo_cache.remove(&(vin.prev_txid, vin.prev_vout));
                        utxo_batch.remove(utxo_key.as_slice());
                        let entry: UtxoEntry = bincode::deserialize(&val)?;
                        if !entry.output.script_pub_key.is_empty() {
                            let mut addr_key = entry.output.script_pub_key;
                            addr_key.extend_from_slice(&utxo_key);
                            addr_batch.remove(addr_key);
                        }
                    } else { bail!("UTXO missing in tx {}.", txid); }
                }
            }

            for (i, vout) in tx.vout.iter().enumerate() {
                // Check for STAKE transaction output (OP_RETURN + b"STAKE")
                // Protocol Rule: Stake output format: 0x6a (OP_RETURN) | 0x05 (PUSH 5) | "STAKE" | 0x14 (PUSH 20) | <PubKeyHash>
                if vout.script_pub_key.len() >= 27 && vout.script_pub_key[0] == 0x6a && vout.script_pub_key[1] == 0x05 && &vout.script_pub_key[2..7] == b"STAKE" {
                    // Extract pubkey hash (20 bytes starting at index 8)
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
                utxo_batch.insert(utxo_key.clone(), serialized);
                if self.utxo_cache.len() < MAX_UTXO_CACHE_SIZE { self.utxo_cache.insert((txid, i as u32), entry); }
                if !vout.script_pub_key.is_empty() {
                    let mut addr_key = vout.script_pub_key.clone(); addr_key.extend_from_slice(&utxo_key); addr_batch.insert(addr_key, &[]);
                }
            }
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

    pub fn calculate_synergistic_work(&self, block: &mut Block) {
        let vrf_opt = &block.header.vrf_proof;
        if vrf_opt.is_none() {
            let easiest = BlockHeader::calculate_target(0x207fffff);
            let target = BlockHeader::calculate_target(block.header.bits);
            let easiest_val = if easiest.is_zero() { BigUint::from(1u32) } else { easiest.clone() };
            let target_val = if target.is_zero() { BigUint::from(1u32) } else { target };
            block.synergistic_work = (easiest_val / target_val).to_u64().unwrap_or(1);
        } else {
            let pow_target_bits = self.consensus_params.max_target_bits;
            let easiest = BlockHeader::calculate_target(0x207fffff);
            let target = BlockHeader::calculate_target(pow_target_bits);
            let easiest_val = if easiest.is_zero() { BigUint::from(1u32) } else { easiest.clone() };
            let target_val = if target.is_zero() { BigUint::from(1u32) } else { target };
            
            let base_pos_work = (easiest_val / target_val).to_u64().unwrap_or(1);

            let entropy_bonus = if let Some(p) = &block.header.vrf_proof {
                 let vrf_hash = sha256d::Hash::hash(p);
                 (vrf_hash.to_byte_array()[0] as u64) % 10 
            } else { 0 };

            block.synergistic_work = base_pos_work + (base_pos_work * entropy_bonus / 100);
        }
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

    pub fn adjust_ldd(&mut self) {
        let total_window_blocks = self.ldd_state.recent_blocks.len();
        if total_window_blocks < 2 { return; }

        let n_pow = self.ldd_state.recent_blocks.iter().filter(|(_, is_pow)| *is_pow).count();
        let n_pos = total_window_blocks.saturating_sub(n_pow);

        // Calculate Observed Mu (Actual Block Spacing)
        let start_time = self.ldd_state.recent_blocks.first().unwrap().0;
        let end_time = self.ldd_state.recent_blocks.last().unwrap().0;
        let duration = end_time.saturating_sub(start_time);
        let observed_mu = SlotDuration((duration as u64) / (total_window_blocks as u64 - 1));

        let network_state = self.dcs.get_consensus_state();
        let target_mu = SlotDuration(self.consensus_params.target_block_time);

        let current_params = LddParams {
            psi: SlotDuration(self.ldd_state.current_psi as u64),
            gamma: SlotDuration(self.ldd_state.current_gamma as u64),
            f_a_pow: Probability::from_num(self.ldd_state.f_a_pow.to_f64()),
            f_a_pos: Probability::from_num(self.ldd_state.f_a_pos.to_f64()),
        };

        let new_params = calculate_next_difficulty(
            &current_params,
            network_state,
            target_mu,
            observed_mu,
            n_pos,
            total_window_blocks
        );

        // Update local state
        self.ldd_state.current_psi = new_params.psi.0 as u32;
        self.ldd_state.current_gamma = new_params.gamma.0 as u32;
        self.ldd_state.f_a_pow = Fixed::from_f64(new_params.f_a_pow.to_f64());
        self.ldd_state.f_a_pos = Fixed::from_f64(new_params.f_a_pos.to_f64());

        // Refresh fallbacks
        let t_fallback = 300.0;
        let b_total = 1.0 / t_fallback;
        let sum_a = self.ldd_state.f_a_pow.to_f64() + self.ldd_state.f_a_pos.to_f64();
        if sum_a > 0.0 {
            self.ldd_state.f_b_pow = Fixed::from_f64(b_total * (self.ldd_state.f_a_pow.to_f64() / sum_a));
            self.ldd_state.f_b_pos = Fixed::from_f64(b_total * (self.ldd_state.f_a_pos.to_f64() / sum_a));
        }

        self.sync_staking_totals();

        self.ldd_state.recent_blocks.clear();
        self.dcs.reset_interval(); 
    }

    pub fn get_next_pow_target(&self, delta: u32) -> BigUint {
        let hazard = self.calculate_hazard(delta, self.ldd_state.f_a_pow, self.ldd_state.f_b_pow);
        let max_target = BigUint::from(1u32) << 256;
        (BigUint::from(hazard.0) * max_target) >> 64
    }

    pub fn get_next_work_required(&self, pow: bool, delta: u32) -> u32 {
        let hazard = if pow {
            self.calculate_hazard(delta, self.ldd_state.f_a_pow, self.ldd_state.f_b_pow)
        } else {
            // Remediation Step 1 support: pass f_b_pos
            self.calculate_hazard(delta, self.ldd_state.f_a_pos, self.ldd_state.f_b_pos)
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

    fn calculate_hazard(&self, delta: u32, f_a: Fixed, f_b: Fixed) -> Fixed {
        let psi = self.ldd_state.current_psi;
        let gamma = self.ldd_state.current_gamma;

        if delta < psi {
            Fixed(0)
        } else if delta < gamma {
            let num = Fixed::from_integer((delta - psi) as u64);
            let den = Fixed::from_integer((gamma - psi) as u64);
            // Remediation Step 1: Linear Interpolation
            if den.0 == 0 { f_b } else { f_a * (num / den) }
        } else {
            f_b // Use correct fallback
        }
    }

    pub fn get_mempool_txs(&mut self) -> Vec<Transaction> { 
        self.mempool.values().cloned().collect()
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
        
        // Populate committed_total_stake with current view
        let committed_total_stake = self.total_staked;

        let mut block = Block::new(now, transactions, self.tip, bits, prev.height + 1, version, 0, committed_total_stake);
        block.beacons = beacons_to_include.to_vec();
        block.header.utxo_root = self.calculate_utxo_root()?;
        Ok(block)
    }

    pub fn add_block(&mut self, mut block: Block) -> Result<()> {
        let hash = block.header.hash();
        if self.blocks_tree.contains_key(hash.as_ref() as &[u8])? { return Ok(()); }
        
        if self.veto_manager.blacklisted_blocks.contains(&hash) { 
            bail!("Rejection: Block {} has been vetoed.", hash); 
        }

        let is_parallel_genesis = block.header.prev_blockhash == sha256d::Hash::all_zeros();
        if !is_parallel_genesis && !self.headers_tree.contains_key(block.header.prev_blockhash.as_ref() as &[u8])? {
            if self.orphan_blocks.len() < MAX_ORPHAN_BLOCKS {
                self.orphan_blocks.insert(hash, block);
                return Ok(());
            } else { bail!("Orphan buffer full"); }
        }

        if let Err(e) = self.verify_dcs_metadata(&block) { bail!("DCS telemetry failed: {}", e); }

        let is_pow = block.header.vrf_proof.is_none();
        let fees = self.calculate_total_fees(&block);

        let prev_hash = block.header.prev_blockhash;
        if prev_hash != sha256d::Hash::all_zeros() {
            let prev_header_bytes = self.headers_tree.get(prev_hash.as_ref() as &[u8])?.unwrap();
            let prev_header: BlockHeader = bincode::deserialize(&prev_header_bytes)?;
            let delta = block.header.time.saturating_sub(prev_header.time);
            
            if block.height > 64 {
                if is_pow {
                    let target = self.get_next_pow_target(delta);
                    if BigUint::from_bytes_be(hash.as_ref()) > target {
                        bail!("Rejection: Block {} does not meet PoW target for delta {}s", hash, delta);
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

                    // Remediation Step 2: Use committed_total_stake from the header
                    let committed_stake = block.header.committed_total_stake;
                    
                    if !self.consensus_engine.check_pos_eligibility(&validator_addr, delta, vrf_hash.as_ref(), committed_stake) {
                        bail!("Rejection: Validator {} not eligible for PoS block at delta {}s", validator_addr, delta);
                    }
                }
            }
        }

        self.calculate_synergistic_work(&mut block);

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
            // CHANGED: Use Fixed rate
            let burn_rate_fixed = self.ldd_state.current_burn_rate;
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
        
        if block.total_work >= self.total_work {
            if block.header.prev_blockhash != self.tip && !is_parallel_genesis { 
                self.handle_reorganization(hash)?; 
            } else { 
                self.tip = hash; 
                self.update_utxo_set(&block)?;
                self.headers.push(block.header.clone());
            }
            
            self.sync_staking_totals();
            for tx in &block.transactions { self.mempool.remove(&tx.id()); }
            self.total_work = block.total_work;
            self.dcs.process_beacons(&block.beacons);
            if self.burst_manager.check_and_activate(&block, fees) { self.finality_gadget.activate(hash, self.total_staked); }
            self.burst_manager.update_state(block.height);

            if !self.is_syncing() {
                self.ldd_state.recent_blocks.push((block.header.time, is_pow));
                
                if block.height >= self.ldd_state.next_adjustment_height { 
                    self.adjust_ldd(); 
                    self.ldd_state.next_adjustment_height = block.height + self.ldd_state.current_adjustment_window as u32;
                    self.meta_tree.insert("next_adjustment_height", self.ldd_state.next_adjustment_height.to_be_bytes().as_slice())?;
                }
            }
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

    fn verify_dcs_metadata(&self, block: &Block) -> Result<()> {
        if block.header.vrf_proof.is_some() { return Ok(()); }
        let consensus_values = self.dcs.calculate_consensus();
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
                // Rollback STAKE transaction (OP_RETURN + b"STAKE")
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
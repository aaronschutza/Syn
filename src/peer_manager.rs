// src/peer_manager.rs - Overhauled with Address Book for Gossip and Verbose Logging

use crate::config::P2PConfig;
use log::{info, warn, debug, trace};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Represents a single peer in the network with reputation and connection metadata.
pub struct Peer {
    pub score: i32,
    pub banned_until: Option<Instant>,
    pub last_seen: Instant,
    pub connected_at: Instant,
    pub is_outbound: bool,
}

pub struct PeerManager {
    peers: HashMap<SocketAddr, Peer>,
    /// Known addresses discovered via gossip (Address Book)
    known_addresses: HashSet<SocketAddr>,
    config: Arc<P2PConfig>,
    outbound_count: usize,
}

impl PeerManager {
    pub fn new(config: Arc<P2PConfig>) -> Self {
        PeerManager {
            peers: HashMap::new(),
            known_addresses: HashSet::new(),
            config,
            outbound_count: 0,
        }
    }

    /// Adds new addresses to the address book (Gossip)
    pub fn add_known_addresses(&mut self, addrs: Vec<SocketAddr>) {
        let mut added_count = 0;
        for addr in addrs {
            if !self.known_addresses.contains(&addr) {
                trace!("Gossip: Learned new peer address {}", addr);
                self.known_addresses.insert(addr);
                added_count += 1;
            }
        }
        if added_count > 0 {
            debug!("PeerManager: Added {} new addresses to address book. Total known: {}", added_count, self.known_addresses.len());
        }
    }

    /// Returns a list of known addresses to share with others
    pub fn get_gossip_addresses(&self) -> Vec<SocketAddr> {
        // Return up to 50 known addresses (increased from 10 to help convergence)
        self.known_addresses.iter().take(50).cloned().collect()
    }

    /// Returns addresses from the book that we are NOT currently connected to
    pub fn get_potential_targets(&self) -> Vec<SocketAddr> {
        self.known_addresses.iter()
            .filter(|a| !self.peers.contains_key(a))
            .cloned()
            .collect()
    }

    pub fn on_connect(&mut self, addr: SocketAddr, is_outbound: bool) {
        let now = Instant::now();
        self.peers.entry(addr).or_insert(Peer {
            score: self.config.initial_score,
            banned_until: None,
            last_seen: now,
            connected_at: now,
            is_outbound,
        });
        // Ensure this is in our known list
        self.known_addresses.insert(addr);
        
        if is_outbound {
            self.outbound_count += 1;
        }
        
        info!("[PEER_MGR] Peer connected: {} (Outbound: {}). Total Connected: {}", addr, is_outbound, self.peers.len());
    }

    pub fn on_disconnect(&mut self, addr: &SocketAddr) {
        if let Some(peer) = self.peers.remove(addr) {
            if peer.is_outbound {
                self.outbound_count = self.outbound_count.saturating_sub(1);
            }
            info!("[PEER_MGR] Peer disconnected: {}. Duration: {:?}. Final Score: {}. Remaining Peers: {}", 
                addr, peer.connected_at.elapsed(), peer.score, self.peers.len());
        } else {
            debug!("[PEER_MGR] Attempted to disconnect unknown peer: {}", addr);
        }
    }

    pub fn report_misbehavior(&mut self, addr: SocketAddr, penalty: i32) {
        // We only track misbehavior for connected peers or known peers we want to ban
        // If not connected, we might want to add a temporary entry or just ignore if it's transient
        let peer = self.peers.entry(addr).or_insert(Peer {
            score: self.config.initial_score,
            banned_until: None,
            last_seen: Instant::now(),
            connected_at: Instant::now(),
            is_outbound: false,
        });

        peer.score -= penalty;
        debug!("[PEER_MGR] Misbehavior reported for {}: penalty={}, new_score={}", addr, penalty, peer.score);

        if peer.score <= self.config.ban_threshold {
            let duration = Duration::from_secs(self.config.ban_duration_secs);
            warn!("[PEER_MGR] Banning peer {} for {}s due to low score ({}).", addr, duration.as_secs(), peer.score);
            peer.banned_until = Some(Instant::now() + duration);
        }
    }

    pub fn is_banned(&mut self, addr: &SocketAddr) -> bool {
        if let Some(peer) = self.peers.get_mut(addr) {
            if let Some(banned_until) = peer.banned_until {
                if Instant::now() < banned_until {
                    return true;
                } else {
                    info!("[PEER_MGR] Ban expired for {}. Resetting score.", addr);
                    peer.banned_until = None;
                    peer.score = self.config.initial_score;
                }
            }
        }
        false
    }

    pub fn needs_outbound(&self) -> bool {
        // Target 8 outbound connections for robust mesh
        self.outbound_count < 8
    }

    pub fn can_accept_inbound(&self) -> bool {
        // AUDIT FIX: Increased hardcoded limit from 8 to 50.
        // A limit of 8 on bootstrap nodes causes immediate fragmentation as the network grows beyond 9 nodes.
        const MAX_INBOUND_CONNECTIONS: usize = 50;
        
        if self.peers.len() >= MAX_INBOUND_CONNECTIONS {
            debug!("[PEER_MGR] Rejecting inbound connection. Capacity full ({}/{})", self.peers.len(), MAX_INBOUND_CONNECTIONS);
            return false;
        }
        true
    }

    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    pub fn get_active_addresses(&self) -> Vec<SocketAddr> {
        self.peers.keys().cloned().collect()
    }

    pub fn get_eviction_candidate(&self) -> Option<SocketAddr> {
        if self.peers.is_empty() { return None; }
        
        // Evict based on lowest score, then oldest connection (if scores equal, prefer keeping newer ones? or older? usually keep stable ones)
        // Here we evict the one with lowest score. If tied, we evict the one connected most recently (least stable)?
        // Let's evict lowest score.
        let mut candidates: Vec<_> = self.peers.iter()
            .map(|(addr, peer)| (addr, peer.score, peer.connected_at))
            .collect();
            
        // Sort: Primary = Score (Ascending), Secondary = Connected At (Descending -> Newer connections first?)
        // Actually, protecting long-lived peers is usually good. So evict newer ones if scores are equal.
        // Sort ascending: Smallest score first. If equal score, largest timestamp (newest) first?
        // Instant is monotonic. Larger instant = Newer.
        candidates.sort_by(|a, b| {
            a.1.cmp(&b.1) // Score
                .then_with(|| b.2.cmp(&a.2)) // Time (Descending: Newest first)
        });

        if let Some((addr, score, time)) = candidates.first() {
            debug!("[PEER_MGR] Eviction candidate selected: {} (Score: {}, Connected: {:?})", addr, score, time);
            Some(**addr)
        } else {
            None
        }
    }
}
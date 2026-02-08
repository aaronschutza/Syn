// src/peer_manager.rs - Overhauled with Address Book for Gossip

use crate::config::P2PConfig;
use log::{warn, debug};
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
        for addr in addrs {
            if !self.known_addresses.contains(&addr) {
                debug!("Gossip: Learned new peer address {}", addr);
                self.known_addresses.insert(addr);
            }
        }
    }

    /// Returns a list of known addresses to share with others
    pub fn get_gossip_addresses(&self) -> Vec<SocketAddr> {
        // Return up to 10 known addresses
        self.known_addresses.iter().take(10).cloned().collect()
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
    }

    pub fn on_disconnect(&mut self, addr: &SocketAddr) {
        if let Some(peer) = self.peers.remove(addr) {
            if peer.is_outbound {
                self.outbound_count = self.outbound_count.saturating_sub(1);
            }
        }
    }

    pub fn report_misbehavior(&mut self, addr: SocketAddr, penalty: i32) {
        let peer = self.peers.entry(addr).or_insert(Peer {
            score: self.config.initial_score,
            banned_until: None,
            last_seen: Instant::now(),
            connected_at: Instant::now(),
            is_outbound: false,
        });

        peer.score -= penalty;
        if peer.score <= self.config.ban_threshold {
            let duration = Duration::from_secs(self.config.ban_duration_secs);
            warn!("Banning peer {} for {}s due to low score.", addr, duration.as_secs());
            peer.banned_until = Some(Instant::now() + duration);
        }
    }

    pub fn is_banned(&mut self, addr: &SocketAddr) -> bool {
        if let Some(peer) = self.peers.get_mut(addr) {
            if let Some(banned_until) = peer.banned_until {
                if Instant::now() < banned_until {
                    return true;
                } else {
                    peer.banned_until = None;
                    peer.score = self.config.initial_score;
                }
            }
        }
        false
    }

    pub fn needs_outbound(&self) -> bool {
        self.outbound_count < 4
    }

    pub fn can_accept_inbound(&self) -> bool {
        self.peers.len() < 8 // Increased for better mesh stability
    }

    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    pub fn get_active_addresses(&self) -> Vec<SocketAddr> {
        self.peers.keys().cloned().collect()
    }

    pub fn get_eviction_candidate(&self) -> Option<SocketAddr> {
        if self.peers.is_empty() { return None; }
        let mut candidates: Vec<_> = self.peers.iter()
            .map(|(addr, peer)| (addr, peer.score, peer.connected_at))
            .collect();
        candidates.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.2.cmp(&b.2)));
        candidates.first().map(|(addr, _, _)| **addr)
    }
}
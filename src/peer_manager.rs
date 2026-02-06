// src/peer_manager.rs - Overhauled Peer Rotation and Churn Logic

use crate::config::P2PConfig;
use log::{info, warn, debug};
use std::collections::HashMap;
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
    config: Arc<P2PConfig>,
    outbound_count: usize,
}

impl PeerManager {
    pub fn new(config: Arc<P2PConfig>) -> Self {
        PeerManager {
            peers: HashMap::new(),
            config,
            outbound_count: 0,
        }
    }

    /// Records a new connection and initializes score and connection time.
    pub fn on_connect(&mut self, addr: SocketAddr, is_outbound: bool) {
        let now = Instant::now();
        self.peers.entry(addr).or_insert(Peer {
            score: self.config.initial_score,
            banned_until: None,
            last_seen: now,
            connected_at: now,
            is_outbound,
        });
        if is_outbound {
            self.outbound_count += 1;
        }
    }

    /// Records a disconnection and updates outbound counts.
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
        warn!("Peer {} misbehaved (-{}). Score: {}", addr, penalty, peer.score);

        if peer.score <= self.config.ban_threshold {
            let duration = Duration::from_secs(self.config.ban_duration_secs);
            info!("Banning peer {} for {}s.", addr, duration.as_secs());
            peer.banned_until = Some(Instant::now() + duration);
        }
    }

    pub fn reward_peer(&mut self, addr: &SocketAddr, reward: i32) {
        if let Some(peer) = self.peers.get_mut(addr) {
            peer.score = (peer.score + reward).min(200);
            peer.last_seen = Instant::now();
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

    /// Synergeia Overhaul: Target 4 outbound peers for ideal network density.
    pub fn needs_outbound(&self) -> bool {
        self.outbound_count < 4
    }

    /// Synergeia Overhaul: Max total peers allowed is 6.
    pub fn can_accept_inbound(&self) -> bool {
        self.peers.len() < 6
    }

    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Returns a candidate for eviction to facilitate network churn.
    /// Prioritizes peers with the lowest score, then oldest peers if scores are tied.
    pub fn get_eviction_candidate(&self) -> Option<SocketAddr> {
        if self.peers.is_empty() { return None; }
        
        let mut candidates: Vec<_> = self.peers.iter()
            .map(|(addr, peer)| (addr, peer.score, peer.connected_at))
            .collect();

        // Sort by score ascending, then by age (older first)
        candidates.sort_by(|a, b| {
            a.1.cmp(&b.1).then_with(|| a.2.cmp(&b.2))
        });

        candidates.first().map(|(addr, _, _)| **addr)
    }
}
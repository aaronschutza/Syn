// src/peer_manager.rs - Reputation-based protection against network attacks

use crate::config::P2PConfig;
use log::{info, warn, debug};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Represents a single peer in the network with reputation tracking.
pub struct Peer {
    pub score: i32,
    pub banned_until: Option<Instant>,
    pub last_seen: Instant,
    pub is_outbound: bool,
}

/// Manages reputation and connection hygiene to mitigate Eclipse and DoS attacks.
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

    /// Records a new connection and initializes score.
    pub fn on_connect(&mut self, addr: SocketAddr, is_outbound: bool) {
        self.peers.entry(addr).or_insert(Peer {
            score: self.config.initial_score,
            banned_until: None,
            last_seen: Instant::now(),
            is_outbound,
        });
        if is_outbound {
            self.outbound_count += 1;
        }
    }

    /// Records a disconnection.
    pub fn on_disconnect(&mut self, addr: &SocketAddr) {
        if let Some(peer) = self.peers.get(addr) {
            if peer.is_outbound {
                self.outbound_count = self.outbound_count.saturating_sub(1);
            }
        }
    }

    /// Report misbehavior (e.g., sending invalid blocks, script failures).
    pub fn report_misbehavior(&mut self, addr: SocketAddr, penalty: i32) {
        let peer = self.peers.entry(addr).or_insert(Peer {
            score: self.config.initial_score,
            banned_until: None,
            last_seen: Instant::now(),
            is_outbound: false,
        });

        peer.score -= penalty;
        warn!("Peer {} misbehaved (-{}). Current score: {}", addr, penalty, peer.score);

        if peer.score <= self.config.ban_threshold {
            let duration = Duration::from_secs(self.config.ban_duration_secs);
            info!("Banning peer {} for {} seconds due to low score.", addr, duration.as_secs());
            peer.banned_until = Some(Instant::now() + duration);
        }
    }

    /// Reward good behavior (e.g., providing a valid block tip).
    pub fn reward_peer(&mut self, addr: &SocketAddr, reward: i32) {
        if let Some(peer) = self.peers.get_mut(addr) {
            peer.score = (peer.score + reward).min(200); // Cap score at 200
            peer.last_seen = Instant::now();
            debug!("Peer {} rewarded (+{}). New score: {}", addr, reward, peer.score);
        }
    }

    pub fn is_banned(&mut self, addr: &SocketAddr) -> bool {
        if let Some(peer) = self.peers.get_mut(addr) {
            if let Some(banned_until) = peer.banned_until {
                if Instant::now() < banned_until {
                    return true;
                } else {
                    info!("Ban expired for peer {}. Resetting reputation.", addr);
                    peer.banned_until = None;
                    peer.score = self.config.initial_score;
                }
            }
        }
        false
    }

    /// Returns whether the node should attempt more outbound connections.
    pub fn needs_outbound(&self) -> bool {
        self.outbound_count < 8 // Target 8 stable outbound peers
    }
}
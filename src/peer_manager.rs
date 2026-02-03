// src/peer_manager.rs

use crate::config::P2PConfig;
use log::{info, warn};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Represents a single peer in the network.
pub struct Peer {
    pub score: i32,
    banned_until: Option<Instant>,
}

/// Manages the reputation of all peers connected to the node.
pub struct PeerManager {
    peers: HashMap<SocketAddr, Peer>,
    config: Arc<P2PConfig>,
}

impl PeerManager {
    /// Creates a new PeerManager instance.
    pub fn new(config: Arc<P2PConfig>) -> Self {
        PeerManager {
            peers: HashMap::new(),
            config,
        }
    }

    /// Report misbehavior and apply a penalty to the peer's score.
    pub fn report_misbehavior(&mut self, addr: SocketAddr, penalty: i32) {
        let peer = self.peers.entry(addr).or_insert(Peer {
            score: self.config.initial_score,
            banned_until: None,
        });

        peer.score -= penalty;
        warn!("Peer {} misbehaved. Score reduced to {}.", addr, peer.score);

        // If a peer's score drops below the threshold, ban them for a set duration.
        if peer.score <= self.config.ban_threshold {
            info!(
                "Banning peer {} for {} minutes.",
                addr,
                self.config.ban_duration_secs / 60
            );
            peer.banned_until = Some(Instant::now() + Duration::from_secs(self.config.ban_duration_secs));
        }
    }

    /// Check if a peer is currently banned.
    pub fn is_banned(&mut self, addr: &SocketAddr) -> bool {
        if let Some(peer) = self.peers.get_mut(addr) {
            if let Some(banned_until) = peer.banned_until {
                if Instant::now() < banned_until {
                    return true; // Still banned
                } else {
                    // Ban has expired, reset them.
                    info!("Ban expired for peer {}. Resetting score.", addr);
                    peer.banned_until = None;
                    peer.score = self.config.initial_score;
                }
            }
        }
        false
    }
}
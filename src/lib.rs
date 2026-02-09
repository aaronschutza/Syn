// src/lib.rs

// This file defines the Synergeia library and its modules.

pub mod block;
pub mod blockchain;
pub mod btc_p2p;
pub mod cli;
pub mod config;
pub mod consensus;
pub mod crypto;
pub mod dcs;
pub mod burst;
pub mod cdf;
pub mod fixed_point;
pub mod governance;
pub mod p2p;
pub mod params;
pub mod peer_manager;
pub mod pos;
pub mod progonos;
pub mod rpc;
pub mod script;
pub mod stk_module;
pub mod transaction;
pub mod wallet;
pub mod runtime;
pub mod engine;
pub mod gov_module;
pub mod spv;
pub mod storage;
pub mod client;
pub mod difficulty;
pub mod sync;
pub mod units;
pub mod weight; // Added

// The tests module contains all the tests for the Synergeia library.
#[cfg(test)]
mod tests {
    // Tests for the fixed-point arithmetic implementation.
    mod fixed_point_tests;
    // Tests for the scripting language.
    mod script_tests;
    // Integration tests for the entire node.
    mod integration_tests;
    // Tests for advanced adaptive features (DCS, Burst, LDD).
    mod advanced_feature_tests;
    // Tests for difficulty adjustment logic (Liveness Repair).
    mod difficulty_tests;
}
// src/crypto.rs

use bitcoin_hashes::{hash160, sha256d, Hash};
use secp256k1::{rand, PublicKey, Secp256k1, SecretKey, All};
use bs58;

/// Generates a new secp256k1 keypair.
pub fn generate_keypair(secp: &Secp256k1<All>) -> (SecretKey, PublicKey) {
    secp.generate_keypair(&mut rand::thread_rng())
}

/// Hashes a public key using SHA-256 and then RIPEMD-160 (HASH160).
pub fn hash_pubkey(pubkey: &PublicKey) -> hash160::Hash {
    hash160::Hash::hash(&pubkey.serialize())
}

/// Creates a Base58Check encoded address from a public key hash.
pub fn address_from_pubkey_hash(pubkey_hash: &hash160::Hash) -> String {
    // Add the version byte (0x00 for mainnet).
    let mut data = vec![0x00]; 
    data.extend_from_slice(pubkey_hash.as_ref());
    // Calculate the checksum (first 4 bytes of a double SHA-256 hash).
    let checksum = &sha256d::Hash::hash(&data)[..4];
    data.extend_from_slice(checksum);
    // Encode the data using Base58.
    bs58::encode(data).into_string()
}

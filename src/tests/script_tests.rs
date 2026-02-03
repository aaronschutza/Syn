// src/tests/script_tests.rs

#[cfg(test)]
mod tests {
    use crate::crypto::{generate_keypair, hash_pubkey};
    use crate::script;
    use bitcoin_hashes::{sha256d, Hash};
    use secp256k1::{Message, Secp256k1};

    /// Tests a valid Pay-to-Public-Key-Hash (P2PKH) script.
    #[test]
    fn test_p2pkh_valid() {
        let secp = Secp256k1::new();
        let (sk, pk) = generate_keypair(&secp);

        // 1. Create a fake "sighash" for the transaction
        let sighash_data = b"this is the data to be signed";
        let sighash = sha256d::Hash::hash(sighash_data);
        let msg = Message::from_digest_slice(sighash.as_ref()).unwrap();

        // 2. Create the signature
        let sig = secp.sign_ecdsa(&msg, &sk);

        // 3. Construct the scriptSig (the "unlocking" script)
        let mut script_sig_parts: Vec<Vec<u8>> = vec![
            sig.serialize_der().to_vec(),
            pk.serialize().to_vec(),
        ];
        
        let mut script_sig = Vec::new();
        for part in script_sig_parts.iter_mut() {
            script_sig.push(part.len() as u8);
            script_sig.append(part);
        }

        // 4. Construct the scriptPubKey (the "locking" script)
        let pubkey_hash = hash_pubkey(&pk);
        let mut script_pub_key = vec![
            0x76, // OP_DUP
            0xa9, // OP_HASH160
            0x14, // Push 20 bytes
        ];
        script_pub_key.extend_from_slice(pubkey_hash.as_ref());
        script_pub_key.extend(&[0x88, 0xac]); // OP_EQUALVERIFY OP_CHECKSIG

        // 5. Evaluate the script
        let result = script::evaluate(&script_sig, &script_pub_key, sighash.as_ref());
        assert!(result, "Valid P2PKH script should evaluate to true");
    }

    /// Tests an invalid P2PKH script with a bad signature.
    #[test]
    fn test_p2pkh_invalid_sig() {
        let secp = Secp256k1::new();
        let (_sk, pk) = generate_keypair(&secp); // Corrected: sk is unused
        let (sk_fake, _) = generate_keypair(&secp); // A different key

        let sighash_data = b"this is the data to be signed";
        let sighash = sha256d::Hash::hash(sighash_data);
        let msg = Message::from_digest_slice(sighash.as_ref()).unwrap();

        // Sign with the wrong key
        let sig = secp.sign_ecdsa(&msg, &sk_fake);

        let mut script_sig_parts: Vec<Vec<u8>> = vec![
            sig.serialize_der().to_vec(),
            pk.serialize().to_vec(),
        ];
        
        let mut script_sig = Vec::new();
        for part in script_sig_parts.iter_mut() {
            script_sig.push(part.len() as u8);
            script_sig.append(part);
        }

        let pubkey_hash = hash_pubkey(&pk);
        let mut script_pub_key = vec![0x76, 0xa9, 0x14];
        script_pub_key.extend_from_slice(pubkey_hash.as_ref());
        script_pub_key.extend(&[0x88, 0xac]);

        let result = script::evaluate(&script_sig, &script_pub_key, sighash.as_ref());
        assert!(!result, "Invalid signature should cause script to fail");
    }
}
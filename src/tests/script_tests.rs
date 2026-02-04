// src/tests/script_tests.rs - Unit tests for enhanced opcode support

#[cfg(test)]
mod tests {
    use crate::crypto::{generate_keypair, hash_pubkey};
    use crate::script;
    use bitcoin_hashes::{sha256d, Hash};
    use secp256k1::{Message, Secp256k1};

    #[test]
    fn test_arithmetic_ops() {
        // OP_2 OP_3 OP_ADD OP_5 OP_EQUAL
        let script_pub_key = vec![
            0x52, // OP_2
            0x53, // OP_3
            0x93, // OP_ADD
            0x55, // OP_5
            0x87, // OP_EQUAL
        ];
        assert!(script::evaluate(&[], &script_pub_key, &[]));

        // OP_10 OP_4 OP_SUB OP_6 OP_EQUAL
        let script_sub = vec![
            0x5a, // OP_10
            0x54, // OP_4
            0x94, // OP_SUB
            0x56, // OP_6
            0x87, // OP_EQUAL
        ];
        assert!(script::evaluate(&[], &script_sub, &[]));
    }

    #[test]
    fn test_logic_and_verify() {
        // OP_1 OP_VERIFY (Should pass)
        assert!(script::evaluate(&[], &[0x51, 0x69], &[]));

        // OP_0 OP_VERIFY (Should fail)
        assert!(!script::evaluate(&[], &[0x00, 0x69], &[]));

        // OP_1 OP_NOT OP_0 OP_EQUAL
        let script_not = vec![0x51, 0x91, 0x00, 0x87];
        assert!(script::evaluate(&[], &script_not, &[]));
    }

    #[test]
    fn test_p2pkh_complete_flow() {
        let secp = Secp256k1::new();
        let (sk, pk) = generate_keypair(&secp);

        let sighash_data = b"transaction_data_to_sign";
        let sighash = sha256d::Hash::hash(sighash_data);
        let msg = Message::from_digest_slice(sighash.as_ref()).unwrap();
        let sig = secp.sign_ecdsa(&msg, &sk);

        // scriptSig: <sig> <pubkey>
        let mut script_sig = Vec::new();
        let der = sig.serialize_der();
        script_sig.push(der.len() as u8);
        script_sig.extend(der);
        let pk_bytes = pk.serialize();
        script_sig.push(pk_bytes.len() as u8);
        script_sig.extend(pk_bytes);

        // scriptPubKey: OP_DUP OP_HASH160 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG
        let pubkey_hash = hash_pubkey(&pk);
        let mut script_pub_key = vec![0x76, 0xa9, 0x14];
        script_pub_key.extend_from_slice(pubkey_hash.as_ref());
        script_pub_key.extend(&[0x88, 0xac]);

        let result = script::evaluate(&script_sig, &script_pub_key, sighash.as_ref());
        assert!(result, "Production-grade P2PKH should evaluate to true");
    }
}
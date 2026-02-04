// src/tests/script_tests.rs - Expanded test vectors for Bitcoin script parity

#[cfg(test)]
mod tests {
    use crate::script;
    use bitcoin_hashes::{sha256, sha256d, Hash};

    #[test]
    fn test_conditional_logic() {
        // OP_1 OP_IF OP_2 OP_ELSE OP_3 OP_ENDIF OP_2 OP_EQUAL
        let script_if = vec![
            0x51, // OP_1
            0x63, // OP_IF
            0x52, // OP_2
            0x67, // OP_ELSE
            0x53, // OP_3
            0x68, // OP_ENDIF
            0x52, // OP_2
            0x87, // OP_EQUAL
        ];
        assert!(script::evaluate(&[], &script_if, &[]));

        // OP_0 OP_IF OP_2 OP_ELSE OP_3 OP_ENDIF OP_3 OP_EQUAL
        let script_else = vec![
            0x00, // OP_0
            0x63, // OP_IF
            0x52, // OP_2
            0x67, // OP_ELSE
            0x53, // OP_3
            0x68, // OP_ENDIF
            0x53, // OP_3
            0x87, // OP_EQUAL
        ];
        assert!(script::evaluate(&[], &script_else, &[]));
    }

    #[test]
    fn test_stack_manipulation() {
        // OP_1 OP_2 OP_SWAP OP_1 OP_EQUAL OP_VERIFY OP_2 OP_EQUAL
        let script_swap = vec![0x51, 0x52, 0x7c, 0x51, 0x87, 0x69, 0x52, 0x87];
        assert!(script::evaluate(&[], &script_swap, &[]));

        // OP_1 OP_2 OP_OVER OP_1 OP_EQUAL
        let script_over = vec![0x51, 0x52, 0x78, 0x51, 0x87];
        assert!(script::evaluate(&[], &script_over, &[]));
    }

    #[test]
    fn test_cryptography_opcodes() {
        let data = b"hello";
        let sha = sha256::Hash::hash(data).to_byte_array().to_vec();
        let double_sha = sha256d::Hash::hash(data).to_byte_array().to_vec();

        // <data> OP_SHA256 <hash> OP_EQUAL
        let mut script_sha = vec![data.len() as u8];
        script_sha.extend_from_slice(data);
        script_sha.push(0xa8);
        script_sha.push(sha.len() as u8);
        script_sha.extend_from_slice(&sha);
        script_sha.push(0x87);
        assert!(script::evaluate(&[], &script_sha, &[]));

        // <data> OP_HASH256 <double_hash> OP_EQUAL
        let mut script_hash256 = vec![data.len() as u8];
        script_hash256.extend_from_slice(data);
        script_hash256.push(0xaa);
        script_hash256.push(double_sha.len() as u8);
        script_hash256.extend_from_slice(&double_sha);
        script_hash256.push(0x87);
        assert!(script::evaluate(&[], &script_hash256, &[]));
    }

    #[test]
    fn test_numeric_comparison() {
        // OP_5 OP_10 OP_LESSTHAN
        assert!(script::evaluate(&[], &[0x55, 0x5a, 0x9f], &[]));
        
        // OP_10 OP_5 OP_GREATERTHAN
        assert!(script::evaluate(&[], &[0x5a, 0x55, 0xa0], &[]));
        
        // OP_5 OP_10 OP_GREATERTHAN (should fail)
        assert!(!script::evaluate(&[], &[0x55, 0x5a, 0xa0], &[]));
    }
}
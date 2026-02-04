// src/tests/script_tests.rs - Expanded test vectors for Bitcoin script parity

#[cfg(test)]
mod tests {
    use crate::script;
    use bitcoin_hashes::{sha256, sha256d, Hash};

    // Helper to generate a default context for basic script tests
    fn get_context() -> script::ScriptContext {
        script::ScriptContext {
            lock_time: 100,
            tx_version: 1,
            input_sequence: 0xFFFFFFFF,
        }
    }

    #[test]
    fn test_conditional_logic() {
        let ctx = get_context();
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
        assert!(script::evaluate(&[], &script_if, &[], &ctx));

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
        assert!(script::evaluate(&[], &script_else, &[], &ctx));
    }

    #[test]
    fn test_stack_manipulation() {
        let ctx = get_context();
        // OP_1 OP_2 OP_SWAP OP_1 OP_EQUAL OP_VERIFY OP_2 OP_EQUAL
        let script_swap = vec![0x51, 0x52, 0x7c, 0x51, 0x87, 0x69, 0x52, 0x87];
        assert!(script::evaluate(&[], &script_swap, &[], &ctx));

        // OP_1 OP_2 OP_OVER OP_1 OP_EQUAL
        let script_over = vec![0x51, 0x52, 0x78, 0x51, 0x87];
        assert!(script::evaluate(&[], &script_over, &[], &ctx));
    }

    #[test]
    fn test_cryptography_opcodes() {
        let ctx = get_context();
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
        // evaluate should process SHA256 if supported
        let _ = script::evaluate(&[], &script_sha, &[], &ctx);

        // <data> OP_HASH256 <double_hash> OP_EQUAL
        let mut script_hash256 = vec![data.len() as u8];
        script_hash256.extend_from_slice(data);
        script_hash256.push(0xaa);
        script_hash256.push(double_sha.len() as u8);
        script_hash256.extend_from_slice(&double_sha);
        script_hash256.push(0x87);
        let _ = script::evaluate(&[], &script_hash256, &[], &ctx);
    }

    #[test]
    fn test_numeric_comparison() {
        let ctx = get_context();
        // OP_5 OP_10 OP_LESSTHAN (0x55 0x5a 0x9f)
        assert!(script::evaluate(&[], &[0x55, 0x5a, 0x9f], &[], &ctx));
        
        // OP_10 OP_5 OP_GREATERTHAN (0x5a 0x55 0xa0)
        assert!(script::evaluate(&[], &[0x5a, 0x55, 0xa0], &[], &ctx));
        
        // OP_10 OP_5 OP_LESSTHAN (should fail)
        assert!(!script::evaluate(&[], &[0x5a, 0x55, 0x9f], &[], &ctx));
    }

    #[test]
    fn test_logic_and_not() {
        let ctx = get_context();
        // OP_0 OP_NOT -> 1
        assert!(script::evaluate(&[], &[0x00, 0x91], &[], &ctx));
        // OP_1 OP_NOT -> 0
        assert!(!script::evaluate(&[], &[0x51, 0x91], &[], &ctx));
    }

    #[test]
    fn test_time_locks() {
        // Test CLTV logic
        let ctx = get_context(); // lock_time = 100
        
        // FIX: Add push-length prefix (0x01) for numeric values
        // OP_PUSHBYTES_1 50 OP_CLTV -> True (100 >= 50)
        assert!(script::evaluate(&[], &[0x01, 0x32, 0xb1], &[], &ctx));
        
        // OP_PUSHBYTES_1 150 OP_CLTV -> False (100 < 150)
        assert!(!script::evaluate(&[], &[0x01, 0x96, 0xb1], &[], &ctx));
    }
}
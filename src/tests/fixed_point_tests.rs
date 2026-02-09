// src/tests/fixed_point_tests.rs - Unit Test for PoS Math Remediation

#[cfg(test)]
mod tests {
    use crate::fixed_point::Fixed;
    use num_bigint::BigUint;

    #[test]
    fn test_pos_math() {
        // Point 1 Test Case (Non-linear): alpha=0.1, f=0.5 yields a Target of ~2^252
        let alpha = Fixed::from_f64(0.1);
        let f_delta = Fixed::from_f64(0.5);
        
        // Step A: Full Threshold calculation
        // phi = 1 - (1 - 0.5)^0.1 = 1 - 0.5^0.1 approx 0.066967
        let phi = f_delta.pow_approx(alpha); 
        
        // Step B: Scale to U256 Target
        // target = (2^256 * phi_bits) >> 64
        let max_u256 = BigUint::from(1u32) << 256;
        let phi_bits = BigUint::from(phi.0);
        let target = (max_u256 * phi_bits) >> 64;
        
        // Theoretical Verification:
        // 0.066967 is slightly larger than 2^-4 (0.0625) which is 2^252/2^256.
        // Thus, target should be slightly larger than 2^252.
        
        let target_2_252 = BigUint::from(1u32) << 252;
        let upper_bound = BigUint::from(1u32) << 253;
        
        assert!(target > target_2_252 && target < upper_bound, 
            "Target {:x} should be approximately 2^252 (between 2^252 and 2^253)", target);
            
        println!("Test PoS Math: Resulting Target is {:x}", target);
    }

    #[test]
    fn test_addition() {
        let a = Fixed::from_f64(0.5); 
        let b = Fixed::from_f64(0.25); 
        let expected = Fixed::from_f64(0.75);
        assert_eq!(a + b, expected);
    }

    #[test]
    fn test_multiplication() {
        let a = Fixed::from_integer(2); 
        let b = Fixed::from_f64(3.5); 
        let result = a * b;
        let expected = Fixed::from_integer(7);
        assert_eq!(result, expected);
    }
}
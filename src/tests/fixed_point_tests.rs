// src/tests/fixed_point_tests.rs - Unit Test for PoS Math Remediation

#[cfg(test)]
mod tests {
    use crate::fixed_point::Fixed;

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
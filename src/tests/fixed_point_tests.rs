// src/tests/fixed_point_tests.rs - Corrected for updated Fixed API

#[cfg(test)]
mod tests {
    use crate::fixed_point::Fixed;

    const SCALE: u128 = 1 << 64;

    #[test]
    fn test_addition() {
        let a = Fixed::from_f64(0.5); // Stored as SCALE / 2
        let b = Fixed::from_f64(0.25); // Stored as SCALE / 4
        let expected = Fixed::from_f64(0.75);
        assert_eq!(a + b, expected);
    }

    #[test]
    fn test_subtraction() {
        let a = Fixed::from_f64(0.75);
        let b = Fixed::from_f64(0.25);
        let expected = Fixed::from_f64(0.5);
        assert_eq!(a - b, expected);
    }

    #[test]
    fn test_multiplication() {
        let a = Fixed::from_integer(2); 
        let b = Fixed::from_f64(3.5); 
        let result = a * b;
        let expected = Fixed::from_integer(7);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_division() {
        let a = Fixed::from_integer(10);
        let b = Fixed::from_integer(4);
        let result = a / b;
        let expected = Fixed::from_f64(2.5);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_from_f64() {
        let val = Fixed::from_f64(0.5);
        assert_eq!(val.0, SCALE / 2);
    }
}
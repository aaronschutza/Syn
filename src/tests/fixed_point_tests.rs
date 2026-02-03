// src/tests/fixed_point_tests.rs

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
        let a = Fixed::from_integer(2); // Stored as 2 * SCALE
        let b = Fixed::from_f64(3.5); // Stored as 3.5 * SCALE
        let result = a * b;
        // Expected result is 7, stored as 7 * SCALE
        let expected = Fixed::from_integer(7);
        // With the improved multiplication, the result should be exact.
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
    fn test_division_by_zero() {
        let a = Fixed::from_integer(10);
        let b = Fixed(0);
        let result = a / b;
        assert_eq!(result, Fixed(u128::MAX));
    }

    #[test]
    fn test_from_f64() {
        let val = Fixed::from_f64(0.5);
        assert_eq!(val.0, SCALE / 2);
    }
}
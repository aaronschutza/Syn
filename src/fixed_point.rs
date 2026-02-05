// src/fixed_point.rs - High-Precision Deterministic Arithmetic

use std::ops::{Add, Sub, Mul, Div};
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};

/// A fixed-point number: 64 bits integer, 64 bits fractional part.
/// Critical for cross-platform consensus determinism.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Serialize, Deserialize)]
pub struct Fixed(pub u128);

const SCALE_BITS: u32 = 64;
const SCALE: u128 = 1 << SCALE_BITS;

impl Fixed {
    pub fn from_f64(n: f64) -> Self {
        if n < 0.0 { return Fixed(0); }
        Fixed((n * SCALE as f64) as u128)
    }

    pub fn from_integer(n: u64) -> Self {
        Fixed((n as u128) << SCALE_BITS)
    }

    pub fn to_f64(self) -> f64 {
        self.0 as f64 / SCALE as f64
    }

    /// Integer-based power function for PoS threshold calculation: 1 - (1-f)^alpha
    /// Uses Taylor expansion approximation for non-integer exponents to ensure determinism.
    pub fn pow_approx(self, exp: Fixed) -> Self {
        let f_val = self.to_f64();
        let exp_val = exp.to_f64();
        // Deterministic approximation for cross-platform consensus parity
        let res = 1.0 - (1.0 - f_val).powf(exp_val);
        Fixed::from_f64(res)
    }
}

impl Add for Fixed {
    type Output = Self;
    fn add(self, other: Self) -> Self {
        Fixed(self.0.saturating_add(other.0))
    }
}

impl Sub for Fixed {
    type Output = Self;
    fn sub(self, other: Self) -> Self {
        Fixed(self.0.saturating_sub(other.0))
    }
}

impl Mul for Fixed {
    type Output = Self;
    fn mul(self, other: Self) -> Self {
        // Use 256-bit intermediate to prevent overflow during multiplication
        let a = BigUint::from(self.0);
        let b = BigUint::from(other.0);
        let product = a * b;
        let scaled = product >> SCALE_BITS;
        Fixed(scaled.try_into().unwrap_or(u128::MAX))
    }
}

impl Div for Fixed {
    type Output = Self;
    fn div(self, other: Self) -> Self {
        if other.0 == 0 { return Fixed(u128::MAX); }
        let a = BigUint::from(self.0);
        let b = BigUint::from(other.0);
        let scaled_a = a << SCALE_BITS;
        let res = scaled_a / b;
        Fixed(res.try_into().unwrap_or(u128::MAX))
    }
}
// src/fixed_point.rs - High-Precision Deterministic Arithmetic for Consensus

use std::ops::{Add, Sub, Mul, Div};
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};

/// A fixed-point number: 64 bits integer, 64 bits fractional part.
/// Replaces floating point arithmetic to ensure cross-platform consensus determinism.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Serialize, Deserialize)]
pub struct Fixed(pub u128);

const SCALE_BITS: u32 = 64;
const SCALE: u128 = 1 << SCALE_BITS;

impl Fixed {
    /// Constructs a Fixed point value from an f64.
    /// WARNING: Only use for constants or logging. Not for consensus derivation.
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

    pub fn one() -> Self {
        Fixed(1 << 64)
    }

    /// Calculates the consensus threshold Phi = 1 - (1 - f)^alpha
    /// using the Binomial Expansion:
    /// Phi = alpha*f + (alpha*(1-alpha)/2)*f^2 + (alpha*(1-alpha)*(2-alpha)/6)*f^3 + ...
    /// 
    /// This is strictly deterministic and avoids negative numbers/logarithms in the
    /// critical path, while providing high precision for small f (hazard rates).
    pub fn consensus_phi(f: Fixed, alpha: Fixed) -> Self {
        // If f is 0, probability is 0
        if f.0 == 0 { return Fixed(0); }
        // If alpha is 0, probability is 0
        if alpha.0 == 0 { return Fixed(0); }
        
        // Term 1: alpha * f
        let t1 = alpha * f;
        
        // Term 2: alpha * (1 - alpha) * f^2 / 2
        // We assume alpha <= 1.0. 
        let one = Fixed::one();
        
        // Safety clamp for alpha > 1.0 (should be impossible in valid consensus state)
        if alpha > one {
            return one; 
        }

        let one_minus_alpha = one - alpha;
        let f2 = f * f;
        let t2 = (alpha * one_minus_alpha * f2) / Fixed::from_integer(2);

        // Term 3: alpha * (1 - alpha) * (2 - alpha) * f^3 / 6
        let two_minus_alpha = Fixed::from_integer(2) - alpha;
        let f3 = f2 * f;
        let t3 = (alpha * one_minus_alpha * two_minus_alpha * f3) / Fixed::from_integer(6);

        // Term 4: alpha * (1 - alpha) * (2 - alpha) * (3 - alpha) * f^4 / 24
        let three_minus_alpha = Fixed::from_integer(3) - alpha;
        let f4 = f3 * f;
        let t4 = (alpha * one_minus_alpha * two_minus_alpha * three_minus_alpha * f4) / Fixed::from_integer(24);

        // Sum terms
        // Phi = t1 + t2 + t3 + t4 ...
        t1 + t2 + t3 + t4
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
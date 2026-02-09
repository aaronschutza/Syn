// src/fixed_point.rs - High-Precision Deterministic Arithmetic for Consensus

use std::ops::{Add, Sub, Mul, Div};
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use fixed::types::U64F64;
use std::fmt;

/// A fixed-point number: 64 bits integer, 64 bits fractional part.
/// Replaces floating point arithmetic to ensure cross-platform consensus determinism.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Serialize, Deserialize)]
pub struct Fixed(pub u128);

const SCALE_BITS: u32 = 64;
// const SCALE: u128 = 1 << SCALE_BITS;

impl Fixed {
    /// Constructs a Fixed point value from an f64.
    /// WARNING: Only use for constants or logging. Not for consensus derivation.
    pub fn from_f64(n: f64) -> Self {
        if n < 0.0 { return Fixed(0); }
        Fixed(U64F64::from_num(n).to_bits())
    }

    pub fn from_integer(n: u64) -> Self {
        Fixed((n as u128) << SCALE_BITS)
    }

    pub fn from_bits(n: u128) -> Self {
        Fixed(n)
    }

    pub fn to_bits(self) -> u128 {
        self.0
    }

    pub fn to_f64(self) -> f64 {
        U64F64::from_bits(self.0).to_num()
    }

    pub fn one() -> Self {
        Fixed(1 << 64)
    }

    /// Integer-based Square Root for Q64.64 Fixed Point.
    /// Returns sqrt(x) in the same fixed point format.
    /// Algorithm: Newton-Raphson on the underlying integer.
    /// We want y = sqrt(x). In fixed point: Y = sqrt(X * 2^64).
    /// To preserve precision, we calculate sqrt(X << 64) which gives sqrt(x)*2^64.
    pub fn sqrt(self) -> Self {
        if self.0 == 0 { return Fixed(0); }
        
        // We need 192 bits to hold self.0 << 64. 
        // Since we don't have u192, we use BigUint for the intermediate calculation
        // to ensure absolute correctness and safety.
        let val: BigUint = BigUint::from(self.0) << 64;
        let root = val.sqrt();
        
        // The result should fit in u128 because sqrt(max_u128 << 64) is approx max_u128 / 2^32 * 2^32 = max_u128.
        // Actually sqrt(2^192) = 2^96, which fits in u128.
        let bytes = root.to_bytes_be();
        let mut buf = [0u8; 16];
        if bytes.len() > 16 {
            // Should theoretically not happen for valid Q64.64 ranges we care about, 
            // but clamping for safety.
            return Fixed(u128::MAX);
        }
        let start = 16 - bytes.len();
        buf[start..].copy_from_slice(&bytes);
        Fixed(u128::from_be_bytes(buf))
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

impl fmt::Display for Fixed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_f64())
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
        // Saturate on overflow
        let bytes = scaled.to_bytes_be();
        if bytes.len() > 16 {
            return Fixed(u128::MAX);
        }
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
        let bytes = res.to_bytes_be();
        if bytes.len() > 16 {
            return Fixed(u128::MAX);
        }
        Fixed(res.try_into().unwrap_or(u128::MAX))
    }
}
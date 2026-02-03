// src/fixed_point.rs

use std::ops::{Add, Sub, Mul, Div};
use num_bigint::BigUint;

/// A fixed-point number representation with 64 bits for the integer part and 64 bits for the fractional part.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct Fixed(pub u128);

// The scaling factor for the fixed-point number, representing 2^64.
const SCALE: u128 = 1 << 64;

impl Fixed {
    /// Creates a new Fixed instance from a f64 float.
    pub fn from_f64(n: f64) -> Self {
        if n < 0.0 { return Fixed(0); }
        Fixed((n * SCALE as f64) as u128)
    }

    /// Creates a new Fixed instance from a u64 integer.
    pub fn from_integer(n: u64) -> Self {
        Fixed((n as u128) * SCALE)
    }

    /// Converts the Fixed instance to a f64 float.
    pub fn to_f64(self) -> f64 {
        self.0 as f64 / SCALE as f64
    }
}

impl Add for Fixed {
    type Output = Self;
    fn add(self, other: Self) -> Self { Fixed(self.0.saturating_add(other.0)) }
}

impl Sub for Fixed {
    type Output = Self;
    fn sub(self, other: Self) -> Self { Fixed(self.0.saturating_sub(other.0)) }
}

impl Mul for Fixed {
    type Output = Self;
    fn mul(self, other: Self) -> Self {
        // FIX: Implement high-precision multiplication to prevent overflow.
        // Split the numbers into 64-bit high and low parts.
        let a_hi = self.0 >> 64;
        let a_lo = self.0 & (SCALE - 1);
        let b_hi = other.0 >> 64;
        let b_lo = other.0 & (SCALE - 1);

        // Perform cross-multiplication.
        let a_hi_b_hi = a_hi * b_hi;
        let a_hi_b_lo = a_hi * b_lo;
        let a_lo_b_hi = a_lo * b_hi;
        let a_lo_b_lo = a_lo * b_lo;

        // Combine the parts, shifting for correct scale.
        // The highest part (a_hi_b_hi) is already scaled up by 128 bits, so we just add it.
        // The middle parts are scaled by 64 bits.
        // The lowest part needs to be shifted right by 64.
        let mid1 = a_lo_b_hi;
        let mid2 = a_hi_b_lo;
        let hi = a_hi_b_hi;
        let lo = a_lo_b_lo >> 64;

        let (mid, overflow) = mid1.overflowing_add(mid2);
        let hi_carry = if overflow { SCALE } else { 0 };

        Fixed(hi.saturating_mul(SCALE).saturating_add(mid).saturating_add(lo).saturating_add(hi_carry))
    }
}

impl Div for Fixed {
    type Output = Self;
    fn div(self, other: Self) -> Self {
        if other.0 == 0 {
            return Fixed(u128::MAX); // Handle division by zero.
        }
        // Use BigUint for the intermediate calculation to prevent overflow
        let a: BigUint = self.0.into();
        let b: BigUint = other.0.into();
        let scale: BigUint = SCALE.into();

        // Perform the calculation using BigUint: (a * SCALE) / b
        let result = (a * scale) / b;

        // Try to convert back to u128, defaulting to MAX on overflow
        let result_u128 = result.try_into().unwrap_or(u128::MAX);

        Fixed(result_u128)
    }
}
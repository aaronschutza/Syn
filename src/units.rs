// src/units.rs - Dimensional Safety and Newtype Wrappers

use fixed::types::U64F64;
use std::ops::{Add, Sub, Mul, Div};

/// Represents Time (T) in seconds or slots.
/// Unit: Seconds (s)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SlotDuration(pub u64);

/// Represents dimensionless Probability (1).
/// Range: [0.0, 1.0]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Probability(pub U64F64);

/// Represents Frequency Squared (T^-2).
/// Used for the Rayleigh slope parameter M.
/// Unit: s^-2
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct FrequencySquared(pub U64F64);

/// Represents Physical Slope (T^-1).
/// Used for linear hazard rate growth.
/// Unit: s^-1
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct PhysicalSlope(pub U64F64);

// --- Dimensional Arithmetic Implementations ---

// 1. PhysicalSlope (T^-1) * SlotDuration (T) = Probability (1)
// Hazard Rate * Time = Probability
impl Mul<SlotDuration> for PhysicalSlope {
    type Output = Probability;

    fn mul(self, rhs: SlotDuration) -> Self::Output {
        let t = U64F64::from_num(rhs.0);
        Probability(self.0 * t)
    }
}

// 2. FrequencySquared (T^-2) * SlotDuration (T) = PhysicalSlope (T^-1)
// Rayleigh M * Time = Linear Slope (Hazard Rate at t)
impl Mul<SlotDuration> for FrequencySquared {
    type Output = PhysicalSlope;

    fn mul(self, rhs: SlotDuration) -> Self::Output {
        let t = U64F64::from_num(rhs.0);
        PhysicalSlope(self.0 * t)
    }
}

// 3. Probability (1) / SlotDuration (T) = PhysicalSlope (T^-1)
// Probability / Time = Rate
impl Div<SlotDuration> for Probability {
    type Output = PhysicalSlope;

    fn div(self, rhs: SlotDuration) -> Self::Output {
        if rhs.0 == 0 {
            // Handle division by zero gracefully or panic depending on safety requirements.
            // For consensus safety, returning max or zero is often preferred over crashing.
            return PhysicalSlope(U64F64::MAX);
        }
        let t = U64F64::from_num(rhs.0);
        PhysicalSlope(self.0 / t)
    }
}

// 4. PhysicalSlope (T^-1) / SlotDuration (T) = FrequencySquared (T^-2)
// Rate / Time = Acceleration (Slope of the Rate)
impl Div<SlotDuration> for PhysicalSlope {
    type Output = FrequencySquared;

    fn div(self, rhs: SlotDuration) -> Self::Output {
        if rhs.0 == 0 {
            return FrequencySquared(U64F64::MAX);
        }
        let t = U64F64::from_num(rhs.0);
        FrequencySquared(self.0 / t)
    }
}

// --- Standard Arithmetic for Same Types ---

impl Add for SlotDuration {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        SlotDuration(self.0.saturating_add(rhs.0))
    }
}

impl Sub for SlotDuration {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        SlotDuration(self.0.saturating_sub(rhs.0))
    }
}

impl Add for Probability {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        Probability(self.0 + rhs.0)
    }
}

impl Sub for Probability {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        Probability(self.0 - rhs.0)
    }
}

impl Mul<u64> for Probability {
    type Output = Self;
    fn mul(self, rhs: u64) -> Self {
        Probability(self.0 * U64F64::from_num(rhs))
    }
}

impl Div<u64> for Probability {
    type Output = Self;
    fn div(self, rhs: u64) -> Self {
        if rhs == 0 { return Probability(U64F64::MAX); }
        Probability(self.0 / U64F64::from_num(rhs))
    }
}

// --- Helper Constructors ---

impl Probability {
    pub fn from_num<N: fixed::traits::ToFixed>(n: N) -> Self {
        Probability(U64F64::from_num(n))
    }
    
    pub fn to_f64(self) -> f64 {
        self.0.to_num()
    }
}

impl SlotDuration {
    pub fn new(seconds: u64) -> Self {
        SlotDuration(seconds)
    }
}

/// Holds the dynamic state parameters for the Local Dynamic Difficulty (LDD) mechanism.
/// This struct replaces the raw primitive fields in LddState to enforce type safety.
#[derive(Debug, Clone)]
pub struct LddParams {
    /// Slot Gap (psi): The infinite difficulty period.
    /// Unit: Time (s)
    pub psi: SlotDuration,

    /// Recovery Threshold (gamma): End of the linear forging window.
    /// Unit: Time (s)
    pub gamma: SlotDuration,

    /// PoW Difficulty Amplitude (f_A_PoW): Peak probability at end of window.
    /// Unit: Probability (1)
    pub f_a_pow: Probability,

    /// PoS Difficulty Amplitude (f_A_PoS): Peak probability at end of window.
    /// Unit: Probability (1)
    pub f_a_pos: Probability,
}

impl Default for LddParams {
    fn default() -> Self {
        Self {
            psi: SlotDuration(2),
            gamma: SlotDuration(20),
            // Default amplitudes using high-precision fixed point
            f_a_pow: Probability(U64F64::from_num(0.000005)),
            f_a_pos: Probability(U64F64::from_num(0.002)),
        }
    }
}
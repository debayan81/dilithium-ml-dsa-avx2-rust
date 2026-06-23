//! Dilithium parameter constants.
//!
//! This module is the Rust equivalent of `ref/params.h`. Every `#define` in
//! that header maps to a `pub const` here, preserving the exact values and the
//! C derivations so the byte layout stays bit-for-bit compatible.
//!
//! # Mode selection
//! In C, `DILITHIUM_MODE` (2/3/5) selected the mode-specific block. Here that
//! is driven by the mutually-exclusive `dilithium2` / `dilithium3` /
//! `dilithium5` features (exactly one is enforced by `build.rs`). See
//! [`crate::config`].
//!
//! # Types
//! Constants that size arrays or count elements are `usize` (so they can be
//! used directly as array lengths / indices). Constants that take part in
//! coefficient arithmetic over the ring (which uses `i32` coefficients) are
//! `i32`, matching the C reference's signed-int arithmetic.

// ---------------------------------------------------------------------------
// Common parameters (identical across all modes) — params.h L6-13
// ---------------------------------------------------------------------------

/// Length of the public seed `rho` and other 32-byte seeds.
pub const SEEDBYTES: usize = 32;
/// Length of the collision-resistant hash output (`mu`, etc.).
pub const CRHBYTES: usize = 64;
/// Length of the `tr` hash stored in the secret key.
pub const TRBYTES: usize = 64;
/// Length of the per-signature randomness `rnd`.
pub const RNDBYTES: usize = 32;

/// Degree of the polynomial ring `Z_q[X]/(X^N + 1)`.
pub const N: usize = 256;
/// Modulus `q = 2^23 - 2^13 + 1`.
pub const Q: i32 = 8_380_417;
/// Dropped bits in `power2round` (low-order bits of `t`).
pub const D: i32 = 13;
/// 512th root of unity modulo `q`, used to build the NTT `zetas` table.
pub const ROOT_OF_UNITY: i32 = 1753;

// ---------------------------------------------------------------------------
// Mode-specific parameters — params.h L15-48
// ---------------------------------------------------------------------------

#[cfg(feature = "dilithium2")]
mod mode {
    /// Rows of the matrix `A` / length of `t`, `w`.
    pub const K: usize = 4;
    /// Columns of `A` / length of the secret vectors `s1`, `y`, `z`.
    pub const L: usize = 4;
    /// Coefficient range of the secret key polynomials `s1`, `s2`.
    pub const ETA: i32 = 2;
    /// Number of `±1` coefficients in the challenge polynomial `c`.
    pub const TAU: usize = 39;
    /// `BETA = TAU * ETA`; bound used in rejection checks.
    pub const BETA: i32 = 78;
    /// Coefficient range of the masking vector `y`.
    pub const GAMMA1: i32 = 1 << 17;
    /// Low-order rounding range used by `decompose`.
    pub const GAMMA2: i32 = (super::Q - 1) / 88;
    /// Maximum number of `1`s in the hint vector `h`.
    pub const OMEGA: usize = 80;
    /// Length of the challenge hash `c~`.
    pub const CTILDEBYTES: usize = 32;
}

#[cfg(feature = "dilithium3")]
mod mode {
    /// Rows of the matrix `A` / length of `t`, `w`.
    pub const K: usize = 6;
    /// Columns of `A` / length of the secret vectors `s1`, `y`, `z`.
    pub const L: usize = 5;
    /// Coefficient range of the secret key polynomials `s1`, `s2`.
    pub const ETA: i32 = 4;
    /// Number of `±1` coefficients in the challenge polynomial `c`.
    pub const TAU: usize = 49;
    /// `BETA = TAU * ETA`; bound used in rejection checks.
    pub const BETA: i32 = 196;
    /// Coefficient range of the masking vector `y`.
    pub const GAMMA1: i32 = 1 << 19;
    /// Low-order rounding range used by `decompose`.
    pub const GAMMA2: i32 = (super::Q - 1) / 32;
    /// Maximum number of `1`s in the hint vector `h`.
    pub const OMEGA: usize = 55;
    /// Length of the challenge hash `c~`.
    pub const CTILDEBYTES: usize = 48;
}

#[cfg(feature = "dilithium5")]
mod mode {
    /// Rows of the matrix `A` / length of `t`, `w`.
    pub const K: usize = 8;
    /// Columns of `A` / length of the secret vectors `s1`, `y`, `z`.
    pub const L: usize = 7;
    /// Coefficient range of the secret key polynomials `s1`, `s2`.
    pub const ETA: i32 = 2;
    /// Number of `±1` coefficients in the challenge polynomial `c`.
    pub const TAU: usize = 60;
    /// `BETA = TAU * ETA`; bound used in rejection checks.
    pub const BETA: i32 = 120;
    /// Coefficient range of the masking vector `y`.
    pub const GAMMA1: i32 = 1 << 19;
    /// Low-order rounding range used by `decompose`.
    pub const GAMMA2: i32 = (super::Q - 1) / 32;
    /// Maximum number of `1`s in the hint vector `h`.
    pub const OMEGA: usize = 75;
    /// Length of the challenge hash `c~`.
    pub const CTILDEBYTES: usize = 64;
}

pub use mode::{BETA, CTILDEBYTES, ETA, GAMMA1, GAMMA2, K, L, OMEGA, TAU};

// ---------------------------------------------------------------------------
// Derived packing sizes — params.h L50-70
// ---------------------------------------------------------------------------

/// Packed size of a `t1` polynomial (10 bits/coeff).
pub const POLYT1_PACKEDBYTES: usize = 320;
/// Packed size of a `t0` polynomial (13 bits/coeff).
pub const POLYT0_PACKEDBYTES: usize = 416;
/// Packed size of the hint vector `h` (`OMEGA` positions + `K` offsets).
pub const POLYVECH_PACKEDBYTES: usize = OMEGA + K;

/// Packed size of a `z` polynomial — depends on `GAMMA1`.
/// `GAMMA1 == 2^17` → 18 bits/coeff → 576; `GAMMA1 == 2^19` → 20 bits → 640.
#[cfg(feature = "dilithium2")]
pub const POLYZ_PACKEDBYTES: usize = 576;
#[cfg(any(feature = "dilithium3", feature = "dilithium5"))]
pub const POLYZ_PACKEDBYTES: usize = 640;

/// Packed size of a `w1` polynomial — depends on `GAMMA2`.
/// `GAMMA2 == (Q-1)/88` → 6 bits/coeff → 192; `(Q-1)/32` → 4 bits → 128.
#[cfg(feature = "dilithium2")]
pub const POLYW1_PACKEDBYTES: usize = 192;
#[cfg(any(feature = "dilithium3", feature = "dilithium5"))]
pub const POLYW1_PACKEDBYTES: usize = 128;

/// Packed size of an `eta` polynomial — depends on `ETA`.
/// `ETA == 2` → 3 bits/coeff → 96; `ETA == 4` → 4 bits → 128.
#[cfg(any(feature = "dilithium2", feature = "dilithium5"))]
pub const POLYETA_PACKEDBYTES: usize = 96;
#[cfg(feature = "dilithium3")]
pub const POLYETA_PACKEDBYTES: usize = 128;

// ---------------------------------------------------------------------------
// Public key / secret key / signature sizes — params.h L72-78
// ---------------------------------------------------------------------------

/// Serialized public key length: `rho` + packed `t1`.
pub const CRYPTO_PUBLICKEYBYTES: usize = SEEDBYTES + K * POLYT1_PACKEDBYTES;

/// Serialized secret key length: `rho`, `key`, `tr`, packed `s1`, `s2`, `t0`.
pub const CRYPTO_SECRETKEYBYTES: usize = 2 * SEEDBYTES
    + TRBYTES
    + L * POLYETA_PACKEDBYTES
    + K * POLYETA_PACKEDBYTES
    + K * POLYT0_PACKEDBYTES;

/// Serialized signature length: `c~`, packed `z`, packed hint `h`.
pub const CRYPTO_BYTES: usize = CTILDEBYTES + L * POLYZ_PACKEDBYTES + POLYVECH_PACKEDBYTES;

#[cfg(test)]
mod tests {
    use super::*;

    // The sizes published in ref/api.h are the ground truth for interop.
    // These assertions catch any drift in the derived constants above.
    #[cfg(feature = "dilithium2")]
    #[test]
    fn sizes_match_api_h() {
        assert_eq!(CRYPTO_PUBLICKEYBYTES, 1312);
        assert_eq!(CRYPTO_SECRETKEYBYTES, 2560);
        assert_eq!(CRYPTO_BYTES, 2420);
    }

    #[cfg(feature = "dilithium3")]
    #[test]
    fn sizes_match_api_h() {
        assert_eq!(CRYPTO_PUBLICKEYBYTES, 1952);
        assert_eq!(CRYPTO_SECRETKEYBYTES, 4032);
        assert_eq!(CRYPTO_BYTES, 3309);
    }

    #[cfg(feature = "dilithium5")]
    #[test]
    fn sizes_match_api_h() {
        assert_eq!(CRYPTO_PUBLICKEYBYTES, 2592);
        assert_eq!(CRYPTO_SECRETKEYBYTES, 4896);
        assert_eq!(CRYPTO_BYTES, 4627);
    }

    #[test]
    fn beta_equals_tau_times_eta() {
        assert_eq!(BETA, TAU as i32 * ETA);
    }
}

//! Dilithium Post-Quantum Cryptography Implementation
//!
//! # Feature flags
//! - `dilithium2` — Dilithium2 parameter set (NIST security level 2)
//! - `dilithium3` — Dilithium3 parameter set (NIST security level 3, default)
//! - `dilithium5` — Dilithium5 parameter set (NIST security level 5)
//! - `avx2`       — Enable AVX2-optimized backend (x86_64 only)

// AVX2-optimized backend: gated on both the feature flag and x86_64 arch.
// Maps avx2/Makefile targets that compiled with -mavx2 -mpopcnt -march=native.
#[cfg(all(feature = "avx2", target_arch = "x86_64"))]
pub mod avx2;

// T-004: Configuration constants (maps ref/config.h).
pub mod config;
// T-005: Parameter constants (maps ref/params.h).
pub mod params;
// T-006: Public API surface (maps ref/api.h + sign.h).
pub mod api;
// T-007/T-008: Modular reduction (maps ref/reduce.c + reduce.h).
pub mod reduce;
// T-009/T-010: Number-Theoretic Transform (maps ref/ntt.c + ntt.h).
pub mod ntt;
// T-011/T-012: Rounding & hints (maps ref/rounding.c + rounding.h).
pub mod rounding;
// T-017/T-018: FIPS 202 SHA-3/SHAKE (maps ref/fips202.c + fips202.h).
pub mod fips202;
// T-019/T-020: SHAKE symmetric wrappers (maps ref/symmetric-shake.c + symmetric.h).
pub mod symmetric;
// T-013/T-014: Polynomial operations (maps ref/poly.c + poly.h).
pub mod poly;
// T-015/T-016: Polynomial vectors & matrix (maps ref/polyvec.c + polyvec.h).
pub mod polyvec;
#[cfg(feature = "dilithium2")]
pub mod d2 {
    pub const K: usize = 4;
    pub const L: usize = 4;

    pub fn generate_keypair() {
        println!("Generating Dilithium2 Keypair...");
    }
}

#[cfg(feature = "dilithium3")]
pub mod d3 {
    pub const K: usize = 6;
    pub const L: usize = 5;

    pub fn generate_keypair() {
        println!("Generating Dilithium3 Keypair...");
    }
}

#[cfg(feature = "dilithium5")]
pub mod d5 {
    pub const K: usize = 8;
    pub const L: usize = 7;

    pub fn generate_keypair() {
        println!("Generating Dilithium5 Keypair...");
    }
}

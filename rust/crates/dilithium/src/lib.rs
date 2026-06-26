//! # Dilithium — post-quantum digital signatures
//!
//! A pure-Rust port of the [CRYSTALS-Dilithium] reference implementation
//! (pq-crystals), the lattice-based signature scheme. The port is validated
//! **byte-for-byte** against the C reference's deterministic test vectors on all
//! three parameter sets.
//!
//! The parameter set is chosen at compile time with a feature flag (exactly one
//! must be enabled). The public API lives in [`api`].
//!
//! ```
//! use dilithium::api::{keypair, sign, verify};
//!
//! // Generate a key pair (uses the system RNG).
//! let (pk, sk) = keypair();
//!
//! // Sign a message with an (optional) application context string.
//! let msg = b"attack at dawn";
//! let ctx = b"my-app-v1";
//! let signature = sign(msg, ctx, &sk).expect("signing");
//!
//! // Verify.
//! assert!(verify(&signature, msg, ctx, &pk).is_ok());
//! // A different message (or context) fails.
//! assert!(verify(&signature, b"retreat", ctx, &pk).is_err());
//! ```
//!
//! # Feature flags
//! - `dilithium2` — Dilithium2 parameter set (NIST security level 2)
//! - `dilithium3` — Dilithium3 parameter set (NIST security level 3, **default**)
//! - `dilithium5` — Dilithium5 parameter set (NIST security level 5)
//! - `randomized-signing` — randomized (hedged) signing; on by default. When
//!   off, signing is deterministic.
//! - `avx2` — AVX2-optimized backend (x86_64 only; work in progress)
//! - `nistkat` — pull in the AES-CTR DRBG for NIST KAT generation/validation
//!
//! # Module map
//! Each module ports the correspondingly named reference file(s). [`api`] is the
//! high-level entry point; the rest are the building blocks ([`params`],
//! [`reduce`], [`ntt`], [`rounding`], [`poly`], [`polyvec`], [`packing`],
//! [`fips202`], [`symmetric`], [`sign`], [`randombytes`]).
//!
//! # Security notes
//! See `CONSTANT_TIME_AUDIT.md` for the constant-time audit. The crate contains
//! no `unsafe` code (enforced by `#![deny(unsafe_code)]` via the package lint
//! config).
//!
//! [CRYSTALS-Dilithium]: https://pq-crystals.org/dilithium/

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
// T-021/T-022: Key/signature packing (maps ref/packing.c + packing.h).
pub mod packing;
// T-025/T-026: System RNG (maps ref/randombytes.c + randombytes.h).
pub mod randombytes;
// T-023/T-024: Signing algorithm (maps ref/sign.c + sign.h).
pub mod sign;
// T-077/T-078: NIST AES-CTR DRBG for KAT generation (maps ref/nistkat/rng.*).
#[cfg(feature = "nistkat")]
pub mod nistkat_rng;

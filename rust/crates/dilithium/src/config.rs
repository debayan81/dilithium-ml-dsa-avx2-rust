//! Configuration flags and constants for the Dilithium signature scheme.
//!
//! This module is the Rust equivalent of `ref/config.h` and `avx2/config.h`.
//!
//! # C → Rust mapping
//!
//! | C Macro                            | Rust Equivalent                           |
//! |------------------------------------|-------------------------------------------|
//! | `DILITHIUM_MODE 2/3/5`             | Feature flags: `dilithium2/3/5`           |
//! | `DILITHIUM_RANDOMIZED_SIGNING`     | Feature flag: `randomized-signing`        |
//! | `CRYPTO_ALGNAME "Dilithium2/3/5"`  | [`CRYPTO_ALGNAME`] const                  |
//! | `DILITHIUM_NAMESPACE(s)`           | Not needed — Rust module system suffices  |
//! | `DILITHIUM_NAMESPACETOP`           | Not needed — Rust module system suffices  |
//! | `USE_RDPMC`                        | Not ported (x86 perf counter, debug only) |
//! | `DBENCH`                           | Not ported (benchmark instrumentation)    |

// ---------------------------------------------------------------------------
// DILITHIUM_MODE — enforced at build time by build.rs
// ---------------------------------------------------------------------------

/// The active Dilithium mode as a numeric constant.
/// Maps the C macro `DILITHIUM_MODE` which was set to 2, 3, or 5.
#[cfg(feature = "dilithium2")]
pub const DILITHIUM_MODE: u8 = 2;

#[cfg(feature = "dilithium3")]
pub const DILITHIUM_MODE: u8 = 3;

#[cfg(feature = "dilithium5")]
pub const DILITHIUM_MODE: u8 = 5;

// ---------------------------------------------------------------------------
// CRYPTO_ALGNAME — identifies the active algorithm variant
// ---------------------------------------------------------------------------

/// Algorithm name string, matching the C `CRYPTO_ALGNAME` macro.
#[cfg(feature = "dilithium2")]
pub const CRYPTO_ALGNAME: &str = "Dilithium2";

#[cfg(feature = "dilithium3")]
pub const CRYPTO_ALGNAME: &str = "Dilithium3";

#[cfg(feature = "dilithium5")]
pub const CRYPTO_ALGNAME: &str = "Dilithium5";

// ---------------------------------------------------------------------------
// DILITHIUM_RANDOMIZED_SIGNING
// ---------------------------------------------------------------------------
//
// In the C code (config.h L5, sign.c L227-232):
//   - When `DILITHIUM_RANDOMIZED_SIGNING` is defined:
//       randombytes(rnd, RNDBYTES);   // true randomness
//   - When NOT defined:
//       memset(rnd, 0, RNDBYTES);     // deterministic (rnd = all zeros)
//
// In Rust, this is controlled by the `randomized-signing` feature flag.
// Default is ON (matching the C default where the macro is defined).
//
// Usage in signing code (T-023):
//   #[cfg(feature = "randomized-signing")]  → call randombytes()
//   #[cfg(not(feature = "randomized-signing"))] → rnd = [0u8; RNDBYTES]

/// Whether randomized signing is enabled.
///
/// When `true`, the signing procedure uses fresh random bytes for the
/// nonce seed `rnd`. When `false`, `rnd` is set to all zeros, making
/// signing deterministic (useful for test vectors and reproducibility).
pub const RANDOMIZED_SIGNING: bool = cfg!(feature = "randomized-signing");

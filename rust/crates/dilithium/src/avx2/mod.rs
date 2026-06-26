//! AVX2-optimized backend for the Dilithium signature scheme.
//!
//! This module mirrors the `avx2/` C source directory and is only compiled
//! when the `avx2` feature is enabled on an x86_64 target.
//!
//! The AVX2 Makefile used these key flags:
//!   `-mavx2 -mpopcnt -march=native -mtune=native -O3`
//!
//! These are applied by `build.rs` via the `cc` crate when linking
//! the assembly files listed below.
//!
//! # Assembly files (linked via build.rs)
//! - `ntt.S`       — AVX2 forward NTT (T-030)
//! - `invntt.S`    — AVX2 inverse NTT (T-031)
//! - `pointwise.S` — AVX2 pointwise Montgomery multiplication (T-032)
//! - `shuffle.S`   — AVX2 NTT shuffle/transpose routines (T-033)
//! - `f1600x4.S`   — 4-way parallel `Keccak-f[1600]` (T-035)
//!
//! # Sub-modules (to be implemented in later tasks)
//! - `consts`    — AVX2-aligned constant tables (T-027)
//! - `align`     — Memory alignment types for AVX2 (T-029)
//! - `ntt`       — NTT Rust bindings / intrinsics (T-030, T-031)
//! - `pointwise` — Pointwise multiply bindings (T-032)
//! - `shuffle`   — Shuffle routine bindings (T-033)
//! - `fips202x4` — 4-way parallel SHAKE/SHA3 (T-036)
//! - `rejsample` — AVX2 rejection sampling (T-038)
//! - `rounding`  — AVX2 rounding functions (T-045)
//! - `poly`      — AVX2 polynomial operations (T-041)
//! - `polyvec`   — AVX2 polynomial vector operations (T-043)
//! - `sign`      — AVX2 signing implementation (T-047)

// Placeholder: sub-modules will be declared here by T-027 through T-054.
// Each sub-module corresponds to a C/ASM file in avx2/ being ported.
//
// Example (once implemented):
//   pub mod consts;    // T-027: AVX2-aligned constant tables
//   pub mod align;     // T-029: Memory alignment types
//   pub mod ntt;       // T-030/T-031: NTT forward/inverse
//   pub mod pointwise; // T-032: Pointwise multiplication
//   pub mod shuffle;   // T-033: Shuffle/transpose
//   pub mod fips202x4; // T-036: 4-way parallel SHAKE
//   pub mod rejsample; // T-038: Rejection sampling
//   pub mod rounding;  // T-045: Rounding functions
//   pub mod poly;      // T-041: Polynomial operations
//   pub mod polyvec;   // T-043: Polynomial vector operations
//   pub mod sign;      // T-047: Signing implementation

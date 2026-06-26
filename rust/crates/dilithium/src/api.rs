//! Public API for the active Dilithium parameter set.
//!
//! This module is the Rust equivalent of `ref/api.h` (and `sign.h`). It
//! exposes an *idiomatic* Rust surface — fixed-size key/signature arrays and
//! `Result`-returning functions — rather than the C convention of out-pointers
//! and `int` status codes.
//!
//! # C → Rust mapping
//!
//! | C function (`..._ref_*`)      | Rust equivalent           |
//! |-------------------------------|---------------------------|
//! | `crypto_sign_keypair`         | [`keypair`]               |
//! | `crypto_sign_signature`       | [`sign`] (detached)       |
//! | `crypto_sign_verify`          | [`verify`]                |
//! | `crypto_sign` (sm = sig‖m)    | [`sign_attached`]         |
//! | `crypto_sign_open`            | [`open`]                  |
//!
//! The C functions returned `0` on success and `-1` on failure; here failure
//! is a typed [`Error`]. Sizes come from [`crate::params`].
//!
//! Implementations are filled in by **T-023** (`src/sign.rs`); the bodies here
//! are `todo!()` placeholders so the API contract compiles and can be linked
//! against now.

use crate::params::{CRYPTO_BYTES, CRYPTO_PUBLICKEYBYTES, CRYPTO_SECRETKEYBYTES};

/// Serialized public-key length, in bytes (`ref/api.h` `*_PUBLICKEYBYTES`).
pub const PUBLICKEYBYTES: usize = CRYPTO_PUBLICKEYBYTES;
/// Serialized secret-key length, in bytes (`ref/api.h` `*_SECRETKEYBYTES`).
pub const SECRETKEYBYTES: usize = CRYPTO_SECRETKEYBYTES;
/// Serialized (detached) signature length, in bytes (`ref/api.h` `*_BYTES`).
pub const SIGNBYTES: usize = CRYPTO_BYTES;

/// Maximum supported length of the application context string `ctx`.
///
/// Matches the C reference, which encodes `ctxlen` in a single byte and
/// rejects `ctxlen > 255` (`sign.c`).
pub const CTX_MAX: usize = 255;

/// A serialized Dilithium public key.
pub type PublicKey = [u8; PUBLICKEYBYTES];
/// A serialized Dilithium secret key.
pub type SecretKey = [u8; SECRETKEYBYTES];
/// A serialized detached Dilithium signature.
pub type Signature = [u8; SIGNBYTES];

/// Errors returned by the Dilithium signing API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Signature verification failed (mirrors C return value `-1` from
    /// `crypto_sign_verify` / `crypto_sign_open`).
    InvalidSignature,
    /// The supplied context string exceeded [`CTX_MAX`] bytes.
    ContextTooLong,
    /// An input buffer had an invalid length (e.g. a signed message shorter
    /// than [`SIGNBYTES`]).
    InvalidLength,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let msg = match self {
            Error::InvalidSignature => "signature verification failed",
            Error::ContextTooLong => "context string longer than 255 bytes",
            Error::InvalidLength => "input buffer had an invalid length",
        };
        f.write_str(msg)
    }
}

impl std::error::Error for Error {}

/// Generate a new key pair using the system RNG.
///
/// Rust equivalent of `crypto_sign_keypair(pk, sk)`.
pub fn keypair() -> (PublicKey, SecretKey) {
    crate::sign::keypair()
}

/// Produce a detached signature over `msg` with application context `ctx`.
///
/// Rust equivalent of `crypto_sign_signature(sig, siglen, m, mlen, ctx,
/// ctxlen, sk)`. Returns [`Error::ContextTooLong`] if `ctx.len() > CTX_MAX`.
pub fn sign(msg: &[u8], ctx: &[u8], sk: &SecretKey) -> Result<Signature, Error> {
    crate::sign::signature(msg, ctx, sk)
}

/// Verify a detached signature `sig` over `msg` with context `ctx`.
///
/// Rust equivalent of `crypto_sign_verify(...)`. Returns `Ok(())` when the
/// signature is valid and [`Error::InvalidSignature`] otherwise.
pub fn verify(sig: &Signature, msg: &[u8], ctx: &[u8], pk: &PublicKey) -> Result<(), Error> {
    crate::sign::verify(sig, msg, ctx, pk)
}

/// Produce an attached signed message (`sig ‖ msg`).
///
/// Rust equivalent of `crypto_sign(sm, smlen, m, mlen, ctx, ctxlen, sk)`.
pub fn sign_attached(msg: &[u8], ctx: &[u8], sk: &SecretKey) -> Result<Vec<u8>, Error> {
    crate::sign::sign_message(msg, ctx, sk)
}

/// Verify an attached signed message `sm` and recover the original message.
///
/// Rust equivalent of `crypto_sign_open(m, mlen, sm, smlen, ctx, ctxlen, pk)`.
/// Returns the recovered message on success.
pub fn open(sm: &[u8], ctx: &[u8], pk: &PublicKey) -> Result<Vec<u8>, Error> {
    crate::sign::open(sm, ctx, pk)
}

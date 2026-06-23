//! SHAKE-based symmetric primitive wrappers.
//!
//! Rust port of `ref/symmetric-shake.c` and `ref/symmetric.h` (T-019 / T-020).
//!
//! Dilithium derives its randomness from two SHAKE streams: SHAKE128 for matrix
//! expansion (`stream128`) and SHAKE256 for the secret/mask sampling
//! (`stream256`). Each is seeded by absorbing `seed ‖ nonce_le16`. These thin
//! wrappers build that input and hand back a [`crate::fips202`] stream.

use crate::fips202::{Shake128Stream, Shake256Stream, SHAKE128_RATE, SHAKE256_RATE};
use crate::params::{CRHBYTES, SEEDBYTES};

/// Bytes squeezed per `stream128` block (`STREAM128_BLOCKBYTES`).
pub const STREAM128_BLOCKBYTES: usize = SHAKE128_RATE;
/// Bytes squeezed per `stream256` block (`STREAM256_BLOCKBYTES`).
pub const STREAM256_BLOCKBYTES: usize = SHAKE256_RATE;

/// `stream128_state` — a SHAKE128 squeezer.
pub type Stream128State = Shake128Stream;
/// `stream256_state` — a SHAKE256 squeezer.
pub type Stream256State = Shake256Stream;

/// Initialise a SHAKE128 stream from `seed ‖ nonce` (little-endian nonce).
///
/// Port of `dilithium_shake128_stream_init` / the `stream128_init` macro.
pub fn stream128_init(seed: &[u8; SEEDBYTES], nonce: u16) -> Stream128State {
    let mut buf = [0u8; SEEDBYTES + 2];
    buf[..SEEDBYTES].copy_from_slice(seed);
    buf[SEEDBYTES] = nonce as u8;
    buf[SEEDBYTES + 1] = (nonce >> 8) as u8;
    Shake128Stream::init_absorb(&buf)
}

/// Initialise a SHAKE256 stream from `seed ‖ nonce` (little-endian nonce).
///
/// Port of `dilithium_shake256_stream_init` / the `stream256_init` macro.
pub fn stream256_init(seed: &[u8; CRHBYTES], nonce: u16) -> Stream256State {
    let mut buf = [0u8; CRHBYTES + 2];
    buf[..CRHBYTES].copy_from_slice(seed);
    buf[CRHBYTES] = nonce as u8;
    buf[CRHBYTES + 1] = (nonce >> 8) as u8;
    Shake256Stream::init_absorb(&buf)
}

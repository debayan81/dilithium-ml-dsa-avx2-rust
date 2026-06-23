//! FIPS 202 (SHA-3 / SHAKE) primitives used by Dilithium.
//!
//! Rust port of `ref/fips202.c` and `ref/fips202.h` (T-017 / T-018).
//!
//! Rather than hand-porting the Keccak-f[1600] permutation, this wraps the
//! audited [`sha3`] crate. The C reference exposes an incremental
//! init/absorb/finalize/squeezeblocks API over a `keccak_state`; Dilithium only
//! ever uses the "absorb everything once, then squeeze blocks" pattern, so the
//! streaming types here take the full input up front in [`Shake128Stream::init_absorb`]
//! / [`Shake256Stream::init_absorb`] and then yield rate-sized blocks. Splitting
//! the absorbed input across calls is equivalent to absorbing the concatenation,
//! so building `seed ‖ nonce` in one buffer matches the C two-call absorb.

use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Shake128, Shake256};

/// SHAKE128 sponge rate in bytes (`fips202.h`).
pub const SHAKE128_RATE: usize = 168;
/// SHAKE256 sponge rate in bytes (`fips202.h`).
pub const SHAKE256_RATE: usize = 136;
/// SHA3-256 sponge rate in bytes (`fips202.h`).
pub const SHA3_256_RATE: usize = 136;
/// SHA3-512 sponge rate in bytes (`fips202.h`).
pub const SHA3_512_RATE: usize = 72;

/// Incremental SHAKE128 squeezer (Rust analogue of `keccak_state` used as a
/// SHAKE128 stream).
pub struct Shake128Stream {
    reader: sha3::Shake128Reader,
}

impl Shake128Stream {
    /// Absorb `input` in full and finalize, ready to squeeze.
    /// Mirrors `shake128_init` + `shake128_absorb_once` + `shake128_finalize`.
    pub fn init_absorb(input: &[u8]) -> Self {
        let mut h = Shake128::default();
        h.update(input);
        Self { reader: h.finalize_xof() }
    }

    /// Squeeze `nblocks` × [`SHAKE128_RATE`] bytes into the front of `out`.
    /// Mirrors `shake128_squeezeblocks`.
    pub fn squeezeblocks(&mut self, out: &mut [u8], nblocks: usize) {
        self.reader.read(&mut out[..nblocks * SHAKE128_RATE]);
    }
}

/// Incremental SHAKE256 squeezer (Rust analogue of `keccak_state` used as a
/// SHAKE256 stream).
pub struct Shake256Stream {
    reader: sha3::Shake256Reader,
}

impl Shake256Stream {
    /// Absorb `input` in full and finalize, ready to squeeze.
    /// Mirrors `shake256_init` + `shake256_absorb_once` + `shake256_finalize`.
    pub fn init_absorb(input: &[u8]) -> Self {
        let mut h = Shake256::default();
        h.update(input);
        Self { reader: h.finalize_xof() }
    }

    /// Squeeze `nblocks` × [`SHAKE256_RATE`] bytes into the front of `out`.
    /// Mirrors `shake256_squeezeblocks`.
    pub fn squeezeblocks(&mut self, out: &mut [u8], nblocks: usize) {
        self.reader.read(&mut out[..nblocks * SHAKE256_RATE]);
    }
}

/// One-shot SHAKE128: write `out.len()` bytes of `SHAKE128(input)`.
/// Port of `shake128`.
pub fn shake128(out: &mut [u8], input: &[u8]) {
    let mut h = Shake128::default();
    h.update(input);
    h.finalize_xof().read(out);
}

/// One-shot SHAKE256: write `out.len()` bytes of `SHAKE256(input)`.
/// Port of `shake256`.
pub fn shake256(out: &mut [u8], input: &[u8]) {
    let mut h = Shake256::default();
    h.update(input);
    h.finalize_xof().read(out);
}

/// One-shot SHA3-256. Port of `sha3_256`.
pub fn sha3_256(out: &mut [u8; 32], input: &[u8]) {
    use sha3::Digest;
    let d = sha3::Sha3_256::digest(input);
    out.copy_from_slice(&d);
}

/// One-shot SHA3-512. Port of `sha3_512`.
pub fn sha3_512(out: &mut [u8; 64], input: &[u8]) {
    use sha3::Digest;
    let d = sha3::Sha3_512::digest(input);
    out.copy_from_slice(&d);
}

#[cfg(test)]
mod tests {
    use super::*;

    // Known SHA-3 / SHAKE answers for the empty input (FIPS 202 test vectors).
    #[test]
    fn sha3_256_empty() {
        let mut out = [0u8; 32];
        sha3_256(&mut out, b"");
        // SHA3-256("") = a7ffc6f8bf1ed766...82d80a4b80f8434a
        assert_eq!(&out[..4], &[0xa7, 0xff, 0xc6, 0xf8]);
        assert_eq!(&out[28..], &[0x80, 0xf8, 0x43, 0x4a]);
    }

    #[test]
    fn sha3_512_empty() {
        let mut out = [0u8; 64];
        sha3_512(&mut out, b"");
        // SHA3-512("") = a69f73cca23a9ac5...
        assert_eq!(&out[..4], &[0xa6, 0x9f, 0x73, 0xcc]);
    }

    #[test]
    fn shake256_empty_prefix() {
        // SHAKE256("") = 46b9dd2b0ba88d13...
        let mut out = [0u8; 32];
        shake256(&mut out, b"");
        assert_eq!(&out[..4], &[0x46, 0xb9, 0xdd, 0x2b]);
    }

    #[test]
    fn shake128_empty_prefix() {
        // SHAKE128("") = 7f9c2ba4e88f827d...
        let mut out = [0u8; 32];
        shake128(&mut out, b"");
        assert_eq!(&out[..4], &[0x7f, 0x9c, 0x2b, 0xa4]);
    }

    #[test]
    fn streamed_blocks_match_one_shot() {
        // Squeezing two blocks incrementally must equal one 2-block read.
        let input = b"dilithium stream test";
        let mut a = [0u8; 2 * SHAKE128_RATE];
        let mut s = Shake128Stream::init_absorb(input);
        s.squeezeblocks(&mut a, 2);

        let mut b = [0u8; 2 * SHAKE128_RATE];
        let mut s2 = Shake128Stream::init_absorb(input);
        s2.squeezeblocks(&mut b[..SHAKE128_RATE], 1);
        s2.squeezeblocks(&mut b[SHAKE128_RATE..], 1);
        assert_eq!(a, b);

        // ...and equal to the one-shot XOF over the same length.
        let mut c = [0u8; 2 * SHAKE128_RATE];
        shake128(&mut c, input);
        assert_eq!(a, c);
    }
}

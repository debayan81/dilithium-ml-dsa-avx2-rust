//! Polynomial operations over `Z_q[X]/(X^256 + 1)`.
//!
//! Rust port of `ref/poly.c` and `ref/poly.h` (T-013 / T-014).
//!
//! The C `poly` struct (a bare `int32_t coeffs[N]`) becomes [`Poly`]. The C
//! free functions `poly_*` become methods / associated functions on `Poly`
//! (the `poly_` prefix is dropped — the type provides the namespace). Functions
//! that wrote results through pointers now return owned [`Poly`] values (or
//! tuples), which is cheap for a reference implementation and keeps call sites
//! clear; the AVX2 backend (T-041) is where layout/perf is tuned.
//!
//! `GAMMA1`/`GAMMA2`/`ETA`-dependent code paths mirror the C `#if` blocks and
//! are selected by the parameter-set feature.

// Indexed loops below mirror the bit-twiddling structure of the C reference
// one-to-one; rewriting them as iterators would obscure the correspondence.
#![allow(clippy::needless_range_loop)]
// The `NBLOCKS` constants reproduce the C `(X + RATE - 1)/RATE` ceiling-division
// macros verbatim; keep that form rather than `div_ceil` for traceability.
#![allow(clippy::manual_div_ceil)]

use crate::fips202::{Shake256Stream, SHAKE256_RATE};
use crate::ntt;
use crate::params::*;
use crate::reduce::{caddq, montgomery_reduce, reduce32};
use crate::rounding::{decompose, make_hint, power2round, use_hint};
use crate::symmetric::{self, STREAM128_BLOCKBYTES, STREAM256_BLOCKBYTES};

/// A polynomial: `N` signed coefficients. Port of the C `poly` struct.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Poly {
    pub coeffs: [i32; N],
}

impl Default for Poly {
    fn default() -> Self {
        Poly { coeffs: [0i32; N] }
    }
}

impl Poly {
    // ---- arithmetic -------------------------------------------------------

    /// Reduce all coefficients to `[-6283008, 6283008]`. Port of `poly_reduce`.
    pub fn reduce(&mut self) {
        for c in self.coeffs.iter_mut() {
            *c = reduce32(*c);
        }
    }

    /// Add `Q` to every negative coefficient. Port of `poly_caddq`.
    pub fn caddq(&mut self) {
        for c in self.coeffs.iter_mut() {
            *c = caddq(*c);
        }
    }

    /// `self + b`, no modular reduction. Port of `poly_add`.
    pub fn add(&self, b: &Poly) -> Poly {
        let mut c = Poly::default();
        for i in 0..N {
            c.coeffs[i] = self.coeffs[i].wrapping_add(b.coeffs[i]);
        }
        c
    }

    /// `self - b`, no modular reduction. Port of `poly_sub`.
    pub fn sub(&self, b: &Poly) -> Poly {
        let mut c = Poly::default();
        for i in 0..N {
            c.coeffs[i] = self.coeffs[i].wrapping_sub(b.coeffs[i]);
        }
        c
    }

    /// Multiply by `2^D` in place. Port of `poly_shiftl`.
    pub fn shiftl(&mut self) {
        for c in self.coeffs.iter_mut() {
            *c <<= D;
        }
    }

    /// Forward NTT in place. Port of `poly_ntt`.
    pub fn ntt(&mut self) {
        ntt::ntt(&mut self.coeffs);
    }

    /// Inverse NTT (×`2^32`) in place. Port of `poly_invntt_tomont`.
    pub fn invntt_tomont(&mut self) {
        ntt::invntt_tomont(&mut self.coeffs);
    }

    /// Pointwise Montgomery product `self ∘ b` (÷`2^32`).
    /// Port of `poly_pointwise_montgomery`.
    pub fn pointwise_montgomery(&self, b: &Poly) -> Poly {
        let mut c = Poly::default();
        for i in 0..N {
            c.coeffs[i] = montgomery_reduce(self.coeffs[i] as i64 * b.coeffs[i] as i64);
        }
        c
    }

    // ---- rounding ---------------------------------------------------------

    /// Split every coefficient `c = a1·2^D + a0`. Returns `(a1, a0)`.
    /// Port of `poly_power2round`.
    pub fn power2round(&self) -> (Poly, Poly) {
        let mut a1 = Poly::default();
        let mut a0 = Poly::default();
        for i in 0..N {
            let (h, l) = power2round(self.coeffs[i]);
            a1.coeffs[i] = h;
            a0.coeffs[i] = l;
        }
        (a1, a0)
    }

    /// Split every coefficient into high/low bits. Returns `(a1, a0)`.
    /// Port of `poly_decompose`.
    pub fn decompose(&self) -> (Poly, Poly) {
        let mut a1 = Poly::default();
        let mut a0 = Poly::default();
        for i in 0..N {
            let (h, l) = decompose(self.coeffs[i]);
            a1.coeffs[i] = h;
            a0.coeffs[i] = l;
        }
        (a1, a0)
    }

    /// Hint polynomial from low part `a0` and high part `a1`.
    /// Returns `(h, popcount)`. Port of `poly_make_hint`.
    pub fn make_hint(a0: &Poly, a1: &Poly) -> (Poly, usize) {
        let mut h = Poly::default();
        let mut s = 0usize;
        for i in 0..N {
            let bit = make_hint(a0.coeffs[i], a1.coeffs[i]);
            h.coeffs[i] = bit as i32;
            s += bit as usize;
        }
        (h, s)
    }

    /// Correct high bits using hint `h`. Port of `poly_use_hint`.
    pub fn use_hint(&self, h: &Poly) -> Poly {
        let mut b = Poly::default();
        for i in 0..N {
            b.coeffs[i] = use_hint(self.coeffs[i], h.coeffs[i] != 0);
        }
        b
    }

    /// Check the infinity norm against bound `bound`.
    ///
    /// Returns `true` if `‖self‖∞ >= bound` (or `bound > (Q-1)/8`), matching
    /// the C convention where `1` means "rejected". Assumes coefficients were
    /// reduced by [`reduce`](Self::reduce). Port of `poly_chknorm`.
    pub fn chknorm(&self, bound: i32) -> bool {
        if bound > (Q - 1) / 8 {
            return true;
        }
        // Constant-time absolute value; we may leak *which* coefficient fails
        // (data-independent) but not the sign of the centered representative.
        for i in 0..N {
            let t = self.coeffs[i] >> 31;
            let t = self.coeffs[i] - (t & self.coeffs[i].wrapping_mul(2));
            if t >= bound {
                return true;
            }
        }
        false
    }

    // ---- sampling ---------------------------------------------------------

    /// Sample uniform coefficients in `[0, Q-1]` from `SHAKE128(seed ‖ nonce)`.
    /// Port of `poly_uniform`.
    pub fn uniform(seed: &[u8; SEEDBYTES], nonce: u16) -> Poly {
        const NBLOCKS: usize = (768 + STREAM128_BLOCKBYTES - 1) / STREAM128_BLOCKBYTES;
        let mut buf = [0u8; NBLOCKS * STREAM128_BLOCKBYTES + 2];

        let mut state = symmetric::stream128_init(seed, nonce);
        state.squeezeblocks(&mut buf, NBLOCKS);

        let mut a = Poly::default();
        let mut buflen = NBLOCKS * STREAM128_BLOCKBYTES;
        let mut ctr = rej_uniform(&mut a.coeffs, &buf[..buflen]);

        while ctr < N {
            let off = buflen % 3;
            for i in 0..off {
                buf[i] = buf[buflen - off + i];
            }
            state.squeezeblocks(&mut buf[off..off + STREAM128_BLOCKBYTES], 1);
            buflen = STREAM128_BLOCKBYTES + off;
            ctr += rej_uniform(&mut a.coeffs[ctr..], &buf[..buflen]);
        }
        a
    }

    /// Sample coefficients in `[-ETA, ETA]` from `SHAKE256(seed ‖ nonce)`.
    /// Port of `poly_uniform_eta`.
    pub fn uniform_eta(seed: &[u8; CRHBYTES], nonce: u16) -> Poly {
        #[cfg(any(feature = "dilithium2", feature = "dilithium5"))]
        const NBLOCKS: usize = (136 + STREAM256_BLOCKBYTES - 1) / STREAM256_BLOCKBYTES;
        #[cfg(feature = "dilithium3")]
        const NBLOCKS: usize = (227 + STREAM256_BLOCKBYTES - 1) / STREAM256_BLOCKBYTES;

        let mut buf = [0u8; NBLOCKS * STREAM256_BLOCKBYTES];
        let mut state = symmetric::stream256_init(seed, nonce);
        state.squeezeblocks(&mut buf, NBLOCKS);

        let mut a = Poly::default();
        let mut ctr = rej_eta(&mut a.coeffs, &buf);
        while ctr < N {
            state.squeezeblocks(&mut buf[..STREAM256_BLOCKBYTES], 1);
            ctr += rej_eta(&mut a.coeffs[ctr..], &buf[..STREAM256_BLOCKBYTES]);
        }
        a
    }

    /// Sample coefficients in `[-(GAMMA1-1), GAMMA1]` by unpacking
    /// `SHAKE256(seed ‖ nonce)`. Port of `poly_uniform_gamma1`.
    pub fn uniform_gamma1(seed: &[u8; CRHBYTES], nonce: u16) -> Poly {
        const NBLOCKS: usize =
            (POLYZ_PACKEDBYTES + STREAM256_BLOCKBYTES - 1) / STREAM256_BLOCKBYTES;
        let mut buf = [0u8; NBLOCKS * STREAM256_BLOCKBYTES];
        let mut state = symmetric::stream256_init(seed, nonce);
        state.squeezeblocks(&mut buf, NBLOCKS);
        Poly::z_unpack(&buf)
    }

    /// Sample the challenge polynomial `c`: `TAU` coefficients in `{-1, 1}`,
    /// the rest zero, from `SHAKE256(seed)`. Port of `poly_challenge`.
    pub fn challenge(seed: &[u8; CTILDEBYTES]) -> Poly {
        let mut buf = [0u8; SHAKE256_RATE];
        let mut state = Shake256Stream::init_absorb(seed);
        state.squeezeblocks(&mut buf, 1);

        let mut signs: u64 = 0;
        for i in 0..8 {
            signs |= (buf[i] as u64) << (8 * i);
        }
        let mut pos = 8usize;

        let mut c = Poly::default();
        for i in (N - TAU)..N {
            let b = loop {
                if pos >= SHAKE256_RATE {
                    state.squeezeblocks(&mut buf, 1);
                    pos = 0;
                }
                let candidate = buf[pos] as usize;
                pos += 1;
                if candidate <= i {
                    break candidate;
                }
            };
            c.coeffs[i] = c.coeffs[b];
            c.coeffs[b] = 1 - 2 * ((signs & 1) as i32);
            signs >>= 1;
        }
        c
    }

    // ---- packing ----------------------------------------------------------

    /// Bit-pack coefficients in `[-ETA, ETA]` into `r` (`POLYETA_PACKEDBYTES`).
    /// Port of `polyeta_pack`.
    pub fn eta_pack(&self, r: &mut [u8]) {
        let a = &self.coeffs;
        #[cfg(any(feature = "dilithium2", feature = "dilithium5"))]
        {
            // ETA == 2: 3 bits per coefficient.
            let mut t = [0u8; 8];
            for i in 0..N / 8 {
                for k in 0..8 {
                    t[k] = (ETA - a[8 * i + k]) as u8;
                }
                r[3 * i] = t[0] | (t[1] << 3) | (t[2] << 6);
                r[3 * i + 1] = (t[2] >> 2) | (t[3] << 1) | (t[4] << 4) | (t[5] << 7);
                r[3 * i + 2] = (t[5] >> 1) | (t[6] << 2) | (t[7] << 5);
            }
        }
        #[cfg(feature = "dilithium3")]
        {
            // ETA == 4: 4 bits per coefficient.
            for i in 0..N / 2 {
                let t0 = (ETA - a[2 * i]) as u8;
                let t1 = (ETA - a[2 * i + 1]) as u8;
                r[i] = t0 | (t1 << 4);
            }
        }
    }

    /// Unpack coefficients in `[-ETA, ETA]`. Port of `polyeta_unpack`.
    pub fn eta_unpack(a: &[u8]) -> Poly {
        let mut r = Poly::default();
        let c = &mut r.coeffs;
        #[cfg(any(feature = "dilithium2", feature = "dilithium5"))]
        {
            for i in 0..N / 8 {
                let g = |j: usize| a[3 * i + j] as u32;
                c[8 * i] = (g(0) & 7) as i32;
                c[8 * i + 1] = ((g(0) >> 3) & 7) as i32;
                c[8 * i + 2] = (((g(0) >> 6) | (g(1) << 2)) & 7) as i32;
                c[8 * i + 3] = ((g(1) >> 1) & 7) as i32;
                c[8 * i + 4] = ((g(1) >> 4) & 7) as i32;
                c[8 * i + 5] = (((g(1) >> 7) | (g(2) << 1)) & 7) as i32;
                c[8 * i + 6] = ((g(2) >> 2) & 7) as i32;
                c[8 * i + 7] = ((g(2) >> 5) & 7) as i32;
                for k in 0..8 {
                    c[8 * i + k] = ETA - c[8 * i + k];
                }
            }
        }
        #[cfg(feature = "dilithium3")]
        {
            for i in 0..N / 2 {
                c[2 * i] = (a[i] & 0x0F) as i32;
                c[2 * i + 1] = (a[i] >> 4) as i32;
                c[2 * i] = ETA - c[2 * i];
                c[2 * i + 1] = ETA - c[2 * i + 1];
            }
        }
        r
    }

    /// Bit-pack `t1` (10-bit coefficients) into `r` (`POLYT1_PACKEDBYTES`).
    /// Port of `polyt1_pack`.
    pub fn t1_pack(&self, r: &mut [u8]) {
        let a = &self.coeffs;
        for i in 0..N / 4 {
            r[5 * i] = a[4 * i] as u8;
            r[5 * i + 1] = ((a[4 * i] >> 8) | (a[4 * i + 1] << 2)) as u8;
            r[5 * i + 2] = ((a[4 * i + 1] >> 6) | (a[4 * i + 2] << 4)) as u8;
            r[5 * i + 3] = ((a[4 * i + 2] >> 4) | (a[4 * i + 3] << 6)) as u8;
            r[5 * i + 4] = (a[4 * i + 3] >> 2) as u8;
        }
    }

    /// Unpack `t1` (10-bit coefficients). Port of `polyt1_unpack`.
    pub fn t1_unpack(a: &[u8]) -> Poly {
        let mut r = Poly::default();
        let c = &mut r.coeffs;
        for i in 0..N / 4 {
            let g = |j: usize| a[5 * i + j] as u32;
            c[4 * i] = ((g(0) | (g(1) << 8)) & 0x3FF) as i32;
            c[4 * i + 1] = (((g(1) >> 2) | (g(2) << 6)) & 0x3FF) as i32;
            c[4 * i + 2] = (((g(2) >> 4) | (g(3) << 4)) & 0x3FF) as i32;
            c[4 * i + 3] = (((g(3) >> 6) | (g(4) << 2)) & 0x3FF) as i32;
        }
        r
    }

    /// Bit-pack `t0` (coefficients in `]-2^{D-1}, 2^{D-1}]`) into `r`
    /// (`POLYT0_PACKEDBYTES`). Port of `polyt0_pack`.
    pub fn t0_pack(&self, r: &mut [u8]) {
        let a = &self.coeffs;
        let mut t = [0u32; 8];
        for i in 0..N / 8 {
            for k in 0..8 {
                t[k] = ((1 << (D - 1)) - a[8 * i + k]) as u32;
            }
            r[13 * i] = t[0] as u8;
            r[13 * i + 1] = ((t[0] >> 8) | (t[1] << 5)) as u8;
            r[13 * i + 2] = (t[1] >> 3) as u8;
            r[13 * i + 3] = ((t[1] >> 11) | (t[2] << 2)) as u8;
            r[13 * i + 4] = ((t[2] >> 6) | (t[3] << 7)) as u8;
            r[13 * i + 5] = (t[3] >> 1) as u8;
            r[13 * i + 6] = ((t[3] >> 9) | (t[4] << 4)) as u8;
            r[13 * i + 7] = (t[4] >> 4) as u8;
            r[13 * i + 8] = ((t[4] >> 12) | (t[5] << 1)) as u8;
            r[13 * i + 9] = ((t[5] >> 7) | (t[6] << 6)) as u8;
            r[13 * i + 10] = (t[6] >> 2) as u8;
            r[13 * i + 11] = ((t[6] >> 10) | (t[7] << 3)) as u8;
            r[13 * i + 12] = (t[7] >> 5) as u8;
        }
    }

    /// Unpack `t0`. Port of `polyt0_unpack`.
    pub fn t0_unpack(a: &[u8]) -> Poly {
        let mut r = Poly::default();
        let c = &mut r.coeffs;
        for i in 0..N / 8 {
            let g = |j: usize| a[13 * i + j] as u32;
            c[8 * i] = ((g(0) | (g(1) << 8)) & 0x1FFF) as i32;
            c[8 * i + 1] = (((g(1) >> 5) | (g(2) << 3) | (g(3) << 11)) & 0x1FFF) as i32;
            c[8 * i + 2] = (((g(3) >> 2) | (g(4) << 6)) & 0x1FFF) as i32;
            c[8 * i + 3] = (((g(4) >> 7) | (g(5) << 1) | (g(6) << 9)) & 0x1FFF) as i32;
            c[8 * i + 4] = (((g(6) >> 4) | (g(7) << 4) | (g(8) << 12)) & 0x1FFF) as i32;
            c[8 * i + 5] = (((g(8) >> 1) | (g(9) << 7)) & 0x1FFF) as i32;
            c[8 * i + 6] = (((g(9) >> 6) | (g(10) << 2) | (g(11) << 10)) & 0x1FFF) as i32;
            c[8 * i + 7] = (((g(11) >> 3) | (g(12) << 5)) & 0x1FFF) as i32;
            for k in 0..8 {
                c[8 * i + k] = (1 << (D - 1)) - c[8 * i + k];
            }
        }
        r
    }

    /// Bit-pack `z` (coefficients in `[-(GAMMA1-1), GAMMA1]`) into `r`
    /// (`POLYZ_PACKEDBYTES`). Port of `polyz_pack`.
    pub fn z_pack(&self, r: &mut [u8]) {
        let a = &self.coeffs;
        #[cfg(feature = "dilithium2")]
        {
            // GAMMA1 == 2^17: 18 bits per coefficient.
            let mut t = [0u32; 4];
            for i in 0..N / 4 {
                for k in 0..4 {
                    t[k] = (GAMMA1 - a[4 * i + k]) as u32;
                }
                r[9 * i] = t[0] as u8;
                r[9 * i + 1] = (t[0] >> 8) as u8;
                r[9 * i + 2] = ((t[0] >> 16) | (t[1] << 2)) as u8;
                r[9 * i + 3] = (t[1] >> 6) as u8;
                r[9 * i + 4] = ((t[1] >> 14) | (t[2] << 4)) as u8;
                r[9 * i + 5] = (t[2] >> 4) as u8;
                r[9 * i + 6] = ((t[2] >> 12) | (t[3] << 6)) as u8;
                r[9 * i + 7] = (t[3] >> 2) as u8;
                r[9 * i + 8] = (t[3] >> 10) as u8;
            }
        }
        #[cfg(any(feature = "dilithium3", feature = "dilithium5"))]
        {
            // GAMMA1 == 2^19: 20 bits per coefficient.
            let mut t = [0u32; 2];
            for i in 0..N / 2 {
                t[0] = (GAMMA1 - a[2 * i]) as u32;
                t[1] = (GAMMA1 - a[2 * i + 1]) as u32;
                r[5 * i] = t[0] as u8;
                r[5 * i + 1] = (t[0] >> 8) as u8;
                r[5 * i + 2] = ((t[0] >> 16) | (t[1] << 4)) as u8;
                r[5 * i + 3] = (t[1] >> 4) as u8;
                r[5 * i + 4] = (t[1] >> 12) as u8;
            }
        }
    }

    /// Unpack `z`. Port of `polyz_unpack`.
    pub fn z_unpack(a: &[u8]) -> Poly {
        let mut r = Poly::default();
        let c = &mut r.coeffs;
        #[cfg(feature = "dilithium2")]
        {
            for i in 0..N / 4 {
                let g = |j: usize| a[9 * i + j] as u32;
                c[4 * i] = ((g(0) | (g(1) << 8) | (g(2) << 16)) & 0x3FFFF) as i32;
                c[4 * i + 1] = (((g(2) >> 2) | (g(3) << 6) | (g(4) << 14)) & 0x3FFFF) as i32;
                c[4 * i + 2] = (((g(4) >> 4) | (g(5) << 4) | (g(6) << 12)) & 0x3FFFF) as i32;
                c[4 * i + 3] = (((g(6) >> 6) | (g(7) << 2) | (g(8) << 10)) & 0x3FFFF) as i32;
                for k in 0..4 {
                    c[4 * i + k] = GAMMA1 - c[4 * i + k];
                }
            }
        }
        #[cfg(any(feature = "dilithium3", feature = "dilithium5"))]
        {
            for i in 0..N / 2 {
                let g = |j: usize| a[5 * i + j] as u32;
                c[2 * i] = ((g(0) | (g(1) << 8) | (g(2) << 16)) & 0xFFFFF) as i32;
                c[2 * i + 1] = ((g(2) >> 4) | (g(3) << 4) | (g(4) << 12)) as i32;
                c[2 * i] = GAMMA1 - c[2 * i];
                c[2 * i + 1] = GAMMA1 - c[2 * i + 1];
            }
        }
        r
    }

    /// Bit-pack `w1` (coefficients in `[0,15]` or `[0,43]`) into `r`
    /// (`POLYW1_PACKEDBYTES`). Port of `polyw1_pack`.
    pub fn w1_pack(&self, r: &mut [u8]) {
        let a = &self.coeffs;
        #[cfg(feature = "dilithium2")]
        {
            // GAMMA2 == (Q-1)/88: 6 bits per coefficient.
            for i in 0..N / 4 {
                r[3 * i] = (a[4 * i] | (a[4 * i + 1] << 6)) as u8;
                r[3 * i + 1] = ((a[4 * i + 1] >> 2) | (a[4 * i + 2] << 4)) as u8;
                r[3 * i + 2] = ((a[4 * i + 2] >> 4) | (a[4 * i + 3] << 2)) as u8;
            }
        }
        #[cfg(any(feature = "dilithium3", feature = "dilithium5"))]
        {
            // GAMMA2 == (Q-1)/32: 4 bits per coefficient.
            for i in 0..N / 2 {
                r[i] = (a[2 * i] | (a[2 * i + 1] << 4)) as u8;
            }
        }
    }
}

/// Rejection-sample uniform coefficients in `[0, Q-1]` from `buf`.
/// Fills up to `a.len()` coefficients; returns the count produced.
/// Port of the static `rej_uniform` in `poly.c`.
fn rej_uniform(a: &mut [i32], buf: &[u8]) -> usize {
    let len = a.len();
    let mut ctr = 0usize;
    let mut pos = 0usize;
    while ctr < len && pos + 3 <= buf.len() {
        let mut t = buf[pos] as u32;
        t |= (buf[pos + 1] as u32) << 8;
        t |= (buf[pos + 2] as u32) << 16;
        t &= 0x7FFFFF;
        pos += 3;
        if t < Q as u32 {
            a[ctr] = t as i32;
            ctr += 1;
        }
    }
    ctr
}

/// Rejection-sample coefficients in `[-ETA, ETA]` from `buf`.
/// Port of the static `rej_eta` in `poly.c`.
fn rej_eta(a: &mut [i32], buf: &[u8]) -> usize {
    let len = a.len();
    let mut ctr = 0usize;
    let mut pos = 0usize;
    while ctr < len && pos < buf.len() {
        let t0 = (buf[pos] & 0x0F) as u32;
        let t1 = (buf[pos] >> 4) as u32;
        pos += 1;

        #[cfg(any(feature = "dilithium2", feature = "dilithium5"))]
        {
            // ETA == 2
            if t0 < 15 {
                let t0 = t0 - (205 * t0 >> 10) * 5;
                a[ctr] = 2 - t0 as i32;
                ctr += 1;
            }
            if t1 < 15 && ctr < len {
                let t1 = t1 - (205 * t1 >> 10) * 5;
                a[ctr] = 2 - t1 as i32;
                ctr += 1;
            }
        }
        #[cfg(feature = "dilithium3")]
        {
            // ETA == 4
            if t0 < 9 {
                a[ctr] = 4 - t0 as i32;
                ctr += 1;
            }
            if t1 < 9 && ctr < len {
                a[ctr] = 4 - t1 as i32;
                ctr += 1;
            }
        }
    }
    ctr
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed32() -> [u8; SEEDBYTES] {
        let mut s = [0u8; SEEDBYTES];
        for (i, b) in s.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7).wrapping_add(1);
        }
        s
    }

    fn seed64() -> [u8; CRHBYTES] {
        let mut s = [0u8; CRHBYTES];
        for (i, b) in s.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(5).wrapping_add(3);
        }
        s
    }

    #[test]
    fn uniform_coeffs_in_range() {
        let a = Poly::uniform(&seed32(), 0);
        assert!(a.coeffs.iter().all(|&c| (0..Q).contains(&c)));
        // With overwhelming probability the polynomial is not all-zero.
        assert!(a.coeffs.iter().any(|&c| c != 0));
    }

    #[test]
    fn uniform_eta_in_range() {
        let a = Poly::uniform_eta(&seed64(), 7);
        assert!(a.coeffs.iter().all(|&c| (-ETA..=ETA).contains(&c)));
    }

    #[test]
    fn uniform_gamma1_in_range() {
        let a = Poly::uniform_gamma1(&seed64(), 9);
        assert!(a.coeffs.iter().all(|&c| (-(GAMMA1 - 1)..=GAMMA1).contains(&c)));
    }

    #[test]
    fn challenge_has_tau_signed_ones() {
        let mut seed = [0u8; CTILDEBYTES];
        for (i, b) in seed.iter_mut().enumerate() {
            *b = i as u8;
        }
        let c = Poly::challenge(&seed);
        let nonzero = c.coeffs.iter().filter(|&&x| x != 0).count();
        assert_eq!(nonzero, TAU);
        assert!(c.coeffs.iter().all(|&x| x == 0 || x == 1 || x == -1));
    }

    #[test]
    fn eta_pack_roundtrip() {
        let a = Poly::uniform_eta(&seed64(), 1);
        let mut buf = [0u8; POLYETA_PACKEDBYTES];
        a.eta_pack(&mut buf);
        assert_eq!(Poly::eta_unpack(&buf), a);
    }

    #[test]
    fn t1_pack_roundtrip() {
        let mut a = Poly::default();
        for i in 0..N {
            a.coeffs[i] = (i as i32 * 7) & 0x3FF; // 10-bit values
        }
        let mut buf = [0u8; POLYT1_PACKEDBYTES];
        a.t1_pack(&mut buf);
        assert_eq!(Poly::t1_unpack(&buf), a);
    }

    #[test]
    fn t0_pack_roundtrip() {
        let mut a = Poly::default();
        let half = 1 << (D - 1); // 4096
        for i in 0..N {
            // coefficients in (-2^{D-1}, 2^{D-1}]
            a.coeffs[i] = half - ((i as i32 * 37) % (2 * half));
        }
        let mut buf = [0u8; POLYT0_PACKEDBYTES];
        a.t0_pack(&mut buf);
        assert_eq!(Poly::t0_unpack(&buf), a);
    }

    #[test]
    fn z_pack_roundtrip() {
        let a = Poly::uniform_gamma1(&seed64(), 3);
        let mut buf = [0u8; POLYZ_PACKEDBYTES];
        a.z_pack(&mut buf);
        assert_eq!(Poly::z_unpack(&buf), a);
    }

    #[test]
    fn w1_pack_zero_is_zero() {
        let a = Poly::default();
        let mut buf = [0xFFu8; POLYW1_PACKEDBYTES];
        a.w1_pack(&mut buf);
        assert!(buf.iter().all(|&b| b == 0));
    }

    #[test]
    fn add_sub_inverse() {
        let a = Poly::uniform(&seed32(), 11);
        let b = Poly::uniform(&seed32(), 12);
        assert_eq!(a.add(&b).sub(&b), a);
    }

    #[test]
    fn chknorm_detects_bound() {
        let mut a = Poly::default();
        a.coeffs[5] = 100;
        assert!(!a.chknorm(101));
        assert!(a.chknorm(100));
        assert!(a.chknorm((Q - 1) / 8 + 1)); // bound too large -> rejected
    }
}

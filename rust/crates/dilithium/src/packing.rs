//! Serialization of keys and signatures.
//!
//! Rust port of `ref/packing.c` and `ref/packing.h` (T-021 / T-022).
//!
//! The C functions wrote through output pointers and advanced them; the Rust
//! versions return owned fixed-size byte arrays (keys/signatures) or owned
//! vectors of polynomials (on unpack). `unpack_sig` returns `None` for a
//! malformed signature, mirroring the C return value `1`.
//!
//! Byte layouts are identical to the reference, so keys and signatures are
//! wire-compatible with the C implementation.

// Indexed loops mirror the C reference's offset arithmetic.
#![allow(clippy::needless_range_loop)]

use crate::params::{
    CRYPTO_BYTES, CRYPTO_PUBLICKEYBYTES, CRYPTO_SECRETKEYBYTES, CTILDEBYTES, K, L, N, OMEGA,
    POLYETA_PACKEDBYTES, POLYT0_PACKEDBYTES, POLYT1_PACKEDBYTES, POLYZ_PACKEDBYTES, SEEDBYTES,
    TRBYTES,
};
use crate::poly::Poly;
use crate::polyvec::{Polyveck, Polyvecl};

/// Bit-pack the public key `pk = (rho, t1)`. Port of `pack_pk`.
pub fn pack_pk(rho: &[u8; SEEDBYTES], t1: &Polyveck) -> [u8; CRYPTO_PUBLICKEYBYTES] {
    let mut pk = [0u8; CRYPTO_PUBLICKEYBYTES];
    pk[..SEEDBYTES].copy_from_slice(rho);
    for i in 0..K {
        let off = SEEDBYTES + i * POLYT1_PACKEDBYTES;
        t1.vec[i].t1_pack(&mut pk[off..off + POLYT1_PACKEDBYTES]);
    }
    pk
}

/// Unpack the public key `pk = (rho, t1)`. Port of `unpack_pk`.
pub fn unpack_pk(pk: &[u8; CRYPTO_PUBLICKEYBYTES]) -> ([u8; SEEDBYTES], Polyveck) {
    let mut rho = [0u8; SEEDBYTES];
    rho.copy_from_slice(&pk[..SEEDBYTES]);
    let mut t1 = Polyveck::default();
    for i in 0..K {
        let off = SEEDBYTES + i * POLYT1_PACKEDBYTES;
        t1.vec[i] = Poly::t1_unpack(&pk[off..off + POLYT1_PACKEDBYTES]);
    }
    (rho, t1)
}

/// Bit-pack the secret key `sk = (rho, key, tr, s1, s2, t0)`. Port of `pack_sk`.
pub fn pack_sk(
    rho: &[u8; SEEDBYTES],
    tr: &[u8; TRBYTES],
    key: &[u8; SEEDBYTES],
    t0: &Polyveck,
    s1: &Polyvecl,
    s2: &Polyveck,
) -> [u8; CRYPTO_SECRETKEYBYTES] {
    let mut sk = [0u8; CRYPTO_SECRETKEYBYTES];
    let mut o = 0;

    sk[o..o + SEEDBYTES].copy_from_slice(rho);
    o += SEEDBYTES;
    sk[o..o + SEEDBYTES].copy_from_slice(key);
    o += SEEDBYTES;
    sk[o..o + TRBYTES].copy_from_slice(tr);
    o += TRBYTES;

    for i in 0..L {
        let off = o + i * POLYETA_PACKEDBYTES;
        s1.vec[i].eta_pack(&mut sk[off..off + POLYETA_PACKEDBYTES]);
    }
    o += L * POLYETA_PACKEDBYTES;

    for i in 0..K {
        let off = o + i * POLYETA_PACKEDBYTES;
        s2.vec[i].eta_pack(&mut sk[off..off + POLYETA_PACKEDBYTES]);
    }
    o += K * POLYETA_PACKEDBYTES;

    for i in 0..K {
        let off = o + i * POLYT0_PACKEDBYTES;
        t0.vec[i].t0_pack(&mut sk[off..off + POLYT0_PACKEDBYTES]);
    }
    sk
}

/// Unpack the secret key. Returns `(rho, tr, key, t0, s1, s2)`.
/// Port of `unpack_sk`.
#[allow(clippy::type_complexity)]
pub fn unpack_sk(
    sk: &[u8; CRYPTO_SECRETKEYBYTES],
) -> (
    [u8; SEEDBYTES],
    [u8; TRBYTES],
    [u8; SEEDBYTES],
    Polyveck,
    Polyvecl,
    Polyveck,
) {
    let mut rho = [0u8; SEEDBYTES];
    let mut key = [0u8; SEEDBYTES];
    let mut tr = [0u8; TRBYTES];
    let mut o = 0;

    rho.copy_from_slice(&sk[o..o + SEEDBYTES]);
    o += SEEDBYTES;
    key.copy_from_slice(&sk[o..o + SEEDBYTES]);
    o += SEEDBYTES;
    tr.copy_from_slice(&sk[o..o + TRBYTES]);
    o += TRBYTES;

    let mut s1 = Polyvecl::default();
    for i in 0..L {
        let off = o + i * POLYETA_PACKEDBYTES;
        s1.vec[i] = Poly::eta_unpack(&sk[off..off + POLYETA_PACKEDBYTES]);
    }
    o += L * POLYETA_PACKEDBYTES;

    let mut s2 = Polyveck::default();
    for i in 0..K {
        let off = o + i * POLYETA_PACKEDBYTES;
        s2.vec[i] = Poly::eta_unpack(&sk[off..off + POLYETA_PACKEDBYTES]);
    }
    o += K * POLYETA_PACKEDBYTES;

    let mut t0 = Polyveck::default();
    for i in 0..K {
        let off = o + i * POLYT0_PACKEDBYTES;
        t0.vec[i] = Poly::t0_unpack(&sk[off..off + POLYT0_PACKEDBYTES]);
    }

    (rho, tr, key, t0, s1, s2)
}

/// Bit-pack the signature `sig = (c, z, h)`. Port of `pack_sig`.
pub fn pack_sig(c: &[u8; CTILDEBYTES], z: &Polyvecl, h: &Polyveck) -> [u8; CRYPTO_BYTES] {
    let mut sig = [0u8; CRYPTO_BYTES];
    sig[..CTILDEBYTES].copy_from_slice(c);

    let zoff = CTILDEBYTES;
    for i in 0..L {
        let off = zoff + i * POLYZ_PACKEDBYTES;
        z.vec[i].z_pack(&mut sig[off..off + POLYZ_PACKEDBYTES]);
    }

    // Encode the hint h into the trailing OMEGA + K bytes (already zeroed).
    let hoff = CTILDEBYTES + L * POLYZ_PACKEDBYTES;
    let mut k = 0usize;
    for i in 0..K {
        for j in 0..N {
            if h.vec[i].coeffs[j] != 0 {
                sig[hoff + k] = j as u8;
                k += 1;
            }
        }
        sig[hoff + OMEGA + i] = k as u8;
    }
    sig
}

/// Unpack the signature `sig = (c, z, h)`. Returns `None` if malformed
/// (mirrors the C return value `1`). Port of `unpack_sig`.
pub fn unpack_sig(sig: &[u8; CRYPTO_BYTES]) -> Option<([u8; CTILDEBYTES], Polyvecl, Polyveck)> {
    let mut c = [0u8; CTILDEBYTES];
    c.copy_from_slice(&sig[..CTILDEBYTES]);

    let zoff = CTILDEBYTES;
    let mut z = Polyvecl::default();
    for i in 0..L {
        let off = zoff + i * POLYZ_PACKEDBYTES;
        z.vec[i] = Poly::z_unpack(&sig[off..off + POLYZ_PACKEDBYTES]);
    }

    // Decode h.
    let hint = &sig[CTILDEBYTES + L * POLYZ_PACKEDBYTES..];
    let mut h = Polyveck::default();
    let mut k = 0usize;
    for i in 0..K {
        let cnt = hint[OMEGA + i] as usize;
        if cnt < k || cnt > OMEGA {
            return None;
        }
        for j in k..cnt {
            // Coefficients must be strictly increasing (strong unforgeability).
            if j > k && hint[j] <= hint[j - 1] {
                return None;
            }
            h.vec[i].coeffs[hint[j] as usize] = 1;
        }
        k = cnt;
    }
    // Extra trailing positions must be zero (strong unforgeability).
    for j in k..OMEGA {
        if hint[j] != 0 {
            return None;
        }
    }

    Some((c, z, h))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::CRHBYTES;

    fn seed(n: u8) -> [u8; SEEDBYTES] {
        core::array::from_fn(|i| (i as u8).wrapping_mul(n).wrapping_add(n))
    }
    fn crh(n: u8) -> [u8; CRHBYTES] {
        core::array::from_fn(|i| (i as u8).wrapping_mul(n).wrapping_add(1))
    }

    #[test]
    fn pk_roundtrip() {
        let rho = seed(3);
        let mut t1 = Polyveck::default();
        for i in 0..K {
            // t1 coefficients are 10-bit standard representatives.
            t1.vec[i] = Poly::t1_unpack(&{
                let mut b = [0u8; POLYT1_PACKEDBYTES];
                for (j, x) in b.iter_mut().enumerate() {
                    *x = (i + j) as u8;
                }
                b
            });
        }
        let pk = pack_pk(&rho, &t1);
        let (rho2, t1b) = unpack_pk(&pk);
        assert_eq!(rho, rho2);
        assert_eq!(t1, t1b);
    }

    #[test]
    fn sk_roundtrip() {
        let rho = seed(2);
        let key = seed(5);
        let tr: [u8; TRBYTES] = core::array::from_fn(|i| (i as u8) ^ 0x5A);
        let s1 = Polyvecl::uniform_eta(&crh(7), 0);
        let s2 = Polyveck::uniform_eta(&crh(7), L as u16);
        // t0 in (-2^{D-1}, 2^{D-1}].
        let mut t0 = Polyveck::default();
        let half = 1 << (crate::params::D - 1);
        for i in 0..K {
            for j in 0..N {
                t0.vec[i].coeffs[j] = half - (((i + j) as i32 * 13) % (2 * half));
            }
        }

        let sk = pack_sk(&rho, &tr, &key, &t0, &s1, &s2);
        let (rho2, tr2, key2, t0b, s1b, s2b) = unpack_sk(&sk);
        assert_eq!((rho, tr, key), (rho2, tr2, key2));
        assert_eq!(t0, t0b);
        assert_eq!(s1, s1b);
        assert_eq!(s2, s2b);
    }

    #[test]
    fn sig_roundtrip() {
        let c: [u8; CTILDEBYTES] = core::array::from_fn(|i| i as u8);
        let z = Polyvecl::uniform_gamma1(&crh(9), 0);

        // Build a sparse, validly-ordered hint vector (<= OMEGA ones total).
        let mut h = Polyveck::default();
        let mut placed = 0;
        'outer: for i in 0..K {
            for j in (0..N).step_by(40) {
                if placed >= OMEGA {
                    break 'outer;
                }
                h.vec[i].coeffs[j] = 1;
                placed += 1;
            }
        }

        let sig = pack_sig(&c, &z, &h);
        let (c2, z2, h2) = unpack_sig(&sig).expect("valid signature");
        assert_eq!(c, c2);
        assert_eq!(z, z2);
        assert_eq!(h, h2);
    }

    #[test]
    fn unpack_sig_rejects_bad_hint() {
        let c = [0u8; CTILDEBYTES];
        let z = Polyvecl::default();
        let h = Polyveck::default();
        let mut sig = pack_sig(&c, &z, &h);
        // Corrupt the last count byte to exceed OMEGA.
        let last = CRYPTO_BYTES - 1;
        sig[last] = (OMEGA + 1) as u8;
        assert!(unpack_sig(&sig).is_none());
    }
}

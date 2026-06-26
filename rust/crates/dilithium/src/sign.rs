//! The Dilithium signature scheme: key generation, signing, verification.
//!
//! Rust port of `ref/sign.c` and `ref/sign.h` (T-023 / T-024).
//!
//! These functions implement the algorithm faithfully (same hashing, same
//! rejection-sampling loop, same byte layouts) and are the real bodies behind
//! the public API in [`crate::api`]. All the `mu` / `rhoprime` / challenge-hash
//! computations use one-shot SHAKE256 over a concatenated buffer, which is
//! equivalent to the C reference's sequential `absorb` calls.

use crate::api::{Error, PublicKey, SecretKey, Signature};
use crate::config::RANDOMIZED_SIGNING;
use crate::fips202::shake256;
use crate::packing;
use crate::params::*;
use crate::poly::Poly;
use crate::polyvec::{matrix_expand, matrix_pointwise_montgomery, Polyveck, Polyvecl};
use crate::randombytes::randombytes;
use subtle::ConstantTimeEq;

/// Generate a key pair from a 32-byte seed `zeta` (deterministic).
///
/// Port of the body of `crypto_sign_keypair`, factored out so tests and KATs
/// can supply a fixed seed. Returns `(pk, sk)`.
pub fn keypair_from_seed(zeta: &[u8; SEEDBYTES]) -> (PublicKey, SecretKey) {
    // Expand zeta||K||L into (rho, rhoprime, key).
    let mut inbuf = [0u8; SEEDBYTES + 2];
    inbuf[..SEEDBYTES].copy_from_slice(zeta);
    inbuf[SEEDBYTES] = K as u8;
    inbuf[SEEDBYTES + 1] = L as u8;

    let mut seedbuf = [0u8; 2 * SEEDBYTES + CRHBYTES];
    shake256(&mut seedbuf, &inbuf);

    let mut rho = [0u8; SEEDBYTES];
    let mut rhoprime = [0u8; CRHBYTES];
    let mut key = [0u8; SEEDBYTES];
    rho.copy_from_slice(&seedbuf[..SEEDBYTES]);
    rhoprime.copy_from_slice(&seedbuf[SEEDBYTES..SEEDBYTES + CRHBYTES]);
    key.copy_from_slice(&seedbuf[SEEDBYTES + CRHBYTES..]);

    // A = ExpandA(rho); short secret vectors s1, s2.
    let mat = matrix_expand(&rho);
    let s1 = Polyvecl::uniform_eta(&rhoprime, 0);
    let s2 = Polyveck::uniform_eta(&rhoprime, L as u16);

    // t = A*s1 + s2.
    let mut s1hat = s1.clone();
    s1hat.ntt();
    let mut t = matrix_pointwise_montgomery(&mat, &s1hat);
    t.reduce();
    t.invntt_tomont();
    let mut t = t.add(&s2);

    // (t1, t0) = Power2Round(t).
    t.caddq();
    let (t1, t0) = t.power2round();

    let pk = packing::pack_pk(&rho, &t1);
    let mut tr = [0u8; TRBYTES];
    shake256(&mut tr, &pk);
    let sk = packing::pack_sk(&rho, &tr, &key, &t0, &s1, &s2);
    (pk, sk)
}

/// Generate a key pair using the system RNG. Port of `crypto_sign_keypair`.
pub fn keypair() -> (PublicKey, SecretKey) {
    let mut zeta = [0u8; SEEDBYTES];
    randombytes(&mut zeta);
    keypair_from_seed(&zeta)
}

/// Core signing routine. Port of `crypto_sign_signature_internal`.
///
/// `pre` is the prefix `(0, ctxlen, ctx)` and `rnd` is the per-signature seed.
fn signature_internal(m: &[u8], pre: &[u8], rnd: &[u8; RNDBYTES], sk: &SecretKey) -> Signature {
    let (rho, tr, key, mut t0, mut s1, mut s2) = packing::unpack_sk(sk);

    // mu = CRH(tr || pre || m).
    let mut mu = [0u8; CRHBYTES];
    {
        let mut buf = Vec::with_capacity(TRBYTES + pre.len() + m.len());
        buf.extend_from_slice(&tr);
        buf.extend_from_slice(pre);
        buf.extend_from_slice(m);
        shake256(&mut mu, &buf);
    }

    // rhoprime = CRH(key || rnd || mu).
    let mut rhoprime = [0u8; CRHBYTES];
    {
        let mut buf = [0u8; SEEDBYTES + RNDBYTES + CRHBYTES];
        buf[..SEEDBYTES].copy_from_slice(&key);
        buf[SEEDBYTES..SEEDBYTES + RNDBYTES].copy_from_slice(rnd);
        buf[SEEDBYTES + RNDBYTES..].copy_from_slice(&mu);
        shake256(&mut rhoprime, &buf);
    }

    let mat = matrix_expand(&rho);
    s1.ntt();
    s2.ntt();
    t0.ntt();

    let mut nonce = 0u16;
    loop {
        // y <- ExpandMask; w = A*y.
        let y = Polyvecl::uniform_gamma1(&rhoprime, nonce);
        nonce = nonce.wrapping_add(1);

        let mut z = y.clone();
        z.ntt();
        let mut w1 = matrix_pointwise_montgomery(&mat, &z);
        w1.reduce();
        w1.invntt_tomont();

        // Decompose w and derive the challenge.
        w1.caddq();
        let (w1, w0) = w1.decompose();

        let mut w1packed = [0u8; K * POLYW1_PACKEDBYTES];
        w1.pack_w1(&mut w1packed);

        let mut ctilde = [0u8; CTILDEBYTES];
        {
            let mut buf = [0u8; CRHBYTES + K * POLYW1_PACKEDBYTES];
            buf[..CRHBYTES].copy_from_slice(&mu);
            buf[CRHBYTES..].copy_from_slice(&w1packed);
            shake256(&mut ctilde, &buf);
        }
        let mut cp = Poly::challenge(&ctilde);
        cp.ntt();

        // z = y + c*s1; reject if it leaks the secret.
        let mut z = s1.pointwise_poly_montgomery(&cp);
        z.invntt_tomont();
        let mut z = z.add(&y);
        z.reduce();
        if z.chknorm(GAMMA1 - BETA) {
            continue;
        }

        // Check that subtracting c*s2 keeps w's high bits / low bits safe.
        let mut h = s2.pointwise_poly_montgomery(&cp);
        h.invntt_tomont();
        let mut w0 = w0.sub(&h);
        w0.reduce();
        if w0.chknorm(GAMMA2 - BETA) {
            continue;
        }

        // Compute c*t0; reject if too large, then build the hint.
        let mut ct0 = t0.pointwise_poly_montgomery(&cp);
        ct0.invntt_tomont();
        ct0.reduce();
        if ct0.chknorm(GAMMA2) {
            continue;
        }

        let w0 = w0.add(&ct0);
        let (h, n) = Polyveck::make_hint(&w0, &w1);
        if n > OMEGA {
            continue;
        }

        return packing::pack_sig(&ctilde, &z, &h);
    }
}

/// Build the prefix `pre = (0, ctxlen, ctx)`, or `Err` if `ctx` is too long.
fn make_pre(ctx: &[u8]) -> Result<Vec<u8>, Error> {
    if ctx.len() > 255 {
        return Err(Error::ContextTooLong);
    }
    let mut pre = Vec::with_capacity(2 + ctx.len());
    pre.push(0);
    pre.push(ctx.len() as u8);
    pre.extend_from_slice(ctx);
    Ok(pre)
}

/// Produce a detached signature over `m` with context `ctx`.
/// Port of `crypto_sign_signature`.
pub fn signature(m: &[u8], ctx: &[u8], sk: &SecretKey) -> Result<Signature, Error> {
    let pre = make_pre(ctx)?;

    let mut rnd = [0u8; RNDBYTES];
    if RANDOMIZED_SIGNING {
        randombytes(&mut rnd);
    } // else: deterministic, rnd stays all-zero.

    Ok(signature_internal(m, &pre, &rnd, sk))
}

/// Produce a detached signature with an explicitly supplied `rnd`.
///
/// This is the deterministic counterpart of [`signature`] (which draws `rnd`
/// from the system RNG). It exists so KAT generation can feed `rnd` from the
/// NIST DRBG and reproduce the reference's randomized-signing byte stream.
pub fn signature_deterministic(
    m: &[u8],
    ctx: &[u8],
    rnd: &[u8; RNDBYTES],
    sk: &SecretKey,
) -> Result<Signature, Error> {
    let pre = make_pre(ctx)?;
    Ok(signature_internal(m, &pre, rnd, sk))
}

/// Produce an attached signed message `sig ‖ m`. Port of `crypto_sign`.
pub fn sign_message(m: &[u8], ctx: &[u8], sk: &SecretKey) -> Result<Vec<u8>, Error> {
    let sig = signature(m, ctx, sk)?;
    let mut sm = Vec::with_capacity(CRYPTO_BYTES + m.len());
    sm.extend_from_slice(&sig);
    sm.extend_from_slice(m);
    Ok(sm)
}

/// Core verification routine. Returns `true` if the signature is valid.
/// Port of `crypto_sign_verify_internal`.
fn verify_internal(sig: &Signature, m: &[u8], pre: &[u8], pk: &PublicKey) -> bool {
    let (rho, t1) = packing::unpack_pk(pk);
    let (c, mut z, h) = match packing::unpack_sig(sig) {
        Some(parts) => parts,
        None => return false,
    };
    if z.chknorm(GAMMA1 - BETA) {
        return false;
    }

    // mu = CRH(H(pk) || pre || m).
    let mut mu = [0u8; CRHBYTES];
    {
        let mut trpk = [0u8; TRBYTES];
        shake256(&mut trpk, pk);
        let mut buf = Vec::with_capacity(TRBYTES + pre.len() + m.len());
        buf.extend_from_slice(&trpk);
        buf.extend_from_slice(pre);
        buf.extend_from_slice(m);
        shake256(&mut mu, &buf);
    }

    // w1' = UseHint(h, A*z - c*t1*2^d).
    let mut cp = Poly::challenge(&c);
    let mat = matrix_expand(&rho);

    z.ntt();
    let w1 = matrix_pointwise_montgomery(&mat, &z);

    cp.ntt();
    let mut t1 = t1;
    t1.shiftl();
    t1.ntt();
    let ct1 = t1.pointwise_poly_montgomery(&cp);

    let mut w1 = w1.sub(&ct1);
    w1.reduce();
    w1.invntt_tomont();
    w1.caddq();
    let w1 = w1.use_hint(&h);

    let mut buf = [0u8; K * POLYW1_PACKEDBYTES];
    w1.pack_w1(&mut buf);

    // c2 = H(mu || w1') and compare to the received challenge.
    let mut c2 = [0u8; CTILDEBYTES];
    {
        let mut hb = [0u8; CRHBYTES + K * POLYW1_PACKEDBYTES];
        hb[..CRHBYTES].copy_from_slice(&mu);
        hb[CRHBYTES..].copy_from_slice(&buf);
        shake256(&mut c2, &hb);
    }
    // Constant-time challenge comparison (T-098): no early-out on the first
    // differing byte. Both values are public during verification, so this is
    // defensive hardening rather than a secret-protecting requirement.
    bool::from(c[..].ct_eq(&c2[..]))
}

/// Verify a detached signature. Port of `crypto_sign_verify`.
pub fn verify(sig: &Signature, m: &[u8], ctx: &[u8], pk: &PublicKey) -> Result<(), Error> {
    let pre = make_pre(ctx)?;
    if verify_internal(sig, m, &pre, pk) {
        Ok(())
    } else {
        Err(Error::InvalidSignature)
    }
}

/// Verify an attached signed message and recover `m`. Port of `crypto_sign_open`.
pub fn open(sm: &[u8], ctx: &[u8], pk: &PublicKey) -> Result<Vec<u8>, Error> {
    if sm.len() < CRYPTO_BYTES {
        return Err(Error::InvalidSignature);
    }
    let (sig_bytes, msg) = sm.split_at(CRYPTO_BYTES);
    let sig: &Signature = sig_bytes.try_into().expect("split at CRYPTO_BYTES");
    verify(sig, msg, ctx, pk)?;
    Ok(msg.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keygen_sign_verify_roundtrip() {
        for i in 0u8..4 {
            let zeta: [u8; SEEDBYTES] = core::array::from_fn(|j| (j as u8).wrapping_add(i));
            let (pk, sk) = keypair_from_seed(&zeta);

            let msg = [i; 59];
            let ctx = b"test-context";

            let sig = signature(&msg, ctx, &sk).expect("sign");
            assert!(
                verify(&sig, &msg, ctx, &pk).is_ok(),
                "valid signature must verify"
            );

            // Wrong message rejected.
            assert!(verify(&sig, b"different message", ctx, &pk).is_err());
            // Wrong context rejected.
            assert!(verify(&sig, &msg, b"other-context", &pk).is_err());
            // Tampered signature rejected.
            let mut bad = sig;
            bad[0] ^= 1;
            assert!(verify(&bad, &msg, ctx, &pk).is_err());
        }
    }

    #[test]
    fn attached_sign_open_roundtrip() {
        let (pk, sk) = keypair();
        let msg = b"attached message body";

        let sm = sign_message(msg, b"", &sk).expect("sign_message");
        assert_eq!(sm.len(), CRYPTO_BYTES + msg.len());

        let recovered = open(&sm, b"", &pk).expect("open");
        assert_eq!(recovered, msg);

        // Truncated / corrupted signed messages are rejected.
        assert!(open(&sm[..CRYPTO_BYTES - 1], b"", &pk).is_err());
        let mut tampered = sm.clone();
        tampered[0] ^= 0xFF;
        assert!(open(&tampered, b"", &pk).is_err());
    }

    #[test]
    fn context_too_long_is_error() {
        let (_pk, sk) = keypair();
        let long_ctx = [0u8; 256];
        assert_eq!(signature(b"m", &long_ctx, &sk), Err(Error::ContextTooLong));
    }

    #[test]
    fn different_keys_reject() {
        let (_pk_a, sk_a) = keypair_from_seed(&[1u8; SEEDBYTES]);
        let (pk_b, _sk_b) = keypair_from_seed(&[2u8; SEEDBYTES]);
        let sig = signature(b"hello", b"", &sk_a).expect("sign");
        assert!(verify(&sig, b"hello", b"", &pk_b).is_err());
    }
}

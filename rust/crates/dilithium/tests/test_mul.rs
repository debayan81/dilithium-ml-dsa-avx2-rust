//! NTT multiplication correctness test.
//!
//! Rust port of `ref/test/test_mul.c` (T-062). Checks the NTT/inverse-NTT
//! round-trip and that pointwise-Montgomery multiplication in the NTT domain
//! matches negacyclic schoolbook multiplication mod `Q`.
//!
//! Run per parameter set, e.g.:
//!   cargo test --test test_mul --no-default-features --features dilithium3

// Indexed loops mirror the C reference (`poly_naivemul`).
#![allow(clippy::needless_range_loop)]

use dilithium::params::{N, Q, SEEDBYTES};
use dilithium::poly::Poly;
use dilithium::reduce::freeze;

const QI64: i64 = Q as i64;

fn modq(x: i64) -> i64 {
    ((x % QI64) + QI64) % QI64
}

/// Negacyclic schoolbook multiplication mod Q (mirrors `poly_naivemul`).
fn naivemul(a: &Poly, b: &Poly) -> Poly {
    let mut r = [0i64; 2 * N];
    for i in 0..N {
        for j in 0..N {
            r[i + j] = (r[i + j] + a.coeffs[i] as i64 * b.coeffs[j] as i64) % QI64;
        }
    }
    for i in N..2 * N {
        r[i - N] = (r[i - N] - r[i]) % QI64;
    }
    let mut c = Poly::default();
    for i in 0..N {
        c.coeffs[i] = r[i] as i32;
    }
    c
}

#[test]
fn ntt_multiplication_matches_schoolbook() {
    let seed = [0x42u8; SEEDBYTES];
    let mut nonce = 0u16;

    for _ in 0..128 {
        let a = Poly::uniform(&seed, nonce);
        nonce += 1;
        let b = Poly::uniform(&seed, nonce);
        nonce += 1;

        // NTT round-trip: ntt -> scale by -114592 -> invntt_tomont == identity.
        let mut c = a;
        c.ntt();
        for x in c.coeffs.iter_mut() {
            *x = (*x as i64 * -114592 % QI64) as i32;
        }
        c.invntt_tomont();
        for j in 0..N {
            assert_eq!(
                modq(c.coeffs[j] as i64),
                modq(a.coeffs[j] as i64),
                "ntt/invntt at {j}"
            );
        }

        // Multiplication: pointwise-montgomery in NTT domain == schoolbook.
        let want = naivemul(&a, &b);
        let mut na = a;
        let mut nb = b;
        na.ntt();
        nb.ntt();
        let mut d = na.pointwise_montgomery(&nb);
        d.invntt_tomont();
        for j in 0..N {
            assert_eq!(freeze(d.coeffs[j]), freeze(want.coeffs[j]), "mul at {j}");
        }
    }
}

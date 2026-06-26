//! End-to-end correctness test: keygen, sign, open, forgery detection.
//!
//! Rust port of `ref/test/test_dilithium.c` (T-060). For each iteration it
//! generates a key pair, signs a random message, opens it, checks the recovered
//! message, then flips a random byte of the signed message and asserts that
//! opening now fails (no trivial forgeries).
//!
//! Run per parameter set, e.g.:
//!   cargo test --test test_dilithium --no-default-features --features dilithium5

use dilithium::api::{keypair, open, sign_attached};
use dilithium::params::CRYPTO_BYTES;
use dilithium::randombytes::randombytes;

const MLEN: usize = 59;
// Fewer than the C reference's 10000 to keep the test fast; still exercises the
// full keygen/sign/open path (with its rejection-sampling loop) many times.
const NTESTS: usize = 48;

#[test]
fn sign_open_and_forgery_detection() {
    let ctx = b"test_dilithium-ctx";

    for _ in 0..NTESTS {
        let mut m = [0u8; MLEN];
        randombytes(&mut m);

        let (pk, sk) = keypair();
        let sm = sign_attached(&m, ctx, &sk).expect("sign");
        assert_eq!(sm.len(), MLEN + CRYPTO_BYTES, "signed message length");

        let recovered = open(&sm, ctx, &pk).expect("open valid signed message");
        assert_eq!(recovered, m.to_vec(), "recovered message must match");

        // Forgery: add a nonzero delta to a random byte; opening must fail.
        let mut sm_bad = sm.clone();
        let mut idx = [0u8; 8];
        randombytes(&mut idx);
        let pos = usize::from_le_bytes(idx) % sm_bad.len();
        let mut delta = [0u8; 1];
        loop {
            randombytes(&mut delta);
            if delta[0] != 0 {
                break;
            }
        }
        sm_bad[pos] = sm_bad[pos].wrapping_add(delta[0]);

        assert!(
            open(&sm_bad, ctx, &pk).is_err(),
            "trivial forgery possible (pos {pos})"
        );
    }
}

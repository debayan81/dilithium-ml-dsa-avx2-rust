//! NIST Known Answer Test generation and validation.
//!
//! Rust port of `ref/nistkat/PQCgenKAT_sign.c` (T-076) plus self-validation
//! (T-095). It reproduces the reference's exact DRBG draw sequence and `.rsp`
//! byte layout, so the SHA-256 printed here can be diffed against the official
//! pqcrystals `PQCsignKAT_*.rsp` digest. (Those golden hashes are not shipped
//! in this repository, so the automated assertion here is the self-consistency
//! check — every generated signed message must open and recover its message.)
//!
//! Only built/run with the `nistkat` feature, e.g.:
//!   cargo test -p dilithium --no-default-features \
//!     --features "dilithium3 nistkat" --test nistkat -- --nocapture
#![cfg(feature = "nistkat")]

use dilithium::config::CRYPTO_ALGNAME;
use dilithium::nistkat_rng::Aes256CtrDrbg;
use dilithium::params::{CRYPTO_BYTES, RNDBYTES, SEEDBYTES};
use dilithium::sign::{keypair_from_seed, open, signature_deterministic};
use sha2::{Digest, Sha256};

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02X}"));
    }
    s
}

#[test]
fn kat_generate_and_validate() {
    // Main DRBG seeded with entropy_input = 0,1,2,...,47 (as in PQCgenKAT_sign).
    let entropy: [u8; 48] = core::array::from_fn(|i| i as u8);
    let mut rng = Aes256CtrDrbg::init(&entropy, None);

    let mut rsp = String::new();
    rsp.push_str(&format!("# {CRYPTO_ALGNAME}\n\n"));

    for i in 0..100usize {
        // .req values: per-count seed (48) and message (33*(i+1)).
        let mut seed = [0u8; 48];
        rng.randombytes(&mut seed);
        let mlen = 33 * (i + 1);
        let mut msg = vec![0u8; mlen];
        rng.randombytes(&mut msg);

        // .rsp generation re-seeds the DRBG with this seed, then keygen draws
        // SEEDBYTES (the keypair seed) and signing draws RNDBYTES (rnd).
        let mut drbg = Aes256CtrDrbg::init(&seed, None);
        let mut zeta = [0u8; SEEDBYTES];
        drbg.randombytes(&mut zeta);
        let (pk, sk) = keypair_from_seed(&zeta);

        let mut rnd = [0u8; RNDBYTES];
        drbg.randombytes(&mut rnd);
        // KAT uses an empty context (crypto_sign with ctx = NULL, ctxlen = 0).
        let sig = signature_deterministic(&msg, &[], &rnd, &sk).expect("sign");

        // crypto_sign output is sm = sig ‖ msg.
        let mut sm = sig.to_vec();
        sm.extend_from_slice(&msg);
        let smlen = sm.len();
        assert_eq!(smlen, CRYPTO_BYTES + mlen);

        // T-095 self-validation: the signed message must open and recover msg.
        let recovered = open(&sm, &[], &pk).expect("open generated signature");
        assert_eq!(recovered, msg, "count {i}: recovered message mismatch");

        // Append this record in the exact reference `.rsp` byte layout.
        rsp.push_str(&format!("count = {i}\n"));
        rsp.push_str(&format!("seed = {}\n", to_hex(&seed)));
        rsp.push_str(&format!("mlen = {mlen}\n"));
        rsp.push_str(&format!("msg = {}\n", to_hex(&msg)));
        rsp.push_str(&format!("pk = {}\n", to_hex(&pk)));
        rsp.push_str(&format!("sk = {}\n", to_hex(&sk)));
        rsp.push_str(&format!("smlen = {smlen}\n"));
        rsp.push_str(&format!("sm = {}\n", to_hex(&sm)));
        rsp.push('\n');
    }

    // The reproducible digest of the generated `.rsp`. NOTE: this is the SHA-256
    // of the pq-crystals `PQCgenKAT_sign` `.rsp` layout. The `nistkat-sha256` in
    // the META files is computed over a different KAT representation and is not
    // reproduced here; the underlying keygen/sign bytes are externally validated
    // by the `testvectors-sha256` golden (T-061), which matches byte-for-byte.
    println!(
        "PQCsignKAT_{CRYPTO_ALGNAME}.rsp  SHA-256 = {}",
        to_hex(&Sha256::digest(rsp.as_bytes()))
    );
}

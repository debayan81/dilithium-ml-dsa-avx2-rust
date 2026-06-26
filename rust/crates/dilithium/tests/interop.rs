//! Cross-implementation interop test: Rust <-> C reference (T-094).
//!
//! With the `interop` feature, `build.rs` compiles and links the pq-crystals
//! `ref/` C (minus `randombytes.c`). This test provides a deterministic
//! `randombytes` from Rust, then checks both directions:
//!   * Rust signs  -> the C reference verifies/opens it.
//!   * C signs      -> the Rust implementation verifies/opens it.
//!
//! A match confirms the two implementations are wire-compatible (which T-061
//! already implies via byte-identical output, but this exercises it directly
//! through the C code over FFI).
//!
//! Run, e.g.:
//!   cargo test -p dilithium --no-default-features \
//!     --features "dilithium3 interop" --test interop
#![cfg(feature = "interop")]
// FFI to the linked C reference necessarily uses `unsafe`; the crate otherwise
// forbids it (see the package `[lints]`).
#![allow(unsafe_code)]

use dilithium::api::{PUBLICKEYBYTES, SECRETKEYBYTES, SIGNBYTES};
use dilithium::params::SEEDBYTES;
use dilithium::sign::{keypair_from_seed, open, sign_message};
use std::sync::atomic::{AtomicU32, Ordering};

/// Deterministic `randombytes` for the linked C reference (which is built
/// without `randombytes.c`). Any byte stream yields valid keys/signatures; a
/// small PRNG keeps the test reproducible.
///
/// # Safety
/// `out` must point to at least `outlen` writable bytes. The C reference always
/// calls it with a valid buffer of the requested length.
#[no_mangle]
pub unsafe extern "C" fn randombytes(out: *mut u8, outlen: usize) {
    static STATE: AtomicU32 = AtomicU32::new(0x1234_5678);
    let buf = core::slice::from_raw_parts_mut(out, outlen);
    for b in buf.iter_mut() {
        let mut v = STATE.fetch_add(0x9E37_79B9, Ordering::Relaxed);
        v ^= v >> 13;
        v = v.wrapping_mul(0x5bd1_e995);
        v ^= v >> 15;
        *b = v as u8;
    }
}

// Namespaced C symbols depend on the parameter set (-DDILITHIUM_MODE).
#[cfg(feature = "dilithium2")]
extern "C" {
    #[link_name = "pqcrystals_dilithium2_ref_keypair"]
    fn c_keypair(pk: *mut u8, sk: *mut u8) -> i32;
    #[link_name = "pqcrystals_dilithium2_ref"]
    fn c_sign(
        sm: *mut u8,
        smlen: *mut usize,
        m: *const u8,
        mlen: usize,
        ctx: *const u8,
        ctxlen: usize,
        sk: *const u8,
    ) -> i32;
    #[link_name = "pqcrystals_dilithium2_ref_open"]
    fn c_open(
        m: *mut u8,
        mlen: *mut usize,
        sm: *const u8,
        smlen: usize,
        ctx: *const u8,
        ctxlen: usize,
        pk: *const u8,
    ) -> i32;
}
#[cfg(feature = "dilithium3")]
extern "C" {
    #[link_name = "pqcrystals_dilithium3_ref_keypair"]
    fn c_keypair(pk: *mut u8, sk: *mut u8) -> i32;
    #[link_name = "pqcrystals_dilithium3_ref"]
    fn c_sign(
        sm: *mut u8,
        smlen: *mut usize,
        m: *const u8,
        mlen: usize,
        ctx: *const u8,
        ctxlen: usize,
        sk: *const u8,
    ) -> i32;
    #[link_name = "pqcrystals_dilithium3_ref_open"]
    fn c_open(
        m: *mut u8,
        mlen: *mut usize,
        sm: *const u8,
        smlen: usize,
        ctx: *const u8,
        ctxlen: usize,
        pk: *const u8,
    ) -> i32;
}
#[cfg(feature = "dilithium5")]
extern "C" {
    #[link_name = "pqcrystals_dilithium5_ref_keypair"]
    fn c_keypair(pk: *mut u8, sk: *mut u8) -> i32;
    #[link_name = "pqcrystals_dilithium5_ref"]
    fn c_sign(
        sm: *mut u8,
        smlen: *mut usize,
        m: *const u8,
        mlen: usize,
        ctx: *const u8,
        ctxlen: usize,
        sk: *const u8,
    ) -> i32;
    #[link_name = "pqcrystals_dilithium5_ref_open"]
    fn c_open(
        m: *mut u8,
        mlen: *mut usize,
        sm: *const u8,
        smlen: usize,
        ctx: *const u8,
        ctxlen: usize,
        pk: *const u8,
    ) -> i32;
}

#[test]
fn rust_signs_c_verifies() {
    // Rust keypair + attached signature.
    let seed = [7u8; SEEDBYTES];
    let (pk, sk) = keypair_from_seed(&seed);
    let msg = b"interop: rust signs, C verifies";
    let sm = sign_message(msg, b"", &sk).expect("rust sign");

    // The C reference opens it.
    let mut recovered = vec![0u8; sm.len()];
    let mut mlen: usize = 0;
    let rc = unsafe {
        c_open(
            recovered.as_mut_ptr(),
            &mut mlen,
            sm.as_ptr(),
            sm.len(),
            core::ptr::null(),
            0,
            pk.as_ptr(),
        )
    };
    assert_eq!(rc, 0, "C reference rejected a valid Rust signature");
    assert_eq!(&recovered[..mlen], msg, "C recovered the wrong message");
}

#[test]
fn c_signs_rust_verifies() {
    // C keypair + attached signature (uses the Rust-provided randombytes).
    let mut pk = [0u8; PUBLICKEYBYTES];
    let mut sk = [0u8; SECRETKEYBYTES];
    assert_eq!(
        unsafe { c_keypair(pk.as_mut_ptr(), sk.as_mut_ptr()) },
        0,
        "C keypair failed"
    );

    let msg = b"interop: C signs, rust verifies";
    let mut sm = vec![0u8; SIGNBYTES + msg.len()];
    let mut smlen: usize = 0;
    let rc = unsafe {
        c_sign(
            sm.as_mut_ptr(),
            &mut smlen,
            msg.as_ptr(),
            msg.len(),
            core::ptr::null(),
            0,
            sk.as_ptr(),
        )
    };
    assert_eq!(rc, 0, "C sign failed");
    sm.truncate(smlen);

    // The Rust implementation opens it.
    let recovered = open(&sm, b"", &pk).expect("Rust rejected a valid C signature");
    assert_eq!(recovered, msg, "Rust recovered the wrong message");
}

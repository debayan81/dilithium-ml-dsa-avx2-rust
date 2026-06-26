//! Performance benchmarks (T-063..T-067).
//!
//! Rust/Criterion port of `ref/test/test_speed.c` (with `cpucycles.c` /
//! `speed_print.c` replaced by Criterion's timing and reporting). Benchmarks the
//! public keypair/sign/verify API plus the hot internal operations.
//!
//! Run for a given parameter set, e.g.:
//!   cargo bench -p dilithium --no-default-features --features dilithium3
//!
//! (Benchmarks aren't public API, so the package-wide `missing_docs` lint is
//! relaxed for the items Criterion's macros generate.)
#![allow(missing_docs)]

use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use dilithium::api::{keypair, sign, verify};
use dilithium::params::{CRHBYTES, CTILDEBYTES, SEEDBYTES};
use dilithium::poly::Poly;
use dilithium::polyvec::matrix_expand;

fn bench(c: &mut Criterion) {
    let seed32 = [0x12u8; SEEDBYTES];
    let seed64 = [0x34u8; CRHBYTES];
    let cseed = [0x56u8; CTILDEBYTES];

    // --- internal operations (mirror test_speed.c) ---
    c.bench_function("matrix_expand", |b| {
        b.iter(|| matrix_expand(black_box(&seed32)))
    });
    c.bench_function("poly_uniform_eta", |b| {
        b.iter(|| Poly::uniform_eta(black_box(&seed64), 0))
    });
    c.bench_function("poly_uniform_gamma1", |b| {
        b.iter(|| Poly::uniform_gamma1(black_box(&seed64), 0))
    });

    let a = Poly::uniform(&seed32, 0);
    let b_poly = Poly::uniform(&seed32, 1);
    c.bench_function("poly_ntt", |bn| {
        bn.iter_batched(|| a, |mut p| p.ntt(), BatchSize::SmallInput)
    });
    let mut a_ntt = a;
    a_ntt.ntt();
    c.bench_function("poly_invntt_tomont", |bn| {
        bn.iter_batched(|| a_ntt, |mut p| p.invntt_tomont(), BatchSize::SmallInput)
    });
    c.bench_function("poly_pointwise_montgomery", |bn| {
        bn.iter(|| black_box(&a).pointwise_montgomery(black_box(&b_poly)))
    });
    c.bench_function("poly_challenge", |bn| {
        bn.iter(|| Poly::challenge(black_box(&cseed)))
    });

    // --- public API ---
    c.bench_function("keypair", |b| b.iter(keypair));

    let (pk, sk) = keypair();
    let msg = b"dilithium benchmark message";
    c.bench_function("sign", |b| {
        b.iter(|| sign(black_box(msg), b"", &sk).unwrap())
    });

    let sig = sign(msg, b"", &sk).unwrap();
    c.bench_function("verify", |b| {
        b.iter(|| verify(black_box(&sig), msg, b"", &pk).unwrap())
    });
}

criterion_group!(benches, bench);
criterion_main!(benches);

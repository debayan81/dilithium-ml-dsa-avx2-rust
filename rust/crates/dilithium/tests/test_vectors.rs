//! Deterministic test-vector generation, validated against the C reference.
//!
//! Rust port of `ref/test/test_vectors.c` (T-061). It reproduces the reference
//! program's stdout **byte-for-byte** for all 10000 iterations and checks the
//! SHA-256 of that stream against the golden digests in the repository's
//! `SHA256SUMS` (`tvecs2`/`tvecs3`/`tvecs5`). A match proves the whole pipeline
//! — sampling, NTT, rounding, packing, keygen, signing — agrees with the C
//! implementation bit-for-bit.
//!
//! Slow (10000 full iterations); marked `#[ignore]`. Run, in release, per set:
//!   cargo test -p dilithium --release --no-default-features \
//!     --features dilithium2 --test test_vectors -- --ignored --nocapture
#![cfg(test)]
// Indexed loops mirror the C reference's printf structure.
#![allow(clippy::needless_range_loop)]

use dilithium::fips202::{shake256, Shake128Stream};
use dilithium::params::{CRHBYTES, CTILDEBYTES, K, N, RNDBYTES, SEEDBYTES};
use dilithium::poly::Poly;
use dilithium::polyvec::{matrix_expand, matrix_pointwise_montgomery, Polyvecl};
use dilithium::sign::{keypair_from_seed, signature_deterministic};
use sha2::{Digest, Sha256};

const NVECTORS: usize = 10000;

/// Golden SHA-256 of the reference `test_vectors` stdout (from `SHA256SUMS`).
#[cfg(feature = "dilithium2")]
const GOLDEN: &str = "5f0d135c0f7fd43f3fb9727265fcd6ec3651eb8c67c04ea5f3d8dfa1d99740d2";
#[cfg(feature = "dilithium3")]
const GOLDEN: &str = "14bf84918ee90e7afbd580191d3eb890d4557e0900b1145e39a8399ef7dd3fba";
#[cfg(feature = "dilithium5")]
const GOLDEN: &str = "759a3ba35210c7e27ff90a7ce5e399295533b82ef125e6ec98af158e00268e44";

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn hex_upper(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02X}"));
    }
    s
}

/// Format the matrix `A` exactly like the C `printf("%8d", ...)` block.
fn fmt_matrix(out: &mut String, mat: &[Polyvecl; K]) {
    out.push_str("A = ([");
    for j in 0..K {
        for k in 0..mat[j].vec.len() {
            for l in 0..N {
                out.push_str(&format!("{:8}", mat[j].vec[k].coeffs[l]));
                if l < N - 1 {
                    out.push_str(", ");
                } else if k < mat[j].vec.len() - 1 {
                    out.push_str("], [");
                } else if j < K - 1 {
                    out.push_str("];\n     [");
                } else {
                    out.push_str("])\n");
                }
            }
        }
    }
}

/// Format a vector of polynomials (`s`, `y`, `w1`, `w0`, `t1`, `t0`).
fn fmt_vec(out: &mut String, name: &str, vecs: &[Poly], width: usize, indent: &str) {
    out.push_str(name);
    out.push_str(" = ([");
    let len = vecs.len();
    for j in 0..len {
        for k in 0..N {
            out.push_str(&format!("{:width$}", vecs[j].coeffs[k]));
            if k < N - 1 {
                out.push_str(", ");
            } else if j < len - 1 {
                out.push_str(&format!("],\n{indent}["));
            } else {
                out.push_str("])\n");
            }
        }
    }
}

/// Format the challenge polynomial `c` (`printf("%2d", ...)`, single bracket).
fn fmt_c(out: &mut String, c: &Poly) {
    out.push_str("c = [");
    for j in 0..N {
        out.push_str(&format!("{:2}", c.coeffs[j]));
        if j < N - 1 {
            out.push_str(", ");
        } else {
            out.push_str("]\n");
        }
    }
}

#[test]
#[ignore = "slow: 10000 iterations; run with --release --ignored"]
fn test_vectors_match_reference() {
    // Deterministic RNG: the continuous SHAKE128("") output stream, exactly as
    // test_vectors.c initialises its keccak_state.
    let mut rng = Shake128Stream::init_absorb(b"");
    let ctx: &[u8] = b"test_vectors\0"; // snprintf("test_vectors") into ctx[CTXLEN=13]

    let mut hasher = Sha256::new();

    for i in 0..NVECTORS {
        // Draw order matches the reference: m, keygen-seed, sign-rnd, seed.
        let mut m = [0u8; 32];
        rng.squeeze(&mut m);

        let mut zeta = [0u8; SEEDBYTES];
        rng.squeeze(&mut zeta);
        let (pk, sk) = keypair_from_seed(&zeta);

        let mut rnd = [0u8; RNDBYTES];
        rng.squeeze(&mut rnd);
        let sig = signature_deterministic(&m, ctx, &rnd, &sk).expect("sign");

        let mut seed = [0u8; CRHBYTES];
        rng.squeeze(&mut seed);

        // Digests printed for pk/sk/sig.
        let mut dpk = [0u8; 32];
        let mut dsk = [0u8; 32];
        let mut dsig = [0u8; 32];
        shake256(&mut dpk, &pk);
        shake256(&mut dsk, &sk);
        shake256(&mut dsig, &sig);

        // Deterministic objects derived from `seed`.
        let rho: [u8; SEEDBYTES] = seed[..SEEDBYTES].try_into().unwrap();
        let mat = matrix_expand(&rho);
        let s = Polyvecl::uniform_eta(&seed, 0);
        let y = Polyvecl::uniform_gamma1(&seed, 0);

        // w = A * NTT(y), then reduce/invntt/caddq; decompose and power2round.
        let mut yntt = y.clone();
        yntt.ntt();
        let mut w = matrix_pointwise_montgomery(&mat, &yntt);
        w.reduce();
        w.invntt_tomont();
        w.caddq();
        let (w1, w0) = w.decompose();
        let (t1, t0) = w.power2round();

        let cseed: [u8; CTILDEBYTES] = seed[..CTILDEBYTES].try_into().unwrap();
        let c = Poly::challenge(&cseed);

        // Build this iteration's output in the exact reference layout.
        let mut out = String::new();
        out.push_str(&format!("count = {i}\n"));
        out.push_str(&format!("m = {}\n", hex_lower(&m)));
        out.push_str(&format!("pk = {}\n", hex_lower(&dpk)));
        out.push_str(&format!("sk = {}\n", hex_lower(&dsk)));
        out.push_str(&format!("sig = {}\n", hex_lower(&dsig)));
        out.push_str(&format!("seed = {}\n", hex_upper(&seed)));
        fmt_matrix(&mut out, &mat);
        fmt_vec(&mut out, "s", &s.vec, 3, "     ");
        fmt_vec(&mut out, "y", &y.vec, 8, "     ");
        fmt_vec(&mut out, "w1", &w1.vec, 2, "      ");
        fmt_vec(&mut out, "w0", &w0.vec, 8, "      ");
        fmt_vec(&mut out, "t1", &t1.vec, 3, "      ");
        fmt_vec(&mut out, "t0", &t0.vec, 5, "      ");
        fmt_c(&mut out, &c);
        out.push('\n');

        hasher.update(out.as_bytes());
    }

    let digest = hex_lower(&hasher.finalize());
    assert_eq!(
        digest, GOLDEN,
        "test_vectors digest mismatch vs SHA256SUMS golden"
    );
}

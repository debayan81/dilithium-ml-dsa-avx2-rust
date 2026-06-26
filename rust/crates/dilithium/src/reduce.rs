//! Modular reduction over `Z_q` (Montgomery and Barrett-style reductions).
//!
//! Rust port of `ref/reduce.c` and `ref/reduce.h` (T-007 / T-008).
//!
//! All routines operate on signed coefficients and reproduce the C reference
//! bit-for-bit. C relies on two's-complement wraparound and arithmetic right
//! shifts of signed integers; Rust's `>>` on `i32`/`i64` is already an
//! arithmetic shift, and the explicit `wrapping_*` calls below make the
//! (defined) wraparound behaviour match C while never panicking in debug
//! builds on overflow.

use crate::params::Q;

/// `2^32 mod Q` — the Montgomery factor (`reduce.h`: `MONT`).
pub const MONT: i32 = -4_186_625;
/// `Q^{-1} mod 2^32` (`reduce.h`: `QINV`).
pub const QINV: i32 = 58_728_449;

/// Montgomery reduction.
///
/// For a finite-field element `a` with `-2^31·Q <= a <= Q·2^31`, computes
/// `r ≡ a·2^{-32} (mod Q)` such that `-Q < r < Q`.
///
/// Port of `montgomery_reduce` (`reduce.c`).
pub fn montgomery_reduce(a: i64) -> i32 {
    // t = (int32_t)a * QINV, keeping only the low 32 bits.
    let t = (a as i32).wrapping_mul(QINV);
    // t = (a - t*Q) >> 32   (arithmetic shift on a signed i64)
    ((a - t as i64 * Q as i64) >> 32) as i32
}

/// Barrell-style reduction to a small signed representative.
///
/// For `a <= 2^31 - 2^22 - 1`, computes `r ≡ a (mod Q)` with
/// `-6283008 <= r <= 6283008`.
///
/// Port of `reduce32` (`reduce.c`).
pub fn reduce32(a: i32) -> i32 {
    let t = (a.wrapping_add(1 << 22)) >> 23;
    a.wrapping_sub(t.wrapping_mul(Q))
}

/// Conditionally add `Q` if the input coefficient is negative.
///
/// Port of `caddq` (`reduce.c`). `a >> 31` is `-1` (all ones) when `a` is
/// negative and `0` otherwise, so `(a >> 31) & Q` adds `Q` only for negatives.
pub fn caddq(a: i32) -> i32 {
    a.wrapping_add((a >> 31) & Q)
}

/// Standard representative `r = a mod^+ Q` in `[0, Q)`.
///
/// Port of `freeze` (`reduce.c`): `reduce32` then `caddq`.
pub fn freeze(a: i32) -> i32 {
    caddq(reduce32(a))
}

#[cfg(test)]
mod tests {
    use super::*;

    const QI64: i64 = Q as i64;

    /// Non-negative residue of `x` modulo `Q`, for comparison in tests.
    fn modq(x: i64) -> i64 {
        ((x % QI64) + QI64) % QI64
    }

    #[test]
    fn caddq_adds_q_only_for_negatives() {
        assert_eq!(caddq(-1), Q - 1);
        assert_eq!(caddq(-Q), 0);
        assert_eq!(caddq(0), 0);
        assert_eq!(caddq(5), 5);
        assert_eq!(caddq(Q - 1), Q - 1);
    }

    #[test]
    fn freeze_is_canonical_and_congruent() {
        for &a in &[
            0,
            1,
            -1,
            Q,
            -Q,
            Q - 1,
            -(Q - 1),
            123_456,
            -123_456,
            6_283_008,
        ] {
            let r = freeze(a);
            assert!((0..Q).contains(&r), "freeze({a}) = {r} out of [0,Q)");
            assert_eq!(r as i64, modq(a as i64), "freeze({a}) wrong residue");
        }
    }

    #[test]
    fn reduce32_in_bound_and_congruent() {
        // Upper end of the documented input domain: 2^31 - 2^22 - 1.
        for &a in &[
            0,
            1,
            -1,
            Q,
            -Q,
            12_345_678,
            -12_345_678,
            i32::MAX - (1 << 22),
        ] {
            let r = reduce32(a);
            assert!(r.abs() <= 6_283_008, "reduce32({a}) = {r} out of bound");
            assert_eq!(
                modq(r as i64),
                modq(a as i64),
                "reduce32({a}) wrong residue"
            );
        }
    }

    #[test]
    fn montgomery_reduce_matches_definition() {
        // r ≡ a·2^{-32} (mod Q)  <=>  r·2^32 ≡ a (mod Q), and -Q < r < Q.
        let two32 = 1i64 << 32;
        for &a in &[
            0i64,
            1,
            -1,
            QI64,
            -QI64,
            QI64 << 20,
            -(QI64 << 20),
            1_234_567_890_123,
        ] {
            let r = montgomery_reduce(a);
            assert!(
                (r as i64) > -QI64 && (r as i64) < QI64,
                "mont({a}) = {r} out of range"
            );
            assert_eq!(modq(r as i64 * two32), modq(a), "mont({a}) wrong residue");
        }
    }

    #[test]
    fn mont_constants_consistent() {
        // MONT ≡ 2^32 (mod Q); QINV ≡ Q^{-1} (mod 2^32).
        assert_eq!(modq(MONT as i64), modq(1i64 << 32));
        assert_eq!((QINV as i64 * Q as i64) as i32 as u32, 1u32);
    }
}

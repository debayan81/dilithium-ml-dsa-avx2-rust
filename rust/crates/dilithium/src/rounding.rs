//! Rounding helpers: `power2round`, `decompose`, and the hint mechanism.
//!
//! Rust port of `ref/rounding.c` and `ref/rounding.h` (T-011 / T-012).
//!
//! The C functions return `a1` and write `a0` through a pointer; the Rust
//! versions return the pair `(a1, a0)` instead. The `decompose` / `use_hint`
//! routines have two variants selected by `GAMMA2` in C; here they are gated on
//! the parameter-set feature (`dilithium2` uses `GAMMA2 = (Q-1)/88`, while
//! `dilithium3` / `dilithium5` use `GAMMA2 = (Q-1)/32`).

use crate::params::{D, GAMMA2, Q};

/// Decompose `a = a1·2^D + a0` with `-2^{D-1} < a0 <= 2^{D-1}`.
///
/// Assumes `a` is a standard representative. Returns `(a1, a0)`.
/// Port of `power2round` (`rounding.c`).
pub fn power2round(a: i32) -> (i32, i32) {
    let a1 = (a + (1 << (D - 1)) - 1) >> D;
    let a0 = a - (a1 << D);
    (a1, a0)
}

/// Decompose `a = a1·ALPHA + a0` (with `ALPHA = 2·GAMMA2`) into high/low bits.
///
/// `-ALPHA/2 < a0 <= ALPHA/2`, except when `a1 = (Q-1)/ALPHA`, where `a1` is set
/// to `0` and `-ALPHA/2 <= a0 < 0`. Assumes `a` is a standard representative.
/// Returns `(a1, a0)`. Port of `decompose` (`rounding.c`).
pub fn decompose(a: i32) -> (i32, i32) {
    let mut a1 = (a + 127) >> 7;

    #[cfg(any(feature = "dilithium3", feature = "dilithium5"))]
    {
        // GAMMA2 == (Q-1)/32
        a1 = (a1.wrapping_mul(1025) + (1 << 21)) >> 22;
        a1 &= 15;
    }
    #[cfg(feature = "dilithium2")]
    {
        // GAMMA2 == (Q-1)/88
        a1 = (a1.wrapping_mul(11275) + (1 << 23)) >> 24;
        a1 ^= ((43 - a1) >> 31) & a1;
    }

    let mut a0 = a.wrapping_sub(a1.wrapping_mul(2 * GAMMA2));
    a0 = a0.wrapping_sub((((Q - 1) / 2 - a0) >> 31) & Q);
    (a1, a0)
}

/// Hint bit: whether the low bits `a0` overflow into the high bits.
///
/// Returns `true` (i.e. C's `1`) on overflow. Port of `make_hint`.
///
/// Branchless equivalent of the C condition
/// `a0 > GAMMA2 || a0 < -GAMMA2 || (a0 == -GAMMA2 && a1 != 0)`. During signing
/// this runs on secret-derived `(a0, a1)` on every (including rejected)
/// attempt, so we compute it without data-dependent branches (T-098). See
/// `CONSTANT_TIME_AUDIT.md`.
pub fn make_hint(a0: i32, a1: i32) -> bool {
    // gt = 1 iff a0 > GAMMA2  (GAMMA2 - a0 is negative).
    let gt = (GAMMA2.wrapping_sub(a0) >> 31) & 1;
    // diff == 0 iff a0 == -GAMMA2; diff < 0 iff a0 < -GAMMA2.
    let diff = a0.wrapping_add(GAMMA2);
    let lt = (diff >> 31) & 1;
    // is_eq = 1 iff diff == 0 (i.e. a0 == -GAMMA2).
    let is_eq = (((diff | diff.wrapping_neg()) >> 31) & 1) ^ 1;
    // a1_nz = 1 iff a1 != 0.
    let a1_nz = ((a1 | a1.wrapping_neg()) >> 31) & 1;
    (gt | lt | (is_eq & a1_nz)) != 0
}

/// Correct the high bits of `a` according to `hint`.
///
/// Port of `use_hint` (`rounding.c`).
pub fn use_hint(a: i32, hint: bool) -> i32 {
    let (a1, a0) = decompose(a);
    if !hint {
        return a1;
    }

    #[cfg(any(feature = "dilithium3", feature = "dilithium5"))]
    {
        // GAMMA2 == (Q-1)/32, high bits live in [0, 15].
        if a0 > 0 {
            (a1 + 1) & 15
        } else {
            (a1 - 1) & 15
        }
    }
    #[cfg(feature = "dilithium2")]
    {
        // GAMMA2 == (Q-1)/88, high bits live in [0, 43].
        if a0 > 0 {
            if a1 == 43 {
                0
            } else {
                a1 + 1
            }
        } else if a1 == 0 {
            43
        } else {
            a1 - 1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Upper bound on the high-bits value `a1` produced by `decompose`.
    #[cfg(feature = "dilithium2")]
    const A1_MAX: i32 = 43;
    #[cfg(any(feature = "dilithium3", feature = "dilithium5"))]
    const A1_MAX: i32 = 15;

    /// Step over the field to get good coverage without sampling all of Z_q.
    fn samples() -> impl Iterator<Item = i32> {
        (0..Q).step_by(9973)
    }

    #[test]
    fn power2round_reconstructs_and_bounds() {
        let half = 1 << (D - 1);
        for a in samples() {
            let (a1, a0) = power2round(a);
            assert_eq!(a1 * (1 << D) + a0, a, "power2round reconstruction at {a}");
            assert!(
                a0 > -half && a0 <= half,
                "power2round a0 out of range at {a}"
            );
        }
    }

    #[test]
    fn decompose_reconstructs_mod_q_and_bounds() {
        let alpha = 2 * GAMMA2;
        for a in samples() {
            let (a1, a0) = decompose(a);
            // a1*ALPHA + a0 ≡ a (mod Q)
            let recon = (a1 as i64 * alpha as i64 + a0 as i64).rem_euclid(Q as i64);
            assert_eq!(recon, a as i64, "decompose reconstruction at {a}");
            assert!(
                a0 > -GAMMA2 && a0 <= GAMMA2,
                "decompose a0 out of range at {a}"
            );
            assert!(
                (0..=A1_MAX).contains(&a1),
                "decompose a1 out of range at {a}"
            );
        }
    }

    #[test]
    fn make_hint_boundary_logic() {
        assert!(!make_hint(0, 7));
        assert!(!make_hint(GAMMA2, 7));
        assert!(make_hint(GAMMA2 + 1, 7));
        assert!(make_hint(-GAMMA2 - 1, 7));
        // a0 == -GAMMA2 overflows only when a1 != 0.
        assert!(!make_hint(-GAMMA2, 0));
        assert!(make_hint(-GAMMA2, 1));
    }

    #[test]
    fn use_hint_zero_is_high_bits_and_in_range() {
        for a in samples() {
            let (a1, _) = decompose(a);
            assert_eq!(
                use_hint(a, false),
                a1,
                "use_hint(_,0) must equal high bits at {a}"
            );
            let corrected = use_hint(a, true);
            assert!((0..=A1_MAX).contains(&corrected), "use_hint range at {a}");
        }
    }
}

//! Number-Theoretic Transform over `Z_q[X]/(X^256 + 1)`.
//!
//! Rust port of `ref/ntt.c` and `ref/ntt.h` (T-009 / T-010).
//!
//! The `zetas` table holds the powers of the 512-th root of unity in
//! Montgomery representation (`zeta_true · 2^32 mod q`), bit-reversed in the
//! order consumed by the butterflies. Because of the Montgomery form, each
//! `montgomery_reduce(zeta * x)` multiplies by the *true* twiddle factor, so
//! [`ntt`] computes the exact forward transform and [`invntt_tomont`] the
//! inverse (scaled by the Montgomery factor `2^32`, as its name says).
//!
//! As in C, no modular reduction is performed after the add/sub steps;
//! coefficients stay well within `i32`. The explicit `wrapping_*` calls match
//! C's two's-complement semantics without panicking in debug builds.

use crate::params::N;
use crate::reduce::montgomery_reduce;

/// Powers of the root of unity in Montgomery form, bit-reversed (`ntt.c`).
/// These constants are precomputed by the PARI/GP script `ref/precomp.gp`.
const ZETAS: [i32; N] = [
    0, 25847, -2608894, -518909, 237124, -777960, -876248, 466468, 1826347, 2353451, -359251,
    -2091905, 3119733, -2884855, 3111497, 2680103, 2725464, 1024112, -1079900, 3585928, -549488,
    -1119584, 2619752, -2108549, -2118186, -3859737, -1399561, -3277672, 1757237, -19422, 4010497,
    280005, 2706023, 95776, 3077325, 3530437, -1661693, -3592148, -2537516, 3915439, -3861115,
    -3043716, 3574422, -2867647, 3539968, -300467, 2348700, -539299, -1699267, -1643818, 3505694,
    -3821735, 3507263, -2140649, -1600420, 3699596, 811944, 531354, 954230, 3881043, 3900724,
    -2556880, 2071892, -2797779, -3930395, -1528703, -3677745, -3041255, -1452451, 3475950,
    2176455, -1585221, -1257611, 1939314, -4083598, -1000202, -3190144, -3157330, -3632928, 126922,
    3412210, -983419, 2147896, 2715295, -2967645, -3693493, -411027, -2477047, -671102, -1228525,
    -22981, -1308169, -381987, 1349076, 1852771, -1430430, -3343383, 264944, 508951, 3097992,
    44288, -1100098, 904516, 3958618, -3724342, -8578, 1653064, -3249728, 2389356, -210977, 759969,
    -1316856, 189548, -3553272, 3159746, -1851402, -2409325, -177440, 1315589, 1341330, 1285669,
    -1584928, -812732, -1439742, -3019102, -3881060, -3628969, 3839961, 2091667, 3407706, 2316500,
    3817976, -3342478, 2244091, -2446433, -3562462, 266997, 2434439, -1235728, 3513181, -3520352,
    -3759364, -1197226, -3193378, 900702, 1859098, 909542, 819034, 495491, -1613174, -43260,
    -522500, -655327, -3122442, 2031748, 3207046, -3556995, -525098, -768622, -3595838, 342297,
    286988, -2437823, 4108315, 3437287, -3342277, 1735879, 203044, 2842341, 2691481, -2590150,
    1265009, 4055324, 1247620, 2486353, 1595974, -3767016, 1250494, 2635921, -3548272, -2994039,
    1869119, 1903435, -1050970, -1333058, 1237275, -3318210, -1430225, -451100, 1312455, 3306115,
    -1962642, -1279661, 1917081, -2546312, -1374803, 1500165, 777191, 2235880, 3406031, -542412,
    -2831860, -1671176, -1846953, -2584293, -3724270, 594136, -3776993, -2013608, 2432395, 2454455,
    -164721, 1957272, 3369112, 185531, -1207385, -3183426, 162844, 1616392, 3014001, 810149,
    1652634, -3694233, -1799107, -3038916, 3523897, 3866901, 269760, 2213111, -975884, 1717735,
    472078, -426683, 1723600, -1803090, 1910376, -1667432, -1104333, -260646, -3833893, -2939036,
    -2235985, -420899, -2286327, 183443, -976891, 1612842, -3545687, -554416, 3919660, -48306,
    -1362209, 3937738, 1400424, -846154, 1976782,
];

/// Forward NTT, in place. Output is in bit-reversed order; no reduction is
/// performed after add/sub. Port of `ntt` (`ntt.c`).
pub fn ntt(a: &mut [i32; N]) {
    let mut k = 0usize;
    let mut len = 128usize;
    while len > 0 {
        let mut start = 0usize;
        while start < N {
            k += 1;
            let zeta = ZETAS[k] as i64;
            let mut j = start;
            while j < start + len {
                let t = montgomery_reduce(zeta * a[j + len] as i64);
                a[j + len] = a[j].wrapping_sub(t);
                a[j] = a[j].wrapping_add(t);
                j += 1;
            }
            start = j + len;
        }
        len >>= 1;
    }
}

/// Inverse NTT, in place, multiplied by the Montgomery factor `2^32`.
///
/// Input coefficients must be smaller than `Q` in absolute value; output
/// coefficients are too. Port of `invntt_tomont` (`ntt.c`).
pub fn invntt_tomont(a: &mut [i32; N]) {
    const F: i64 = 41978; // mont^2 / 256
    let mut k = 256usize;
    let mut len = 1usize;
    while len < N {
        let mut start = 0usize;
        while start < N {
            k -= 1;
            let zeta = -(ZETAS[k] as i64);
            let mut j = start;
            while j < start + len {
                let t = a[j];
                a[j] = t.wrapping_add(a[j + len]);
                a[j + len] = t.wrapping_sub(a[j + len]);
                a[j + len] = montgomery_reduce(zeta * a[j + len] as i64);
                j += 1;
            }
            start = j + len;
        }
        len <<= 1;
    }
    for x in a.iter_mut() {
        *x = montgomery_reduce(F * *x as i64);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::Q;
    use crate::reduce::freeze;

    const QI64: i64 = Q as i64;

    fn modq(x: i64) -> i64 {
        ((x % QI64) + QI64) % QI64
    }

    /// Tiny deterministic generator → coefficients in `[0, Q)`.
    fn fill(seed: u64) -> [i32; N] {
        let mut s = seed.wrapping_add(0x9E3779B97F4A7C15);
        let mut out = [0i32; N];
        for c in out.iter_mut() {
            // xorshift64*
            s ^= s >> 12;
            s ^= s << 25;
            s ^= s >> 27;
            let r = s.wrapping_mul(0x2545F4914F6CDD1D);
            *c = (r % Q as u64) as i32;
        }
        out
    }

    /// Negacyclic schoolbook multiplication mod Q (mirrors `poly_naivemul`).
    fn naivemul(a: &[i32; N], b: &[i32; N]) -> [i32; N] {
        let mut r = [0i64; 2 * N];
        for i in 0..N {
            for j in 0..N {
                r[i + j] = (r[i + j] + a[i] as i64 * b[j] as i64) % QI64;
            }
        }
        for i in N..2 * N {
            r[i - N] = (r[i - N] - r[i]) % QI64;
        }
        let mut c = [0i32; N];
        for i in 0..N {
            c[i] = r[i] as i32;
        }
        c
    }

    #[test]
    fn ntt_invntt_roundtrip() {
        // Mirrors test_mul.c: ntt, scale by -114592, invntt_tomont == identity.
        for seed in 0..16 {
            let a = fill(seed);
            let mut c = a;
            ntt(&mut c);
            for x in c.iter_mut() {
                *x = (*x as i64 * -114592 % QI64) as i32;
            }
            invntt_tomont(&mut c);
            for j in 0..N {
                assert_eq!(
                    modq(c[j] as i64),
                    modq(a[j] as i64),
                    "roundtrip mismatch at {j}"
                );
            }
        }
    }

    #[test]
    fn ntt_multiplication_matches_schoolbook() {
        // Mirrors test_mul.c: pointwise-montgomery product in NTT domain.
        for seed in 0..16 {
            let a = fill(seed);
            let b = fill(seed ^ 0xABCD);
            let want = naivemul(&a, &b);

            let mut na = a;
            let mut nb = b;
            ntt(&mut na);
            ntt(&mut nb);
            let mut d = [0i32; N];
            for j in 0..N {
                d[j] = montgomery_reduce(na[j] as i64 * nb[j] as i64);
            }
            invntt_tomont(&mut d);

            for j in 0..N {
                assert_eq!(freeze(d[j]), freeze(want[j]), "product mismatch at {j}");
            }
        }
    }
}

//! Vectors of polynomials and the matrix `A`.
//!
//! Rust port of `ref/polyvec.c` and `ref/polyvec.h` (T-015 / T-016).
//!
//! `polyvecl` (length `L`) and `polyveck` (length `K`) become [`Polyvecl`] and
//! [`Polyveck`]. As in [`crate::poly`], C pointer out-params become returned
//! values, and the `polyvec*` free functions become methods / associated
//! functions. The matrix `A` is `[Polyvecl; K]`, built and consumed by the
//! free functions [`matrix_expand`] and [`matrix_pointwise_montgomery`].

// Indexed loops mirror the C reference (and carry per-index nonces); keeping
// them indexed preserves the one-to-one correspondence.
#![allow(clippy::needless_range_loop)]

use crate::params::{CRHBYTES, K, L, POLYW1_PACKEDBYTES, SEEDBYTES};
use crate::poly::Poly;

/// Vector of `L` polynomials. Port of the C `polyvecl` struct.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Polyvecl {
    pub vec: [Poly; L],
}

/// Vector of `K` polynomials. Port of the C `polyveck` struct.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Polyveck {
    pub vec: [Poly; K],
}

impl Default for Polyvecl {
    fn default() -> Self {
        Polyvecl { vec: [Poly::default(); L] }
    }
}

impl Default for Polyveck {
    fn default() -> Self {
        Polyveck { vec: [Poly::default(); K] }
    }
}

// ===========================================================================
// Matrix A (length-K vector of length-L vectors)
// ===========================================================================

/// ExpandA: build matrix `A` from seed `rho` via `SHAKE128(rho ‖ j ‖ i)`.
/// Port of `polyvec_matrix_expand`.
pub fn matrix_expand(rho: &[u8; SEEDBYTES]) -> [Polyvecl; K] {
    let mut mat: [Polyvecl; K] = core::array::from_fn(|_| Polyvecl::default());
    for i in 0..K {
        for j in 0..L {
            mat[i].vec[j] = Poly::uniform(rho, ((i as u16) << 8) + j as u16);
        }
    }
    mat
}

/// Compute `t = A · v` in the NTT domain (`t_i = <A_i, v>`).
/// Port of `polyvec_matrix_pointwise_montgomery`.
pub fn matrix_pointwise_montgomery(mat: &[Polyvecl; K], v: &Polyvecl) -> Polyveck {
    let mut t = Polyveck::default();
    for i in 0..K {
        t.vec[i] = mat[i].pointwise_acc_montgomery(v);
    }
    t
}

// ===========================================================================
// Vectors of length L
// ===========================================================================

impl Polyvecl {
    /// Sample each entry from `[-ETA, ETA]` with consecutive nonces.
    /// Port of `polyvecl_uniform_eta`.
    pub fn uniform_eta(seed: &[u8; CRHBYTES], nonce: u16) -> Polyvecl {
        let mut v = Polyvecl::default();
        for i in 0..L {
            v.vec[i] = Poly::uniform_eta(seed, nonce.wrapping_add(i as u16));
        }
        v
    }

    /// Sample each entry from `[-(GAMMA1-1), GAMMA1]` with nonces `L·nonce + i`.
    /// Port of `polyvecl_uniform_gamma1`.
    pub fn uniform_gamma1(seed: &[u8; CRHBYTES], nonce: u16) -> Polyvecl {
        let mut v = Polyvecl::default();
        for i in 0..L {
            let n = ((L as u32) * nonce as u32 + i as u32) as u16;
            v.vec[i] = Poly::uniform_gamma1(seed, n);
        }
        v
    }

    /// Reduce every coefficient. Port of `polyvecl_reduce`.
    pub fn reduce(&mut self) {
        for p in self.vec.iter_mut() {
            p.reduce();
        }
    }

    /// `self + v`, no modular reduction. Port of `polyvecl_add`.
    pub fn add(&self, v: &Polyvecl) -> Polyvecl {
        let mut w = Polyvecl::default();
        for i in 0..L {
            w.vec[i] = self.vec[i].add(&v.vec[i]);
        }
        w
    }

    /// Forward NTT on every entry. Port of `polyvecl_ntt`.
    pub fn ntt(&mut self) {
        for p in self.vec.iter_mut() {
            p.ntt();
        }
    }

    /// Inverse NTT (×`2^32`) on every entry. Port of `polyvecl_invntt_tomont`.
    pub fn invntt_tomont(&mut self) {
        for p in self.vec.iter_mut() {
            p.invntt_tomont();
        }
    }

    /// Pointwise-multiply each entry by `a` (Montgomery).
    /// Port of `polyvecl_pointwise_poly_montgomery`.
    pub fn pointwise_poly_montgomery(&self, a: &Poly) -> Polyvecl {
        let mut r = Polyvecl::default();
        for i in 0..L {
            r.vec[i] = a.pointwise_montgomery(&self.vec[i]);
        }
        r
    }

    /// Inner product `<self, v>` (Montgomery), accumulated into one poly.
    /// Port of `polyvecl_pointwise_acc_montgomery`.
    pub fn pointwise_acc_montgomery(&self, v: &Polyvecl) -> Poly {
        let mut w = self.vec[0].pointwise_montgomery(&v.vec[0]);
        for i in 1..L {
            let t = self.vec[i].pointwise_montgomery(&v.vec[i]);
            w = w.add(&t);
        }
        w
    }

    /// `true` if any entry's infinity norm reaches `bound`.
    /// Port of `polyvecl_chknorm`.
    pub fn chknorm(&self, bound: i32) -> bool {
        self.vec.iter().any(|p| p.chknorm(bound))
    }
}

// ===========================================================================
// Vectors of length K
// ===========================================================================

impl Polyveck {
    /// Sample each entry from `[-ETA, ETA]` with consecutive nonces.
    /// Port of `polyveck_uniform_eta`.
    pub fn uniform_eta(seed: &[u8; CRHBYTES], nonce: u16) -> Polyveck {
        let mut v = Polyveck::default();
        for i in 0..K {
            v.vec[i] = Poly::uniform_eta(seed, nonce.wrapping_add(i as u16));
        }
        v
    }

    /// Reduce every coefficient. Port of `polyveck_reduce`.
    pub fn reduce(&mut self) {
        for p in self.vec.iter_mut() {
            p.reduce();
        }
    }

    /// Add `Q` to negative coefficients. Port of `polyveck_caddq`.
    pub fn caddq(&mut self) {
        for p in self.vec.iter_mut() {
            p.caddq();
        }
    }

    /// `self + v`, no modular reduction. Port of `polyveck_add`.
    pub fn add(&self, v: &Polyveck) -> Polyveck {
        let mut w = Polyveck::default();
        for i in 0..K {
            w.vec[i] = self.vec[i].add(&v.vec[i]);
        }
        w
    }

    /// `self - v`, no modular reduction. Port of `polyveck_sub`.
    pub fn sub(&self, v: &Polyveck) -> Polyveck {
        let mut w = Polyveck::default();
        for i in 0..K {
            w.vec[i] = self.vec[i].sub(&v.vec[i]);
        }
        w
    }

    /// Multiply every entry by `2^D`. Port of `polyveck_shiftl`.
    pub fn shiftl(&mut self) {
        for p in self.vec.iter_mut() {
            p.shiftl();
        }
    }

    /// Forward NTT on every entry. Port of `polyveck_ntt`.
    pub fn ntt(&mut self) {
        for p in self.vec.iter_mut() {
            p.ntt();
        }
    }

    /// Inverse NTT (×`2^32`) on every entry. Port of `polyveck_invntt_tomont`.
    pub fn invntt_tomont(&mut self) {
        for p in self.vec.iter_mut() {
            p.invntt_tomont();
        }
    }

    /// Pointwise-multiply each entry by `a` (Montgomery).
    /// Port of `polyveck_pointwise_poly_montgomery`.
    pub fn pointwise_poly_montgomery(&self, a: &Poly) -> Polyveck {
        let mut r = Polyveck::default();
        for i in 0..K {
            r.vec[i] = a.pointwise_montgomery(&self.vec[i]);
        }
        r
    }

    /// `true` if any entry's infinity norm reaches `bound`.
    /// Port of `polyveck_chknorm`.
    pub fn chknorm(&self, bound: i32) -> bool {
        self.vec.iter().any(|p| p.chknorm(bound))
    }

    /// Split every entry into `(v1, v0)` via `power2round`.
    /// Port of `polyveck_power2round`.
    pub fn power2round(&self) -> (Polyveck, Polyveck) {
        let mut v1 = Polyveck::default();
        let mut v0 = Polyveck::default();
        for i in 0..K {
            let (h, l) = self.vec[i].power2round();
            v1.vec[i] = h;
            v0.vec[i] = l;
        }
        (v1, v0)
    }

    /// Split every entry into high/low bits via `decompose`.
    /// Port of `polyveck_decompose`.
    pub fn decompose(&self) -> (Polyveck, Polyveck) {
        let mut v1 = Polyveck::default();
        let mut v0 = Polyveck::default();
        for i in 0..K {
            let (h, l) = self.vec[i].decompose();
            v1.vec[i] = h;
            v0.vec[i] = l;
        }
        (v1, v0)
    }

    /// Hint vector from low part `v0` and high part `v1`.
    /// Returns `(h, total_popcount)`. Port of `polyveck_make_hint`.
    pub fn make_hint(v0: &Polyveck, v1: &Polyveck) -> (Polyveck, usize) {
        let mut h = Polyveck::default();
        let mut s = 0usize;
        for i in 0..K {
            let (hi, si) = Poly::make_hint(&v0.vec[i], &v1.vec[i]);
            h.vec[i] = hi;
            s += si;
        }
        (h, s)
    }

    /// Correct high bits of every entry using hint `h`.
    /// Port of `polyveck_use_hint`.
    pub fn use_hint(&self, h: &Polyveck) -> Polyveck {
        let mut w = Polyveck::default();
        for i in 0..K {
            w.vec[i] = self.vec[i].use_hint(&h.vec[i]);
        }
        w
    }

    /// Pack `w1` of every entry into `r` (`K · POLYW1_PACKEDBYTES`).
    /// Port of `polyveck_pack_w1`.
    pub fn pack_w1(&self, r: &mut [u8]) {
        for i in 0..K {
            self.vec[i].w1_pack(&mut r[i * POLYW1_PACKEDBYTES..(i + 1) * POLYW1_PACKEDBYTES]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::{ETA, GAMMA1, N, Q};
    use crate::reduce::freeze;

    const QI64: i64 = Q as i64;

    /// Negacyclic schoolbook multiplication mod Q.
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

    fn rho() -> [u8; SEEDBYTES] {
        core::array::from_fn(|i| (i as u8).wrapping_mul(3).wrapping_add(1))
    }

    fn crh() -> [u8; CRHBYTES] {
        core::array::from_fn(|i| (i as u8).wrapping_mul(11).wrapping_add(2))
    }

    #[test]
    fn matrix_expand_coeffs_in_range() {
        let mat = matrix_expand(&rho());
        for row in &mat {
            for p in &row.vec {
                assert!(p.coeffs.iter().all(|&c| (0..Q).contains(&c)));
            }
        }
    }

    #[test]
    fn uniform_eta_vectors_in_range() {
        let l = Polyvecl::uniform_eta(&crh(), 0);
        let k = Polyveck::uniform_eta(&crh(), 100);
        assert!(l.vec.iter().all(|p| p.coeffs.iter().all(|&c| (-ETA..=ETA).contains(&c))));
        assert!(k.vec.iter().all(|p| p.coeffs.iter().all(|&c| (-ETA..=ETA).contains(&c))));
    }

    #[test]
    fn pointwise_acc_matches_schoolbook() {
        // Build two length-L vectors with valid (reduced) coefficients.
        let mut u = Polyvecl::default();
        let mut v = Polyvecl::default();
        for i in 0..L {
            u.vec[i] = Poly::uniform(&rho(), i as u16);
            v.vec[i] = Poly::uniform(&rho(), 100 + i as u16);
        }

        // Reference: sum of negacyclic products.
        let mut acc = Poly::default();
        for i in 0..L {
            acc = acc.add(&naivemul(&u.vec[i], &v.vec[i]));
        }

        // NTT path: ntt both, pointwise-accumulate, invntt.
        let mut un = u.clone();
        let mut vn = v.clone();
        un.ntt();
        vn.ntt();
        let mut w = un.pointwise_acc_montgomery(&vn);
        w.invntt_tomont();

        for i in 0..N {
            assert_eq!(freeze(w.coeffs[i]), freeze(acc.coeffs[i]), "mismatch at coeff {i}");
        }
    }

    #[test]
    fn power2round_reconstructs() {
        let mut v = Polyveck::uniform_eta(&crh(), 5);
        v.reduce();
        v.caddq(); // standard representatives in [0, Q)
        let (v1, v0) = v.power2round();
        for i in 0..K {
            for j in 0..N {
                let recon = v1.vec[i].coeffs[j] * (1 << crate::params::D) + v0.vec[i].coeffs[j];
                assert_eq!(recon, v.vec[i].coeffs[j]);
            }
        }
    }

    #[test]
    fn decompose_reconstructs_mod_q() {
        let mut v = Polyveck::default();
        for i in 0..K {
            v.vec[i] = Poly::uniform(&rho(), 200 + i as u16); // already in [0, Q)
        }
        let alpha = 2 * crate::params::GAMMA2 as i64;
        let (v1, v0) = v.decompose();
        for i in 0..K {
            for j in 0..N {
                let recon =
                    (v1.vec[i].coeffs[j] as i64 * alpha + v0.vec[i].coeffs[j] as i64).rem_euclid(QI64);
                assert_eq!(recon, v.vec[i].coeffs[j] as i64);
            }
        }
    }

    #[test]
    fn make_use_hint_count_consistent() {
        // Canonical decomposition produces an all-zero hint (count 0).
        let mut v = Polyveck::default();
        for i in 0..K {
            v.vec[i] = Poly::uniform(&rho(), 300 + i as u16);
        }
        let (v1, v0) = v.decompose();
        let (h, count) = Polyveck::make_hint(&v0, &v1);
        assert_eq!(count, 0);
        // use_hint with the zero hint returns the high bits unchanged.
        assert_eq!(v.use_hint(&h), v1);
    }

    #[test]
    fn chknorm_vector_bounds() {
        let mut v = Polyveck::default();
        v.vec[0].coeffs[0] = GAMMA1;
        assert!(v.chknorm(GAMMA1));
        assert!(!v.chknorm(GAMMA1 + 1));
    }

    #[test]
    fn pack_w1_length_and_zero() {
        let v = Polyveck::default();
        let mut r = vec![0xFFu8; K * POLYW1_PACKEDBYTES];
        v.pack_w1(&mut r);
        assert!(r.iter().all(|&b| b == 0));
    }
}

//! NIST AES-256-CTR DRBG for deterministic Known Answer Tests.
//!
//! Rust port of `ref/nistkat/rng.c` and `ref/nistkat/rng.h` (T-077 / T-078).
//!
//! This is the deterministic RNG NIST mandates for KAT generation. The C
//! reference kept a single global `DRBG_ctx` and used OpenSSL for AES; here the
//! state is an explicit [`Aes256CtrDrbg`] value and AES-256-ECB comes from the
//! `aes` crate. Only compiled with the `nistkat` feature.
//!
//! It is **not** a general-purpose RNG — use [`crate::randombytes`] for that.

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes256;

/// Single-block AES-256 in ECB mode (`AES256_ECB` in the C reference).
fn aes256_ecb(key: &[u8; 32], input: &[u8; 16]) -> [u8; 16] {
    let cipher = Aes256::new(GenericArray::from_slice(key));
    let mut block = *GenericArray::from_slice(input);
    cipher.encrypt_block(&mut block);
    block.into()
}

/// Increment the 128-bit counter `v` as a big-endian integer (C: the `j=15..0`
/// carry loop used by `randombytes` and `AES256_CTR_DRBG_Update`).
fn increment(v: &mut [u8; 16]) {
    for j in (0..16).rev() {
        if v[j] == 0xff {
            v[j] = 0x00;
        } else {
            v[j] += 1;
            break;
        }
    }
}

/// The NIST AES-256 CTR_DRBG. Port of `AES256_CTR_DRBG_struct` + its functions.
pub struct Aes256CtrDrbg {
    key: [u8; 32],
    v: [u8; 16],
}

impl Aes256CtrDrbg {
    /// `AES256_CTR_DRBG_Update`: run three counter blocks, optionally XOR in
    /// `provided_data`, and split the result into the new `(Key, V)`.
    fn update(&mut self, provided_data: Option<&[u8; 48]>) {
        let mut temp = [0u8; 48];
        for i in 0..3 {
            increment(&mut self.v);
            let block = aes256_ecb(&self.key, &self.v);
            temp[16 * i..16 * i + 16].copy_from_slice(&block);
        }
        if let Some(pd) = provided_data {
            for i in 0..48 {
                temp[i] ^= pd[i];
            }
        }
        self.key.copy_from_slice(&temp[..32]);
        self.v.copy_from_slice(&temp[32..]);
    }

    /// `randombytes_init`: seed the DRBG from 48 bytes of entropy and an
    /// optional 48-byte personalization string.
    pub fn init(entropy_input: &[u8; 48], personalization: Option<&[u8; 48]>) -> Self {
        let mut seed_material = *entropy_input;
        if let Some(p) = personalization {
            for i in 0..48 {
                seed_material[i] ^= p[i];
            }
        }
        let mut drbg = Aes256CtrDrbg {
            key: [0u8; 32],
            v: [0u8; 16],
        };
        drbg.update(Some(&seed_material));
        drbg
    }

    /// `randombytes`: fill `out` with deterministic DRBG output and re-key.
    pub fn randombytes(&mut self, out: &mut [u8]) {
        let mut i = 0;
        let mut remaining = out.len();
        while remaining > 0 {
            increment(&mut self.v);
            let block = aes256_ecb(&self.key, &self.v);
            if remaining > 15 {
                out[i..i + 16].copy_from_slice(&block);
                i += 16;
                remaining -= 16;
            } else {
                out[i..i + remaining].copy_from_slice(&block[..remaining]);
                remaining = 0;
            }
        }
        self.update(None);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aes256_ecb_known_answer() {
        // FIPS-197 / NIST KAT: AES-256 ECB of the all-zero block under the
        // all-zero key = dc95c078a2408989ad48a21492842087.
        let ct = aes256_ecb(&[0u8; 32], &[0u8; 16]);
        assert_eq!(
            ct,
            [
                0xdc, 0x95, 0xc0, 0x78, 0xa2, 0x40, 0x89, 0x89, 0xad, 0x48, 0xa2, 0x14, 0x92, 0x84,
                0x20, 0x87
            ]
        );
    }

    #[test]
    fn matches_canonical_nist_seed() {
        // After init with entropy_input = 0,1,...,47 (no personalization), the
        // first 48-byte draw is the canonical NIST PQC KAT `count = 0` seed,
        // identical across every NIST PQC submission that uses this DRBG. This
        // externally validates the DRBG against a known answer.
        let entropy: [u8; 48] = core::array::from_fn(|i| i as u8);
        let mut rng = Aes256CtrDrbg::init(&entropy, None);
        let mut seed = [0u8; 48];
        rng.randombytes(&mut seed);
        let hex: String = seed.iter().map(|b| format!("{b:02X}")).collect();
        assert_eq!(
            hex,
            "061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7\
             056A8C266F9EF97ED08541DBD2E1FFA1"
        );
    }

    #[test]
    fn drbg_is_deterministic() {
        let entropy: [u8; 48] = core::array::from_fn(|i| i as u8);
        let mut a = Aes256CtrDrbg::init(&entropy, None);
        let mut b = Aes256CtrDrbg::init(&entropy, None);
        let mut xa = [0u8; 80];
        let mut xb = [0u8; 80];
        a.randombytes(&mut xa);
        b.randombytes(&mut xb);
        assert_eq!(xa, xb);
        // Distinct successive draws (stream advances).
        let mut xc = [0u8; 80];
        a.randombytes(&mut xc);
        assert_ne!(xa, xc);
    }
}

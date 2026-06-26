//! System random-byte generation.
//!
//! Rust port of `ref/randombytes.c` and `ref/randombytes.h` (T-025 / T-026).
//!
//! The C reference wrapped the OS RNG (`/dev/urandom`, `getrandom`, etc.). Here
//! we delegate to the [`getrandom`] crate, which targets the platform CSPRNG.

/// Fill `out` with cryptographically secure random bytes.
///
/// Port of `randombytes(out, outlen)` — the length is `out.len()`.
///
/// # Panics
/// Panics if the operating system RNG is unavailable, matching the C
/// reference's assumption that randomness can always be obtained.
pub fn randombytes(out: &mut [u8]) {
    getrandom::getrandom(out).expect("system randomness (getrandom) is unavailable");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fills_and_varies() {
        let mut a = [0u8; 64];
        let mut b = [0u8; 64];
        randombytes(&mut a);
        randombytes(&mut b);
        // A 64-byte all-zero draw (or two identical draws) is astronomically
        // unlikely; treat it as an RNG failure.
        assert!(a.iter().any(|&x| x != 0));
        assert_ne!(a, b);
    }
}

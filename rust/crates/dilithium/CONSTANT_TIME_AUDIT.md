# Constant-Time Audit (T-098)

This document records the constant-time (CT) audit of the Dilithium Rust port.
Scope: every module under `src/`. The goal is that no operation on **secret**
data has a data-dependent branch, memory-access pattern, or variable-time
instruction.

Secrets in Dilithium are the secret key components — `s1`, `s2`, `t0`, the seed
`key`, and the per-signature nonce seed `rhoprime` (derived from `key`). Public
values include `rho`, the matrix `A`, the public key, the message, the context,
the challenge hash `c~`, and the final signature (`z`, the hint `h`, `c~`).

Verification handles only public data, so its timing is not security-relevant;
the audit focuses on key generation and signing.

## Summary of findings

| Site | Status | Notes |
|------|--------|-------|
| `reduce` (montgomery/reduce32/caddq/freeze) | ✅ inherently CT | pure shifts/masks, no branches |
| `ntt` / `invntt_tomont` | ✅ inherently CT | fixed access pattern, data-oblivious |
| `rounding::power2round` / `decompose` | ✅ inherently CT | branchless arithmetic (`>>31 & Q` trick) |
| `rounding::make_hint` | ✅ **hardened (T-098)** | was 3 short-circuiting comparisons → now branchless |
| `rounding::use_hint` | ✅ verify-only | runs only in verification (public data) |
| `poly::chknorm` | ✅ **hardened (T-098)** | branchless abs + no early-return |
| `polyvec::{Polyvecl,Polyveck}::chknorm` | ✅ **hardened (T-098)** | accumulate without short-circuit |
| `poly` packing (`eta/t0/t1/z/w1`) | ✅ inherently CT | data-oblivious bit manipulation |
| `sign` challenge compare (`c == c2`) | ✅ **hardened (T-098)** | `subtle::ConstantTimeEq`, no early-out (public, defensive) |
| `poly::challenge` rejection | ⚠️ accepted | rejection on **public** `c~`; matches reference |
| `poly::{rej_uniform,rej_eta}` rejection | ⚠️ accepted | sampling time; matches reference (see below) |
| signing rejection loop / `n > OMEGA` | ⚠️ accepted | leaks **count** of attempts only; intrinsic to Dilithium |
| `fips202` (SHAKE/SHA3) | ✅ delegated | RustCrypto `sha3`, constant-time Keccak |
| `randombytes` (`getrandom`) | ✅ n/a | OS CSPRNG |
| `nistkat_rng` (AES-CTR DRBG) | ✅ test-only | `nistkat` feature; KAT generation, no production secrets |

`unsafe` blocks: **0** across the crate (T-097) — the port is entirely safe
Rust, so there are no manually-managed memory or pointer operations to audit.

## Hardening performed

These changes remove data-dependent branches on secret-derived values. All were
verified to be **byte-for-byte output-identical** to the C reference by the
`test_vectors` golden test (T-061) on all three parameter sets, so only timing
changed, not results.

1. **`poly::chknorm`** — the C reference early-returns on the first violating
   coefficient and documents that the leaked *index* is data-independent. We
   tighten this: the branchless absolute value is kept, the `t >= bound` test is
   made branchless (`(bound-1 - t) >> 31`), and results are OR-accumulated with
   no early exit. Only the final yes/no (the return value, which the caller acts
   on regardless) is observable.

2. **`polyvec::*::chknorm`** — replaced the short-circuiting `.any(...)` with a
   `|=` accumulation over all entries, so timing does not reveal which
   polynomial in the vector violates the bound.

3. **`rounding::make_hint`** — replaced
   `a0 > GAMMA2 || a0 < -GAMMA2 || (a0 == -GAMMA2 && a1 != 0)` with a branchless
   bit-twiddling computation. `make_hint` runs on secret-derived `(a0, a1)` on
   every signing attempt, *including rejected ones whose output is never
   published*, so removing the per-coefficient branch closes a (minor)
   rejected-attempt timing channel.

4. **`sign` challenge comparison** — `c == c2` (array `==` short-circuits on the
   first differing byte) replaced with `subtle::ConstantTimeEq`. Both operands
   are public during verification, so this is defensive hygiene aligned with
   common library practice rather than a secret-protecting necessity.

## Accepted (matches the reference design)

The following are data-dependent but are part of Dilithium's accepted design and
are preserved as in the pq-crystals reference:

- **Rejection sampling** (`rej_uniform`, `rej_eta`, `poly::challenge`,
  `poly::uniform*`): the number of bytes consumed / iterations depends on the
  hash stream. For `rej_uniform` (matrix `A`) and `challenge` the stream derives
  from **public** inputs (`rho`, `c~`). For `rej_eta` the stream derives from
  `rhoprime`; the reference treats the resulting timing as non-exploitable for
  these distributions, and we follow that stance.

- **Signing rejection loop**: the number of attempts before acceptance, and the
  `n > OMEGA` hint-weight check, are observable. This leaks only an attempt
  *count*, which is intrinsic to Fiat–Shamir-with-aborts and does not reveal
  secret coefficients. Matches the reference.

## Possible future hardening (out of scope here)

- A fully data-oblivious rejection-sampling layer (constant number of Keccak
  squeezes, masked selection) would remove the accepted sampling-timing
  channels, at a performance cost. The reference does not do this.
- Zeroization of secret key material / intermediate secrets on drop (e.g. via
  `zeroize`) is a separate concern from timing and is not addressed here.

## How to re-verify

- No `unsafe`: `grep -r unsafe src/` → none.
- Output unchanged by hardening: run the T-061 golden test per set
  (`--features dilithiumN --test test_vectors -- --ignored`, release).
- Branch-condition correctness for `make_hint`: the `make_hint_boundary_logic`
  unit test in `rounding.rs` pins the exact truth table.

# Dilithium (Rust)

A pure-Rust port of the [CRYSTALS-Dilithium] reference implementation
(pq-crystals) — the lattice-based post-quantum digital signature scheme.

The port is **validated byte-for-byte against the C reference**: it reproduces
the reference `test_vectors` output (10000 iterations) and its SHA-256 matches
the upstream `SHA256SUMS` golden digests on all three parameter sets.

## Workspace layout

```
rust/
├── crates/
│   ├── dilithium/        # the library crate
│   │   ├── src/          # ports of ref/*.c + *.h (one module per file)
│   │   ├── tests/        # integration tests + KAT/vector validation
│   │   └── CONSTANT_TIME_AUDIT.md
│   └── cli/              # tiny demo binary (keygen → sign → verify)
├── clippy.toml
└── rustfmt.toml
```

## Parameter sets (features)

Exactly **one** parameter set must be enabled (enforced at build time):

| Feature | Security level | Default |
|---------|----------------|---------|
| `dilithium2` | NIST level 2 | |
| `dilithium3` | NIST level 3 | ✅ |
| `dilithium5` | NIST level 5 | |

Other features: `randomized-signing` (on by default; off → deterministic
signing), `avx2` (optimized backend, WIP), `nistkat` (AES-CTR DRBG for KAT
generation).

## Build & run

```sh
# Build the library (default = Dilithium3).
cargo build -p dilithium

# Pick a different parameter set.
cargo build -p dilithium --no-default-features --features dilithium5

# Run the demo CLI.
cargo run -p cli
```

## Usage

```rust
use dilithium::api::{keypair, sign, verify};

let (pk, sk) = keypair();
let msg = b"attack at dawn";
let ctx = b"my-app-v1";              // application context (may be empty)

let signature = sign(msg, ctx, &sk).expect("signing");
assert!(verify(&signature, msg, ctx, &pk).is_ok());
```

The API also provides `sign_attached` / `open` (signed-message form), and the
sizes `PUBLICKEYBYTES` / `SECRETKEYBYTES` / `SIGNBYTES`. Keys and signatures are
fixed-size byte arrays, wire-compatible with the C reference.

## Tests & validation

```sh
# Unit + fast integration tests (per parameter set).
cargo test -p dilithium --no-default-features --features dilithium3

# Byte-for-byte golden validation vs the C reference (slow; 10000 iters).
cargo test -p dilithium --release --no-default-features \
  --features dilithium2 --test test_vectors -- --ignored

# NIST KAT generation + self-validation.
cargo test -p dilithium --no-default-features \
  --features "dilithium3 nistkat" --test nistkat -- --nocapture
```

## Benchmarks

Criterion benchmarks (keypair/sign/verify + internal NTT/sampling ops), the
Rust replacement for `test_speed.c`:

```sh
cargo bench -p dilithium --no-default-features --features dilithium3 \
  --bench bench_dilithium
```

(`--bench bench_dilithium` targets the Criterion harness specifically, so the
library's unit-test harness doesn't intercept the benchmark flags.)

## Coverage

The Rust replacement for `runlcov.sh`, using [`cargo-llvm-cov`]:

```sh
cargo llvm-cov -p dilithium --no-default-features --features "dilithium3 nistkat"
```

## API docs

```sh
cargo doc -p dilithium --no-deps --open
```

[`cargo-llvm-cov`]: https://github.com/taiki-e/cargo-llvm-cov

## Security notes

- **No `unsafe`**: the crate is 100% safe Rust (`#![deny(unsafe_code)]`).
- **Constant-time**: secret-dependent operations are branchless; see
  [`crates/dilithium/CONSTANT_TIME_AUDIT.md`](crates/dilithium/CONSTANT_TIME_AUDIT.md).
- This is a faithful research/port implementation; it has not been
  independently audited for production use.

## License

CC0-1.0 / public domain, matching the upstream pq-crystals reference.

[CRYSTALS-Dilithium]: https://pq-crystals.org/dilithium/

// Build script for the Dilithium crate.
// (Build scripts aren't part of the public API; missing_docs doesn't apply.)
#![allow(missing_docs)]
//
// Responsibilities (mirrors what the Makefiles did):
//
// T-002 (ref/Makefile):
//   - Enforce exactly one DILITHIUM_MODE (dilithium2/3/5 feature) is selected.
//
// T-003 (avx2/Makefile):
//   - When the `avx2` feature is enabled, compile and link the AVX2 assembly
//     files (.S) using the `cc` crate with the correct CPU flags:
//     -mavx2 -mpopcnt -march=native -mtune=native
//   - Guard with target_arch = "x86_64" to prevent non-x86_64 builds from
//     attempting to compile x86-specific assembly.
//
// AVX2 assembly files (from avx2/Makefile SOURCES + KECCAK_SOURCES):
//   ntt.S       — Forward NTT (AVX2)
//   invntt.S    — Inverse NTT (AVX2)
//   pointwise.S — Pointwise Montgomery multiplication (AVX2)
//   shuffle.S   — NTT pack/unpack shuffle routines (AVX2)
//   f1600x4.S   — 4-way parallel Keccak-f[1600] permutation (AVX2)

fn main() {
    // -----------------------------------------------------------------------
    // T-002: Enforce exactly one Dilithium parameter set is selected.
    // In build scripts, features are exposed via CARGO_FEATURE_* env vars.
    // -----------------------------------------------------------------------
    let d2 = std::env::var("CARGO_FEATURE_DILITHIUM2").is_ok();
    let d3 = std::env::var("CARGO_FEATURE_DILITHIUM3").is_ok();
    let d5 = std::env::var("CARGO_FEATURE_DILITHIUM5").is_ok();
    let selected = d2 as u8 + d3 as u8 + d5 as u8;

    if selected == 0 {
        panic!(
            "No Dilithium parameter set selected! \
             Enable exactly one of: dilithium2, dilithium3, or dilithium5. \
             Example: cargo build --features dilithium3"
        );
    }
    if selected > 1 {
        panic!(
            "Multiple Dilithium parameter sets selected! \
             Enable exactly one of: dilithium2, dilithium3, or dilithium5. \
             The C Makefile compiles each mode as a separate binary; \
             in Rust we enforce mutual exclusivity via this build script."
        );
    }

    // -----------------------------------------------------------------------
    // T-094: Compile and link the reference `ref/` C for the interop test.
    //
    // We compile every ref/ source EXCEPT randombytes.c; the interop test
    // provides a `randombytes` symbol from Rust, so the C reference is
    // deterministic and needs no platform RNG. Symbols are namespaced
    // pqcrystals_dilithium{2,3,5}_ref_* via -DDILITHIUM_MODE.
    // -----------------------------------------------------------------------
    #[cfg(feature = "interop")]
    {
        let mode = if d2 {
            2
        } else if d5 {
            5
        } else {
            3
        };
        let ref_src = "../../../ref";
        let sources = [
            "sign.c",
            "packing.c",
            "polyvec.c",
            "poly.c",
            "ntt.c",
            "reduce.c",
            "rounding.c",
            "fips202.c",
            "symmetric-shake.c",
        ];
        let mut build = cc::Build::new();
        build.include(ref_src);
        build.define("DILITHIUM_MODE", mode.to_string().as_str());
        build.opt_level(2);
        for src in &sources {
            let path = format!("{}/{}", ref_src, src);
            build.file(&path);
            println!("cargo::rerun-if-changed={}", path);
        }
        build.compile("dilithium_ref_c");
        println!("cargo::rustc-link-lib=static=dilithium_ref_c");
    }

    // -----------------------------------------------------------------------
    // T-003: Conditionally compile AVX2 assembly when `avx2` feature is set.
    //
    // This is gated with #[cfg(feature = "avx2")] rather than a runtime check
    // because the `cc` crate is an optional build-dependency — it only exists
    // when the `avx2` feature is enabled. A runtime `if` would still try to
    // compile `cc::Build::new()` and fail when `cc` isn't available.
    // -----------------------------------------------------------------------
    #[cfg(feature = "avx2")]
    {
        let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
        if target_arch != "x86_64" {
            panic!(
                "The `avx2` feature is only supported on x86_64 targets. \
                 Current target architecture: '{}'. \
                 Disable the `avx2` feature for this target.",
                target_arch
            );
        }

        // Path to the AVX2 C source directory relative to this build.rs.
        // cc paths are relative to the crate root (rust/crates/dilithium/):
        //   ../        -> rust/crates
        //   ../../     -> rust
        //   ../../../  -> dilithium-master  (project root, where avx2/ lives)
        // Adjust if sources are moved into the Rust tree.
        let avx2_src = "../../../avx2";

        // Assembly files from avx2/Makefile SOURCES and KECCAK_SOURCES that
        // contain x86-64 AVX2 instructions — must be compiled with -mavx2.
        let asm_files = [
            "ntt.S",       // T-030: Forward NTT
            "invntt.S",    // T-031: Inverse NTT
            "pointwise.S", // T-032: Pointwise multiplication
            "shuffle.S",   // T-033: NTT shuffle/transpose
            "f1600x4.S",   // T-035: 4-way parallel Keccak-f[1600]
        ];

        // Companion C sources the assembly depends on. consts.c provides the
        // `qdata` constant tables that ntt.S / invntt.S / pointwise.S reference
        // by symbol; without it the static lib has unresolved symbols.
        //
        // NOTE: we deliberately do NOT compile the rest of the avx2/ C backend
        // (poly.c, polyvec.c, sign.c, packing.c, fips202.c, fips202x4.c,
        // rejsample.c, symmetric-shake.c). Those are being ported to Rust in
        // later tasks (T-027/T-036/T-038/T-041/T-043/T-047/…). Compiling them
        // from C here would defeat the port and risk duplicate symbols against
        // the Rust implementations. Add each one only as its Rust port lands
        // and is shown to need the C reference for bring-up.
        let c_files = [
            "consts.c", // T-027: AVX2-aligned constant tables (qdata)
        ];

        let mut build = cc::Build::new();

        // Mirror Makefile AVX2 CFLAGS exactly:
        //   -mavx2 -mpopcnt -march=native -mtune=native -O3
        build
            .flag("-mavx2")
            .flag("-mpopcnt")
            .flag("-march=native")
            .flag("-mtune=native")
            .opt_level(3);

        // The .S files `#include "params.h"` and the GAS macro file
        // `shuffle.inc`; consts.c includes consts.h/params.h. Put avx2/ on the
        // include search path so the (pre)processor can resolve all of them.
        build.include(avx2_src);

        // Mirror the Makefile's `-DDILITHIUM_MODE=2/3/5`. The assembly expands
        // DILITHIUM_NAMESPACE(...) from this; without it the `ntt_avx` etc.
        // symbols never get their namespaced names.
        let dilithium_mode = if d2 {
            2
        } else if d5 {
            5
        } else {
            3
        };
        build.define("DILITHIUM_MODE", dilithium_mode.to_string().as_str());

        for src in asm_files.iter().chain(c_files.iter()) {
            let path = format!("{}/{}", avx2_src, src);
            build.file(&path);
            // Tell Cargo to re-run build.rs if any source file changes
            println!("cargo::rerun-if-changed={}", path);
        }
        // shuffle.inc is `%include`d by shuffle.S but isn't a compile unit;
        // still track it so edits trigger a rebuild.
        println!("cargo::rerun-if-changed={}/shuffle.inc", avx2_src);

        build.compile("dilithium_avx2");

        // Tell the linker to link the compiled AVX2 static library
        println!("cargo::rustc-link-lib=static=dilithium_avx2");
    }

    // Re-run this build script if it changes
    println!("cargo::rerun-if-changed=build.rs");
}

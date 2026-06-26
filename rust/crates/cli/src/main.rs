//! Small demo CLI: generate a key pair, sign a message, and verify it.
//!
//! The parameter set is fixed at compile time by the `dilithium` dependency's
//! feature selection in `Cargo.toml` (Dilithium3 here).

use dilithium::api::{keypair, sign, verify, PUBLICKEYBYTES, SECRETKEYBYTES, SIGNBYTES};
use dilithium::config::CRYPTO_ALGNAME;

fn main() {
    println!("Dilithium CLI — {CRYPTO_ALGNAME}");
    println!(
        "  public key: {PUBLICKEYBYTES} B, secret key: {SECRETKEYBYTES} B, signature: {SIGNBYTES} B"
    );

    let (pk, sk) = keypair();
    println!("Generated key pair.");

    let msg = b"Hello from the Dilithium Rust port!";
    let ctx = b"cli-demo";

    let signature = sign(msg, ctx, &sk).expect("signing failed");
    println!("Signed a {}-byte message.", msg.len());

    match verify(&signature, msg, ctx, &pk) {
        Ok(()) => println!("Signature verified: OK"),
        Err(e) => {
            eprintln!("Signature verification FAILED: {e}");
            std::process::exit(1);
        }
    }

    // Demonstrate that tampering is detected.
    assert!(verify(&signature, b"a different message", ctx, &pk).is_err());
    println!("Tampered-message check correctly rejected.");
}

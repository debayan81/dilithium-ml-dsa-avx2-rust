use dilithium::d3; // Only d3 is available because we specified the "dilithium3" feature

fn main() {
    println!("Dilithium CLI Initialized!");
    d3::generate_keypair();
}
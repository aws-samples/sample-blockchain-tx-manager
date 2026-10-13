//! Simple wallet generator using alloy
//! Run with: cargo +nightly -Zscript scripts/gen_wallet.rs

//! ```cargo
//! [dependencies]
//! alloy = { version = "1", features = ["signers"] }
//! hex = "0.4"
//! ```

use alloy::signers::local::PrivateKeySigner;

fn main() {
    let signer = PrivateKeySigner::random();
    let address = signer.address();
    let private_key = hex::encode(signer.credential().to_bytes());
    
    eprintln!("Address: {}", address);
    eprintln!("Private Key: 0x{}", private_key);
    eprintln!();
    println!("{{\"{}\": \"0x{}\"}}", address, private_key);
}

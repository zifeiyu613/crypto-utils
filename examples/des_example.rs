use rand::Rng;
use crypto_utils::prelude::*;
use crypto_utils::symmetric::SymmetricCipher;

fn main() -> Result<(), anyhow::Error> {
    println!("=== DES Encryption Examples ===");

    // Generate a random DES key
    let mut key = [0u8; 8];
    rand::thread_rng().fill(&mut key[..]);
    println!("Generated DES key: {}", bytes_to_hex(&key));

    let plaintext = "This is a secret message for DES encryption!";
    println!("Original message: {}", plaintext);

    // DES-CBC
    let cipher = DesCbc::new(&key, None)?;
    let encrypted = cipher.encrypt_str(plaintext)?;
    println!("DES-CBC Encrypted (Base64): {}", encrypted);

    let decrypted = cipher.decrypt_str(&encrypted)?;
    println!("DES-CBC Decrypted: {}", decrypted);

    // Example with convenience functions
    println!("=== Using Convenience Functions ===");

    let encrypted = des_encrypt_string(&key, plaintext, None)?;
    println!("DES Encrypted: {}", encrypted);

    let decrypted = des_decrypt_string(&key, &encrypted)?;
    println!("DES Decrypted: {}", decrypted);

    Ok(())
}

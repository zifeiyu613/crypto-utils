use crypto_utils::prelude::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!(
        "=== AES Encryption Examples ===
"
    );

    // Generate a random AES-256 key
    let key = generate_random_key(32);
    println!("Generated AES-256 key: {}", bytes_to_hex(&key));

    let plaintext = "This is a secret message that needs encryption!";
    println!("Original message: {}", plaintext);

    // AES-CBC (recommended)
    let cipher = AesCbc::new(&key, None)?;
    let encrypted = cipher.encrypt_str(plaintext)?;
    println!(
        "
AES-CBC Encrypted (Base64): {}",
        encrypted
    );

    let decrypted = cipher.decrypt_str(&encrypted)?;
    println!("AES-CBC Decrypted: {}", decrypted);

    // AES-ECB (for compatibility with legacy systems)
    let ecb_cipher = AesEcb::new(&key)?;
    let ecb_encrypted = ecb_cipher.encrypt_str(plaintext)?;
    println!(
        "
AES-ECB Encrypted (Base64): {}",
        ecb_encrypted
    );

    let ecb_decrypted = ecb_cipher.decrypt_str(&ecb_encrypted)?;
    println!("AES-ECB Decrypted: {}", ecb_decrypted);

    // Example with convenience functions
    println!(
        "
=== Using Convenience Functions ==="
    );

    let aes128_key: [u8; 16] = key[0..16].try_into().unwrap();
    let encrypted = aes128_cbc_encrypt(&aes128_key, plaintext.as_bytes(), None)?;
    println!("AES-128 Encrypted: {}", encrypted);

    let decrypted = aes128_cbc_decrypt(&aes128_key, &encrypted)?;
    println!("AES-128 Decrypted: {}", String::from_utf8_lossy(&decrypted));

    Ok(())
}

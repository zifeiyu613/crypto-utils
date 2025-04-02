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

    println!("=== Using Convenience Functions ===");

    let cipher = "0OSQhJvlfRmcbqDk2S900CCCg32hO2U+m5Gs3tYEC9ZdgTRTBNbCO8DQLujuQtnJG+3hhfuIkA84CLNPxcvw4g0UEWczPnJBxZkFUtlS+HW/bTXg1zD2xp2UR/5oXkc+3aek0ejN07Oq5J0WESiyl1SBEaPveNKRAIehfkQmb7WZMolwF2bHTUuhAyAC5d085DcXhcnjXEpbJ9hPrvPJcdvs1eLxWGZqc8A59yAxfwVLV/Kp76wALFuipzxy9tfexcNjbYvqaqLBbvH4cvYQtA==";
    let key = "spef11kg".as_bytes();
    let iv = [0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF];
    let des = DesCbc::new(key, Some(iv))?;
    println!("Decrypted Decipher: {}", des.decrypt_str(cipher)?);
    Ok(())
}

use crypto_utils::prelude::*;

fn main() -> Result<(), anyhow::Error> {
    println!("=== Hashing Examples ===
");

    let data = "Hello, world!";

    // SHA256
    let hash = sha256_hex(data.as_bytes());
    println!("SHA-256 hash of '{}': {}", data, hash);

    // SHA512
    let hash = sha512_hex(data.as_bytes());
    println!("SHA-512 hash of '{}': {}", data, hash);

    // HMAC-SHA256
    let key = "secret-key".as_bytes();
    let hmac = hmac_sha256_base64(key, data.as_bytes())?;
    println!("HMAC-SHA256 of '{}' with key 'secret-key': {}", data, hmac);

    // Password hashing
    let password = "my-secure-password";

    let hasher = PasswordHasher::default();
    let password_hash = hasher.hash_password(password)?;
    println!("Password hash: {}", password_hash);

    // Verify password
    let is_valid = hasher.verify_password(password, &password_hash)?;
    println!("Password verification result: {}", is_valid);

    // Verify with wrong password
    let is_valid = hasher.verify_password("wrong-password", &password_hash)?;
    println!("Verification with wrong password: {}", is_valid);

    Ok(())
}

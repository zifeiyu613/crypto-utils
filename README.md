# crypto-utils

[![Crates.io](https://img.shields.io/crates/v/crypto-utils.svg)](https://crates.io/crates/crypto-utils)
[![Documentation](https://docs.rs/crypto-utils/badge.svg)](https://docs.rs/crypto-utils)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE)

A comprehensive, easy-to-use cryptographic utility library for Rust applications.

## Features

- **Symmetric Encryption**
    - AES (128/192/256-bit) in CBC and ECB modes
    - DES in CBC mode
    - PKCS7 padding

- **Asymmetric Encryption**
    - RSA encryption/decryption
    - RSA signing/verification

- **Hashing & Authentication**
    - SHA-256 and SHA-512 hashing
    - HMAC-SHA256
    - Password hashing with PBKDF2
    - Secure password verification

- **Utilities**
    - Base64 encoding/decoding
    - Random key generation
    - Hex encoding/decoding

- **Developer-Friendly**
    - Consistent API across all algorithms
    - Comprehensive error handling
    - Detailed documentation and examples

## Installation

Add `crypto-utils` to your `Cargo.toml`:

```toml
[dependencies]
crypto-utils = "0.1.0"
```

## Quick Start

### Symmetric Encryption

```rust
use crypto_utils::prelude::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate a random 256-bit AES key
    let key = generate_random_key(32);
    
    // Create an AES-CBC cipher
    let cipher = AesCbc::new(&key, None)?;
    
    // Encrypt a message
    let encrypted = cipher.encrypt_str("Secret message")?;
    println!("Encrypted: {}", encrypted);
    
    // Decrypt the message
    let decrypted = cipher.decrypt_str(&encrypted)?;
    println!("Decrypted: {}", decrypted);
    
    Ok(())
}
```

### Password Hashing

```rust
use crypto_utils::prelude::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a password hasher with default settings
    let hasher = PasswordHasher::default();
    
    // Hash a password
    let password = "secure-user-password";
    let hash = hasher.hash_password(password)?;
    
    println!("Password hash: {}", hash);
    
    // Verify a password
    let is_valid = hasher.verify_password(password, &hash)?;
    println!("Password valid: {}", is_valid);
    
    Ok(())
}
```

### RSA Encryption & Signing

```rust
use crypto_utils::prelude::*;
use crypto_utils::asymmetric::rsa::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate a new 2048-bit RSA key pair
    let (private_key, public_key) = generate_rsa_keypair(2048)?;
    
    // Create a key pair from the private key
    let key_pair = RsaKeyPair::from_private_key_pem(&private_key)?;
    
    // Encrypt a message
    let message = "Secret RSA message";
    let encrypted = key_pair.encrypt(message.as_bytes())?;
    
    // Decrypt the message
    let decrypted = key_pair.decrypt(&encrypted)?;
    println!("Decrypted: {}", String::from_utf8_lossy(&decrypted));
    
    // Sign a message
    let signature = key_pair.sign(message.as_bytes())?;
    
    // Verify the signature
    let is_valid = key_pair.verify(message.as_bytes(), &signature)?;
    println!("Signature valid: {}", is_valid);
    
    Ok(())
}
```

## Detailed Usage

### Symmetric Encryption

#### AES Encryption

```rust

// AES-256 CBC mode (recommended)
let key = generate_random_key(32); // 32 bytes = 256 bits
let cipher = AesCbc::new(&key, None)?; // Random IV will be generated

// With a specific IV
let iv = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
let cipher = AesCbc::new(&key, Some(&iv))?;

// Using convenience functions
let key_128: [u8; 16] = [/* ... */]; // 16 bytes for AES-128
let encrypted = aes128_cbc_encrypt(&key_128, data.as_bytes(), None)?;
let decrypted = aes128_cbc_decrypt(&key_128, &encrypted)?;

// AES-256 using convenience functions
let key_256: [u8; 32] = [/* ... */]; // 32 bytes for AES-256
let encrypted = aes256_cbc_encrypt(&key_256, data.as_bytes(), None)?;
let decrypted = aes256_cbc_decrypt(&key_256, &encrypted)?;
```

#### DES Encryption

```rust
// DES CBC mode
let key = [1, 2, 3, 4, 5, 6, 7, 8]; // 8 bytes for DES
let cipher = DesCbc::new(&key, None)?;

// Using convenience functions
let encrypted = des_encrypt_string(&key, "Secret message", None)?;
let decrypted = des_decrypt_string(&key, &encrypted)?;
```

### Hashing

```rust
// SHA-256
let hash = sha256_hex("data".as_bytes());

// SHA-512
let hash = sha512_hex("data".as_bytes());

// HMAC-SHA256
let key = "secret-key".as_bytes();
let hmac = hmac_sha256_base64(key, "data".as_bytes())?;
```

### Password Handling

```rust
// Create a password hasher with custom settings
let hasher = PasswordHasher::new(150_000, 32); // 150,000 iterations, 32-byte salt

// Or use the default settings (100,000 iterations, 16-byte salt)
let hasher = PasswordHasher::default();

// Hash a password
let hash = hasher.hash_password("user-password")?;

// Verify a password
let is_valid = hasher.verify_password("user-password", &hash)?;
```

### Asymmetric Encryption

```rust
// Generate a new RSA key pair
let key_pair = RsaKeyPair::generate(2048)?;

// Export keys to PEM format
let private_pem = key_pair.private_key_to_pem()?;
let public_pem = key_pair.public_key_to_pem()?;

// Load from existing keys
let from_private = RsaKeyPair::from_private_key_pem(&private_pem)?;
let public_only = RsaKeyPair::from_public_key_pem(&public_pem)?;

// Encrypt with a public key
let encrypted = rsa_encrypt(&public_pem, "data".as_bytes())?;

// Decrypt with a private key
let decrypted = rsa_decrypt(&private_pem, &encrypted)?;

// Sign data
let signature = rsa_sign(&private_pem, "data".as_bytes())?;

// Verify signature
let is_valid = rsa_verify(&public_pem, "data".as_bytes(), &signature)?;
```

## Security Considerations

- AES-CBC is recommended over AES-ECB for most use cases
- Always use a secure random source for key generation
- Consider key management carefully in your application
- Follow security best practices for storing password hashes
- The library automatically handles IV generation and storage for you
- Avoid using DES for new applications (included for legacy compatibility)

## Error Handling

All functions in this library return a `CryptoResult<T>` which is an alias for `Result<T, CryptoError>`. The `CryptoError` enum provides detailed information about what went wrong:

```rust
// Example of handling crypto errors
match cipher.encrypt_str("data") {
    Ok(encrypted) => println!("Encrypted: {}", encrypted),
    Err(CryptoError::InvalidKey(msg)) => eprintln!("Key error: {}", msg),
    Err(CryptoError::EncryptionError(msg)) => eprintln!("Encryption failed: {}", msg),
    Err(e) => eprintln!("Other error: {}", e),
}
```

## Supported Algorithms

### Symmetric Encryption
- AES-128, AES-192, AES-256 (CBC mode)
- AES-128, AES-192, AES-256 (ECB mode, not recommended for security-sensitive applications)
- DES (CBC mode, legacy support)

### Asymmetric Encryption
- RSA with PKCS#1 v1.5 padding
- RSA signing with PKCS#1 v1.5 and SHA-256

### Hashing
- SHA-256
- SHA-512
- HMAC-SHA256
- PBKDF2 with HMAC-SHA256

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

Please make sure your code passes all tests and adheres to the Rust style guidelines.

## License

This project is licensed under either of:

- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Acknowledgments

- The Rust Cryptography Working Group for providing excellent cryptographic primitives
- All contributors who help improve this library

---

Made with ❤️ for the Rust community.
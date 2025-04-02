//! Hash function implementations

use sha2::{Sha256, Sha512, Digest};
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2;
use rand::{Rng, thread_rng};

use crate::error::{CryptoError, CryptoResult};
use crate::util::{encode_base64, decode_base64};

/// Calculate SHA-256 hash of data and return it as a hex string
pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    hex::encode(result)
}

/// Calculate SHA-512 hash of data and return it as a hex string
pub fn sha512_hex(data: &[u8]) -> String {
    let mut hasher = Sha512::new();
    hasher.update(data);
    let result = hasher.finalize();
    hex::encode(result)
}

/// Calculate HMAC-SHA256 of data with the given key
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> CryptoResult<Vec<u8>> {
    type HmacSha256 = Hmac<Sha256>;

    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|_| CryptoError::InvalidKey("Invalid HMAC key".into()))?;

    mac.update(data);
    let result = mac.finalize();
    Ok(result.into_bytes().to_vec())
}

/// Calculate HMAC-SHA256 of data with the given key and return as Base64
pub fn hmac_sha256_base64(key: &[u8], data: &[u8]) -> CryptoResult<String> {
    let hmac = hmac_sha256(key, data)?;
    encode_base64(&hmac)
}

/// Password hashing with PBKDF2-HMAC-SHA256
pub struct PasswordHasher {
    iterations: u32,
    salt_length: usize,
}

impl Default for PasswordHasher {
    fn default() -> Self {
        Self {
            iterations: 100_000, // Recommended minimum as of 2023
            salt_length: 16,
        }
    }
}

impl PasswordHasher {
    /// Create a new password hasher with custom parameters
    pub fn new(iterations: u32, salt_length: usize) -> Self {
        Self {
            iterations,
            salt_length,
        }
    }

}

//! Symmetric encryption algorithms

pub mod aes;
pub mod des;

/// Common trait for symmetric encryption
pub trait SymmetricCipher {
    /// Encrypt data and return base64-encoded result
    fn encrypt(&self, data: &[u8]) -> crate::error::CryptoResult<String>;

    /// Decrypt base64-encoded ciphertext
    fn decrypt(&self, data: &str) -> crate::error::CryptoResult<Vec<u8>>;

    /// Convenience method for encrypting a string
    fn encrypt_str(&self, data: &str) -> crate::error::CryptoResult<String> {
        self.encrypt(data.as_bytes())
    }

    /// Convenience method for decrypting to a string
    fn decrypt_str(&self, data: &str) -> crate::error::CryptoResult<String> {
        let bytes = self.decrypt(data)?;
        Ok(String::from_utf8_lossy(&bytes).to_string())
    }
}

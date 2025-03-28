//! Asymmetric encryption algorithms

pub mod rsa;

/// Common trait for asymmetric encryption
pub trait AsymmetricCipher {
    /// Encrypt data and return base64-encoded result
    fn encrypt(&self, data: &[u8]) -> crate::error::CryptoResult<String>;

    /// Decrypt base64-encoded ciphertext
    fn decrypt(&self, data: &str) -> crate::error::CryptoResult<Vec<u8>>;

    /// Sign data and return base64-encoded signature
    fn sign(&self, data: &[u8]) -> crate::error::CryptoResult<String>;

    /// Verify data against base64-encoded signature
    fn verify(&self, data: &[u8], signature: &str) -> crate::error::CryptoResult<bool>;
}

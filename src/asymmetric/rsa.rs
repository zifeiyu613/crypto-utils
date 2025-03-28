//! RSA encryption implementation

use rsa::{
    PublicKey, RsaPrivateKey, RsaPublicKey,
    pkcs8::{EncodePublicKey, EncodePrivateKey, DecodePublicKey, DecodePrivateKey},
    Pkcs1v15Encrypt, Pkcs1v15Sign
};
use sha2::{Sha256, Digest};

use crate::error::{CryptoError, CryptoResult};
use crate::util::{encode_base64, decode_base64};
use super::AsymmetricCipher;

/// RSA key pair for encryption and signing
pub struct RsaKeyPair {
    private_key: Option<RsaPrivateKey>,
    public_key: RsaPublicKey,
}

impl RsaKeyPair {
    /// Generate a new RSA key pair with the specified bits (e.g., 2048, 4096)
    pub fn generate(bits: usize) -> CryptoResult<Self> {
        let mut rng = rand::thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, bits)
            .map_err(|e| CryptoError::EncryptionError(format!("Failed to generate RSA key: {}", e)))?;

        let public_key = RsaPublicKey::from(&private_key);

        Ok(Self {
            private_key: Some(private_key),
            public_key,
        })
    }

    /// Create a key pair from an existing private key in PKCS#8 PEM format
    pub fn from_private_key_pem(pem: &str) -> CryptoResult<Self> {
        let private_key = RsaPrivateKey::from_pkcs8_pem(pem)
            .map_err(|e| CryptoError::InvalidKey(format!("Invalid private key PEM: {}", e)))?;

        let public_key = RsaPublicKey::from(&private_key);

        Ok(Self {
            private_key: Some(private_key),
            public_key,
        })
    }

    /// Create a public-key-only instance from a public key in PKCS#8 PEM format
    pub fn from_public_key_pem(pem: &str) -> CryptoResult<Self> {
        let public_key = RsaPublicKey::from_public_key_pem(pem)
            .map_err(|e| CryptoError::InvalidKey(format!("Invalid public key PEM: {}", e)))?;

        Ok(Self {
            private_key: None,
            public_key,
        })
    }

    /// Export the private key as PKCS#8 PEM
    pub fn private_key_to_pem(&self) -> CryptoResult<String> {
        match &self.private_key {
            Some(private_key) => {
                private_key.to_pkcs8_pem(rsa::pkcs8::LineEnding::default())
                    .map_err(|e| CryptoError::EncryptionError(format!("Failed to export private key: {}", e)))
                    .map(|pem| pem.to_string())
            },
            None => Err(CryptoError::UnsupportedOperation("No private key available".into())),
        }
    }

    /// Export the public key as PKCS#8 PEM
    pub fn public_key_to_pem(&self) -> CryptoResult<String> {
        self.public_key.to_public_key_pem(rsa::pkcs8::LineEnding::default())
            .map_err(|e| CryptoError::EncryptionError(format!("Failed to export public key: {}", e)))
            .map(|pem| pem.to_string())
    }

    /// Check if this instance has a private key
    pub fn has_private_key(&self) -> bool {
        self.private_key.is_some()
    }
}

impl AsymmetricCipher for RsaKeyPair {
    fn encrypt(&self, data: &[u8]) -> CryptoResult<String> {
        let mut rng = rand::thread_rng();
        let encrypted = self.public_key.encrypt(&mut rng, Pkcs1v15Encrypt, data)
            .map_err(|e| CryptoError::EncryptionError(format!("RSA encryption failed: {}", e)))?;

        encode_base64(&encrypted)
    }

    fn decrypt(&self, data: &str) -> CryptoResult<Vec<u8>> {
        let private_key = match &self.private_key {
            Some(key) => key,
            None => return Err(CryptoError::UnsupportedOperation("No private key available for decryption".into())),
        };

        let encrypted_data = decode_base64(data)?;

        private_key.decrypt(Pkcs1v15Encrypt, &encrypted_data)
            .map_err(|e| CryptoError::DecryptionError(format!("RSA decryption failed: {}", e)))
    }

    fn sign(&self, data: &[u8]) -> CryptoResult<String> {
        let private_key = match &self.private_key {
            Some(key) => key,
            None => return Err(CryptoError::UnsupportedOperation("No private key available for signing".into())),
        };

        // Hash the data with SHA-256
        let mut hasher = Sha256::new();
        hasher.update(data);
        let hashed = hasher.finalize();

        let signature = private_key.sign(Pkcs1v15Sign::new::<Sha256>(), &hashed)
            .map_err(|e| CryptoError::EncryptionError(format!("RSA signing failed: {}", e)))?;

        encode_base64(&signature)
    }

    fn verify(&self, data: &[u8], signature: &str) -> CryptoResult<bool> {
        let signature_bytes = decode_base64(signature)?;

        // Hash the data with SHA-256
        let mut hasher = Sha256::new();
        hasher.update(data);
        let hashed = hasher.finalize();

        let result = self.public_key.verify(
            Pkcs1v15Sign::new::<Sha256>(),
            &hashed,
            &signature_bytes
        );

        Ok(result.is_ok())
    }
}

// Convenience functions

/// Generate a new RSA key pair and return it as PEM strings (private, public)
pub fn generate_rsa_keypair(bits: usize) -> CryptoResult<(String, String)> {
    let keypair = RsaKeyPair::generate(bits)?;
    let private_pem = keypair.private_key_to_pem()?;
    let public_pem = keypair.public_key_to_pem()?;
    Ok((private_pem, public_pem))
}

/// Encrypt data using an RSA public key
pub fn rsa_encrypt(public_key_pem: &str, data: &[u8]) -> CryptoResult<String> {
    let keypair = RsaKeyPair::from_public_key_pem(public_key_pem)?;
    keypair.encrypt(data)
}

/// Decrypt data using an RSA private key
pub fn rsa_decrypt(private_key_pem: &str, data: &str) -> CryptoResult<Vec<u8>> {
    let keypair = RsaKeyPair::from_private_key_pem(private_key_pem)?;
    keypair.decrypt(data)
}

/// Sign data using an RSA private key
pub fn rsa_sign(private_key_pem: &str, data: &[u8]) -> CryptoResult<String> {
    let keypair = RsaKeyPair::from_private_key_pem(private_key_pem)?;
    keypair.sign(data)
}

/// Verify a signature using an RSA public key
pub fn rsa_verify(public_key_pem: &str, data: &[u8], signature: &str) -> CryptoResult<bool> {
    let keypair = RsaKeyPair::from_public_key_pem(public_key_pem)?;
    keypair.verify(data, signature)
}

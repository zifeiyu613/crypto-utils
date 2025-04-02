//! Error types for cryptographic operations

use thiserror::Error;

/// Centralized error type for all crypto operations
#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Invalid key: {0}")]
    InvalidKey(String),

    #[error("Invalid data format: {0}")]
    InvalidData(String),

    #[error("Invalid padding: {0}")]
    InvalidPadding(String),

    #[error("Invalid encoding: {0}")]
    InvalidEncoding(String),

    #[error("Encryption error: {0}")]
    EncryptionError(String),

    #[error("Decryption error: {0}")]
    DecryptionError(String),

    #[error("Hash error: {0}")]
    HashError(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Unsupported operation: {0}")]
    UnsupportedOperation(String),


}

/// Result type for all crypto operations
pub type CryptoResult<T> = Result<T, CryptoError>;

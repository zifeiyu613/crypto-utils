//! # Crypto Utils
//!
//! `crypto-utils` is a comprehensive cryptographic utility library providing
//! easy-to-use APIs for various encryption, hashing, and signing algorithms.
//!
//! ## Features
//!
//! - Symmetric encryption (AES, DES)
//! - Asymmetric encryption (RSA)
//! - Hashing (SHA2, MD5)
//! - HMAC authentication
//! - Password hashing with salt

pub mod error;
pub mod symmetric;
pub mod asymmetric;
pub mod hash;
pub mod util;

// Re-export commonly used items
pub use error::CryptoError;

// Simplified API for common operations
pub mod prelude {
    pub use crate::error::*;
    pub use crate::symmetric::aes::*;
    pub use crate::symmetric::des::*;
    pub use crate::hash::*;
    pub use crate::util::*;
}

/// Library version information
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

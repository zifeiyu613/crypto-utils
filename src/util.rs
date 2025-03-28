//! Utility functions for crypto operations

use base64::Engine;
use rand::Rng;
use crate::error::{CryptoError, CryptoResult};

/// Encode data as Base64
pub fn encode_base64(data: &[u8]) -> CryptoResult<String> {
    Ok(base64::engine::general_purpose::STANDARD.encode(data))
}

/// Decode Base64 data
pub fn decode_base64(encoded: &str) -> CryptoResult<Vec<u8>> {
    base64::engine::general_purpose::STANDARD.decode(encoded)
        .map_err(|_| CryptoError::InvalidEncoding("Invalid Base64 data".into()))
}

/// Apply PKCS7 padding to data for the given block size
pub fn pkcs7_pad(data: &[u8], block_size: usize) -> Vec<u8> {
    let pad_len = block_size - (data.len() % block_size);
    let mut padded = Vec::with_capacity(data.len() + pad_len);
    padded.extend_from_slice(data);
    padded.extend(vec![pad_len as u8; pad_len]);
    padded
}

/// Remove PKCS7 padding from data
pub fn pkcs7_unpad(data: &[u8]) -> CryptoResult<Vec<u8>> {
    if data.is_empty() {
        return Err(CryptoError::InvalidPadding("Empty data".into()));
    }

    let last_byte = *data.last().unwrap() as usize;
    if last_byte == 0 || last_byte > data.len() {
        return Err(CryptoError::InvalidPadding("Invalid padding value".into()));
    }

    // Validate padding
    let padding_start = data.len() - last_byte;
    if !data[padding_start..].iter().all(|&x| x == last_byte as u8) {
        return Err(CryptoError::InvalidPadding("Inconsistent padding bytes".into()));
    }

    Ok(data[..padding_start].to_vec())
}

/// Generate a random key of the specified length
pub fn generate_random_key(length: usize) -> Vec<u8> {
    let mut key = vec![0u8; length];
    rand::thread_rng().fill(&mut key[..]);
    key
}

/// Convert a hex string to bytes
pub fn hex_to_bytes(hex: &str) -> CryptoResult<Vec<u8>> {
    hex::decode(hex)
        .map_err(|_| CryptoError::InvalidEncoding("Invalid hex string".into()))
}

/// Convert bytes to a hex string
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}



#[cfg(test)]
mod tests {
    use super::*;



    #[test]
    fn test_decode_encode_base64() -> CryptoResult<()> {

        let str = "this is a test msg ~~~";

        let result =decode_base64(str)?;

        let result = encode_base64(&result)?;

        assert_eq!(result, str);

        Ok(())
    }

}
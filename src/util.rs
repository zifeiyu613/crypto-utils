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
// pub fn pkcs7_pad(data: &[u8], block_size: usize) -> Vec<u8> {
//     let pad_len = block_size - (data.len() % block_size);
//     let mut padded = Vec::with_capacity(data.len() + pad_len);
//     padded.extend_from_slice(data);
//     padded.extend(vec![pad_len as u8; pad_len]);
//     padded
// }

// PKCS7填充函数
// pub fn pkcs7_pad(data: &[u8], block_size: usize) -> Vec<u8> {
//     let padding_length = block_size - (data.len() % block_size);
//     let mut padded = data.to_vec();
//     padded.extend(std::iter::repeat(padding_length as u8).take(padding_length));
//     padded
// }

// PKCS7 填充
pub fn pkcs7_pad(data: &[u8], block_size: usize) -> Vec<u8> {
    let mut padded = data.to_vec();
    let pad_len = block_size - (data.len() % block_size);
    padded.extend(vec![pad_len as u8; pad_len]);
    padded
}


// PKCS7去填充函数
pub fn pkcs7_unpad(data: &[u8]) -> CryptoResult<Vec<u8>> {
    if data.is_empty() {
        return Err(CryptoError::InvalidData("Empty data".into()));
    }

    let padding_length = data[data.len() - 1] as usize;

    // 验证填充长度的有效性
    if padding_length == 0 || padding_length > 8 {
        return Err(CryptoError::InvalidData("Invalid padding".into()));
    }

    // 检查填充是否一致
    for i in 1..=padding_length {
        if data[data.len() - i] != padding_length as u8 {
            return Err(CryptoError::InvalidData("Invalid padding".into()));
        }
    }

    // 返回去除填充后的原始数据
    Ok(data[..data.len() - padding_length].to_vec())
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
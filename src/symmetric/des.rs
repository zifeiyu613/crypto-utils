//! DES encryption implementations

use std::error::Error;
use cipher::generic_array::GenericArray;
use cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use des::Des;
use rand::{thread_rng, Rng};

use super::SymmetricCipher;
use crate::error::{CryptoError, CryptoResult};
use crate::util::{decode_base64, encode_base64, pkcs7_pad, pkcs7_unpad};

/// DES-CBC cipher with PKCS7 padding
pub struct DesCbc {
    key: [u8; 8],
    iv: Option<[u8; 8]>,
}

impl DesCbc {
    /// Create a new DES-CBC instance with the provided key and optional IV
    pub fn new(key: &[u8], iv: Option<[u8; 8]>) -> CryptoResult<Self> {
        if key.len() != 8 {
            return Err(CryptoError::InvalidKey("DES key must be 8 bytes".into()));
        }

        let mut key_array = [0u8; 8];
        key_array.copy_from_slice(key);

        let iv_opt = match iv {
            Some(iv_data) => {
                if iv_data.len() != 8 {
                    return Err(CryptoError::InvalidKey("DES IV must be 8 bytes".into()));
                }

                let mut iv_array = [0u8; 8];
                iv_array.copy_from_slice(&iv_data);
                Some(iv_array)
            },
            None => {
                let mut random_iv = [0u8; 8];
                thread_rng().fill(&mut random_iv);
                Some(random_iv)
            },
        };

        Ok(Self { key: key_array, iv: iv_opt })
    }
}

impl SymmetricCipher for DesCbc {
    fn encrypt(&self, data: &[u8]) -> CryptoResult<String> {

        let padded_data = pkcs7_pad(data, 8);

        let key = GenericArray::from(self.key);
        let cipher = Des::new(&key);

        let mut encrypted_data = Vec::with_capacity(padded_data.len());

        // 生成随机IV
        let mut iv = self.iv.unwrap();

        // CBC 模式加密
        for chunk in padded_data.chunks(8) {
            // 与 IV 或前一个密文块异或
            let mut block = [0u8; 8];
            for i in 0..8 {
                block[i] = chunk[i] ^ iv[i];
            }
            let mut block = GenericArray::from(block);
            cipher.encrypt_block(&mut block);

            // 更新 IV 为当前密文块
            iv.copy_from_slice(block.as_slice());

            encrypted_data.extend_from_slice(block.as_slice());
        }
        // Base64编码
        encode_base64(&encrypted_data)
    }

    // key: [u8; 8], iv: [u8; 8],
    fn decrypt(&self, data: &str) -> CryptoResult<Vec<u8>> {
        let decoded = decode_base64(data)?;

        // 验证密文长度
        if decoded.len() < 16 || (decoded.len() - 8) % 8 != 0 {
            return Err(CryptoError::InvalidData("Invalid ciphertext length".into()));
        }
        let encrypted_data = &decoded;

        let key = GenericArray::from(self.key);
        let cipher = Des::new(&key);

        let mut decrypted_data = Vec::with_capacity(encrypted_data.len());
        let mut current_iv = self.iv.unwrap();

        // CBC 模式解密
        for chunk in encrypted_data.chunks(8) {
            let mut block = [0u8; 8];
            block.copy_from_slice(chunk);

            let encrypted_block = GenericArray::from(block);
            let mut decrypted_block = encrypted_block.clone();
            cipher.decrypt_block(&mut decrypted_block);

            // 与 IV 异或
            for i in 0..8 {
                block[i] = decrypted_block[i] ^ current_iv[i];
            }
            // 更新 IV 为上一个密文块
            current_iv.copy_from_slice(chunk);
            decrypted_data.extend_from_slice(&block);
        }

        let decrypted_data = pkcs7_unpad(&decrypted_data)?;
        Ok(decrypted_data)
    }

}

// Convenience functions

/// Encrypt data using DES in CBC mode
pub fn des_cbc_encrypt(key: &[u8; 8], data: &[u8], iv: Option<[u8; 8]>) -> CryptoResult<String> {
    let cipher = DesCbc::new(key, iv)?;
    cipher.encrypt(data)
}

/// Decrypt data using DES in CBC mode
pub fn des_cbc_decrypt(key: &[u8; 8], data: &str) -> CryptoResult<Vec<u8>> {
    let cipher = DesCbc::new(key, None)?;
    cipher.decrypt(data)
}

/// Convenience function to encrypt a string using DES-CBC and return a Base64 string
pub fn des_encrypt_string(key: &[u8; 8], data: &str, iv: Option<[u8; 8]>) -> CryptoResult<String> {
    let cipher = DesCbc::new(key, iv)?;
    cipher.encrypt_str(data)
}

/// Convenience function to decrypt a Base64 string to a string using DES-CBC
pub fn des_decrypt_string(key: &[u8; 8], data: &str, iv: Option<[u8; 8]>) -> CryptoResult<String> {
    let cipher = DesCbc::new(key, iv)?;
    cipher.decrypt_str(data)
}

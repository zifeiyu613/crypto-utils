//! AES encryption implementations

use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit, KeySizeUser};
use aes::cipher::{KeyIvInit, block_padding::Pkcs7};
use aes::{Aes128, Aes192, Aes256};
use cipher::BlockEncryptMut;
use cipher::BlockDecryptMut;
use cipher::generic_array::{GenericArray, typenum::Unsigned};
use rand::{Rng, thread_rng};

use crate::error::{CryptoError, CryptoResult};
use crate::symmetric::SymmetricCipher;
use crate::util::{decode_base64, encode_base64, pkcs7_pad, pkcs7_unpad};

/// AES-CBC cipher with PKCS7 padding
pub struct AesCbc {
    key: Vec<u8>,
    iv: Option<Vec<u8>>,
}

impl AesCbc {
    /// 创建一个新的 AES-CBC（密码分组链接模式）加密实例
    ///
    /// # 参数说明
    /// - key: 加密密钥，长度要求：
    ///   * 16 字节 = 128 位 (AES-128)
    ///   * 24 字节 = 192 位 (AES-192)
    ///   * 32 字节 = 256 位 (AES-256)
    ///
    /// # IV（初始化向量）
    /// - 如果 IV 参数为 None，加密时会自动生成随机 IV
    /// - 每次加密操作都会使用新的随机 IV，增加安全性
    ///
    /// # 示例
    /// ```
    /// use crypto_utils::prelude::*;
    ///
    /// let key = [0u8; 32]; // 256位密钥
    /// let aes = AesCbc::new(&key, None);
    /// ```
    pub fn new(key: &[u8], iv: Option<&[u8]>) -> CryptoResult<Self> {
        match key.len() {
            16 | 24 | 32 => {
                let iv_vec = match iv {
                    Some(iv) => {
                        if iv.len() != 16 {
                            return Err(CryptoError::InvalidKey("IV must be 16 bytes".into()));
                        }
                        Some(iv.to_vec())
                    }
                    None => None,
                };

                Ok(Self {
                    key: key.to_vec(),
                    iv: iv_vec,
                })
            }
            _ => Err(CryptoError::InvalidKey(
                "AES key must be 16 (AES-128), 24 (AES-192), or 32 (AES-256) bytes".into(),
            )),
        }
    }
}

impl SymmetricCipher for AesCbc {
    fn encrypt(&self, data: &[u8]) -> CryptoResult<String> {
        let iv = match &self.iv {
            Some(iv) => iv.clone(),
            None => {
                let mut random_iv = vec![0u8; 16];
                thread_rng().fill(&mut random_iv[..]);
                random_iv
            }
        };

        match self.key.len() {
            16 => {
                type Aes128CbcEnc = cbc::Encryptor<Aes128>;
                let cipher = Aes128CbcEnc::new_from_slices(&self.key, &iv).map_err(|_| {
                    CryptoError::EncryptionError("Failed to initialize cipher".into())
                })?;

                let ciphertext = cipher.encrypt_padded_vec_mut::<Pkcs7>(data);

                let mut result = iv;
                result.extend_from_slice(&ciphertext);

                encode_base64(&result)
            }
            24 => {
                type Aes192CbcEnc = cbc::Encryptor<Aes192>;
                let cipher = Aes192CbcEnc::new_from_slices(&self.key, &iv).map_err(|_| {
                    CryptoError::EncryptionError("Failed to initialize cipher".into())
                })?;

                let ciphertext = cipher.encrypt_padded_vec_mut::<Pkcs7>(data);

                let mut result = iv;
                result.extend_from_slice(&ciphertext);

                encode_base64(&result)
            }
            32 => {
                type Aes256CbcEnc = cbc::Encryptor<Aes256>;
                let cipher = Aes256CbcEnc::new_from_slices(&self.key, &iv).map_err(|_| {
                    CryptoError::EncryptionError("Failed to initialize cipher".into())
                })?;

                // let mut buffer = data.to_vec();
                let ciphertext = cipher.encrypt_padded_vec_mut::<Pkcs7>(data);

                let mut result = iv;
                result.extend_from_slice(&ciphertext);

                encode_base64(&result)
            }
            _ => Err(CryptoError::InvalidKey("Invalid key length".into())),
        }
    }

    fn decrypt(&self, data: &str) -> CryptoResult<Vec<u8>> {
        let encrypted_bytes = decode_base64(data)?;

        if encrypted_bytes.len() < 16 {
            return Err(CryptoError::InvalidData("Ciphertext too short".into()));
        }

        // Extract IV and ciphertext
        let (iv, ciphertext) = encrypted_bytes.split_at(16);

        let mut buffer = ciphertext.to_vec();

        match self.key.len() {
            16 => {
                type Aes128CbcDec = cbc::Decryptor<Aes128>;
                let cipher = Aes128CbcDec::new_from_slices(&self.key, iv).map_err(|_| {
                    CryptoError::DecryptionError("Failed to initialize cipher".into())
                })?;

                let plaintext = cipher.decrypt_padded_mut::<Pkcs7>(&mut buffer)
                    .map_err(|_| CryptoError::DecryptionError("Decryption failed".into()))?;
                Ok(plaintext.to_vec())
            }
            24 => {
                type Aes192CbcDec = cbc::Decryptor<Aes192>;
                let cipher = Aes192CbcDec::new_from_slices(&self.key, iv).map_err(|_| {
                    CryptoError::DecryptionError("Failed to initialize cipher".into())
                })?;

                let plaintext = cipher.decrypt_padded_mut::<Pkcs7>(&mut buffer)
                    .map_err(|_| CryptoError::DecryptionError("Decryption failed".into()))?;
                Ok(plaintext.to_vec())
            }
            32 => {
                type Aes256CbcDec = cbc::Decryptor<Aes256>;
                let cipher = Aes256CbcDec::new_from_slices(&self.key, iv).map_err(|_| {
                    CryptoError::DecryptionError("Failed to initialize cipher".into())
                })?;

                let plaintext = cipher.decrypt_padded_mut::<Pkcs7>(&mut buffer)
                    .map_err(|_| CryptoError::DecryptionError("Decryption failed".into()))?;
                Ok(plaintext.to_vec())
            }
            _ => Err(CryptoError::InvalidKey("Invalid key length".into())),
        }
    }
}

/// AES-ECB cipher (not recommended for secure applications)
pub struct AesEcb {
    key: Vec<u8>,
}

impl AesEcb {
    /// Create a new AES-ECB instance with the given key
    ///
    /// Key must be 16, 24, or 32 bytes for AES-128, AES-192, or AES-256 respectively.
    ///
    /// # Security Warning
    ///
    /// ECB mode is not secure for most applications as it does not hide data patterns.
    /// Consider using AesCbc instead.
    pub fn new(key: &[u8]) -> CryptoResult<Self> {
        match key.len() {
            16 | 24 | 32 => Ok(Self { key: key.to_vec() }),
            _ => Err(CryptoError::InvalidKey(
                "AES key must be 16 (AES-128), 24 (AES-192), or 32 (AES-256) bytes".into(),
            )),
        }
    }
}

impl SymmetricCipher for AesEcb {
    fn encrypt(&self, data: &[u8]) -> CryptoResult<String> {
        match self.key.len() {
            16 => ecb_encrypt_with_cipher::<Aes128>(&self.key, data),
            24 => ecb_encrypt_with_cipher::<Aes192>(&self.key, data),
            32 => ecb_encrypt_with_cipher::<Aes256>(&self.key, data),
            _ => Err(CryptoError::InvalidKey("Invalid key length".into())),
        }
    }

    fn decrypt(&self, data: &str) -> CryptoResult<Vec<u8>> {
        match self.key.len() {
            16 => ecb_decrypt_with_cipher::<Aes128>(&self.key, data),
            24 => ecb_decrypt_with_cipher::<Aes192>(&self.key, data),
            32 => ecb_decrypt_with_cipher::<Aes256>(&self.key, data),
            _ => Err(CryptoError::InvalidKey("Invalid key length".into())),
        }
    }
}

// Helper Functions

/// Internal function for ECB mode encryption
fn ecb_encrypt_with_cipher<C>(key: &[u8], data: &[u8]) -> CryptoResult<String>
where
    C: KeyInit + BlockEncrypt,
    <C as KeySizeUser>::KeySize: Unsigned,
{
    let cipher = C::new_from_slice(key)
        .map_err(|_| CryptoError::InvalidKey("Failed to initialize cipher".into()))?;

    let block_size = C::block_size();
    let padded_data = pkcs7_pad(data, block_size);
    let mut encrypted_data = Vec::with_capacity(padded_data.len());

    for chunk in padded_data.chunks(block_size) {
        let mut block = GenericArray::default();
        block.copy_from_slice(chunk);
        cipher.encrypt_block(&mut block);
        encrypted_data.extend_from_slice(block.as_slice());
    }

    encode_base64(&encrypted_data)
}

/// Internal function for ECB mode decryption
fn ecb_decrypt_with_cipher<C>(key: &[u8], encrypted_data: &str) -> CryptoResult<Vec<u8>>
where
    C: KeyInit + BlockDecrypt,
    <C as KeySizeUser>::KeySize: Unsigned,
{
    let encrypted_bytes = decode_base64(encrypted_data)?;

    let cipher = C::new_from_slice(key)
        .map_err(|_| CryptoError::InvalidKey("Failed to initialize cipher".into()))?;

    let block_size = C::block_size();

    if encrypted_bytes.len() % block_size != 0 {
        return Err(CryptoError::InvalidData("Invalid ciphertext length".into()));
    }

    let mut decrypted_data = Vec::with_capacity(encrypted_bytes.len());

    for chunk in encrypted_bytes.chunks(block_size) {
        let mut block = GenericArray::default();
        block.copy_from_slice(chunk);
        cipher.decrypt_block(&mut block);
        decrypted_data.extend_from_slice(block.as_slice());
    }

    pkcs7_unpad(&decrypted_data)
        .map_err(|e| CryptoError::InvalidPadding(e.to_string()))
}

// Convenience functions

/// AES-128 CBC encryption
pub fn aes128_cbc_encrypt(
    key: &[u8; 16],
    data: &[u8],
    iv: Option<&[u8; 16]>,
) -> CryptoResult<String> {
    let cipher = match iv {
        Some(iv_data) => AesCbc::new(key, Some(iv_data))?,
        None => AesCbc::new(key, None)?,
    };
    cipher.encrypt(data)
}

/// AES-128 CBC decryption
pub fn aes128_cbc_decrypt(key: &[u8; 16], data: &str) -> CryptoResult<Vec<u8>> {
    let cipher = AesCbc::new(key, None)?;
    cipher.decrypt(data)
}

/// AES-256 CBC encryption
pub fn aes256_cbc_encrypt(
    key: &[u8; 32],
    data: &[u8],
    iv: Option<&[u8; 16]>,
) -> CryptoResult<String> {
    let cipher = match iv {
        Some(iv_data) => AesCbc::new(key, Some(iv_data))?,
        None => AesCbc::new(key, None)?,
    };
    cipher.encrypt(data)
}

/// AES-256 CBC decryption
pub fn aes256_cbc_decrypt(key: &[u8; 32], data: &str) -> CryptoResult<Vec<u8>> {
    let cipher = AesCbc::new(key, None)?;
    cipher.decrypt(data)
}

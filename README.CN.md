# crypto-utils

[![Crates.io](https://img.shields.io/crates/v/crypto-utils.svg)](https://crates.io/crates/crypto-utils)
[![Documentation](https://docs.rs/crypto-utils/badge.svg)](https://docs.rs/crypto-utils)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE)

全面、易用的Rust加密工具库。

## 功能特点

- **对称加密**
  - AES (128/192/256位) CBC和ECB模式
  - DES CBC模式
  - PKCS7填充

- **非对称加密**
  - RSA加密/解密
  - RSA签名/验证

- **哈希与认证**
  - SHA-256和SHA-512哈希
  - HMAC-SHA256
  - 基于PBKDF2的密码哈希
  - 安全的密码验证

- **实用工具**
  - Base64编码/解码
  - 随机密钥生成
  - 十六进制编码/解码

- **开发者友好**
  - 所有算法统一的API接口
  - 全面的错误处理
  - 详细的文档和示例

## 安装

在`Cargo.toml`中添加`crypto-utils`依赖：

```toml
[dependencies]
crypto-utils = "0.1.0"
```

## 快速入门

### 对称加密

```rust
use crypto_utils::prelude::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 生成随机的256位AES密钥
    let key = generate_random_key(32);
    
    // 创建AES-CBC加密器
    let cipher = AesCbc::new(&key, None)?;
    
    // 加密消息
    let encrypted = cipher.encrypt_str("秘密消息")?;
    println!("加密结果: {}", encrypted);
    
    // 解密消息
    let decrypted = cipher.decrypt_str(&encrypted)?;
    println!("解密结果: {}", decrypted);
    
    Ok(())
}
```

### 密码哈希

```rust
use crypto_utils::prelude::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 创建默认设置的密码哈希器
    let hasher = PasswordHasher::default();
    
    // 哈希密码
    let password = "安全的用户密码";
    let hash = hasher.hash_password(password)?;
    
    println!("密码哈希: {}", hash);
    
    // 验证密码
    let is_valid = hasher.verify_password(password, &hash)?;
    println!("密码验证结果: {}", is_valid);
    
    Ok(())
}
```

### RSA加密与签名

```rust
use crypto_utils::prelude::*;
use crypto_utils::asymmetric::rsa::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 生成新的2048位RSA密钥对
    let (private_key, public_key) = generate_rsa_keypair(2048)?;
    
    // 从私钥创建密钥对
    let key_pair = RsaKeyPair::from_private_key_pem(&private_key)?;
    
    // 加密消息
    let message = "RSA加密的秘密消息";
    let encrypted = key_pair.encrypt(message.as_bytes())?;
    
    // 解密消息
    let decrypted = key_pair.decrypt(&encrypted)?;
    println!("解密结果: {}", String::from_utf8_lossy(&decrypted));
    
    // 签名消息
    let signature = key_pair.sign(message.as_bytes())?;
    
    // 验证签名
    let is_valid = key_pair.verify(message.as_bytes(), &signature)?;
    println!("签名验证结果: {}", is_valid);
    
    Ok(())
}
```

## 详细使用说明

### 对称加密

#### AES加密

```rust
// AES-256 CBC模式（推荐）
let key = generate_random_key(32); // 32字节 = 256位
let cipher = AesCbc::new(&key, None)?; // 将生成随机IV

// 使用指定的IV
let iv = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
let cipher = AesCbc::new(&key, Some(&iv))?;

// 使用便捷函数
let key_128: [u8; 16] = [/* ... */]; // 16字节用于AES-128
let encrypted = aes128_cbc_encrypt(&key_128, data.as_bytes(), None)?;
let decrypted = aes128_cbc_decrypt(&key_128, &encrypted)?;

// 使用便捷函数的AES-256
let key_256: [u8; 32] = [/* ... */]; // 32字节用于AES-256
let encrypted = aes256_cbc_encrypt(&key_256, data.as_bytes(), None)?;
let decrypted = aes256_cbc_decrypt(&key_256, &encrypted)?;
```

#### DES加密

```rust
// DES CBC模式
let key = [1, 2, 3, 4, 5, 6, 7, 8]; // DES需要8字节
let cipher = DesCbc::new(&key, None)?;

// 使用便捷函数
let encrypted = des_encrypt_string(&key, "秘密消息", None)?;
let decrypted = des_decrypt_string(&key, &encrypted)?;
```

### 哈希

```rust
// SHA-256
let hash = sha256_hex("数据".as_bytes());

// SHA-512
let hash = sha512_hex("数据".as_bytes());

// HMAC-SHA256
let key = "密钥".as_bytes();
let hmac = hmac_sha256_base64(key, "数据".as_bytes())?;
```

### 密码处理

```rust
// 创建自定义设置的密码哈希器
let hasher = PasswordHasher::new(150_000, 32); // 150,000次迭代，32字节盐值

// 或使用默认设置（100,000次迭代，16字节盐值）
let hasher = PasswordHasher::default();

// 哈希密码
let hash = hasher.hash_password("用户密码")?;

// 验证密码
let is_valid = hasher.verify_password("用户密码", &hash)?;
```

### 非对称加密

```rust
// 生成新的RSA密钥对
let key_pair = RsaKeyPair::generate(2048)?;

// 导出密钥为PEM格式
let private_pem = key_pair.private_key_to_pem()?;
let public_pem = key_pair.public_key_to_pem()?;

// 从已有密钥加载
let from_private = RsaKeyPair::from_private_key_pem(&private_pem)?;
let public_only = RsaKeyPair::from_public_key_pem(&public_pem)?;

// 用公钥加密
let encrypted = rsa_encrypt(&public_pem, "数据".as_bytes())?;

// 用私钥解密
let decrypted = rsa_decrypt(&private_pem, &encrypted)?;

// 签名数据
let signature = rsa_sign(&private_pem, "数据".as_bytes())?;

// 验证签名
let is_valid = rsa_verify(&public_pem, "数据".as_bytes(), &signature)?;
```

## 安全考虑事项

- 对于大多数用例，推荐使用AES-CBC而非AES-ECB
- 始终使用安全的随机源生成密钥
- 在应用程序中谨慎考虑密钥管理
- 遵循存储密码哈希的安全最佳实践
- 本库会自动处理IV生成和存储
- 避免在新应用中使用DES（仅为兼容遗留系统而提供）

## 错误处理

本库中的所有函数都返回`CryptoResult<T>`，这是`Result<T, CryptoError>`的别名。`CryptoError`枚举提供了详细的错误信息：

```rust
// 加密错误处理示例
match cipher.encrypt_str("数据") {
    Ok(encrypted) => println!("加密结果: {}", encrypted),
    Err(CryptoError::InvalidKey(msg)) => eprintln!("密钥错误: {}", msg),
    Err(CryptoError::EncryptionError(msg)) => eprintln!("加密失败: {}", msg),
    Err(e) => eprintln!("其他错误: {}", e),
}
```

## 支持的算法

### 对称加密
- AES-128、AES-192、AES-256（CBC模式）
- AES-128、AES-192、AES-256（ECB模式，不推荐用于安全敏感应用）
- DES（CBC模式，用于遗留系统支持）

### 非对称加密
- 使用PKCS#1 v1.5填充的RSA
- 使用PKCS#1 v1.5和SHA-256的RSA签名

### 哈希
- SHA-256
- SHA-512
- HMAC-SHA256
- 基于HMAC-SHA256的PBKDF2

## 贡献指南

欢迎贡献！请随时提交Pull Request。

1. Fork仓库
2. 创建你的特性分支（`git checkout -b feature/amazing-feature`）
3. 提交你的更改（`git commit -m '添加某个惊人特性'`）
4. 推送到分支（`git push origin feature/amazing-feature`）
5. 开启一个Pull Request

请确保你的代码通过所有测试，并符合Rust风格指南。

## 许可证

本项目采用以下任一许可证：

- Apache许可证 2.0版本（[LICENSE-APACHE](LICENSE-APACHE)或http://www.apache.org/licenses/LICENSE-2.0）
- MIT许可证（[LICENSE-MIT](LICENSE-MIT)或http://opensource.org/licenses/MIT）

由您选择。

## 致谢

- Rust加密工作组提供的优秀加密基元
- 所有帮助改进这个库的贡献者

---

为Rust社区用❤️制作。
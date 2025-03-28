use crypto_utils::asymmetric::AsymmetricCipher;
use crypto_utils::asymmetric::rsa::*;

fn main() -> Result<(), anyhow::Error> {

    println!("=== RSA Encryption and Signing Examples ===");

    // 生成 RSA 密钥对
    println!("1. 生成 RSA 密钥对 (2048位)");
    let (private_key, public_key) = generate_rsa_keypair(2048)?;
    println!("  - 私钥长度: {} 字符", private_key.len());
    println!("  - 公钥长度: {} 字符", public_key.len());

    // 使用公钥加密数据
    let message = "这是需要加密的敏感信息";
    println!("2. 使用公钥加密数据");
    println!("  - 原始消息: {}", message);

    let encrypted = rsa_encrypt(&public_key, message.as_bytes())?;
    println!("  - 加密后 (Base64): {}", encrypted);

    // 使用私钥解密数据
    println!("3. 使用私钥解密数据");
    let decrypted = rsa_decrypt(&private_key, &encrypted)?;
    println!("  - 解密后: {}", String::from_utf8_lossy(&decrypted));

    // 使用创建的密钥对加载
    println!("4. 从 PEM 文件创建 RSA 密钥对");
    let key_pair = RsaKeyPair::from_private_key_pem(&private_key)?;
    println!("  - 成功从私钥创建密钥对");

    let public_only = RsaKeyPair::from_public_key_pem(&public_key)?;
    println!("  - 成功从公钥创建密钥对 (仅公钥)");

    // 签名示例
    println!("5. 签名与验证");
    let data_to_sign = "需要签名的重要数据";
    println!("  - 待签名数据: {}", data_to_sign);

    // 使用私钥签名
    let signature = key_pair.sign(data_to_sign.as_bytes())?;
    println!("  - 签名 (Base64): {}", signature);

    // 使用公钥验证签名
    let is_valid = public_only.verify(data_to_sign.as_bytes(), &signature)?;
    println!("  - 签名验证结果: {}", is_valid);

    // 验证被篡改的数据
    let tampered_data = "被篡改的数据";
    let is_valid = public_only.verify(tampered_data.as_bytes(), &signature)?;
    println!("  - 篡改数据验证结果: {}", is_valid);

    // 使用便捷函数进行签名和验证
    println!("6. 使用便捷函数进行签名和验证");
    let signature = rsa_sign(&private_key, data_to_sign.as_bytes())?;
    println!("  - 使用便捷函数生成的签名 (Base64): {}", signature);

    let is_valid = rsa_verify(&public_key, data_to_sign.as_bytes(), &signature)?;
    println!("  - 使用便捷函数验证签名: {}", is_valid);

    // 密钥导出
    println!("7. 密钥导出示例");
    let exported_private = key_pair.private_key_to_pem()?;
    let exported_public = key_pair.public_key_to_pem()?;

    println!("  - 导出的私钥长度: {} 字符", exported_private.len());
    println!("  - 导出的公钥长度: {} 字符", exported_public.len());

    println!("=== RSA 操作完成 ===");
    Ok(())
}

//! AES-256-GCM encryption utilities

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use anyhow::{Context, Result};
use pbkdf2::pbkdf2_hmac;
use rand::RngCore;
use sha2::{Digest, Sha256};

// Constants
const BYTES_IV: usize = 12;
const BYTES_SALT: usize = 16;
const MIN_KDF_ITER_COUNT: u32 = 10000;

/// Generate random bytes
pub fn generate_random(bytes: usize) -> Result<Vec<u8>> {
    let mut result = vec![0u8; bytes];
    rand::thread_rng().fill_bytes(&mut result);
    Ok(result)
}

/// Calculate SHA-256 hash of data
pub fn sha256sum(data: &[u8]) -> Vec<u8> {
    Sha256::digest(data).to_vec()
}

/// Derive key from passphrase using PBKDF2-HMAC-SHA256
pub fn derive_key(passphrase: &[u8], salt: &[u8], kdf_iter_count: u32) -> Vec<u8> {
    let iterations = if kdf_iter_count < MIN_KDF_ITER_COUNT {
        MIN_KDF_ITER_COUNT
    } else {
        kdf_iter_count
    };

    let mut result = vec![0u8; 32]; // SHA-256 output size
    pbkdf2_hmac::<Sha256>(passphrase, salt, iterations, &mut result);
    result
}

/// Encrypt data using AES-256-GCM
pub fn encrypt(passphrase: &[u8], plaintext: &[u8], kdf_iter_count: u32) -> Result<Vec<u8>> {
    // Generate salt and derive key
    let salt = generate_random(BYTES_SALT)?;
    let key = derive_key(passphrase, &salt, kdf_iter_count);

    // Initialize cipher
    let cipher = Aes256Gcm::new_from_slice(&key).context("Failed to initialize cipher")?;

    // Generate IV (nonce)
    let iv = generate_random(BYTES_IV)?;
    let nonce = Nonce::from_slice(&iv);

    // Encrypt the plaintext
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| anyhow::anyhow!("Encryption failed"))?;

    // Combine all parts: iv + ciphertext + salt
    let mut result = iv.to_vec();
    result.extend_from_slice(&ciphertext);
    result.extend_from_slice(&salt);

    Ok(result)
}

/// Decrypt data using AES-256-GCM
pub fn decrypt(passphrase: &[u8], data: &[u8], kdf_iter_count: u32) -> Result<Vec<u8>> {
    // Split the data into its components
    let salt_idx = data.len() - BYTES_SALT;
    let iv = &data[0..BYTES_IV];
    let ciphertext = &data[BYTES_IV..salt_idx];
    let salt = &data[salt_idx..];

    // Derive the key
    let key = derive_key(passphrase, salt, kdf_iter_count);

    // Initialize cipher
    let cipher = Aes256Gcm::new_from_slice(&key).context("Failed to initialize cipher")?;

    let nonce = Nonce::from_slice(iv);

    // Decrypt the ciphertext
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| anyhow::anyhow!("Decryption failed"))?;

    Ok(plaintext)
}

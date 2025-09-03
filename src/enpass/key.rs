//! Key derivation functionality for Enpass vault

use anyhow::{anyhow, Context, Result};
use pbkdf2::pbkdf2_hmac;
use sha2::{Digest, Sha512};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use super::keyfile::load_keyfile_password;

/// Constants for key derivation
pub const KEY_DERIVATION_ALGO: &str = "pbkdf2";
pub const DB_ENCRYPTION_ALGO: &str = "aes-256-cbc";
pub const SALT_LENGTH: usize = 16;
pub const MASTER_KEY_LENGTH: usize = 64;

/// Generate master password to decrypt the vault database
pub fn generate_master_password(password: &[u8], keyfile_path: Option<&Path>) -> Result<Vec<u8>> {
    if let Some(keyfile) = keyfile_path {
        log::debug!("Using keyfile");

        let keyfile_bytes =
            load_keyfile_password(keyfile).context("Failed to load keyfile password")?;

        let mut master_password = password.to_vec();
        master_password.extend_from_slice(&keyfile_bytes);

        Ok(master_password)
    } else {
        log::debug!("Not using keyfile");

        if password.is_empty() {
            return Err(anyhow!("Empty master password provided"));
        }

        Ok(password.to_vec())
    }
}

/// Extract the encryption salt stored in the database
pub fn extract_salt<P: AsRef<Path>>(db_path: P) -> Result<Vec<u8>> {
    let mut file = File::open(&db_path)
        .with_context(|| format!("Could not open database: {:?}", db_path.as_ref()))?;

    let mut salt = vec![0u8; SALT_LENGTH];
    file.seek(SeekFrom::Start(0))?;
    file.read_exact(&mut salt)
        .context("Could not read database salt")?;

    Ok(salt)
}

/// Derive the SQLCipher crypto key
pub fn derive_key(
    master_password: &[u8],
    salt: &[u8],
    kdf_algo: &str,
    encryption_algo: &str,
    kdf_iterations: i32,
) -> Result<Vec<u8>> {
    if kdf_algo != KEY_DERIVATION_ALGO {
        return Err(anyhow!(
            "Key derivation algorithm has changed, open up a GitHub issue"
        ));
    }

    if encryption_algo != DB_ENCRYPTION_ALGO {
        return Err(anyhow!(
            "Database encryption algorithm has changed, open up a GitHub issue"
        ));
    }

    // Create a buffer for the derived key
    let mut derived_key = vec![0u8; Sha512::output_size()];

    // Derive the key using PBKDF2-HMAC-SHA512
    pbkdf2_hmac::<Sha512>(
        master_password,
        salt,
        kdf_iterations as u32,
        &mut derived_key,
    );

    Ok(derived_key)
}

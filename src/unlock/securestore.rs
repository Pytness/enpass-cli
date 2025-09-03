//! Secure storage for vault credentials

use anyhow::{anyhow, Context, Result};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::Instant;

use super::aes256gcm::{decrypt, encrypt, sha256sum};

const FILE_NAME_PREF: &str = "enpasscli-";

/// Secure storage for vault credentials
pub struct SecureStore {
    file_path: PathBuf,
    passphrase: Vec<u8>,
    kdf_iter_count: u32,
    was_read_successfully: bool,
}

impl SecureStore {
    /// Create a new secure store
    pub fn new(name: &str) -> Result<Self> {
        log::debug!("Loading store file");
        let file_path = get_store_file_path(name)?;

        Ok(Self {
            file_path,
            passphrase: Vec::new(),
            kdf_iter_count: 0,
            was_read_successfully: false,
        })
    }

    /// Generate passphrase from PIN
    pub fn generate_passphrase(
        &mut self,
        pin: &str,
        pepper: &str,
        kdf_iter_count: u32,
    ) -> Result<()> {
        log::debug!(
            "Generating store passphrase from pin (kdfIterCount={})",
            kdf_iter_count
        );
        self.kdf_iter_count = kdf_iter_count;

        let mut data = pin.as_bytes().to_vec();
        data.extend_from_slice(pepper.as_bytes());

        self.passphrase = sha256sum(&data);
        Ok(())
    }

    /// Read data from the store
    pub fn read(&mut self) -> Result<Option<Vec<u8>>> {
        if self.passphrase.is_empty() {
            return Err(anyhow!("Empty store passphrase"));
        }

        log::debug!("Reading store data");
        let data = match fs::read(&self.file_path) {
            Ok(data) if !data.is_empty() => data,
            _ => return Ok(None), // nothing to read
        };

        log::debug!("Decrypting store data");
        let start = Instant::now();
        let db_key = decrypt(&self.passphrase, &data, self.kdf_iter_count)?;
        let duration = start.elapsed();

        log::trace!("Decrypted in {}ms", duration.as_millis());
        self.was_read_successfully = !db_key.is_empty();

        Ok(Some(db_key))
    }

    /// Write data to the store
    pub fn write(&mut self, db_key: &[u8]) -> Result<()> {
        if self.was_read_successfully {
            return Ok(()); // no need to overwrite if read was successful
        }

        if self.passphrase.is_empty() {
            return Err(anyhow!("Empty store passphrase"));
        }

        log::debug!("Encrypting store data");
        let data = encrypt(&self.passphrase, db_key, self.kdf_iter_count)?;

        log::debug!("Writing store data");
        fs::write(&self.file_path, &data)?;

        Ok(())
    }

    /// Clean up the store file
    pub fn clean(&mut self) -> Result<()> {
        self.was_read_successfully = false;
        fs::remove_file(&self.file_path)?;
        Ok(())
    }
}

fn get_store_file_path(name: &str) -> Result<PathBuf> {
    let store_filename = format!("{}{}", FILE_NAME_PREF, name);
    let temp_dirs = [
        std::env::var("TMPDIR").unwrap_or_default(),
        std::env::var("XDG_RUNTIME_DIR").unwrap_or_default(),
        "/dev/shm".to_string(),
        std::env::temp_dir().to_string_lossy().to_string(),
    ];

    for temp_dir in &temp_dirs {
        if temp_dir.is_empty() {
            continue;
        }

        log::debug!("Trying store directory: {}", temp_dir);
        let store_file_path = Path::new(temp_dir).join(&store_filename);

        match OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600) // rw-------
            .open(&store_file_path)
        {
            Ok(_) => return Ok(store_file_path),
            Err(e) => log::debug!("Skipping store directory: {}", e),
        }
    }

    Err(anyhow!("Failed to find a suitable store directory"))
}

impl Drop for SecureStore {
    fn drop(&mut self) {
        // Ensure passphrase is cleared from memory
        for byte in &mut self.passphrase {
            *byte = 0;
        }
    }
}

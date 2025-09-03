//! Enpass vault info handling

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

/// Information about the vault from vault.json file
#[derive(Debug, Serialize, Deserialize)]
pub struct VaultInfo {
    pub encryption_algo: String,
    pub have_keyfile: i32,
    pub kdf_algo: String,
    pub kdf_iter: i32,
    pub vault_items_count: i32,
    pub vault_name: String,
    pub version: i32,
}

impl VaultInfo {
    /// Load vault info from a JSON file
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = fs::read_to_string(path).context("Failed to read vault info file")?;

        let info: VaultInfo =
            serde_json::from_str(&content).context("Failed to parse vault info JSON")?;

        log::debug!("Vault info loaded: {} (v{})", info.vault_name, info.version);

        Ok(info)
    }

    /// Check if this vault has a keyfile
    pub fn has_keyfile(&self) -> bool {
        self.have_keyfile == 1
    }
}

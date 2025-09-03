//! Vault handling for Enpass

use anyhow::{anyhow, Context, Result};
use rusqlite::{Connection, Row, ToSql};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::{
    card::Card,
    key::{derive_key, extract_salt, generate_master_password, MASTER_KEY_LENGTH},
    vault_info::VaultInfo,
};

const VAULT_FILENAME: &str = "vault.enpassdb";
const VAULT_INFO_FILENAME: &str = "vault.json";

/// Credentials for opening a vault
pub struct VaultCredentials {
    pub keyfile_path: Option<PathBuf>,
    pub password: Option<String>,
    pub db_key: Option<Vec<u8>>,
}

impl VaultCredentials {
    /// Check if the credentials are complete enough to open the vault
    pub fn is_complete(&self) -> bool {
        self.password.is_some() || self.db_key.is_some()
    }
}

/// Vault is the container for vault-related operations
pub struct Vault {
    // Settings for filtering entries
    pub filter_fields: Vec<String>,
    pub filter_and: bool,

    // File paths
    database_path: PathBuf,
    vault_info_path: PathBuf,

    // Database connection
    db: Option<Connection>,

    // Vault info
    vault_info: VaultInfo,
}

impl Vault {
    /// Create a new vault instance and load vault info
    pub fn new<P: AsRef<Path>>(vault_path: P) -> Result<Self> {
        let vault_path = vault_path.as_ref();

        if vault_path.to_string_lossy().is_empty() {
            return Err(anyhow!("Empty vault path provided"));
        }

        let database_path = vault_path.join(VAULT_FILENAME);
        let vault_info_path = vault_path.join(VAULT_INFO_FILENAME);

        log::debug!("Checking provided vault paths");
        check_paths(&database_path, &vault_info_path)?;

        log::debug!("Loading vault info");
        let vault_info = VaultInfo::load_from_file(&vault_info_path)?;

        log::debug!(
            "Initialized paths: db_path={}, info_path={}",
            VAULT_FILENAME,
            VAULT_INFO_FILENAME
        );

        Ok(Self {
            filter_fields: vec!["title".to_string(), "subtitle".to_string()],
            filter_and: false,
            database_path,
            vault_info_path,
            db: None,
            vault_info,
        })
    }

    /// Open a connection to the Enpass database
    pub fn open(&mut self, credentials: &VaultCredentials) -> Result<()> {
        log::debug!("Generating database key");
        let db_key = self.generate_and_set_db_key(credentials)?;

        log::debug!("Opening encrypted database");
        self.db = Some(self.open_encrypted_database(&self.database_path, &db_key)?);

        // Verify the connection works by checking for the 'item' table
        let mut stmt = self
            .connection()?
            .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='item'")?;

        let table_name: String = stmt.query_row([], |row| row.get(0))?;
        if table_name != "item" {
            return Err(anyhow!("Could not connect to database"));
        }

        Ok(())
    }

    /// Close the connection to the database
    pub fn close(&mut self) {
        if let Some(db) = self.db.take() {
            match db.close() {
                Ok(_) => log::debug!("Closed vault"),
                Err(e) => log::debug!("Error closing vault: {:?}", e),
            }
        }
    }

    /// Get entries from the vault filtered by type and filters
    pub fn get_entries(&self, card_type: &str, filters: &[String]) -> Result<Vec<Card>> {
        if self.connection().is_err() || self.vault_info.vault_name.is_empty() {
            return Err(anyhow!("Vault is not initialized"));
        }

        let rows = self.execute_entry_query(card_type, filters)?;
        let mut cards = Vec::<Card>::new();

        for row in rows {
            let card: Card = row.into();
            cards.push(card);
        }

        Ok(cards)
    }

    /// Get a single entry from the vault
    pub fn get_entry(&self, card_type: &str, filters: &[String], unique: bool) -> Result<Card> {
        let cards = self.get_entries(card_type, filters)?;

        let mut result = None;
        for card in cards {
            if card.is_trashed() || card.is_deleted() {
                continue;
            } else if result.is_none() {
                result = Some(card);
            } else if unique {
                return Err(anyhow!("Multiple cards match that title"));
            } else {
                break;
            }
        }

        result.ok_or_else(|| anyhow!("Card not found"))
    }

    // Private helper methods

    fn connection(&self) -> Result<&Connection> {
        self.db
            .as_ref()
            .ok_or_else(|| anyhow!("Database not connected"))
    }

    fn open_encrypted_database(&self, path: &Path, db_key: &[u8]) -> Result<Connection> {
        // The raw key for the sqlcipher database is given
        // by the first MASTER_KEY_LENGTH characters of the hex-encoded key
        let key_hex = hex::encode(db_key);
        let key_str = &key_hex[..MASTER_KEY_LENGTH];

        let conn = Connection::open(path)?;

        // Set up SQLCipher encryption
        conn.pragma_update(None, "key", &format!("x'{}'", key_str))?;
        conn.pragma_update(None, "cipher_compatibility", &3)?;

        Ok(conn)
    }

    fn generate_and_set_db_key(&self, credentials: &VaultCredentials) -> Result<Vec<u8>> {
        if let Some(key) = &credentials.db_key {
            log::debug!("Skipping database key generation, already set");
            return Ok(key.clone());
        }

        let password = if let Some(password) = &credentials.password {
            password.as_bytes()
        } else {
            return Err(anyhow!("Empty vault password provided"));
        };

        let keyfile_path = credentials.keyfile_path.as_ref();

        if keyfile_path.is_none() && self.vault_info.has_keyfile() {
            return Err(anyhow!("You should specify a keyfile"));
        } else if keyfile_path.is_some() && !self.vault_info.has_keyfile() {
            return Err(anyhow!("You are specifying an unnecessary keyfile"));
        }

        log::debug!("Generating master password");
        let master_password =
            generate_master_password(password, keyfile_path.map(|p| p.as_path()))?;

        log::debug!("Extracting salt from database");
        let key_salt = extract_salt(&self.database_path)?;

        log::debug!("Deriving decryption key");
        let db_key = derive_key(
            &master_password,
            &key_salt,
            &self.vault_info.kdf_algo,
            &self.vault_info.encryption_algo,
            self.vault_info.kdf_iter,
        )?;

        Ok(db_key)
    }

    fn execute_entry_query(&self, card_type: &str, filters: &[String]) -> Result<Vec<Card>> {
        let conn = self.connection()?;

        let mut query = String::from(
            "SELECT uuid, type, created_at, field_updated_at, title,
                   subtitle, note, trashed, item.deleted, category,
                   label, value, key, last_used, sensitive, item.icon
            FROM item
            INNER JOIN itemfield ON uuid = item_uuid",
        );

        let mut where_clauses: Vec<String> = vec!["item.deleted = ?".to_string()];

        let zero: i64 = 0;
        let mut params: Vec<String> = vec!["0".to_string()]; // Exclude deleted items
        if !card_type.is_empty() {
            where_clauses.push("type = ?".to_string());
            params.push(card_type.to_string());
        }
        for filter in filters {
            let mut field_clauses = Vec::<String>::new();
            for field in &self.filter_fields {
                field_clauses.push(format!("{} LIKE ?", field));
                let pattern = format!("%{}%", filter);
                params.push(pattern.to_owned())
            }

            let combined = if self.filter_and {
                field_clauses.join(" AND ")
            } else {
                field_clauses.join(" OR ")
            };
            where_clauses.push(format!("({})", combined));
        }
        if !where_clauses.is_empty() {
            query.push_str(" WHERE ");
            query.push_str(&where_clauses.join(" AND "));
        }
        query.push_str(" ORDER BY title COLLATE NOCASE ASC");
        log::debug!("Executing query: {}", query);
        let mut stmt = conn.prepare(&query)?;

        let sql_params: Vec<&dyn ToSql> = params.iter().map(|p| p as &dyn ToSql).collect();

        let rows = stmt
            .query_map(sql_params.as_slice(), |row| {
                let card = Card::from(row);
                Ok(card)
            })
            .context("Failed to execute query")?
            .filter_map(|res| res.ok())
            .collect();

        Ok(rows)
    }
}

fn check_paths(database_path: &Path, vault_info_path: &Path) -> Result<()> {
    if !database_path.exists() {
        return Err(anyhow!("Vault does not exist: {}", database_path.display()));
    }

    if !vault_info_path.exists() {
        return Err(anyhow!(
            "Vault info file does not exist: {}",
            vault_info_path.display()
        ));
    }

    Ok(())
}

impl Drop for Vault {
    fn drop(&mut self) {
        self.close();
    }
}

//! Card structure for Enpass items

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use anyhow::{anyhow, Context, Result};
use rusqlite::Row;
use std::fmt;

/// Card represents an item in the Enpass vault
pub struct Card {
    // Plaintext fields
    pub uuid: String,
    pub created_at: i64,
    pub card_type: String,
    pub updated_at: i64,
    pub title: String,
    pub subtitle: String,
    pub note: String,
    pub trashed: i64,
    pub deleted: i64,
    pub category: String,
    pub label: String,
    pub last_used: i64,
    pub sensitive: bool,
    pub icon: String,
    pub raw_value: String,

    // Encrypted fields
    pub value: String,
    pub item_key: Vec<u8>,
}

impl Card {
    /// Check if the card is in trash
    pub fn is_trashed(&self) -> bool {
        self.trashed != 0
    }

    /// Check if the card is deleted
    pub fn is_deleted(&self) -> bool {
        self.deleted != 0
    }

    /// Decrypt the card value
    pub fn decrypt(&self) -> Result<String> {
        // Intercept item fields without value
        if self.value.is_empty() {
            return Ok(String::new());
        }

        // Intercept non-password item fields, their value isn't encrypted
        if self.card_type != "password" {
            return Ok(self.value.clone());
        }

        // The key consists of the AES key (32 bytes) and a nonce (12 bytes) for GCM
        if self.item_key.len() < 44 {
            return Err(anyhow!("Invalid key length"));
        }

        let key = &self.item_key[..32];
        let nonce = &self.item_key[32..44];

        // If the item is deleted, the nonce may be empty
        if nonce.iter().all(|&b| b == 0) {
            return Err(anyhow!("This item has been deleted"));
        }

        // Decode the hex-encoded ciphertext + tag
        let ciphertext_and_tag =
            hex::decode(&self.value).context("Could not decode card hex cipherstring")?;

        // AAD is the UUID without dashes
        let header =
            hex::decode(self.uuid.replace('-', "")).context("Could not decode card hex AAD")?;

        // Initialize the cipher
        let cipher = Aes256Gcm::new_from_slice(key).context("Could not initialize card cipher")?;

        let nonce = Nonce::from_slice(nonce);

        // Decrypt the ciphertext and verify the AAD
        let plaintext = cipher
            .decrypt(
                nonce,
                [&header[..], &ciphertext_and_tag[..]].concat().as_ref(),
            )
            .map_err(|_| anyhow!("Could not decrypt data"))?;

        String::from_utf8(plaintext).context("Decrypted data is not valid UTF-8")
    }
}

impl From<&Row<'_>> for Card {
    fn from(row: &Row<'_>) -> Self {
        Card {
            uuid: row.get("uuid").unwrap_or_default(),
            created_at: row.get("createdAt").unwrap_or_default(),
            card_type: row.get("type").unwrap_or_default(),
            updated_at: row.get("updatedAt").unwrap_or_default(),
            title: row.get("title").unwrap_or_default(),
            subtitle: row.get("subtitle").unwrap_or_default(),
            note: row.get("note").unwrap_or_default(),
            trashed: row.get("trashed").unwrap_or_default(),
            deleted: row.get("deleted").unwrap_or_default(),
            category: row.get("category").unwrap_or_default(),
            label: row.get("label").unwrap_or_default(),
            last_used: row.get("lastUsed").unwrap_or_default(),
            sensitive: row.get::<_, i64>("sensitive").unwrap_or(0) != 0,
            icon: row.get("icon").unwrap_or_default(),
            raw_value: row.get("value").unwrap_or_default(),
            value: row.get("value").unwrap_or_default(),
            item_key: row
                .get::<_, Option<Vec<u8>>>("itemKey")
                .unwrap_or(None)
                .unwrap_or_default(),
        }
    }
}

impl fmt::Debug for Card {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Card")
            .field("uuid", &self.uuid)
            .field("title", &self.title)
            .field("subtitle", &self.subtitle)
            .field("card_type", &self.card_type)
            .field("category", &self.category)
            .field("trashed", &self.trashed)
            .field("deleted", &self.deleted)
            .finish()
    }
}

/// Simple representation of a card for output
pub struct CardOutput {
    pub title: String,
    pub login: String,
    pub category: String,
    pub label: String,
    pub card_type: String,
    pub password: Option<String>,
}

impl From<&Card> for CardOutput {
    fn from(card: &Card) -> Self {
        CardOutput {
            title: card.title.clone(),
            login: card.subtitle.clone(),
            category: card.category.clone(),
            label: card.label.clone(),
            card_type: card.card_type.clone(),
            password: None,
        }
    }
}

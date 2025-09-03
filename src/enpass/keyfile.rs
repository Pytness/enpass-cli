//! Keyfile handling for Enpass vault

use anyhow::{anyhow, Context, Result};
use std::fs;
use std::path::Path;
use xml::reader::{EventReader, XmlEvent};

/// Load password from keyfile (XML format with hex-encoded key)
pub fn load_keyfile_password<P: AsRef<Path>>(path: P) -> Result<Vec<u8>> {
    let content = fs::read_to_string(&path)
        .with_context(|| format!("Failed to read keyfile: {:?}", path.as_ref()))?;

    let key_hex =
        extract_key_from_xml(&content).context("Failed to extract key from keyfile XML")?;

    hex::decode(key_hex).context("Failed to decode hex bytes from keyfile")
}

/// Extract the key content from XML
fn extract_key_from_xml(xml_content: &str) -> Result<String> {
    let parser = EventReader::from_str(xml_content);
    let mut inside_key = false;
    let mut key_content = String::new();

    for event in parser {
        match event {
            Ok(XmlEvent::StartElement { name, .. }) => {
                if name.local_name == "key" {
                    inside_key = true;
                }
            }
            Ok(XmlEvent::Characters(content)) if inside_key => {
                key_content = content;
            }
            Ok(XmlEvent::EndElement { name }) => {
                if name.local_name == "key" {
                    inside_key = false;
                }
            }
            Err(e) => return Err(anyhow!("XML parsing error: {}", e)),
            _ => {}
        }
    }

    if key_content.is_empty() {
        return Err(anyhow!("No key found in keyfile XML"));
    }

    Ok(key_content)
}

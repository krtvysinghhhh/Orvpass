#![allow(dead_code)]
use crate::vault::database;
use orvpass_core::crypto::{decrypt, derive_master_key, encrypt, generate_salt};
use orvpass_core::models::VaultItem;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

const BACKUP_MAGIC: &[u8] = b"ORVPASS_BACKUP_V1";

pub fn execute_backup(output_path: Option<String>) {
    let items = database::load_items();
    let password = database::get_master_password();
    if password.is_empty() {
        println!("\x1b[1;38;2;248;113;113m✖ Error:\x1b[0m Master password required to encrypt backup.");
        return;
    }

    let json_bytes = match serde_json::to_vec(&items) {
        Ok(b) => b,
        Err(e) => {
            println!("\x1b[1;38;2;248;113;113m✖ Serialization error:\x1b[0m {}", e);
            return;
        }
    };

    let salt = generate_salt();
    let key = match derive_master_key(password.as_bytes(), &salt) {
        Ok(k) => k,
        Err(e) => {
            println!("\x1b[1;38;2;248;113;113m✖ Key derivation error:\x1b[0m {:?}", e);
            return;
        }
    };

    let enc_data = match encrypt(&key, &json_bytes) {
        Ok(ed) => ed,
        Err(e) => {
            println!("\x1b[1;38;2;248;113;113m✖ Encryption error:\x1b[0m {:?}", e);
            return;
        }
    };

    let mut archive = Vec::new();
    archive.extend_from_slice(BACKUP_MAGIC);
    archive.extend_from_slice(&salt);
    archive.extend_from_slice(&enc_data.nonce);
    archive.extend_from_slice(&enc_data.ciphertext);

    let default_name = format!(
        "orvpass_backup_{}.enc",
        chrono::Utc::now().format("%Y%m%d_%H%M%S")
    );
    let target = output_path.unwrap_or(default_name);

    if let Err(e) = fs::write(&target, &archive) {
        println!("\x1b[1;38;2;248;113;113m✖ Error creating backup:\x1b[0m {}", e);
        return;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&target, fs::Permissions::from_mode(0o600));
    }

    let mut hasher = Sha256::new();
    hasher.update(&archive);
    let hash_hex = hex::encode(hasher.finalize());

    println!("\x1b[1;38;2;52;211;153m✔ Encrypted vault snapshot backup created successfully!\x1b[0m");
    println!("  📁 File:       {}", target);
    println!("  📦 Items:      {}", items.len());
    println!("  🛡️  Cipher:     ChaCha20-Poly1305 + Argon2id");
    println!("  🔒 SHA-256:    {}", hash_hex);
}

pub fn execute_restore(input_path: &str) {
    let path = Path::new(input_path);
    if !path.exists() {
        println!("\x1b[1;38;2;248;113;113m✖ Error:\x1b[0m File '{}' does not exist.", input_path);
        return;
    }

    let bytes = match fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            println!("\x1b[1;38;2;248;113;113m✖ Failed to read backup file:\x1b[0m {}", e);
            return;
        }
    };

    let items: Vec<VaultItem> = if bytes.starts_with(BACKUP_MAGIC) {
        let header_len = BACKUP_MAGIC.len();
        if bytes.len() < header_len + 16 + 12 + 16 {
            println!("\x1b[1;38;2;248;113;113m✖ Malformed encrypted backup file.\x1b[0m");
            return;
        }

        let mut salt = [0u8; 16];
        salt.copy_from_slice(&bytes[header_len..header_len + 16]);

        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&bytes[header_len + 16..header_len + 28]);

        let ciphertext = &bytes[header_len + 28..];

        let password = database::get_master_password();
        if password.is_empty() {
            println!("\x1b[1;38;2;248;113;113m✖ Master password required to decrypt backup.\x1b[0m");
            return;
        }

        let key = match derive_master_key(password.as_bytes(), &salt) {
            Ok(k) => k,
            Err(e) => {
                println!("\x1b[1;38;2;248;113;113m✖ Key derivation failed:\x1b[0m {:?}", e);
                return;
            }
        };

        let enc_data = orvpass_core::crypto::EncryptedData {
            nonce,
            ciphertext: ciphertext.to_vec(),
        };

        let decrypted = match decrypt(&key, &enc_data) {
            Ok(d) => d,
            Err(_) => {
                println!("\x1b[1;38;2;248;113;113m✖ Decryption failed.\x1b[0m Incorrect password or corrupt backup.");
                return;
            }
        };

        match serde_json::from_slice(&decrypted) {
            Ok(items) => items,
            Err(e) => {
                println!("\x1b[1;38;2;248;113;113m✖ Invalid payload format in backup:\x1b[0m {}", e);
                return;
            }
        }
    } else {
        // Fallback for legacy unencrypted JSON backup
        println!("\x1b[38;2;251;191;36m⚠️  Notice: Restoring from unencrypted legacy backup format.\x1b[0m");
        match serde_json::from_slice(&bytes) {
            Ok(items) => items,
            Err(e) => {
                println!("\x1b[1;38;2;248;113;113m✖ Invalid backup file format:\x1b[0m {}", e);
                return;
            }
        }
    };

    let count = items.len();
    if let Err(e) = database::save_items(&items) {
        println!("\x1b[1;38;2;248;113;113m✖ Failed to restore vault:\x1b[0m {}", e);
    } else {
        println!(
            "\x1b[1;38;2;52;211;153m✔ Vault restored successfully!\x1b[0m Total {} item(s) restored into encrypted vault.",
            count
        );
    }
}

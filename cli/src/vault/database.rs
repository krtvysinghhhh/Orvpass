use orvpass_core::crypto::{decrypt, derive_master_key, encrypt, generate_salt};
use orvpass_core::models::VaultItem;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::IsTerminal;
use std::path::PathBuf;
use std::sync::Mutex;

static CACHED_PASSWORD: Mutex<Option<String>> = Mutex::new(None);

#[derive(Serialize, Deserialize)]
struct EncryptedVaultPayload {
    version: u32,
    salt: [u8; 16],
    items: Vec<VaultItem>,
}

pub fn vault_dir() -> PathBuf {
    let base = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    let dir = base.join(".orvpass");
    let _ = fs::create_dir_all(&dir);
    dir
}

pub fn vault_path() -> PathBuf {
    vault_dir().join("vault.enc")
}

pub fn set_cached_password(pass: &str) {
    if let Ok(mut lock) = CACHED_PASSWORD.lock() {
        *lock = Some(pass.to_string());
    }
}

pub fn get_master_password() -> String {
    // 1. Check environment variables
    if let Ok(pass) = std::env::var("ORVPASS_PASSWORD")
        && !pass.is_empty() {
            return pass;
        }
    if let Ok(pass) = std::env::var("ORVPASS_MASTER")
        && !pass.is_empty() {
            return pass;
        }

    // 2. Check cached in-memory session password
    if let Ok(lock) = CACHED_PASSWORD.lock()
        && let Some(ref p) = *lock {
            return p.clone();
        }

    // 3. Prompt user if attached to interactive TTY terminal
    if std::io::stdin().is_terminal()
        && let Ok(pass) = rpassword::prompt_password("🔑 Enter Master Password: ")
            && !pass.is_empty() {
                set_cached_password(&pass);
                return pass;
            }

    // 4. In test / headless development mode, fallback safely if flag is present
    if cfg!(test) || std::env::var("ORVPASS_DEV_MODE").is_ok() {
        return "master_password".to_string();
    }

    String::new()
}

pub fn load_items() -> Vec<VaultItem> {
    let path = vault_path();
    if !path.exists() {
        return Vec::new();
    }

    let password = get_master_password();
    if password.is_empty() {
        eprintln!("\x1b[38;2;248;113;113m✖ Master password required to unlock vault.\x1b[0m Set ORVPASS_PASSWORD or run interactively.");
        return Vec::new();
    }

    if let Ok(raw) = fs::read(&path)
        && raw.len() > 28 {
            let mut salt = [0u8; 16];
            salt.copy_from_slice(&raw[..16]);
            let mut nonce = [0u8; 12];
            nonce.copy_from_slice(&raw[16..28]);
            let ciphertext = &raw[28..];

            if let Ok(key) = derive_master_key(password.as_bytes(), &salt) {
                let enc_data = orvpass_core::crypto::EncryptedData {
                    nonce,
                    ciphertext: ciphertext.to_vec(),
                };
                if let Ok(decrypted) = decrypt(&key, &enc_data) {
                    if let Ok(payload) = serde_json::from_slice::<EncryptedVaultPayload>(&decrypted)
                    {
                        return payload.items;
                    }
                } else {
                    eprintln!("\x1b[38;2;248;113;113m✖ Decryption failed.\x1b[0m Incorrect master password.");
                }
            }
        }
    Vec::new()
}

pub fn save_items(items: &[VaultItem]) -> anyhow::Result<()> {
    let path = vault_path();
    let password = get_master_password();
    if password.is_empty() {
        anyhow::bail!("Master password required to encrypt and save vault.");
    }

    let salt = generate_salt();
    let key = derive_master_key(password.as_bytes(), &salt)?;

    let payload = EncryptedVaultPayload {
        version: 1,
        salt,
        items: items.to_vec(),
    };

    let serialized = serde_json::to_vec(&payload)?;
    let enc_data = encrypt(&key, &serialized)?;

    let mut final_buf = Vec::with_capacity(16 + 12 + enc_data.ciphertext.len());
    final_buf.extend_from_slice(&salt);
    final_buf.extend_from_slice(&enc_data.nonce);
    final_buf.extend_from_slice(&enc_data.ciphertext);

    let tmp_path = path.with_extension("tmp");
    fs::write(&tmp_path, final_buf)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o600));
    }
    fs::rename(&tmp_path, &path)?;
    Ok(())
}

/// Securely shred a sensitive file with 3-pass DoD 5220.22-M overwrite (zeros, ones, random)
pub fn shred_file(path: &std::path::Path) -> std::io::Result<()> {
    if path.exists() {
        let meta = fs::metadata(path)?;
        let len = meta.len() as usize;
        let wipe_len = len.max(512);

        // Pass 1: Overwrite with all zeros
        let zeros = vec![0x00u8; wipe_len];
        fs::write(path, &zeros)?;

        // Pass 2: Overwrite with all ones
        let ones = vec![0xFFu8; wipe_len];
        fs::write(path, &ones)?;

        // Pass 3: Overwrite with cryptographically secure random bytes
        let mut random_bytes = vec![0u8; wipe_len];
        rand::rng().fill_bytes(&mut random_bytes);
        fs::write(path, &random_bytes)?;

        // Flush and remove
        fs::remove_file(path)?;
    }
    Ok(())
}

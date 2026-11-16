use orvpass_core::models::{ItemData, ItemType, VaultItem};
use orvpass_core::totp::generate_totp;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub fn extract_totp_secret(item: &VaultItem) -> Option<String> {
    // 1. Check custom fields
    for field in &item.custom_fields {
        let name_lower = field.name.to_lowercase();
        if name_lower == "totp"
            || name_lower == "totp_secret"
            || name_lower == "otp"
            || name_lower == "secret"
            || name_lower.contains("2fa")
        {
            return Some(field.value.clone());
        }
        if field.value.starts_with("otpauth://")
            && let Some(pos) = field.value.find("secret=") {
                let s = &field.value[pos + 7..];
                let end = s.find('&').unwrap_or(s.len());
                return Some(s[..end].to_string());
            }
    }

    // 2. If item is marked as Totp type, password holds the secret
    if item.item_type == ItemType::Totp
        && let ItemData::Login(l) = &item.data
            && let Some(p) = &l.password {
                return Some(p.clone());
            }

    // 3. Check URLs in Login data
    if let ItemData::Login(l) = &item.data {
        for url in &l.urls {
            if url.starts_with("otpauth://")
                && let Some(pos) = url.find("secret=") {
                    let s = &url[pos + 7..];
                    let end = s.find('&').unwrap_or(s.len());
                    return Some(s[..end].to_string());
                }
        }
    }

    None
}

pub fn execute(name: &str, watch: bool, copy: bool) {
    let items = crate::vault::database::load_items();
    let found = items
        .iter()
        .find(|i| i.title.eq_ignore_ascii_case(name))
        .or_else(|| {
            items
                .iter()
                .find(|i| i.title.to_lowercase().contains(&name.to_lowercase()))
        });

    let secret_str = if let Some(item) = found {
        if let Some(s) = extract_totp_secret(item) {
            s
        } else {
            println!(
                "\x1b[38;2;251;191;36m⚠️  Item '{}' found, but has no TOTP 2FA secret configured.\x1b[0m",
                item.title
            );
            println!(
                "\x1b[38;2;148;163;184m👉 Add a custom field named 'totp' with your Base32 secret.\x1b[0m"
            );
            return;
        }
    } else {
        // If not found in vault, check if user provided a raw Base32 secret string
        if name.len() >= 8 && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '=') {
            name.to_string()
        } else {
            println!(
                "\x1b[1;38;2;248;113;113m✖ Error:\x1b[0m Credential '{}' not found in vault.",
                name
            );
            return;
        }
    };

    let display_title = found.map(|i| i.title.as_str()).unwrap_or(name);

    if watch {
        println!("⏱️  ORVPASS LIVE 2FA TOTP: {}", display_title);
        println!("Press Ctrl+C to stop watching.");
        loop {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let seconds_left = 30 - (now % 30);
            let code = generate_totp(secret_str.as_bytes(), 30).unwrap_or(0);

            print!(
                "\r  Code: \x1b[1;32m{:06}\x1b[0m  (Refreshes in {:02}s)   ",
                code, seconds_left
            );
            use std::io::Write;
            let _ = std::io::stdout().flush();
            thread::sleep(Duration::from_millis(500));
        }
    } else {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let seconds_left = 30 - (now % 30);
        let code = generate_totp(secret_str.as_bytes(), 30).unwrap_or(0);
        let formatted = format!("{:06}", code);

        if copy {
            crate::clipboard::copy_with_notification(&formatted, 15);
            println!(
                "📋 Copied TOTP 2FA code {} for '{}' (Valid for {}s)",
                formatted, display_title, seconds_left
            );
        } else {
            println!(
                "2FA Code for {}: \x1b[1;32m{}\x1b[0m (Expires in {}s)",
                display_title, formatted, seconds_left
            );
        }
    }
}

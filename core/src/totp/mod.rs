use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum TotpAlgorithm {
    Sha1,
    Sha256,
    Sha512,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TotpSecret {
    value: String,
}

impl TotpSecret {
    pub fn new(value: &str) -> Result<Self, TotpError> {
        Ok(Self {
            value: value.to_string(),
        })
    }

    pub fn value(&self) -> &str {
        &self.value
    }
}

impl std::fmt::Debug for TotpSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TotpSecret")
            .field("value", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct TotpConfig {
    pub digits: u32,
    pub period_seconds: u64,
    pub skew_steps: u32,
    pub algorithm: TotpAlgorithm,
}

impl Default for TotpConfig {
    fn default() -> Self {
        Self {
            digits: 6,
            period_seconds: 30,
            skew_steps: 0,
            algorithm: TotpAlgorithm::Sha1,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum TotpError {
    InvalidTimestamp,
    InvalidSecret,
    CryptoError,
}

impl std::fmt::Display for TotpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TotpError::InvalidTimestamp => write!(f, "Invalid timestamp: must be greater than zero"),
            TotpError::InvalidSecret => write!(f, "Invalid secret or Base32 encoding"),
            TotpError::CryptoError => write!(f, "Cryptographic failure during TOTP generation"),
        }
    }
}

impl std::error::Error for TotpError {}

/// Standard RFC 3174 SHA-1 implementation for RFC 6238 TOTP compliance
#[allow(clippy::all)]
fn sha1_digest(data: &[u8]) -> [u8; 20] {
    let mut h0 = 0x67452301u32;
    let mut h1 = 0xEFCDAB89u32;
    let mut h2 = 0x98BADCFEu32;
    let mut h3 = 0x10325476u32;
    let mut h4 = 0xC3D2E1F0u32;

    let bit_len = (data.len() as u64) * 8;
    let mut msg = data.to_vec();
    msg.push(0x80);
    while (msg.len() + 8) % 64 != 0 {
        msg.push(0x00);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let mut a = h0;
        let mut b = h1;
        let mut c = h2;
        let mut d = h3;
        let mut e = h4;

        for i in 0..80 {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1u32),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDCu32),
                _ => (b ^ c ^ d, 0xCA62C1D6u32),
            };

            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(w[i]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
    }

    let mut out = [0u8; 20];
    out[0..4].copy_from_slice(&h0.to_be_bytes());
    out[4..8].copy_from_slice(&h1.to_be_bytes());
    out[8..12].copy_from_slice(&h2.to_be_bytes());
    out[12..16].copy_from_slice(&h3.to_be_bytes());
    out[16..20].copy_from_slice(&h4.to_be_bytes());
    out
}

/// Generic HMAC function supporting SHA-1, SHA-256, and SHA-512
#[allow(clippy::all)]
fn hmac(algorithm: TotpAlgorithm, key: &[u8], message: &[u8]) -> Vec<u8> {
    let block_size = match algorithm {
        TotpAlgorithm::Sha512 => 128,
        _ => 64,
    };

    let key = if key.len() > block_size {
        match algorithm {
            TotpAlgorithm::Sha1 => sha1_digest(key).to_vec(),
            TotpAlgorithm::Sha256 => Sha256::digest(key).to_vec(),
            TotpAlgorithm::Sha512 => Sha512::digest(key).to_vec(),
        }
    } else {
        key.to_vec()
    };

    let mut padded_key = key;
    padded_key.resize(block_size, 0);

    let mut o_key_pad = vec![0x5cu8; block_size];
    let mut i_key_pad = vec![0x36u8; block_size];

    for i in 0..block_size {
        o_key_pad[i] ^= padded_key[i];
        i_key_pad[i] ^= padded_key[i];
    }

    let inner_hash = match algorithm {
        TotpAlgorithm::Sha1 => {
            let mut data = i_key_pad;
            data.extend_from_slice(message);
            sha1_digest(&data).to_vec()
        }
        TotpAlgorithm::Sha256 => {
            let mut h = Sha256::new();
            h.update(&i_key_pad);
            h.update(message);
            h.finalize().to_vec()
        }
        TotpAlgorithm::Sha512 => {
            let mut h = Sha512::new();
            h.update(&i_key_pad);
            h.update(message);
            h.finalize().to_vec()
        }
    };

    match algorithm {
        TotpAlgorithm::Sha1 => {
            let mut data = o_key_pad;
            data.extend_from_slice(&inner_hash);
            sha1_digest(&data).to_vec()
        }
        TotpAlgorithm::Sha256 => {
            let mut h = Sha256::new();
            h.update(&o_key_pad);
            h.update(&inner_hash);
            h.finalize().to_vec()
        }
        TotpAlgorithm::Sha512 => {
            let mut h = Sha512::new();
            h.update(&o_key_pad);
            h.update(&inner_hash);
            h.finalize().to_vec()
        }
    }
}

/// Standard Base32 decoder (RFC 4648)
pub fn decode_base32(raw: &str) -> Result<Vec<u8>, TotpError> {
    let clean: String = raw
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '=')
        .collect();

    let mut bits: u32 = 0;
    let mut bit_count: u32 = 0;
    let mut out = Vec::new();

    for c in clean.chars() {
        let val = match c.to_ascii_uppercase() {
            'A'..='Z' => (c.to_ascii_uppercase() as u8 - b'A') as u32,
            '2'..='7' => (c as u8 - b'2' + 26) as u32,
            _ => return Err(TotpError::InvalidSecret),
        };

        bits = (bits << 5) | val;
        bit_count += 5;

        if bit_count >= 8 {
            bit_count -= 8;
            out.push((bits >> bit_count) as u8);
            bits &= (1 << bit_count) - 1;
        }
    }

    Ok(out)
}

/// RFC 6238 TOTP computation at a specific timestamp
pub fn compute_totp(
    key: &[u8],
    timestamp: u64,
    period_seconds: u64,
    digits: u32,
    algorithm: TotpAlgorithm,
) -> Result<u32, TotpError> {
    if period_seconds == 0 {
        return Err(TotpError::InvalidTimestamp);
    }
    let step = timestamp / period_seconds;
    let step_bytes = step.to_be_bytes();

    let mac = hmac(algorithm, key, &step_bytes);
    if mac.is_empty() {
        return Err(TotpError::CryptoError);
    }

    let offset = (mac[mac.len() - 1] & 0x0f) as usize;
    if offset + 4 > mac.len() {
        return Err(TotpError::CryptoError);
    }

    let binary = ((mac[offset] as u32 & 0x7f) << 24)
        | ((mac[offset + 1] as u32 & 0xff) << 16)
        | ((mac[offset + 2] as u32 & 0xff) << 8)
        | (mac[offset + 3] as u32 & 0xff);

    let modulus = 10u32.pow(digits.clamp(6, 8));
    Ok(binary % modulus)
}

/// Generate TOTP code based on current wall-clock time
pub fn generate_totp(secret: &[u8], period: u64) -> Result<u32, TotpError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // If secret can be parsed as valid Base32, use decoded key; otherwise use raw bytes
    let key = match std::str::from_utf8(secret) {
        Ok(s) => decode_base32(s).unwrap_or_else(|_| secret.to_vec()),
        Err(_) => secret.to_vec(),
    };

    compute_totp(&key, now, period, 6, TotpAlgorithm::Sha1)
}

/// Generate function adhering to configuration and timestamp
pub fn generate(
    secret: &TotpSecret,
    timestamp: u64,
    config: TotpConfig,
) -> Result<TotpSecret, TotpError> {
    if timestamp == 0 {
        return Err(TotpError::InvalidTimestamp);
    }

    let key = decode_base32(secret.value()).unwrap_or_else(|_| secret.value().as_bytes().to_vec());
    let code = compute_totp(
        &key,
        timestamp,
        config.period_seconds,
        config.digits,
        config.algorithm,
    )?;

    let formatted = match config.digits {
        8 => format!("{:08}", code),
        _ => format!("{:06}", code),
    };

    TotpSecret::new(&formatted)
}

pub fn normalize_totp_secret(raw: &str) -> String {
    let clean: String = raw.chars().filter(|c| c.is_ascii_alphanumeric()).collect();
    let pad_len = (8 - (clean.len() % 8)) % 8;
    clean.to_uppercase() + &"=".repeat(pad_len)
}

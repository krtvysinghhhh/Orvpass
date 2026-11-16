// Pure-Rust Shamir Secret Sharing (k-of-n) over GF(2^8)
// Uses Rijndael's irreducible polynomial x^8 + x^4 + x^3 + x + 1 (0x11b)
// Ensures true information-theoretic security where any k distinct shares
// recover the secret, and any fewer than k shares reveal zero information.

use rand::RngCore;

/// Multiplication in GF(2^8) modulo 0x11b
fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut p: u8 = 0;
    while a > 0 && b > 0 {
        if b & 1 != 0 {
            p ^= a;
        }
        let hi_bit_set = (a & 0x80) != 0;
        a <<= 1;
        if hi_bit_set {
            a ^= 0x1b; // 0x11b mod 0x100
        }
        b >>= 1;
    }
    p
}

/// Multiplicative inverse in GF(2^8) using Fermat's Little Theorem: a^254 = a^-1
fn gf_inv(a: u8) -> u8 {
    if a == 0 {
        panic!("Division by zero in GF(2^8)");
    }
    let mut res = 1u8;
    let mut base = a;
    let mut exp = 254;
    while exp > 0 {
        if exp & 1 == 1 {
            res = gf_mul(res, base);
        }
        base = gf_mul(base, base);
        exp >>= 1;
    }
    res
}

/// Division in GF(2^8): a / b = a * b^-1
fn gf_div(a: u8, b: u8) -> u8 {
    if a == 0 {
        return 0;
    }
    gf_mul(a, gf_inv(b))
}

/// Evaluate polynomial P(x) = c_0 + c_1*x + ... + c_{k-1}*x^{k-1} in GF(2^8)
fn eval_poly(coeffs: &[u8], x: u8) -> u8 {
    let mut y = 0u8;
    for &c in coeffs.iter().rev() {
        y = gf_mul(y, x) ^ c;
    }
    y
}

/// Split a secret into n shares such that any k shares can reconstruct it.
/// Requirements: 1 <= k <= n <= 255.
pub fn split_secret(secret: &[u8], k: usize, n: usize) -> Vec<String> {
    if k == 0 || n == 0 || k > n || n > 255 {
        return Vec::new();
    }

    if k == 1 {
        // If threshold is 1, all shares are identical to secret
        return (1..=n)
            .map(|i| {
                let mut shard = vec![i as u8, 1u8];
                shard.extend_from_slice(secret);
                hex::encode(shard)
            })
            .collect();
    }

    let mut rng = rand::rng();
    let mut shares_bytes: Vec<Vec<u8>> = (1..=n)
        .map(|i| vec![i as u8, k as u8])
        .collect();

    for share in shares_bytes.iter_mut() {
        share.reserve(secret.len());
    }

    // For each byte of the secret, create a random polynomial of degree k-1
    let mut coeffs = vec![0u8; k];
    for &secret_byte in secret {
        coeffs[0] = secret_byte;
        rng.fill_bytes(&mut coeffs[1..]);

        for (i, share) in shares_bytes.iter_mut().enumerate() {
            let x = (i + 1) as u8;
            let y = eval_poly(&coeffs, x);
            share.push(y);
        }
    }

    shares_bytes.into_iter().map(hex::encode).collect()
}

/// Reconstruct the secret using Lagrange interpolation in GF(2^8) at x = 0.
pub fn recover_secret(shards: &[String]) -> Result<Vec<u8>, String> {
    if shards.is_empty() {
        return Err("No shards provided".to_string());
    }

    let mut parsed: Vec<Vec<u8>> = Vec::with_capacity(shards.len());
    for s in shards {
        let b = hex::decode(s).map_err(|e| format!("Invalid hex shard: {}", e))?;
        if b.len() < 3 {
            return Err("Malformed shard: payload too short".to_string());
        }
        parsed.push(b);
    }

    let k = parsed[0][1] as usize;
    if k == 0 {
        return Err("Invalid threshold in shard".to_string());
    }

    // De-duplicate shards by x coordinate
    let mut unique_shares: Vec<&Vec<u8>> = Vec::new();
    for share in &parsed {
        if !unique_shares.iter().any(|s| s[0] == share[0]) {
            unique_shares.push(share);
        }
    }

    if unique_shares.len() < k {
        return Err(format!(
            "Insufficient distinct shards: have {}, need {}",
            unique_shares.len(),
            k
        ));
    }

    // Use exactly k shares for interpolation
    let active_shares = &unique_shares[..k];
    let secret_len = active_shares[0].len() - 2;

    for s in active_shares.iter().skip(1) {
        if s.len() - 2 != secret_len {
            return Err("Inconsistent shard lengths".to_string());
        }
    }

    let xs: Vec<u8> = active_shares.iter().map(|s| s[0]).collect();

    // Compute Lagrange basis polynomials at x = 0
    // l_j(0) = Prod_{m != j} (0 - x_m) / (x_j - x_m) = Prod_{m != j} x_m / (x_j ^ x_m)
    let mut basis = vec![1u8; k];
    for j in 0..k {
        let mut num = 1u8;
        let mut den = 1u8;
        for m in 0..k {
            if m != j {
                num = gf_mul(num, xs[m]);
                den = gf_mul(den, xs[j] ^ xs[m]);
            }
        }
        basis[j] = gf_div(num, den);
    }

    let mut secret = Vec::with_capacity(secret_len);
    for byte_idx in 0..secret_len {
        let mut val = 0u8;
        for j in 0..k {
            let y_j = active_shares[j][byte_idx + 2];
            val ^= gf_mul(y_j, basis[j]);
        }
        secret.push(val);
    }

    Ok(secret)
}

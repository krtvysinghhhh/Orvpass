use orvpass_core::totp::{TotpAlgorithm, TotpConfig, TotpError, TotpSecret, generate};

#[test]
fn sha256_generation_is_stable() {
    let secret = TotpSecret::new("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").unwrap();

    let config = TotpConfig {
        digits: 8,
        period_seconds: 30,
        algorithm: TotpAlgorithm::Sha256,
        skew_steps: 0,
    };

    let first = generate(&secret, 59, config).unwrap();
    let second = generate(&secret, 59, config).unwrap();

    assert_eq!(first.value(), second.value());
}

#[test]
fn sha512_generation_is_stable() {
    let secret = TotpSecret::new("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").unwrap();

    let config = TotpConfig {
        digits: 8,
        period_seconds: 30,
        algorithm: TotpAlgorithm::Sha512,
        skew_steps: 0,
    };

    let first = generate(&secret, 59, config).unwrap();
    let second = generate(&secret, 59, config).unwrap();

    assert_eq!(first.value(), second.value());
}

#[test]
fn zero_timestamp_is_rejected() {
    let secret = TotpSecret::new("JBSWY3DPEHPK3PXP").unwrap();

    assert!(matches!(
        generate(&secret, 0, TotpConfig::default()),
        Err(TotpError::InvalidTimestamp)
    ));
}

#[test]
fn secret_does_not_appear_in_debug_output() {
    let secret = TotpSecret::new("JBSWY3DPEHPK3PXP").unwrap();
    let debug = format!("{secret:?}");

    assert!(!debug.contains("JBSWY3DPEHPK3PXP"));
}

#[test]
fn test_rfc6238_standard_vectors() {
    // Official RFC 6238 Test Vector:
    // Secret: "12345678901234567890" in ASCII
    // At Unix time 59 (step 1 with 30s period):
    // SHA1 8-digit OTP = "94287082" (last 6 digits: "287082")
    let secret = TotpSecret::new("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").unwrap();
    let config = TotpConfig {
        digits: 8,
        period_seconds: 30,
        algorithm: TotpAlgorithm::Sha1,
        skew_steps: 0,
    };

    let otp = generate(&secret, 59, config).unwrap();
    assert_eq!(otp.value(), "94287082");

    let config_6 = TotpConfig {
        digits: 6,
        period_seconds: 30,
        algorithm: TotpAlgorithm::Sha1,
        skew_steps: 0,
    };
    let otp_6 = generate(&secret, 59, config_6).unwrap();
    assert_eq!(otp_6.value(), "287082");
}

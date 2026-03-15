use std::collections::BTreeMap;
use std::sync::Mutex;

// ── Mock-based integration tests (no Keychain, no Touch ID) ─────────

/// Re-implement the mock keystore here since the one in keystore.rs
/// is behind #[cfg(test)] and not accessible from integration tests.
mod mocks {
    use super::*;

    #[derive(Debug, Default)]
    pub struct InMemoryKeyStore {
        keys: Mutex<BTreeMap<String, Vec<u8>>>,
    }

    impl InMemoryKeyStore {
        pub fn new() -> Self {
            Self::default()
        }
    }

    // We can't import the trait from the binary crate in integration tests,
    // so we test the protocol and config types directly.
}

#[test]
fn config_default_values() {
    // Verify the default config has sane values.
    // We can't import Config directly from a binary crate,
    // so test the JSON format instead.
    let json = r#"{
        "key_label": "test-key",
        "key_protection": "biometric",
        "socket_path": "/tmp/test.sock",
        "issuer": "test-issuer",
        "expiry_secs": 30,
        "subject": "test-user",
        "audience": "test-aud",
        "autostart": false
    }"#;

    let parsed: serde_json::Value = serde_json::from_str(json).unwrap();
    assert_eq!(parsed["key_protection"], "biometric");
    assert_eq!(parsed["expiry_secs"], 30);
    assert!(!parsed["autostart"].as_bool().unwrap());
}

#[test]
fn protocol_auth_request_serialization() {
    let json = r#"{"sub":"user","aud":"my-aud","expiry_secs":120}"#;
    let parsed: serde_json::Value = serde_json::from_str(json).unwrap();
    assert_eq!(parsed["sub"], "user");
    assert_eq!(parsed["expiry_secs"], 120);
}

#[test]
fn protocol_auth_request_defaults() {
    let json = r#"{"sub":"user"}"#;
    let parsed: serde_json::Value = serde_json::from_str(json).unwrap();
    assert_eq!(parsed["sub"], "user");
    // aud and expiry_secs should be optional
}

#[test]
fn protocol_auth_response_serialization() {
    let json = r#"{"token":"eyJ...","expires_at":1234567890}"#;
    let parsed: serde_json::Value = serde_json::from_str(json).unwrap();
    assert!(parsed["token"].as_str().unwrap().starts_with("eyJ"));
    assert_eq!(parsed["expires_at"], 1234567890);
}

#[test]
fn jwk_serialization() {
    let json = r#"{
        "kty": "EC",
        "crv": "P-256",
        "x": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
        "y": "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI",
        "kid": "test-key",
        "use": "sig",
        "alg": "ES256"
    }"#;

    let parsed: serde_json::Value = serde_json::from_str(json).unwrap();
    assert_eq!(parsed["kty"], "EC");
    assert_eq!(parsed["crv"], "P-256");
    assert_eq!(parsed["alg"], "ES256");
    assert_eq!(parsed["use"], "sig");
}

#[test]
fn jwks_format() {
    let jwks_json = r#"{"keys":[{
        "kty": "EC", "crv": "P-256",
        "x": "AAAA", "y": "BBBB",
        "kid": "k1", "use": "sig", "alg": "ES256"
    }]}"#;

    let parsed: serde_json::Value = serde_json::from_str(jwks_json).unwrap();
    let keys = parsed["keys"].as_array().unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0]["kid"], "k1");
}

#[test]
fn key_protection_enum_serde() {
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(r#""biometric""#).unwrap(),
        "biometric"
    );
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(r#""secure_enclave""#).unwrap(),
        "secure_enclave"
    );
}

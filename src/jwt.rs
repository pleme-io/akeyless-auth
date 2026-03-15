use crate::error::{Error, Result};
use crate::protocol::Jwks;
use crate::traits::{KeyStore, TokenIssuer};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};

/// JWT claims for Akeyless OAuth2/JWT authentication.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Claims {
    pub sub: String,
    pub iss: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub aud: String,
    pub iat: i64,
    pub exp: i64,
    pub jti: String,
}

/// Issues ES256 JWTs signed by a `KeyStore` (Touch ID per token).
#[derive(Debug)]
pub struct JwtTokenIssuer<K: KeyStore> {
    key_store: K,
    key_label: String,
}

impl<K: KeyStore> JwtTokenIssuer<K> {
    pub fn new(key_store: K, key_label: String) -> Self {
        Self {
            key_store,
            key_label,
        }
    }

    fn sign_jwt(&self, claims: &Claims) -> Result<String> {
        let header = serde_json::json!({
            "alg": "ES256",
            "typ": "JWT",
            "kid": self.key_label
        });

        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?);
        let claims_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims)?);
        let signing_input = format!("{header_b64}.{claims_b64}");

        let der_sig = self
            .key_store
            .sign(&self.key_label, signing_input.as_bytes())?;

        let jws_sig = der_to_jws(&der_sig)?;
        let sig_b64 = URL_SAFE_NO_PAD.encode(&jws_sig);

        Ok(format!("{signing_input}.{sig_b64}"))
    }
}

impl<K: KeyStore> TokenIssuer for JwtTokenIssuer<K> {
    fn issue(&self, claims: &Claims) -> Result<String> {
        self.sign_jwt(claims)
    }

    fn jwks(&self) -> Result<String> {
        let jwk = self.key_store.public_key_jwk(&self.key_label)?;
        let jwks = Jwks { keys: vec![jwk] };
        serde_json::to_string_pretty(&jwks).map_err(Error::from)
    }
}

/// Convert DER-encoded ECDSA signature to JWS format (R || S, 64 bytes).
///
/// DER: 0x30 <len> 0x02 <r_len> <r_bytes> 0x02 <s_len> <s_bytes>
/// JWS: <r_32_bytes> <s_32_bytes> (left-padded to 32 bytes each)
fn der_to_jws(der: &[u8]) -> Result<Vec<u8>> {
    if der.len() < 8 {
        return Err(Error::Signing(format!(
            "DER signature too short: {} bytes",
            der.len()
        )));
    }
    if der[0] != 0x30 {
        return Err(Error::Signing(format!(
            "expected DER SEQUENCE (0x30), got 0x{:02x}",
            der[0]
        )));
    }

    let mut pos = 2; // skip 0x30 <total_len>

    // Read R integer
    if pos >= der.len() || der[pos] != 0x02 {
        return Err(Error::Signing("expected INTEGER tag (0x02) for R".into()));
    }
    pos += 1;
    if pos >= der.len() {
        return Err(Error::Signing("truncated DER: missing R length".into()));
    }
    let r_len = der[pos] as usize;
    pos += 1;
    if pos + r_len > der.len() {
        return Err(Error::Signing(format!(
            "truncated DER: R length {r_len} exceeds buffer (pos={pos}, total={})",
            der.len()
        )));
    }
    let r_bytes = &der[pos..pos + r_len];
    pos += r_len;

    // Read S integer
    if pos >= der.len() || der[pos] != 0x02 {
        return Err(Error::Signing("expected INTEGER tag (0x02) for S".into()));
    }
    pos += 1;
    if pos >= der.len() {
        return Err(Error::Signing("truncated DER: missing S length".into()));
    }
    let s_len = der[pos] as usize;
    pos += 1;
    if pos + s_len > der.len() {
        return Err(Error::Signing(format!(
            "truncated DER: S length {s_len} exceeds buffer (pos={pos}, total={})",
            der.len()
        )));
    }
    let s_bytes = &der[pos..pos + s_len];

    // Trim leading zero bytes (DER integers are signed, may have 0x00 prefix)
    let r_trimmed = trim_leading_zero(r_bytes);
    let s_trimmed = trim_leading_zero(s_bytes);

    if r_trimmed.len() > 32 || s_trimmed.len() > 32 {
        return Err(Error::Signing(format!(
            "integer too large for P-256: R={} bytes, S={} bytes",
            r_trimmed.len(),
            s_trimmed.len()
        )));
    }

    // Pad to exactly 32 bytes each, left-aligned
    let mut result = vec![0u8; 64];
    result[32 - r_trimmed.len()..32].copy_from_slice(r_trimmed);
    result[64 - s_trimmed.len()..64].copy_from_slice(s_trimmed);

    Ok(result)
}

fn trim_leading_zero(bytes: &[u8]) -> &[u8] {
    if bytes.first() == Some(&0) && bytes.len() > 1 {
        &bytes[1..]
    } else {
        bytes
    }
}

// ── Mock implementations ───────────────────────────────────────────────

#[cfg(test)]
pub mod mocks {
    use super::*;

    /// Token issuer that returns a fixed token (no signing).
    #[derive(Debug)]
    pub struct StaticTokenIssuer {
        pub token: String,
    }

    impl TokenIssuer for StaticTokenIssuer {
        fn issue(&self, _claims: &Claims) -> Result<String> {
            Ok(self.token.clone())
        }
        fn jwks(&self) -> Result<String> {
            Ok(r#"{"keys":[]}"#.into())
        }
    }

    /// Token issuer that always fails.
    #[derive(Debug)]
    pub struct FailingTokenIssuer;

    impl TokenIssuer for FailingTokenIssuer {
        fn issue(&self, _claims: &Claims) -> Result<String> {
            Err(Error::BiometricDenied)
        }
        fn jwks(&self) -> Result<String> {
            Ok(r#"{"keys":[]}"#.into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keystore::mocks::InMemoryKeyStore;
    use crate::traits::KeyStore;

    #[test]
    fn issue_jwt_with_mock_keystore() {
        let store = InMemoryKeyStore::new();
        store.generate("test-key").unwrap();

        let issuer = JwtTokenIssuer::new(store, "test-key".into());
        let claims = Claims {
            sub: "test-user".into(),
            iss: "akeyless-auth".into(),
            aud: String::new(),
            iat: 1000,
            exp: 1060,
            jti: "unique-id".into(),
        };

        let token = issuer.issue(&claims).unwrap();
        assert_eq!(token.split('.').count(), 3);

        let header_b64 = token.split('.').next().unwrap();
        let header_bytes = URL_SAFE_NO_PAD.decode(header_b64).unwrap();
        let header: serde_json::Value = serde_json::from_slice(&header_bytes).unwrap();
        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["typ"], "JWT");
        assert_eq!(header["kid"], "test-key");
    }

    #[test]
    fn jwks_output() {
        let store = InMemoryKeyStore::new();
        store.generate("test-key").unwrap();

        let issuer = JwtTokenIssuer::new(store, "test-key".into());
        let jwks_str = issuer.jwks().unwrap();
        let jwks: Jwks = serde_json::from_str(&jwks_str).unwrap();
        assert_eq!(jwks.keys.len(), 1);
        assert_eq!(jwks.keys[0].alg, "ES256");
    }

    #[test]
    fn claims_serde_roundtrip() {
        let claims = Claims {
            sub: "user".into(),
            iss: "issuer".into(),
            aud: "audience".into(),
            iat: 1000,
            exp: 1060,
            jti: "id".into(),
        };
        let json = serde_json::to_string(&claims).unwrap();
        let restored: Claims = serde_json::from_str(&json).unwrap();
        assert_eq!(claims, restored);
    }

    #[test]
    fn claims_empty_aud_skipped() {
        let claims = Claims {
            sub: "u".into(), iss: "i".into(), aud: String::new(),
            iat: 0, exp: 0, jti: "j".into(),
        };
        let json = serde_json::to_string(&claims).unwrap();
        assert!(!json.contains("aud"));
    }

    #[test]
    fn der_to_jws_valid() {
        let r = vec![0x01; 32];
        let s = vec![0x02; 32];
        let mut der = vec![0x30, 68, 0x02, 32];
        der.extend_from_slice(&r);
        der.push(0x02);
        der.push(32);
        der.extend_from_slice(&s);

        let jws = der_to_jws(&der).unwrap();
        assert_eq!(jws.len(), 64);
        assert_eq!(&jws[..32], &r[..]);
        assert_eq!(&jws[32..], &s[..]);
    }

    #[test]
    fn der_to_jws_too_short() {
        assert!(der_to_jws(&[0x30, 0x00]).is_err());
    }

    #[test]
    fn der_to_jws_wrong_tag() {
        assert!(der_to_jws(&[0x31, 0, 0, 0, 0, 0, 0, 0]).is_err());
    }

    #[test]
    fn der_to_jws_truncated_r() {
        // R length says 32 but only 2 bytes follow
        assert!(der_to_jws(&[0x30, 10, 0x02, 32, 0x01, 0x02]).is_err());
    }

    #[test]
    fn der_to_jws_oversized_integer() {
        // R is 33 bytes (after trimming leading zero, still 33)
        let mut der = vec![0x30, 72, 0x02, 33];
        der.extend_from_slice(&vec![0x01; 33]);
        der.push(0x02);
        der.push(32);
        der.extend_from_slice(&vec![0x02; 32]);
        assert!(der_to_jws(&der).is_err());
    }

    #[test]
    fn static_token_issuer() {
        let issuer = mocks::StaticTokenIssuer {
            token: "fixed-token".into(),
        };
        let claims = Claims {
            sub: "u".into(), iss: "i".into(), aud: String::new(),
            iat: 0, exp: 0, jti: "j".into(),
        };
        assert_eq!(issuer.issue(&claims).unwrap(), "fixed-token");
    }

    #[test]
    fn failing_token_issuer() {
        let issuer = mocks::FailingTokenIssuer;
        let claims = Claims {
            sub: "u".into(), iss: "i".into(), aud: String::new(),
            iat: 0, exp: 0, jti: "j".into(),
        };
        assert!(issuer.issue(&claims).is_err());
    }
}

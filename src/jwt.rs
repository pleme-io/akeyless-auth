use crate::error::{Error, Result};
use crate::protocol::{AuthResponse, Jwk, Jwks};
use crate::traits::{KeyStore, TokenIssuer};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};

/// JWT claims for Akeyless OAuth2/JWT authentication.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    /// Subject (who is authenticating).
    pub sub: String,
    /// Issuer (this daemon).
    pub iss: String,
    /// Audience (Akeyless access ID or endpoint).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub aud: String,
    /// Issued at (Unix timestamp).
    pub iat: i64,
    /// Expires at (Unix timestamp).
    pub exp: i64,
    /// JWT ID (unique per token, prevents replay).
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

    /// Build a signed JWT manually (header.payload.signature).
    ///
    /// We construct the JWT by hand because `jsonwebtoken` requires
    /// key bytes, but our key is in the Keychain/Secure Enclave and
    /// only accessible via `SecKey::create_signature` (Touch ID).
    fn sign_jwt(&self, claims: &Claims) -> Result<String> {
        // Header: {"alg":"ES256","typ":"JWT","kid":"<label>"}
        let header = serde_json::json!({
            "alg": "ES256",
            "typ": "JWT",
            "kid": self.key_label
        });

        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?);
        let claims_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims)?);
        let signing_input = format!("{header_b64}.{claims_b64}");

        // Sign with the Keystore (triggers Touch ID!)
        let der_sig = self
            .key_store
            .sign(&self.key_label, signing_input.as_bytes())?;

        // Convert DER-encoded ECDSA signature to JWS fixed-length format (R || S, 64 bytes)
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

/// Convert a DER-encoded ECDSA signature to JWS format (R || S, 64 bytes).
///
/// DER format: 0x30 <len> 0x02 <r_len> <r_bytes> 0x02 <s_len> <s_bytes>
/// JWS format: <r_32_bytes> <s_32_bytes> (left-padded to 32 bytes each)
fn der_to_jws(der: &[u8]) -> Result<Vec<u8>> {
    if der.len() < 8 || der[0] != 0x30 {
        return Err(Error::Signing("invalid DER signature".into()));
    }

    let mut pos = 2; // skip 0x30 <total_len>

    // Read R
    if der[pos] != 0x02 {
        return Err(Error::Signing("expected 0x02 for R integer".into()));
    }
    pos += 1;
    let r_len = der[pos] as usize;
    pos += 1;
    let r_bytes = &der[pos..pos + r_len];
    pos += r_len;

    // Read S
    if der[pos] != 0x02 {
        return Err(Error::Signing("expected 0x02 for S integer".into()));
    }
    pos += 1;
    let s_len = der[pos] as usize;
    pos += 1;
    let s_bytes = &der[pos..pos + s_len];

    // Pad/trim to exactly 32 bytes each
    let mut result = vec![0u8; 64];
    let r_trimmed = trim_leading_zero(r_bytes);
    let s_trimmed = trim_leading_zero(s_bytes);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keystore::mocks::InMemoryKeyStore;

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
        // JWT has 3 parts separated by dots
        assert_eq!(token.split('.').count(), 3);

        // Header is valid JSON
        let header_b64 = token.split('.').next().unwrap();
        let header_bytes = URL_SAFE_NO_PAD.decode(header_b64).unwrap();
        let header: serde_json::Value = serde_json::from_slice(&header_bytes).unwrap();
        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["typ"], "JWT");
        assert_eq!(header["kid"], "test-key");

        // Claims are valid JSON
        let claims_b64 = token.split('.').nth(1).unwrap();
        let claims_bytes = URL_SAFE_NO_PAD.decode(claims_b64).unwrap();
        let decoded: Claims = serde_json::from_slice(&claims_bytes).unwrap();
        assert_eq!(decoded.sub, "test-user");
        assert_eq!(decoded.iss, "akeyless-auth");
        assert_eq!(decoded.exp, 1060);
    }

    #[test]
    fn jwks_output() {
        let store = InMemoryKeyStore::new();
        store.generate("test-key").unwrap();

        let issuer = JwtTokenIssuer::new(store, "test-key".into());
        let jwks_str = issuer.jwks().unwrap();
        let jwks: Jwks = serde_json::from_str(&jwks_str).unwrap();
        assert_eq!(jwks.keys.len(), 1);
        assert_eq!(jwks.keys[0].kty, "EC");
        assert_eq!(jwks.keys[0].crv, "P-256");
        assert_eq!(jwks.keys[0].alg, "ES256");
        assert_eq!(jwks.keys[0].kid, "test-key");
    }

    #[test]
    fn claims_serialization() {
        let claims = Claims {
            sub: "user".into(),
            iss: "issuer".into(),
            aud: String::new(),
            iat: 1000,
            exp: 1060,
            jti: "id".into(),
        };
        let json = serde_json::to_string(&claims).unwrap();
        // aud should be skipped when empty
        assert!(!json.contains("aud"));

        let claims_with_aud = Claims {
            aud: "my-audience".into(),
            ..claims
        };
        let json = serde_json::to_string(&claims_with_aud).unwrap();
        assert!(json.contains("my-audience"));
    }

    #[test]
    fn der_to_jws_conversion() {
        // A synthetic DER-encoded P-256 signature
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
}

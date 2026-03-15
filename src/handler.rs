use crate::error::Result;
use crate::jwt::Claims;
use crate::protocol::{AuthRequest, AuthResponse};
use crate::traits::{RequestHandler, TokenIssuer};

/// Default request handler that delegates to a `TokenIssuer`.
#[derive(Debug)]
pub struct DefaultHandler<T: TokenIssuer> {
    issuer: T,
    default_issuer_claim: String,
    default_subject: String,
    default_audience: String,
    default_expiry_secs: u64,
}

impl<T: TokenIssuer> DefaultHandler<T> {
    pub fn new(
        issuer: T,
        default_issuer_claim: String,
        default_subject: String,
        default_audience: String,
        default_expiry_secs: u64,
    ) -> Self {
        Self {
            issuer,
            default_issuer_claim,
            default_subject,
            default_audience,
            default_expiry_secs,
        }
    }
}

impl<T: TokenIssuer> RequestHandler for DefaultHandler<T> {
    fn handle(&self, req: &AuthRequest) -> Result<AuthResponse> {
        let now = chrono::Utc::now().timestamp();
        let expiry = if req.expiry_secs > 0 {
            req.expiry_secs
        } else {
            self.default_expiry_secs
        };
        let exp = now + expiry as i64;

        let claims = Claims {
            sub: if req.sub.is_empty() {
                self.default_subject.clone()
            } else {
                req.sub.clone()
            },
            iss: self.default_issuer_claim.clone(),
            aud: if req.aud.is_empty() {
                self.default_audience.clone()
            } else {
                req.aud.clone()
            },
            iat: now,
            exp,
            jti: uuid::Uuid::new_v4().to_string(),
        };

        let token = self.issuer.issue(&claims)?;

        Ok(AuthResponse {
            token,
            expires_at: exp,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use crate::keystore::mocks::InMemoryKeyStore;
    use crate::jwt::JwtTokenIssuer;
    use crate::traits::KeyStore;

    #[test]
    fn handler_issues_token() {
        let store = InMemoryKeyStore::new();
        store.generate("test").unwrap();
        let issuer = JwtTokenIssuer::new(store, "test".into());
        let handler = DefaultHandler::new(
            issuer,
            "akeyless-auth".into(),
            "default-user".into(),
            "default-aud".into(),
            60,
        );

        let req = AuthRequest {
            sub: "my-user".into(),
            aud: String::new(),
            expiry_secs: 30,
        };

        let resp = handler.handle(&req).unwrap();
        assert!(!resp.token.is_empty());
        assert!(resp.expires_at > 0);

        // Verify JWT has 3 parts
        assert_eq!(resp.token.split('.').count(), 3);
    }

    #[test]
    fn handler_uses_defaults_for_empty_fields() {
        let store = InMemoryKeyStore::new();
        store.generate("test").unwrap();
        let issuer = JwtTokenIssuer::new(store, "test".into());
        let handler = DefaultHandler::new(
            issuer,
            "my-issuer".into(),
            "default-sub".into(),
            "default-aud".into(),
            120,
        );

        let req = AuthRequest {
            sub: String::new(), // empty → use default
            aud: String::new(), // empty → use default
            expiry_secs: 0,     // 0 → use default
        };

        let resp = handler.handle(&req).unwrap();
        // Decode claims to verify defaults were applied
        let claims_b64 = resp.token.split('.').nth(1).unwrap();
        let claims_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(claims_b64)
            .unwrap();
        let claims: Claims = serde_json::from_slice(&claims_bytes).unwrap();

        assert_eq!(claims.sub, "default-sub");
        assert_eq!(claims.iss, "my-issuer");
        assert_eq!(claims.aud, "default-aud");
        // Expiry should be ~120 seconds from iat
        assert_eq!(claims.exp - claims.iat, 120);
    }
}

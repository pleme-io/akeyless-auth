use crate::error::Result;
use crate::protocol::{AuthRequest, AuthResponse, Jwk};

/// Generates, stores, and signs with cryptographic keys.
///
/// Default: `KeychainKeyStore` — biometric-protected macOS Keychain.
/// Future: `SecureEnclaveKeyStore` — hardware-backed (requires Apple Developer ID).
pub trait KeyStore: Send + Sync + std::fmt::Debug {
    /// Generate a new P-256 key pair with biometric protection.
    /// Returns the key label for future reference.
    fn generate(&self, label: &str) -> Result<()>;

    /// Check if a key with the given label exists.
    fn exists(&self, label: &str) -> Result<bool>;

    /// Sign data using the key (triggers Touch ID).
    fn sign(&self, label: &str, data: &[u8]) -> Result<Vec<u8>>;

    /// Export the public key as a JWK.
    fn public_key_jwk(&self, label: &str) -> Result<Jwk>;

    /// Delete a key.
    fn delete(&self, label: &str) -> Result<()>;
}

/// Issues signed JWTs for Akeyless authentication.
///
/// Uses a `KeyStore` for signing (Touch ID per token).
pub trait TokenIssuer: Send + Sync + std::fmt::Debug {
    /// Issue a signed JWT. Triggers biometric authentication.
    fn issue(&self, claims: &crate::jwt::Claims) -> Result<String>;

    /// Export the JWKS containing the public key for Akeyless configuration.
    fn jwks(&self) -> Result<String>;
}

/// Handles incoming authentication requests over a transport.
pub trait RequestHandler: Send + Sync + std::fmt::Debug {
    /// Handle a single authentication request.
    fn handle(&self, req: &AuthRequest) -> Result<AuthResponse>;
}

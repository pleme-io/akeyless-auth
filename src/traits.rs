use crate::error::Result;
use crate::jwt::Claims;
use crate::protocol::{AuthRequest, AuthResponse, Jwk};
use std::path::Path;

/// Generates, stores, and signs with cryptographic keys.
///
/// Default: `KeychainKeyStore` — biometric-protected macOS Keychain.
/// Future: `SecureEnclaveKeyStore` — hardware-backed (requires Apple Developer ID).
/// Mock: `InMemoryKeyStore` — no Keychain, no Touch ID.
pub trait KeyStore: Send + Sync + std::fmt::Debug {
    /// Generate a new P-256 key pair with biometric protection.
    fn generate(&self, label: &str) -> Result<()>;

    /// Check if a key with the given label exists.
    fn exists(&self, label: &str) -> Result<bool>;

    /// Sign data using the key (triggers Touch ID on real implementations).
    fn sign(&self, label: &str, data: &[u8]) -> Result<Vec<u8>>;

    /// Export the public key as a JWK.
    fn public_key_jwk(&self, label: &str) -> Result<Jwk>;

    /// Delete a key.
    fn delete(&self, label: &str) -> Result<()>;
}

/// Issues signed JWTs for Akeyless authentication.
///
/// Uses a `KeyStore` for signing (Touch ID per token on real implementations).
/// Mock: `StaticTokenIssuer` — returns a fixed token.
pub trait TokenIssuer: Send + Sync + std::fmt::Debug {
    /// Issue a signed JWT. Triggers biometric authentication on real implementations.
    fn issue(&self, claims: &Claims) -> Result<String>;

    /// Export the JWKS containing the public key for Akeyless configuration.
    #[allow(dead_code)]
    fn jwks(&self) -> Result<String>;
}

/// Handles incoming authentication requests.
///
/// Composes a `TokenIssuer` with claim defaults.
/// Mock: record requests, return canned responses.
pub trait RequestHandler: Send + Sync + std::fmt::Debug {
    /// Handle a single authentication request.
    fn handle(&self, req: &AuthRequest) -> Result<AuthResponse>;
}

/// Transport layer for the daemon.
#[allow(dead_code)] // Public API — not yet used in binary, available for library consumers
///
/// Default: `UnixSocketTransport` — Unix domain socket.
/// Mock: `ChannelTransport` — in-process for testing.
pub trait Transport: Send + Sync + std::fmt::Debug {
    /// Start serving, dispatching requests to the handler.
    fn serve(
        &self,
        path: &Path,
        handler: &dyn RequestHandler,
    ) -> impl std::future::Future<Output = Result<()>> + Send;

    /// Request a token from a running daemon.
    fn request(
        &self,
        path: &Path,
        req: &AuthRequest,
    ) -> impl std::future::Future<Output = Result<AuthResponse>> + Send;
}

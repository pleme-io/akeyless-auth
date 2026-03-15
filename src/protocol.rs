//! Core data structures — everything in akeyless-auth derives from these.
//!
//! These types form the protocol boundary between daemon, client, and Nix module.
//! All are serializable, clonable, and debuggable.

use serde::{Deserialize, Serialize};

/// A JSON Web Key (P-256 EC public key).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Jwk {
    pub kty: String,
    pub crv: String,
    pub x: String,      // base64url x coordinate
    pub y: String,      // base64url y coordinate
    pub kid: String,    // key ID
    #[serde(rename = "use")]
    pub key_use: String,
    pub alg: String,
}

/// A JSON Web Key Set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

/// Request from a client to the auth daemon.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthRequest {
    /// Subject claim for the JWT.
    pub sub: String,

    /// Audience claim.
    #[serde(default)]
    pub aud: String,

    /// JWT expiry in seconds from now. 0 = use daemon default.
    #[serde(default = "default_expiry")]
    pub expiry_secs: u64,
}

fn default_expiry() -> u64 {
    60
}

/// Response from the auth daemon (success).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthResponse {
    /// The signed JWT (ES256).
    pub token: String,

    /// When the token expires (Unix timestamp).
    pub expires_at: i64,
}

/// Error response from the auth daemon.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
}

/// Union type for daemon responses — success or error.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum DaemonResponse {
    Ok(AuthResponse),
    Err(ErrorResponse),
}

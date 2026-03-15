use serde::{Deserialize, Serialize};

/// A JSON Web Key (P-256 EC public key).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jwk {
    pub kty: String,    // "EC"
    pub crv: String,    // "P-256"
    pub x: String,      // base64url-encoded x coordinate
    pub y: String,      // base64url-encoded y coordinate
    pub kid: String,    // key ID (label)
    #[serde(rename = "use")]
    pub key_use: String, // "sig"
    pub alg: String,    // "ES256"
}

/// A JSON Web Key Set.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

/// Request from a client to the auth daemon.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthRequest {
    /// Subject claim for the JWT (e.g., username or machine ID).
    pub sub: String,

    /// Audience claim (Akeyless access ID or URL).
    #[serde(default)]
    pub aud: String,

    /// JWT expiry in seconds from now.
    #[serde(default = "default_expiry")]
    pub expiry_secs: u64,
}

fn default_expiry() -> u64 {
    60
}

/// Response from the auth daemon.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResponse {
    /// The signed JWT (ES256).
    pub token: String,

    /// When the token expires (Unix timestamp).
    pub expires_at: i64,
}

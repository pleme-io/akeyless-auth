use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Key protection mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyProtection {
    /// Biometric-protected Keychain (no Apple Developer Program required).
    /// Key stored in software Keychain, Touch ID required for signing.
    Biometric,

    /// Secure Enclave hardware key (requires Apple Developer Program code signing).
    /// Key never leaves hardware, Touch ID required for signing.
    SecureEnclave,
}

impl Default for KeyProtection {
    fn default() -> Self {
        Self::Biometric
    }
}

/// Configuration for akeyless-auth.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Key label in the Keychain / Secure Enclave.
    #[serde(default = "default_key_label")]
    pub key_label: String,

    /// Key protection mode.
    #[serde(default)]
    pub key_protection: KeyProtection,

    /// Unix socket path for the daemon.
    #[serde(default = "default_socket_path")]
    pub socket_path: PathBuf,

    /// JWT issuer claim.
    #[serde(default = "default_issuer")]
    pub issuer: String,

    /// Default JWT expiry in seconds.
    #[serde(default = "default_expiry_secs")]
    pub expiry_secs: u64,

    /// Default subject claim.
    #[serde(default = "default_subject")]
    pub subject: String,

    /// Default audience claim (typically Akeyless access ID).
    #[serde(default)]
    pub audience: String,

    /// Whether to auto-start the daemon via launchd.
    #[serde(default = "default_autostart")]
    pub autostart: bool,
}

fn default_key_label() -> String {
    "com.pleme.akeyless-auth".into()
}

fn default_socket_path() -> PathBuf {
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("/tmp"));
    home.join(".config/akeyless-auth/sock")
}

fn default_issuer() -> String {
    "akeyless-auth".into()
}

fn default_expiry_secs() -> u64 {
    60
}

fn default_subject() -> String {
    std::env::var("USER").unwrap_or_else(|_| "unknown".into())
}

fn default_autostart() -> bool {
    true
}

impl Default for Config {
    fn default() -> Self {
        Self {
            key_label: default_key_label(),
            key_protection: KeyProtection::default(),
            socket_path: default_socket_path(),
            issuer: default_issuer(),
            expiry_secs: default_expiry_secs(),
            subject: default_subject(),
            audience: String::new(),
            autostart: default_autostart(),
        }
    }
}

impl Config {
    /// Load config from `AKEYLESS_AUTH_CONFIG` env var or
    /// `~/.config/akeyless-auth/config.json`, falling back to defaults.
    pub fn load() -> Self {
        let path = std::env::var("AKEYLESS_AUTH_CONFIG")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                dirs::config_dir()
                    .unwrap_or_else(|| PathBuf::from("/tmp"))
                    .join("akeyless-auth/config.json")
            });

        if path.exists() {
            if let Ok(content) = std::fs::read_to_string(&path) {
                if let Ok(config) = serde_json::from_str(&content) {
                    return config;
                }
                eprintln!(
                    "[akeyless-auth] warning: failed to parse {}, using defaults",
                    path.display()
                );
            }
        }

        Self::default()
    }
}

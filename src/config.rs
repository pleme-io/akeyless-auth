use serde::{Deserialize, Serialize};
use shikumi::{ConfigDiscovery, ProviderChain};
use std::path::PathBuf;

/// Key protection mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyProtection {
    /// Biometric-protected Keychain (no Apple Developer Program required).
    Biometric,
    /// Secure Enclave hardware key (requires Apple Developer Program code signing).
    SecureEnclave,
}

impl Default for KeyProtection {
    fn default() -> Self {
        Self::Biometric
    }
}

/// Configuration for akeyless-auth.
///
/// Loaded via shikumi with standard pleme-io conventions:
///   1. Environment variable: `AKEYLESS_AUTH_CONFIG` (path override)
///   2. Env var overrides: `AKEYLESS_AUTH_KEY_LABEL`, `AKEYLESS_AUTH_EXPIRY_SECS`, etc.
///   3. Config file: `~/.config/akeyless-auth/akeyless-auth.yaml` (XDG)
///   4. Hardcoded defaults (this struct's Default impl)
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

    /// JWT configuration.
    #[serde(default)]
    pub jwt: JwtConfig,

    /// Daemon configuration.
    #[serde(default)]
    pub daemon: DaemonConfig,
}

/// JWT-specific configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtConfig {
    /// JWT issuer claim.
    #[serde(default = "default_issuer")]
    pub issuer: String,

    /// Default subject claim. Empty = current username.
    #[serde(default)]
    pub subject: String,

    /// Default audience claim (Akeyless access ID or endpoint).
    #[serde(default)]
    pub audience: String,

    /// Default JWT expiry in seconds.
    #[serde(default = "default_expiry_secs")]
    pub expiry_secs: u64,
}

impl Default for JwtConfig {
    fn default() -> Self {
        Self {
            issuer: default_issuer(),
            subject: String::new(),
            audience: String::new(),
            expiry_secs: default_expiry_secs(),
        }
    }
}

/// Daemon-specific configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonConfig {
    /// Whether to auto-start the daemon via launchd.
    #[serde(default = "default_autostart")]
    pub autostart: bool,

    /// Log level (trace, debug, info, warn, error).
    #[serde(default = "default_log_level")]
    pub log_level: String,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            autostart: default_autostart(),
            log_level: default_log_level(),
        }
    }
}

fn default_key_label() -> String {
    "com.pleme.akeyless-auth".into()
}

fn default_socket_path() -> PathBuf {
    let xdg = std::env::var("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
            PathBuf::from(home).join(".config")
        });
    xdg.join("akeyless-auth/sock")
}

fn default_issuer() -> String {
    "akeyless-auth".into()
}

fn default_expiry_secs() -> u64 {
    60
}

fn default_autostart() -> bool {
    true
}

fn default_log_level() -> String {
    "info".into()
}

fn default_subject() -> String {
    std::env::var("USER").unwrap_or_else(|_| "unknown".into())
}

impl Default for Config {
    fn default() -> Self {
        Self {
            key_label: default_key_label(),
            key_protection: KeyProtection::default(),
            socket_path: default_socket_path(),
            jwt: JwtConfig::default(),
            daemon: DaemonConfig::default(),
        }
    }
}

impl Config {
    /// Load config via shikumi: env override → env vars → YAML/TOML file → defaults.
    ///
    /// Discovery order:
    ///   1. `$AKEYLESS_AUTH_CONFIG` — explicit path
    ///   2. `~/.config/akeyless-auth/akeyless-auth.yaml`
    ///   3. `~/.config/akeyless-auth/akeyless-auth.toml`
    ///   4. Defaults
    ///
    /// All fields overridable via `AKEYLESS_AUTH_` prefix:
    ///   `AKEYLESS_AUTH_KEY_LABEL`, `AKEYLESS_AUTH_JWT__EXPIRY_SECS`, etc.
    pub fn load() -> Self {
        let discovery = ConfigDiscovery::new("akeyless-auth")
            .env_override("AKEYLESS_AUTH_CONFIG");

        let mut chain = ProviderChain::new()
            .with_defaults(&Self::default())
            .with_env("AKEYLESS_AUTH_");

        if let Ok(path) = discovery.discover() {
            chain = chain.with_file(&path);
        }

        match chain.extract::<Self>() {
            Ok(mut config) => {
                // Fill in default subject if empty.
                if config.jwt.subject.is_empty() {
                    config.jwt.subject = default_subject();
                }
                config
            }
            Err(e) => {
                eprintln!("[akeyless-auth] config error: {e}, using defaults");
                Self::default()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_valid() {
        let cfg = Config::default();
        assert_eq!(cfg.key_label, "com.pleme.akeyless-auth");
        assert_eq!(cfg.key_protection, KeyProtection::Biometric);
        assert_eq!(cfg.jwt.expiry_secs, 60);
        assert_eq!(cfg.jwt.issuer, "akeyless-auth");
        assert!(cfg.daemon.autostart);
        assert_eq!(cfg.daemon.log_level, "info");
    }

    #[test]
    fn config_serde_roundtrip() {
        let cfg = Config::default();
        let yaml = serde_json::to_string_pretty(&cfg).unwrap();
        let restored: Config = serde_json::from_str(&yaml).unwrap();
        assert_eq!(restored.key_label, cfg.key_label);
        assert_eq!(restored.jwt.expiry_secs, cfg.jwt.expiry_secs);
    }

    #[test]
    fn key_protection_serde() {
        let b: KeyProtection = serde_json::from_str(r#""biometric""#).unwrap();
        assert_eq!(b, KeyProtection::Biometric);
        let se: KeyProtection = serde_json::from_str(r#""secure_enclave""#).unwrap();
        assert_eq!(se, KeyProtection::SecureEnclave);
    }

    #[test]
    fn jwt_config_defaults() {
        let jwt = JwtConfig::default();
        assert_eq!(jwt.issuer, "akeyless-auth");
        assert_eq!(jwt.expiry_secs, 60);
        assert!(jwt.subject.is_empty());
        assert!(jwt.audience.is_empty());
    }

    #[test]
    fn daemon_config_defaults() {
        let daemon = DaemonConfig::default();
        assert!(daemon.autostart);
        assert_eq!(daemon.log_level, "info");
    }
}

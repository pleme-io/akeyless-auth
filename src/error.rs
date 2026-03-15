use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
#[allow(dead_code)] // Variants are public API, not all used in the binary yet
pub enum Error {
    #[error("keystore error: {0}")]
    KeyStore(String),

    #[error("signing error: {0}")]
    Signing(String),

    #[error("key not found: {label}")]
    KeyNotFound { label: String },

    #[error("socket error: {0}")]
    Socket(#[from] std::io::Error),

    #[error("socket path already in use: {0}")]
    SocketInUse(PathBuf),

    #[error("config error: {0}")]
    Config(String),

    #[error("biometric authentication required but not available")]
    BiometricUnavailable,

    #[error("biometric authentication denied by user")]
    BiometricDenied,

    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("daemon error: {0}")]
    Daemon(String),
}

pub type Result<T> = std::result::Result<T, Error>;

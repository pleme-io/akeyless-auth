use clap::{Parser, Subcommand};

mod config;
mod error;
mod handler;
mod jwt;
mod keystore;
mod protocol;
mod socket;
mod traits;

use config::Config;
use handler::DefaultHandler;
use jwt::JwtTokenIssuer;
use keystore::KeychainKeyStore;
use traits::{KeyStore, RequestHandler};

#[derive(Parser)]
#[command(
    name = "akeyless-auth",
    about = "Biometric-gated Akeyless authentication — Touch ID for every secret access"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a new key pair (Touch ID required).
    Init,

    /// Print the JWKS containing the public key (for Akeyless auth method setup).
    Jwks,

    /// Start the authentication daemon (listens on Unix socket).
    Daemon,

    /// Request a signed JWT from the daemon (or directly, triggering Touch ID).
    Token {
        /// Subject claim override.
        #[arg(long)]
        sub: Option<String>,

        /// Audience claim override.
        #[arg(long)]
        aud: Option<String>,

        /// JWT expiry in seconds.
        #[arg(long)]
        expiry: Option<u64>,

        /// Sign directly without daemon (triggers Touch ID in this process).
        #[arg(long)]
        direct: bool,
    },

    /// Check daemon status and key existence.
    Status,

    /// Delete the key pair from the Keychain.
    Delete,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let cfg = Config::load();
    let store = KeychainKeyStore::new(cfg.key_protection);

    match cli.command {
        Command::Init => {
            store.generate(&cfg.key_label)?;
            eprintln!("[akeyless-auth] key generated: {}", cfg.key_label);
            eprintln!("[akeyless-auth] protection: {:?}", cfg.key_protection);

            // Print JWKS for convenience.
            let jwk = store.public_key_jwk(&cfg.key_label)?;
            let jwks = protocol::Jwks { keys: vec![jwk] };
            println!("{}", serde_json::to_string_pretty(&jwks)?);

            eprintln!();
            eprintln!("[akeyless-auth] copy the JWKS above into your Akeyless auth method:");
            eprintln!("  akeyless create-auth-method-oauth2 \\");
            eprintln!("    --name /pleme-cli-biometric \\");
            eprintln!("    --jwks-json-data '<paste JWKS>' \\");
            eprintln!("    --unique-identifier sub");
        }

        Command::Jwks => {
            let jwk = store.public_key_jwk(&cfg.key_label)?;
            let jwks = protocol::Jwks { keys: vec![jwk] };
            println!("{}", serde_json::to_string_pretty(&jwks)?);
        }

        Command::Daemon => {
            let issuer = JwtTokenIssuer::new(store, cfg.key_label.clone());
            let handler = DefaultHandler::new(
                issuer,
                cfg.issuer.clone(),
                cfg.subject.clone(),
                cfg.audience.clone(),
                cfg.expiry_secs,
            );
            socket::serve(&cfg.socket_path, &handler).await?;
        }

        Command::Token {
            sub,
            aud,
            expiry,
            direct,
        } => {
            let req = protocol::AuthRequest {
                sub: sub.unwrap_or_default(),
                aud: aud.unwrap_or_default(),
                expiry_secs: expiry.unwrap_or(0),
            };

            if direct {
                // Sign directly in this process (Touch ID prompt here).
                let issuer = JwtTokenIssuer::new(store, cfg.key_label.clone());
                let handler = DefaultHandler::new(
                    issuer,
                    cfg.issuer,
                    cfg.subject,
                    cfg.audience,
                    cfg.expiry_secs,
                );
                let resp = handler.handle(&req)?;
                println!("{}", resp.token);
            } else {
                // Request from daemon via socket.
                let resp = socket::request_token(&cfg.socket_path, &req).await?;
                println!("{}", resp.token);
            }
        }

        Command::Status => {
            let key_exists = store.exists(&cfg.key_label)?;
            let daemon_running = cfg.socket_path.exists();

            eprintln!("[akeyless-auth] key label:   {}", cfg.key_label);
            eprintln!("[akeyless-auth] protection:  {:?}", cfg.key_protection);
            eprintln!(
                "[akeyless-auth] key exists:  {}",
                if key_exists { "yes" } else { "no" }
            );
            eprintln!(
                "[akeyless-auth] daemon:      {}",
                if daemon_running { "running" } else { "stopped" }
            );
            eprintln!("[akeyless-auth] socket:      {}", cfg.socket_path.display());
            eprintln!("[akeyless-auth] issuer:      {}", cfg.issuer);
            eprintln!("[akeyless-auth] subject:     {}", cfg.subject);
            eprintln!("[akeyless-auth] expiry:      {}s", cfg.expiry_secs);
            eprintln!("[akeyless-auth] autostart:   {}", cfg.autostart);

            if !key_exists {
                eprintln!();
                eprintln!("  run `akeyless-auth init` to generate a key");
            }
        }

        Command::Delete => {
            store.delete(&cfg.key_label)?;
            eprintln!("[akeyless-auth] key deleted: {}", cfg.key_label);
        }
    }

    Ok(())
}

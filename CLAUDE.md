# akeyless-auth

> **★★★ CSE / Knowable Construction.** This repo operates under **Constructive Substrate Engineering** — canonical specification at [`pleme-io/theory/CONSTRUCTIVE-SUBSTRATE-ENGINEERING.md`](https://github.com/pleme-io/theory/blob/main/CONSTRUCTIVE-SUBSTRATE-ENGINEERING.md). The Compounding Directive (operational rules: solve once, load-bearing fixes only, idiom-first, models stay current, direction beats velocity) is in the org-level pleme-io/CLAUDE.md ★★★ section. Read both before non-trivial changes.


Biometric-gated Akeyless authentication. Touch ID required for every secret access.

## Why

Without akeyless-auth, Akeyless credentials (`access-id` + `access-key`) are plaintext
files on disk. Any process — including an LLM agent — can read them and access all secrets.

With akeyless-auth, there are **no static credentials**. A P-256 signing key lives in the
macOS Keychain, protected by Touch ID. Every authentication produces a short-lived JWT
that requires your fingerprint. An LLM can request secrets, but you must physically approve
each request.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  akeyless-auth daemon (Rust, launchd)                       │
│                                                              │
│  P-256 key in Keychain (Touch ID protected)                 │
│  Listens on Unix socket                                      │
│                                                              │
│  On request:                                                 │
│    1. Build JWT claims (sub, iss, aud, exp, jti)             │
│    2. Sign with Keychain key → Touch ID prompt!              │
│    3. Return signed JWT (ES256, expires in 60s)              │
└──────────────────────┬──────────────────────────────────────┘
                       │ JWT
                       ▼
┌─────────────────────────────────────────────────────────────┐
│  akeyless-nix / akeyless CLI                                │
│                                                              │
│  POST /auth with JWT → Akeyless validates against JWKS      │
│  GET /get-secret-value with token → secret returned          │
└─────────────────────────────────────────────────────────────┘
```

## Security Properties

| Property | Status |
|----------|--------|
| Private key leaves Keychain | **Never** — signing happens inside Keychain |
| LLM can sign JWTs without Touch ID | **No** — hardware-enforced biometric |
| JWT replayable | **No** — 60s expiry + unique jti per token |
| Credentials on disk | **None** — no access-key files |
| Works offline | **No** — requires Akeyless API |
| Requires Apple Developer Program | **No** for biometric mode, **Yes** for Secure Enclave |

## Key Protection Modes

| Mode | Key Location | Touch ID | Apple Developer Program |
|------|-------------|----------|------------------------|
| `biometric` (default) | macOS Keychain (software) | Required per sign | Not required |
| `secure_enclave` | Secure Enclave (hardware) | Required per sign | Required ($99/yr) |

Both modes require Touch ID. The difference is where the key material lives.
Biometric mode is sufficient for the LLM threat model.

## Rust Architecture

```
src/
├── main.rs          # CLI: init, jwks, daemon, token, status, delete
├── traits.rs        # KeyStore, TokenIssuer, RequestHandler, Transport
├── keystore.rs      # KeychainKeyStore + InMemoryKeyStore (mock)
├── jwt.rs           # JwtTokenIssuer + Claims + DER→JWS conversion
├── handler.rs       # DefaultHandler (claims builder + issuer)
├── socket.rs        # Unix socket serve/request (resilient to errors)
├── protocol.rs      # Core data structures (Jwk, Jwks, AuthRequest, AuthResponse)
├── config.rs        # shikumi-based config (XDG, env vars, YAML/TOML)
└── error.rs         # Error types
```

### Trait Boundaries

Every I/O boundary is behind a trait for testability:

| Trait | Default | Mock |
|-------|---------|------|
| `KeyStore` | `KeychainKeyStore` | `InMemoryKeyStore` |
| `TokenIssuer` | `JwtTokenIssuer<K>` | `StaticTokenIssuer`, `FailingTokenIssuer` |
| `RequestHandler` | `DefaultHandler<T>` | Compose with mock issuers |
| `Transport` | Unix socket functions | (trait defined for future use) |

### Core Data Structures (protocol.rs)

All types derive `Debug, Clone, PartialEq, Eq, Serialize, Deserialize`:

- `Jwk` — P-256 EC public key in JWK format
- `Jwks` — JWK Set (for Akeyless auth method registration)
- `AuthRequest` — client → daemon (sub, aud, expiry_secs)
- `AuthResponse` — daemon → client (token, expires_at)
- `ErrorResponse` — daemon → client on failure (error message)
- `DaemonResponse` — union: `AuthResponse | ErrorResponse`

### Config (shikumi)

Uses the standard pleme-io config pattern via shikumi:

```yaml
# ~/.config/akeyless-auth/akeyless-auth.yaml
key_label: com.pleme.akeyless-auth
key_protection: biometric

socket_path: ~/.config/akeyless-auth/sock

jwt:
  issuer: akeyless-auth
  subject: luis
  audience: p-nn5huxl36myiam
  expiry_secs: 60

daemon:
  autostart: true
  log_level: info
```

Override any field via environment variables:
```bash
AKEYLESS_AUTH_CONFIG=/path/to/config.yaml     # path override
AKEYLESS_AUTH_KEY_PROTECTION=secure_enclave   # field override
AKEYLESS_AUTH_JWT__EXPIRY_SECS=300            # nested field (__ separator)
```

Precedence: defaults → env vars → config file.

## CLI

```bash
akeyless-auth init          # Generate key (Touch ID), print JWKS
akeyless-auth jwks          # Print JWKS for Akeyless config
akeyless-auth daemon        # Start socket listener
akeyless-auth token         # Get JWT via daemon
akeyless-auth token --direct # Get JWT directly (Touch ID in this process)
akeyless-auth status        # Check key/daemon/config
akeyless-auth delete        # Remove key from Keychain
```

## Nix Integration

Home-manager module with configurable launchd agent:

```nix
akeyless-auth = {
  enable = true;
  keyProtection = "biometric";
  issuer = "akeyless-auth";
  audience = "p-nn5huxl36myiam";
  expirySecs = 60;
  autostart = true;    # launchd RunAtLoad + KeepAlive
  logLevel = "info";
};
```

## Integration with akeyless-nix

akeyless-nix's `auth.rs` gains a `BiometricJwt` auth method that:
1. Connects to akeyless-auth daemon socket
2. Requests a JWT (Touch ID prompt appears)
3. Uses the JWT to authenticate to Akeyless API
4. Fetches secrets with the resulting token

## Dependencies

- `security-framework` 3.7 — macOS Keychain/Secure Enclave P-256 operations
- `shikumi` — config discovery, layering, hot-reload (standard pleme-io pattern)
- `tokio` — async Unix socket daemon
- `base64` — JWK/JWT encoding
- `chrono` + `uuid` — JWT claims (iat/exp/jti)

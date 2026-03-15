# Setup Guide: Biometric-Gated Akeyless Authentication

## Overview

This guide walks through replacing plaintext Akeyless credentials with
Touch ID-protected authentication. After setup, every secret access
requires your fingerprint — no static credentials exist on disk.

## Prerequisites

- macOS with Touch ID (Apple Silicon or Touch Bar)
- Akeyless account with admin access
- akeyless CLI installed (`akeyless` command available)
- Existing API key auth method (the one you're replacing)

## Step 1: Generate the Signing Key

```bash
akeyless-auth init
```

This triggers Touch ID and generates a P-256 key pair in your macOS Keychain.
The output is a JWKS (JSON Web Key Set) containing the public key:

```json
{
  "keys": [
    {
      "kty": "EC",
      "crv": "P-256",
      "x": "...",
      "y": "...",
      "kid": "com.pleme.akeyless-auth",
      "use": "sig",
      "alg": "ES256"
    }
  ]
}
```

Save this output — you'll need it for step 2.

## Step 2: Register with Akeyless

Create an OAuth2/JWT auth method in Akeyless that trusts your public key:

```bash
# Create the auth method
akeyless create-auth-method-oauth2 \
  --name /pleme-cli-biometric \
  --jwks-json-data '{"keys":[...paste from step 1...]}' \
  --unique-identifier sub

# Associate your existing admin role
akeyless assoc-role-am \
  --am-name /pleme-cli-biometric \
  --role-name /pleme-admin
```

The `--unique-identifier sub` tells Akeyless to use the JWT `sub` claim
as the identity. This maps to your username by default.

## Step 3: Test the Flow

```bash
# Direct mode (Touch ID in this process):
akeyless-auth token --direct

# This prints a JWT like: eyJhbGciOiJFUzI1NiI...

# Verify it works with Akeyless:
TOKEN=$(akeyless-auth token --direct)
akeyless get-secret-value \
  --name /pleme/test/hello \
  --token "$TOKEN"
```

You should see Touch ID prompt, then the secret value.

## Step 4: Start the Daemon

```bash
akeyless-auth daemon
```

Or configure auto-start via the Nix module (see below).

With the daemon running, clients request tokens via Unix socket
instead of triggering Touch ID directly:

```bash
akeyless-auth token   # requests from daemon, daemon triggers Touch ID
```

## Step 5: Configure akeyless-nix (Future)

Once `akeyless-nix` gains the `BiometricJwt` auth method:

```nix
# In your secrets config:
blackmatter.components.secrets = {
  enable = true;
  backend = "akeyless";
  akeyless.templateEngine = "igata";
  # No access-key needed! Auth goes through akeyless-auth daemon.
};
```

## Step 6: Remove Static Credentials

Once the biometric flow is verified:

1. Remove `akeyless/access-key` from `secrets.yaml` (sops)
2. Keep `akeyless/access-id` as a fallback identifier
3. Optionally disable the API key auth method in Akeyless

## Nix Module Configuration

```nix
# In your home-manager config:
akeyless-auth = {
  enable = true;
  keyProtection = "biometric";
  audience = "p-nn5huxl36myiam";  # your Akeyless access ID
  expirySecs = 60;
  autostart = true;
};
```

## Config File

`~/.config/akeyless-auth/akeyless-auth.yaml`:

```yaml
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

## Troubleshooting

### "key not found"
Run `akeyless-auth init` to generate a key. If you previously deleted
a key, you'll need to re-register the JWKS with Akeyless (step 2).

### "biometric authentication denied"
You cancelled the Touch ID prompt. Try again.

### Daemon not responding
Check: `akeyless-auth status`
Restart: `akeyless-auth daemon` or `launchctl kickstart -k gui/$(id -u)/io.pleme.akeyless-auth`

### JWT rejected by Akeyless
Verify the JWKS matches: `akeyless-auth jwks` should match what's
registered in the auth method. If you regenerated the key, you need
to update the Akeyless auth method with the new JWKS.

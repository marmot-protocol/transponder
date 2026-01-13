# Transponder

A privacy-preserving push notification server for [Marmot](https://github.com/marmot-protocol/marmot) group messaging, implementing the [MIP-05 specification](https://github.com/marmot-protocol/marmot/blob/master/05.md).

## Overview

Transponder enables push notifications for Marmot-compatible messaging apps while preserving user privacy. It operates as a Nostr client, subscribing to relays for gift-wrapped notification requests and dispatching silent push notifications to APNs (Apple) and FCM (Google).

### Privacy Properties

- **Stateless**: No persistent storage of tokens or user data
- **Cannot learn**: Message content, sender/recipient identities, or group membership
- **Minimal metadata**: Only knows that a notification event occurred

## Requirements

- Rust 1.90+
- APNs credentials (for iOS notifications)
- FCM service account (for Android notifications)

## Quick Start

```bash
# Clone and build
git clone https://github.com/marmot-protocol/transponder.git
cd transponder
cargo build --release

# Configure (copy and edit the example config)
cp config/default.toml config/local.toml
# Edit config/local.toml with your credentials

# Run
./target/release/transponder --config config/local.toml
```

## Configuration

Transponder uses TOML configuration files with environment variable overrides. The configuration is loaded in the following order (later sources override earlier ones):

1. Default values built into the application
2. Configuration file specified via `--config`
3. Environment variables with prefix `TRANSPONDER_`

### Configuration File Reference

```toml
[server]
# Server's Nostr private key in hex format (64 hex characters)
# REQUIRED - Generate with: openssl rand -hex 32
# SECURITY: Store in environment variable for production
private_key = ""

[relays]
# ClearNet relays to subscribe to
clearnet = [
    "wss://relay.damus.io",
    "wss://nos.lol"
]

# Tor/onion relays (optional, enables enhanced privacy)
# Requires the server to have Tor connectivity
onion = []

# Reconnection settings (reserved for future use)
reconnect_interval_secs = 5
max_reconnect_attempts = 10

[apns]
# Enable APNs for iOS push notifications
enabled = false

# Authentication method: "token" (recommended) or "certificate"
auth_method = "token"

# For token-based auth (recommended):
# - key_id: The 10-character Key ID from Apple Developer Console
# - team_id: Your 10-character Apple Team ID
# - private_key_path: Path to the .p8 file downloaded from Apple
key_id = ""
team_id = ""
private_key_path = ""

# For certificate-based auth:
# - certificate_path: Path to the .p12 certificate file
# - certificate_password: Password for the .p12 file
certificate_path = ""
certificate_password = ""

# APNs environment: "production" or "sandbox"
# Use "sandbox" for development/testing, "production" for App Store builds
environment = "production"

# Your iOS app's bundle identifier (e.g., "com.example.myapp")
bundle_id = ""

[fcm]
# Enable FCM for Android push notifications
enabled = false

# Path to the Firebase service account JSON file
# Download from: Firebase Console > Project Settings > Service Accounts
service_account_path = ""

# Firebase project ID (optional if present in service account JSON)
project_id = ""

[health]
# Enable the health check HTTP server
enabled = true

# Address and port to bind the health server to
# Use "127.0.0.1:8080" to restrict to localhost only
bind_address = "0.0.0.0:8080"

[logging]
# Log level: "trace", "debug", "info", "warn", "error", "off"
level = "info"

# Log format: "json" (structured, for production) or "pretty" (human-readable)
format = "json"
```

### Environment Variables

Override any config value using environment variables with the pattern `TRANSPONDER_<SECTION>_<KEY>`:

```bash
# Required: Server private key
export TRANSPONDER_SERVER_PRIVATE_KEY="your-64-char-hex-private-key"

# Push services
export TRANSPONDER_APNS_ENABLED=true
export TRANSPONDER_APNS_KEY_ID="ABCD123456"
export TRANSPONDER_APNS_TEAM_ID="TEAM123456"
export TRANSPONDER_APNS_PRIVATE_KEY_PATH="/path/to/AuthKey.p8"
export TRANSPONDER_APNS_BUNDLE_ID="com.example.app"

export TRANSPONDER_FCM_ENABLED=true
export TRANSPONDER_FCM_SERVICE_ACCOUNT_PATH="/path/to/service-account.json"

# Relays (JSON array format)
export TRANSPONDER_RELAYS_CLEARNET='["wss://relay.example.com","wss://relay2.example.com"]'

# Logging
export TRANSPONDER_LOGGING_LEVEL="debug"
export TRANSPONDER_LOGGING_FORMAT="pretty"
```

### Generating a Server Private Key

The server requires a secp256k1 private key for Nostr identity and token decryption:

```bash
# Using OpenSSL
openssl rand -hex 32

# Using Python
python3 -c "import secrets; print(secrets.token_hex(32))"
```

The corresponding public key will be logged on startup. Share this public key with clients so they can encrypt notification tokens for your server.

## Docker

### Building

```bash
docker build -t transponder .
```

### Running

```bash
docker run -d \
  --name transponder \
  -p 8080:8080 \
  -v /path/to/config.toml:/etc/transponder/config.toml:ro \
  -v /path/to/credentials:/credentials:ro \
  -e TRANSPONDER_SERVER_PRIVATE_KEY="your-hex-key" \
  transponder
```

### Docker Compose

```yaml
version: '3.8'
services:
  transponder:
    build: .
    ports:
      - "8080:8080"
    volumes:
      - ./config/local.toml:/etc/transponder/config.toml:ro
      - ./credentials:/credentials:ro
    environment:
      TRANSPONDER_SERVER_PRIVATE_KEY: "${TRANSPONDER_PRIVATE_KEY}"
    healthcheck:
      test: ["CMD", "wget", "-q", "--spider", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 3
```

## Health Checks

When enabled, Transponder exposes HTTP endpoints for monitoring:

| Endpoint | Description | Success |
|----------|-------------|---------|
| `GET /health` | Liveness check - is the server running? | Always 200 OK |
| `GET /ready` | Readiness check - can the server process requests? | 200 if relays connected and at least one push service configured |

### Readiness Response

```json
{
  "status": "ready",
  "relays_connected": true,
  "apns_configured": true,
  "fcm_configured": false
}
```

## How It Works

1. **Subscribe**: Transponder connects to configured Nostr relays and subscribes to `kind:1059` (gift-wrapped) events addressed to its public key.

2. **Unwrap**: When an event arrives, it unwraps the NIP-59 gift wrap to extract the inner `kind:446` notification request.

3. **Decrypt**: Each encrypted token in the request is decrypted using ECDH + HKDF + ChaCha20-Poly1305 (per MIP-05).

4. **Dispatch**: Tokens are routed to APNs or FCM based on platform identifier, sending silent push notifications.

5. **Wake**: Client apps wake up, fetch messages from relays, and display notifications locally.

```
Nostr Relays (ClearNet/Tor)
         │
         │ kind:1059 events
         ▼
    ┌─────────────┐
    │ Transponder │
    │             │
    │  Unwrap     │
    │  Decrypt    │
    │  Dispatch   │
    └─────────────┘
         │
    ┌────┴────┐
    ▼         ▼
  APNs      FCM
```

## Security Considerations

### Credential Management

- **Never commit credentials** to version control
- **Use environment variables** for sensitive values in production
- **Restrict file permissions** on config files: `chmod 600 config/local.toml`
- **Mount credentials read-only** in Docker: `-v /path:/credentials:ro`

### Private Key Security

The server private key is critical:
- It is used to decrypt all notification tokens
- Compromise allows decryption of device tokens (but not message content)
- Store in a secrets manager (HashiCorp Vault, AWS Secrets Manager, etc.) for production
- Rotate periodically and update clients with the new public key

### Network Security

- **TLS everywhere**: All connections to relays, APNs, and FCM use TLS
- **Health endpoint exposure**: Consider binding to localhost (`127.0.0.1:8080`) and using a reverse proxy
- **Firewall rules**: Only expose port 8080 if health checks are needed externally

### Logging Security

- **Never logged**: Device tokens, private keys, decrypted content
- **Logged at debug level**: Push success/failure counts (no identifying info)
- **Use JSON format** in production for structured log aggregation
- **Set level to "info"** or higher in production

### Operational Security

- Run as a **non-root user** (the Docker image does this automatically)
- Use **read-only filesystems** where possible
- Enable **health checks** for orchestration systems
- Monitor for **unusual error rates** which may indicate attacks

## Development

```bash
# Run tests
cargo test

# Run with verbose logging
RUST_LOG=debug cargo run -- --config config/local.toml

# Format code
cargo fmt

# Lint
cargo clippy -- -D warnings

# Build release binary
cargo build --release
```

## Troubleshooting

### "Failed to connect to any relay"
- Check relay URLs are correct and accessible
- For onion relays, ensure Tor connectivity
- Verify firewall allows outbound WebSocket connections

### "APNs authentication error"
- Verify key_id, team_id, and bundle_id are correct
- Ensure the .p8 key file is readable and not corrupted
- Check the key hasn't been revoked in Apple Developer Console

### "FCM authentication error"
- Verify service account JSON file is valid
- Ensure the service account has Firebase Cloud Messaging permissions
- Check project_id matches the Firebase project

### Health check returns "not_ready"
- Check relay connections in logs
- Verify at least one push service (APNs or FCM) is properly configured

## License

[MIT](LICENSE)

## Related

- [Marmot Protocol](https://github.com/marmot-protocol/marmot) - Privacy-preserving group messaging
- [MIP-05 Specification](https://github.com/marmot-protocol/marmot/blob/master/05.md) - Push notification protocol
- [NIP-59](https://github.com/nostr-protocol/nips/blob/master/59.md) - Gift wrap specification

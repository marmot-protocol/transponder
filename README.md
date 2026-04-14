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
- Optional: build with `--features tor` only if you need onion relay support

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

Tor relay support is disabled in the default build. If you need `.onion` relays, build and run with `--features tor`.

## Configuration

Transponder uses TOML configuration files with environment variable overrides. The configuration is loaded in the following order (later sources override earlier ones):

1. Default values built into the application
2. Configuration file specified via `--config`
3. Environment variables with prefix `TRANSPONDER_`

### Configuration File Reference

```toml
[server]
# Server's Nostr private key in hex format (64 hex characters)
# REQUIRED - Generate with: transponder generate-keys
# SECURITY: Store in environment variable for production
private_key = ""

# Graceful shutdown timeout in seconds
shutdown_timeout_secs = 10

# Event deduplication cache size (default: 100000)
# max_dedup_cache_size = 100000

# Rate limiting to prevent spam and replay attacks
# max_rate_limit_cache_size = 100000           # LRU cache size per limiter
# max_tokens_per_event = 100                   # Per notification event
# encrypted_token_rate_limit_per_minute = 240  # Per encrypted token (replay protection)
# encrypted_token_rate_limit_per_hour = 5000
# device_token_rate_limit_per_minute = 240     # Per device (spam protection)
# device_token_rate_limit_per_hour = 5000

[relays]
# ClearNet relays to subscribe to
clearnet = [
    "wss://relay.damus.io",
    "wss://nos.lol"
]

# Tor/onion relays (optional)
# Requires a build with `--features tor` and a host that can support Tor traffic
onion = []

# Reconnection settings (reserved for future use)
reconnect_interval_secs = 5
max_reconnect_attempts = 10

[apns]
# Enable APNs for iOS push notifications
enabled = false

# Token-based auth credentials:
# - key_id: The 10-character Key ID from Apple Developer Console
# - team_id: Your 10-character Apple Team ID
# - private_key_path: Path to the .p8 file downloaded from Apple
key_id = ""
team_id = ""
private_key_path = ""

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

[metrics]
# Whether Prometheus metrics are enabled
# Metrics are exposed at /metrics on the health server port
enabled = true

[logging]
# Log level: "trace", "debug", "info", "warn", "error", "off"
level = "info"

# Log format: "json" (structured, for production) or "pretty" (human-readable)
format = "json"
```

### Environment Variables

Override any config value using environment variables with the pattern `TRANSPONDER_<SECTION>_<KEY>`.
The first underscore after `TRANSPONDER` separates the section from the key, so
`TRANSPONDER_SERVER_PRIVATE_KEY` maps to `server.private_key`:

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

# Relays (comma-separated)
export TRANSPONDER_RELAYS_CLEARNET="wss://relay.example.com,wss://relay2.example.com"
export TRANSPONDER_RELAYS_ONION="wss://exampleonionrelay.onion" # requires `--features tor`

# Logging
export TRANSPONDER_LOGGING_LEVEL="debug"
export TRANSPONDER_LOGGING_FORMAT="pretty"
```

### Generating a Server Key Pair

The server requires a secp256k1 private key for Nostr identity and token decryption. Use the built-in command to generate a new key pair:

```bash
# Using transponder (recommended)
./target/release/transponder generate-keys
```

This outputs:
- **Private key (hex)**: 64-character hex string for your config
- **Public key (hex)**: For clients that need the raw public key
- **Public key (npub)**: Bech32-encoded format, easier to share

Alternatively, you can use [nak](https://github.com/fiatjaf/nak), a general-purpose Nostr CLI tool:

```bash
# Install nak (requires Go)
go install github.com/fiatjaf/nak@latest

# Generate a new key pair
nak key generate
```

Share the public key with clients so they can encrypt notification tokens for your server.

## Docker

### Building

```bash
docker login dhi.io
docker build -t transponder .
```

To build an image with onion relay support enabled:

```bash
docker login dhi.io
docker build --build-arg CARGO_FEATURES='--features tor' -t transponder:tor .
```

### Running

```bash
docker run -d \
  --name transponder \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  -p 127.0.0.1:8080:8080 \
  -v /path/to/config.toml:/etc/transponder/config.toml:ro \
  -v /path/to/credentials:/credentials:ro \
  -e TRANSPONDER_SERVER_PRIVATE_KEY="your-hex-key" \
  transponder
```

### Docker Compose

A hardened `docker-compose.yml` is included. It starts only Transponder.

```bash
docker compose up -d

# View logs
docker compose logs -f transponder
```

Services and ports:
- **Transponder**: `http://localhost:8080` (health, readiness, metrics)

### Runtime Notes

- The production image now uses Docker Hardened Images for both build and runtime stages.
- Base images are pinned by digest for reproducible deploys.
- Docker health checks use `transponder healthcheck`, so the container does not need `wget` or `curl`.
- The build context intentionally excludes local configs and credentials via `.dockerignore`.
- Tor relay support is disabled in the default build and must be enabled explicitly with `--features tor`.

## Production Deployment

The repository now includes a production deployment bundle:

- [compose.prod.yml](compose.prod.yml)
- [config/production.toml.example](config/production.toml.example)
- [deploy/production.env.example](deploy/production.env.example)
- [docs/deployment.md](docs/deployment.md)
- [deploy/transponder.service.example](deploy/transponder.service.example)

Recommended deployment flow:

```bash
cp config/production.toml.example config/production.toml
cp deploy/production.env.example deploy/production.env
mkdir -p credentials secrets
chmod 700 credentials secrets

printf '%s\n' 'YOUR_64_CHAR_HEX_PRIVATE_KEY' > secrets/server_private_key
chmod 600 secrets/server_private_key

docker login dhi.io
docker build -t transponder:local .
docker compose -f compose.prod.yml --env-file deploy/production.env up -d
```

The production bundle uses `TRANSPONDER_SERVER_PRIVATE_KEY_FILE` so the server private key can be mounted as a file instead of injected directly as an environment variable.

If you plan to configure onion relays, build the image with `--build-arg CARGO_FEATURES='--features tor'` first and point `TRANSPONDER_IMAGE` at that Tor-enabled image tag.

### Machine Sizing

Transponder is lightweight compared with a database-backed service, but it does have real memory and network needs from relay connections, decryption work, push fan-out, and optional Tor support.

Starting guidance:

- Test or evaluation node: `1 vCPU`, `1 GB RAM`
- Small production node, clearnet only: `2 vCPU`, `2 GB RAM`
- Recommended production node, especially with onion relays: `2 vCPU`, `4 GB RAM`
- Higher-traffic or Tor-heavy deployment: `4 vCPU`, `8 GB RAM`

Disk guidance:

- `20 GB` is enough for Transponder alone
- `40 GB` gives you comfortable headroom for logs, credential rotation, and general host overhead

For the full host-prep, `systemd` example, and upgrade flow, see [docs/deployment.md](docs/deployment.md).

### Dependency Audit

Run a local vulnerability audit with:

```bash
just audit
```

or directly:

```bash
cargo audit
```

`just audit` uses the repository audit policy for the optional Tor dependency tree. The default build does not enable Tor, and the remaining ignored advisories are upstream in that optional graph. Use `just audit-strict` if you want the raw unfiltered report.

## Health Checks

When enabled, Transponder exposes HTTP endpoints for monitoring:

| Endpoint | Description | Success |
|----------|-------------|---------|
| `GET /health` | Liveness check - is the server running? | Always 200 OK |
| `GET /ready` | Readiness check - can the server process requests? | 200 if relays connected and at least one push service configured |
| `GET /metrics` | Prometheus metrics (when metrics enabled) | 200 with metrics in Prometheus text format |

### Readiness Response

```json
{
  "status": "ready",
  "relays_connected": true,
  "apns_configured": true,
  "fcm_configured": false
}
```

## Metrics

Transponder exposes Prometheus metrics at `/metrics` on the health server port (default 8080). Metrics are enabled by default and can be disabled via configuration.

### Available Metrics

#### Event Processing

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `transponder_events_received_total` | Counter | - | Total events received from relays |
| `transponder_events_processed_total` | Counter | - | Total events successfully processed |
| `transponder_events_deduplicated_total` | Counter | - | Total events skipped (already processed) |
| `transponder_events_failed_total` | Counter | - | Total events that failed processing |
| `transponder_events_in_flight` | Gauge | - | Current number of events actively being processed |
| `transponder_event_processing_duration_seconds` | Histogram | `outcome` | End-to-end duration of event processing |
| `transponder_gift_wrap_unwrap_duration_seconds` | Histogram | `outcome` | Duration of NIP-59 gift-wrap unwraps |
| `transponder_notification_parse_duration_seconds` | Histogram | `outcome` | Duration of notification tag validation, base64 decode, and token splitting |
| `transponder_tokens_per_event` | Histogram | - | Number of encrypted tokens carried by each parsed event |
| `transponder_notification_content_size_bytes` | Histogram | - | Size in bytes of the base64-decoded encrypted token blob from kind 446 notification content |
| `transponder_dedup_cache_size` | Gauge | - | Current deduplication cache size |
| `transponder_dedup_cache_evictions_total` | Counter | - | Total dedup cache evictions |
| `transponder_tokens_decrypted_total` | Counter | - | Total tokens successfully decrypted |
| `transponder_tokens_decryption_failed_total` | Counter | - | Total token decryption failures |
| `transponder_token_decrypt_duration_seconds` | Histogram | `outcome` | Duration of individual token decrypt operations |
| `transponder_notifications_admitted_per_event` | Histogram | - | Number of notifications admitted to the push dispatcher per event |

#### Token Rate Limiting

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `transponder_tokens_rate_limited_total` | Counter | `type`, `reason` | Tokens skipped due to rate limiting |
| `transponder_rate_limit_cache_size` | Gauge | `type` | Current rate limit cache size |
| `transponder_rate_limit_evictions_total` | Counter | `type` | Rate limit cache evictions |

Label values: `type` = `encrypted_token` or `device_token`; `reason` = `minute` or `hour`

`outcome` values vary by metric group:
- Event processing: `processed`, `duplicate`, `failed`
- Gift-wrap unwrap, notification parse, token decrypt, and push admission: `success`, `failed`

#### Push Notifications

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `transponder_push_dispatched_total` | Counter | `platform` | Notifications dispatched to push services |
| `transponder_push_success_total` | Counter | `platform` | Successful push notifications |
| `transponder_push_failed_total` | Counter | `platform`, `reason` | Failed push notifications |
| `transponder_push_queue_size` | Gauge | - | Current push queue size |
| `transponder_push_queue_capacity` | Gauge | - | Maximum number of notifications the push queue can hold |
| `transponder_push_semaphore_available` | Gauge | - | Available concurrent push permits |
| `transponder_push_concurrency_limit` | Gauge | - | Maximum number of concurrent outbound push requests |
| `transponder_push_queue_rejected_total` | Counter | - | Notifications rejected before admission because the push queue was full, the dispatcher was shutting down, or the queue channel was closed |
| `transponder_push_dispatch_admission_duration_seconds` | Histogram | `outcome` | Time spent admitting notifications into the push dispatcher |
| `transponder_push_retries_total` | Counter | `platform` | Push retry attempts |
| `transponder_push_request_duration_seconds` | Histogram | `platform` | Push request duration |
| `transponder_push_response_status_total` | Counter | `platform`, `status` | Push responses by HTTP status |
| `transponder_auth_token_refreshes_total` | Counter | `service` | Auth token refreshes (JWT/OAuth) |

#### Relay Connections

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `transponder_relays_connected` | Gauge | `type` | Currently connected relays |
| `transponder_relays_configured` | Gauge | `type` | Configured relays |
| `transponder_relay_notifications_lagged_total` | Counter | - | Number of times the relay notification receiver reported lag |
| `transponder_relay_notifications_dropped_total` | Counter | - | Total relay notifications dropped because the receiver lagged |

#### Server Info

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `transponder_server_start_time_seconds` | Gauge | - | Unix timestamp when server started |
| `transponder_server_info` | Gauge | `version` | Server version info |

### Security Note

All metrics are designed to be safe for exposure. They do not include device tokens, user identifiers, message content, or relay URLs.

## Monitoring Integration

Transponder exposes Prometheus-format metrics at `/metrics`, but the repository no longer bundles Prometheus, Grafana, or a reverse proxy. That is intentional: operators can scrape and visualize Transponder using whatever monitoring stack they already trust.

Typical patterns:

- scrape `http://127.0.0.1:8080/metrics` from a local Prometheus, VictoriaMetrics, or similar agent
- forward metrics through an existing reverse proxy or VPN if you need remote scraping
- keep `/metrics` internal-only unless you have a deliberate access-control story

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
- **Prefer mounted secret files** for the server private key in Docker/Compose
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
- **Prefer localhost binds** in Compose and publish through a reverse proxy only when needed
- **Default inbound policy**: SSH only
- **Do not publish** the health or metrics port directly to the public internet unless you have a clear access-control plan
- **Outbound policy**: Allow HTTPS egress to relays, APNs, and FCM; onion relay support may require broader Tor-compatible egress
- **Tor is opt-in**: The default build rejects onion relay configuration unless you compile with `--features tor`

### Logging Security

- **Never logged**: Device tokens, private keys, decrypted content
- **Logged at debug level**: Push success/failure counts (no identifying info)
- **Use JSON format** in production for structured log aggregation
- **Set level to "info"** or higher in production

### Operational Security

- Run as a **non-root user** (the Docker image does this automatically)
- Prefer **rootless Docker** on the host when feasible
- Use **read-only filesystems** where possible
- Enable **health checks** for orchestration systems
- Monitor for **unusual error rates** which may indicate attacks

## Development

```bash
# Run tests
cargo test

# Run the optional Tor relay build
cargo test --features tor

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
- If you configured onion relays, confirm the binary was built with `--features tor`
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

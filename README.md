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
# REQUIRED - Generate with: transponder generate-keys
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

A `docker-compose.yml` is included with Transponder, Prometheus, and Grafana services:

```bash
# Start all services (Transponder + monitoring stack)
docker compose up -d

# Start only Transponder
docker compose up -d transponder

# View logs
docker compose logs -f transponder
```

Services and ports:
- **Transponder**: `http://localhost:8080` (health, readiness, metrics)
- **Prometheus**: `http://localhost:9090` (metrics storage and queries)
- **Grafana**: `http://localhost:3000` (dashboards, default login: admin/admin)

See [Monitoring with Prometheus & Grafana](#monitoring-with-prometheus--grafana) for more details.

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

| Metric | Type | Description |
|--------|------|-------------|
| `transponder_events_received_total` | Counter | Total events received from relays |
| `transponder_events_processed_total` | Counter | Total events successfully processed |
| `transponder_events_deduplicated_total` | Counter | Total events skipped (already processed) |
| `transponder_events_failed_total` | Counter | Total events that failed processing |
| `transponder_dedup_cache_size` | Gauge | Current deduplication cache size |
| `transponder_dedup_cache_evictions_total` | Counter | Total dedup cache evictions |
| `transponder_tokens_decrypted_total` | Counter | Total tokens successfully decrypted |
| `transponder_tokens_decryption_failed_total` | Counter | Total token decryption failures |

#### Push Notifications

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `transponder_push_dispatched_total` | Counter | `platform` | Notifications dispatched to push services |
| `transponder_push_success_total` | Counter | `platform` | Successful push notifications |
| `transponder_push_failed_total` | Counter | `platform`, `reason` | Failed push notifications |
| `transponder_push_queue_size` | Gauge | - | Current push queue size |
| `transponder_push_queue_dropped_total` | Counter | - | Notifications dropped (queue full) |
| `transponder_push_semaphore_available` | Gauge | - | Available concurrent push permits |
| `transponder_push_retries_total` | Counter | `platform` | Push retry attempts |
| `transponder_push_request_duration_seconds` | Histogram | `platform` | Push request duration |
| `transponder_push_response_status_total` | Counter | `platform`, `status` | Push responses by HTTP status |
| `transponder_auth_token_refreshes_total` | Counter | `service` | Auth token refreshes (JWT/OAuth) |

#### Relay Connections

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `transponder_relays_connected` | Gauge | `type` | Currently connected relays |
| `transponder_relays_configured` | Gauge | `type` | Configured relays |

#### Server Info

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `transponder_server_start_time_seconds` | Gauge | - | Unix timestamp when server started |
| `transponder_server_info` | Gauge | `version` | Server version info |

### Security Note

All metrics are designed to be safe for exposure. They do not include device tokens, user identifiers, message content, or relay URLs.

## Monitoring with Prometheus & Grafana

The repository includes a ready-to-use monitoring stack with Prometheus and Grafana via Docker Compose.

### Quick Start

```bash
# Start Transponder with the full monitoring stack
docker compose up -d

# Access the services:
# - Transponder health: http://localhost:8080/health
# - Transponder metrics: http://localhost:8080/metrics
# - Prometheus: http://localhost:9090
# - Grafana: http://localhost:3000 (admin/admin)
```

### Architecture

```
┌─────────────┐     scrape      ┌────────────┐     query     ┌─────────┐
│ Transponder │◄────────────────│ Prometheus │◄──────────────│ Grafana │
│  :8080      │    /metrics     │  :9090     │               │  :3000  │
└─────────────┘                 └────────────┘               └─────────┘
```

### Configuration Files

| File | Description |
|------|-------------|
| `docker-compose.yml` | Service definitions for all containers |
| `monitoring/prometheus/prometheus.yml` | Prometheus scrape configuration |
| `monitoring/grafana/provisioning/datasources/datasource.yml` | Grafana datasource setup |

### Prometheus Configuration

The default Prometheus configuration scrapes Transponder metrics every 15 seconds:

```yaml
# monitoring/prometheus/prometheus.yml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'transponder'
    static_configs:
      - targets: ['transponder:8080']
```

### Example PromQL Queries

```promql
# Push notification success rate (last 5 minutes)
sum(rate(transponder_push_success_total[5m])) / sum(rate(transponder_push_dispatched_total[5m]))

# Events processed per second
rate(transponder_events_processed_total[1m])

# Push request latency (p99)
histogram_quantile(0.99, rate(transponder_push_request_duration_seconds_bucket[5m]))

# Current relay connections by type
transponder_relays_connected

# Token decryption failure rate
rate(transponder_tokens_decryption_failed_total[5m]) / rate(transponder_tokens_decrypted_total[5m])
```

### Running Without Monitoring

To run only Transponder without Prometheus and Grafana:

```bash
docker compose up -d transponder
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

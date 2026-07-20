# Transponder

A privacy-preserving push notification server for [Marmot](https://github.com/marmot-protocol/marmot) group messaging. Its canonical protocol target is the adopted [Marmot push-notifications feature](https://github.com/marmot-protocol/marmot/blob/master/features/push-notifications.md).

## Overview

Transponder enables push notifications for Marmot-compatible messaging apps while preserving user privacy. It operates as a Nostr client, subscribing to relays for gift-wrapped notification triggers and dispatching silent push notifications to APNs (Apple) and FCM (Google).

### Protocol Status

The adopted Marmot surface documents supersede the deprecated MIP-era documents. For Transponder work, use these sources:

- [Push notifications](https://github.com/marmot-protocol/marmot/blob/master/features/push-notifications.md) — normative token encryption, token gossip, kind `446` trigger, replay, freshness, and retention behavior
- [Nostr transport](https://github.com/marmot-protocol/marmot/blob/master/transports/nostr.md) — normative NIP-59 wrapping, account inbox relays, relay URL profile, and transport encoding rules
- [MIP coverage](https://github.com/marmot-protocol/marmot/blob/master/mip-coverage.md) — historical mapping only; it is not a normative protocol surface

The current Transponder implementation predates the adopted `marmot-push-v1` interop surface and is not yet fully `marmot-push-v1` compatible. In particular, it still uses the MIP-era HKDF labels and version tag, accepts the old optional `encoding` tag, and deduplicates on outer gift-wrap event IDs with optional durable retention. The adopted specification instead requires `marmot-push-token-v1` / `marmot-push-token-encryption`, a kind `446` rumor whose only tag is `["v", "marmot-push-v1"]`, and short-lived deduplication on `SHA-256` of the decoded trigger content rather than the rewrappable outer event ID. Operational sections below describe the current server behavior; they must not be read as claims of `marmot-push-v1` conformance until the implementation and test vectors are migrated.

The maintained MIP-05 implementation is preserved in the [`release/mip05-v1`](https://github.com/marmot-protocol/transponder/tree/release/mip05-v1) branch and the immutable [`transponder-mip05-v1.0.0`](https://github.com/marmot-protocol/transponder/releases/tag/transponder-mip05-v1.0.0) release. Existing MIP-05 services should build from that release line rather than from `master`; `master` is the forward-looking Marmot Push development line.

### Privacy Properties

- **No persisted secrets or message/user content**: Device tokens, trigger plaintext, message content, group identifiers, and recipient linkage are not persisted; the current compatibility replay state retains only public gift-wrap event IDs and processing timestamps, while the adopted feature separately defines short-lived trigger-content-hash retention
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
# Server's Nostr private key in hex format (64 hex characters).
# Prefer private_key_file for production: it keeps the secret out of the config
# file and lets the server enforce file permissions on it. An inline value here
# (or in TRANSPONDER_SERVER_PRIVATE_KEY) is read through a dedicated zeroizing
# path that never stores it in the config parser's un-zeroized buffers.
private_key = ""

# Alternative: path to a file containing the private key.
# The file must be mode 0600 (not group/world readable) or the server refuses
# to start, mirroring the 0600 that generate-keys writes.
# Generate with: transponder generate-keys --output /path/to/server.key
# private_key_file = "/run/secrets/transponder_private_key"

# Graceful shutdown timeout in seconds (must be >= 1; 0 skips the drain)
shutdown_timeout_secs = 10

# Volatile event deduplication cache size when durable replay state is disabled
# (default: 100000; must be >= 1). With dedup_state_path set, all terminal event
# IDs inside dedup_retention_secs are retained for the full NIP-59 lookback.
# max_dedup_cache_size = 100000

# Optional durable replay state for processed gift-wrap event IDs.
# Production deployments should set this to a writable path so restarts do not
# re-dispatch the NIP-59 2-day subscription backlog.
# Stores only public event IDs and timestamps; no tokens, keys, payloads,
# identities, or relay URLs.
# dedup_state_path = "/var/lib/transponder/dedup-events.log"
# dedup_retention_secs = 173100
# max_notification_age_secs = 3600
# max_notification_future_skew_secs = 300

# Rate limiting to prevent spam and replay attacks. Size fields must be >= 1;
# a value of 0 is rejected at startup (it previously either silently swapped in
# the default or rejected every event).
# max_rate_limit_cache_size = 100000           # Tracked keys per limiter, not total timestamps
# max_tokens_per_event = 100                   # Per notification event
# encrypted_token_rate_limit_per_minute = 240  # Per encrypted token (replay protection)
# encrypted_token_rate_limit_per_hour = 5000
# device_token_rate_limit_per_minute = 240     # Per device (spam protection)
# device_token_rate_limit_per_hour = 5000

# CPU-exhaustion DoS protection (admission control before gift-wrap unwrap)
# max_concurrent_event_processing = 64            # Bounds in-flight unwrap (ECDH) work
# global_unwrap_rate_limit_per_minute = 600       # Global pre-unwrap throttle (all senders)
# global_unwrap_rate_limit_per_hour = 30000

[relays]
# ClearNet relays to subscribe to
clearnet = [
    "wss://relay.eu.whitenoise.chat",
    "wss://relay.us.whitenoise.chat"
]

# Reject ws:// ClearNet relays by default. Enable only for local development
# with loopback/mock relays that cannot serve TLS.
allow_unencrypted_clearnet_relays = false

# Tor/onion relays (optional)
# Requires a build with `--features tor` and a host that can support Tor traffic.
# Each entry must be a ws:// or wss:// URL with a .onion host; a clearnet or
# malformed entry here is rejected at startup instead of silently degrading to
# clearnet.
onion = []

# Reconnection settings
# reconnect_interval_secs is the base retry interval and must be between 1 and 300 seconds
# max_reconnect_attempts caps retries after the initial failed attempt; 0 disables retries
reconnect_interval_secs = 5
max_reconnect_attempts = 10

# Startup wait for the first relay to connect (must be between 1 and 300 seconds)
# connection_timeout_secs = 30

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

# APNs payload mode: "silent" or "nse_prototype_alert"
# Keep production silent. Use nse_prototype_alert only for staging NSE prototype testing.
payload_mode = "silent"

[fcm]
# Enable FCM for Android push notifications
enabled = false

# Path to the Firebase service account JSON file
# Download from: Firebase Console > Project Settings > Service Accounts
service_account_path = ""

# Firebase project ID (optional if present in service account JSON)
project_id = ""

[health]
# Enable the /health and /ready endpoints
enabled = true

# Address and port to bind the health/metrics listener to. Must be a valid
# IP:port socket address (a hostname like "localhost:8080" or an out-of-range
# port is rejected at startup). Keep this on localhost unless an internal proxy,
# VPN, or load balancer needs it.
bind_address = "127.0.0.1:8080"

[metrics]
# Whether Prometheus metrics are enabled.
# /metrics is served on health.bind_address whenever metrics are enabled, even
# if the health endpoints (health.enabled) are disabled.
enabled = true

[logging]
# Log level: "trace", "debug", "info", "warn", "error", "off".
# level = "off" silences all console output while keeping the subscriber active.
level = "info"

# Log format: "json" (structured, for production) or "pretty" (human-readable).
# Only "json" or "pretty" are accepted; any other value (including "off") is
# rejected at startup. To silence logs, set level = "off".
format = "json"

[glitchtip]
# Error and panic reporting to a GlitchTip (Sentry-compatible) instance.
# Disabled while dsn is empty. Prefer TRANSPONDER_GLITCHTIP_DSN over committing
# the DSN. Only transponder's own ERROR events and panics are sent.
dsn = ""
environment = "production"
# traces_sample_rate = 0.0   # 0.0..=1.0; 0.0 = errors only (recommended)
```

Rate-limit memory scales with admitted hits, not just tracked keys. Each active
key can retain up to `per_minute + per_hour` `Instant` timestamps for precise
sliding-window enforcement. Worst-case timestamp storage is therefore
`max_rate_limit_cache_size × (per_minute + per_hour)` per limiter: with the
defaults, `100000 × (240 + 5000) ≈ 524M` timestamps for the encrypted-token
limiter (about 8.4 GB at 16 bytes per timestamp, before `VecDeque` overhead),
and the same bound again for the device-token limiter. Lower
`max_rate_limit_cache_size` on memory-constrained deployments.

`max_rate_limit_cache_size` is an aggregate key budget per limiter. Large
caches are sharded for lock locality, and a new key can be rejected when its
routed shard has no stale or below-limit victim even if sibling shards still
have free entries. Size the cache with that stripe-local admission behavior in
mind.

### Environment Variables

Override any config value using environment variables with the pattern `TRANSPONDER_<SECTION>_<KEY>`.
The first underscore after `TRANSPONDER` separates the section from the key, so
`TRANSPONDER_SERVER_PRIVATE_KEY_FILE` maps to `server.private_key_file`:

```bash
# Recommended: mounted server private key file
export TRANSPONDER_SERVER_PRIVATE_KEY_FILE="/run/secrets/transponder_private_key"

# Also supported, but easier to capture in shell history or logs:
# export TRANSPONDER_SERVER_PRIVATE_KEY="your-64-char-hex-private-key"

# Push services
export TRANSPONDER_APNS_ENABLED=true
export TRANSPONDER_APNS_KEY_ID="ABCD123456"
export TRANSPONDER_APNS_TEAM_ID="TEAM123456"
export TRANSPONDER_APNS_PRIVATE_KEY_PATH="/path/to/AuthKey.p8"
export TRANSPONDER_APNS_BUNDLE_ID="com.example.app"
export TRANSPONDER_APNS_PAYLOAD_MODE="silent"

export TRANSPONDER_FCM_ENABLED=true
export TRANSPONDER_FCM_SERVICE_ACCOUNT_PATH="/path/to/service-account.json"

# Relays (comma-separated)
export TRANSPONDER_RELAYS_CLEARNET="wss://relay.eu.whitenoise.chat,wss://relay.us.whitenoise.chat"
export TRANSPONDER_RELAYS_ONION="wss://exampleonionrelay.onion" # requires `--features tor`

# Logging
export TRANSPONDER_LOGGING_LEVEL="info"
export TRANSPONDER_LOGGING_FORMAT="pretty"
export RUST_LOG="info,transponder=debug,nostr_relay_pool=info,nostr_sdk=info,nostr=info,reqwest=warn,hyper=warn,hyper_util=warn,h2=warn,tower=warn,rustls=warn,tungstenite=warn,tokio_tungstenite=warn"
```

### Generating a Server Key Pair

The server requires a secp256k1 private key for Nostr identity and token decryption. Use the built-in command to generate a new key pair and write the secret directly to a restricted file:

```bash
# Using transponder (recommended)
./target/release/transponder generate-keys --output secrets/server_private_key
```

This outputs:
- **Public key (hex)**: For clients that need the raw public key
- **Public key (npub)**: Bech32-encoded format, easier to share

The private key is not printed by default. Use `--show-private-key` only in a secure, non-logged terminal session.

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
  -v /path/to/state:/var/lib/transponder:rw \
  -e TRANSPONDER_SERVER_PRIVATE_KEY="your-hex-key" \
  -e TRANSPONDER_SERVER_DEDUP_STATE_PATH="/var/lib/transponder/dedup-events.log" \
  -e TRANSPONDER_HEALTH_BIND_ADDRESS="0.0.0.0:8080" \
  transponder
```

Docker port publishing needs the service to listen on the container interface. The command above still binds the host side to `127.0.0.1`, keeping the endpoints local to the host by default.

The container runs as UID/GID `65532`. If you bind-mount a host state directory, create it so that user can write the replay log:

```bash
sudo install -d -m 0700 -o 65532 -g 65532 /path/to/state
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
- The build context intentionally excludes local configs, credentials, and state via `.dockerignore`.
- Mount `/var/lib/transponder` persistently in production so processed gift-wrap event IDs survive restarts and reconnects.
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
sudo install -d -m 0700 -o 65532 -g 65532 state

./target/release/transponder generate-keys --output secrets/server_private_key

docker login dhi.io
docker build -t transponder:local .
docker compose -f compose.prod.yml --env-file deploy/production.env up -d
```

The production bundle uses `TRANSPONDER_SERVER_PRIVATE_KEY_FILE` so the server private key can be mounted as a file instead of injected directly as an environment variable. It also mounts `./state` at `/var/lib/transponder` for durable replay suppression state.

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
| `GET /ready` | Readiness check - can the server currently deliver notifications? | 200 if relays connected, at least one push service configured, and no configured push service is in a sustained delivery-failure streak |
| `GET /metrics` | Prometheus metrics (when metrics enabled - served even if the health endpoints are disabled) | 200 with metrics in Prometheus text format |

The default bind address is `127.0.0.1:8080` so these unauthenticated endpoints stay local. If external health checks are required, bind to a specific internal interface or put the endpoints behind a reverse proxy, VPN, or load balancer with access controls. The listener additionally enforces a per-request timeout, a small request-body limit, and a global concurrency cap.

### Readiness Response

```json
{
  "status": "ready",
  "relays_connected": true,
  "apns_configured": true,
  "fcm_configured": false,
  "apns_delivering": true,
  "fcm_delivering": true
}
```

Readiness probes are side-effect-free: they read a cached relay-status snapshot maintained by a background refresher instead of enumerating the relay pool per request. The `*_delivering` fields expose a passive per-provider signal derived from real send outcomes - a provider is reported as not delivering (and `/ready` returns 503) once it accumulates a sustained streak of consecutive hard send failures (authentication rejections, permanent errors, or exhausted retries) with no intervening success. The signal never probes the providers, so with zero push traffic it retains its last observed state.

## Metrics

Transponder exposes Prometheus metrics at `/metrics` on the health server port (default 8080 on localhost). Metrics are enabled by default and can be disabled via configuration. The `/metrics` endpoint is served whenever metrics are enabled, even when the health endpoints (`health.enabled = false`) are disabled.

### Available Metrics

#### Event Processing

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `transponder_events_received_total` | Counter | - | Total events received from relays |
| `transponder_events_processed_total` | Counter | - | Total events successfully processed |
| `transponder_events_deduplicated_total` | Counter | - | Total events skipped (already processed) |
| `transponder_events_failed_total` | Counter | - | Total events that failed processing |
| `transponder_events_shed_total` | Counter | - | Total events shed by global admission control before the gift-wrap unwrap (ECDH) was attempted |
| `transponder_events_in_flight` | Gauge | - | Current number of events actively being processed |
| `transponder_event_processing_duration_seconds` | Histogram | `outcome` | End-to-end duration of event processing |
| `transponder_gift_wrap_unwrap_duration_seconds` | Histogram | `outcome` | Duration of NIP-59 gift-wrap unwraps |
| `transponder_notification_parse_duration_seconds` | Histogram | `outcome` | Duration of notification tag validation, base64 decode, and token splitting |
| `transponder_tokens_per_event` | Histogram | - | Number of encrypted tokens carried by each parsed event |
| `transponder_notification_content_size_bytes` | Histogram | - | Size in bytes of the raw base64 token content received in kind 446 notification triggers |
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
| `transponder_rate_limit_cache_size` | Gauge | `type` | Current rate limit cache size in tracked keys, not stored timestamps |
| `transponder_rate_limit_evictions_total` | Counter | `type` | Stale rate limit entries removed during cleanup |
| `transponder_rate_limit_admission_evictions_total` | Counter | `type` | Rate limit entries evicted on the admission hot path to admit a new key |

Label values: `type` = `encrypted_token` or `device_token`; `reason` = `minute`, `hour`, or `capacity`

Under cache pressure, below-limit keys may be evicted to admit new keys. That resets their sliding-window hit counts (a precision trade-off, not a bypass). Capacity is enforced per routed shard, so a key can be rejected with `reason="capacity"` while other shards still have room; monitor `transponder_rate_limit_admission_evictions_total` and `transponder_tokens_rate_limited_total{reason="capacity"}` to size `max_rate_limit_cache_size`.

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

Metrics do not include device tokens, user identifiers, message content, or relay URLs, but aggregate operational data can still reveal traffic patterns and deployment state. Keep `/metrics` internal-only unless it is protected by a deliberate access-control layer.

## Monitoring Integration

Transponder exposes Prometheus-format metrics at `/metrics`, but the repository no longer bundles Prometheus, Grafana, or a reverse proxy. That is intentional: operators can scrape and visualize Transponder using whatever monitoring stack they already trust.

Typical patterns:

- scrape `http://127.0.0.1:8080/metrics` from a local Prometheus, VictoriaMetrics, or similar agent
- forward metrics through an existing reverse proxy or VPN if you need remote scraping
- keep `/metrics` internal-only unless you have a deliberate access-control story

### Error reporting (GlitchTip)

Transponder can report errors and panics to a [GlitchTip](https://glitchtip.com/) instance (or any Sentry-compatible endpoint). It is disabled unless you set a DSN via the `[glitchtip]` config section or `TRANSPONDER_GLITCHTIP_DSN`.

To preserve the server's privacy guarantees, only `ERROR`-level events emitted by Transponder's own code, plus panics, are sent — dependency-crate errors (which can embed URLs and device tokens) and all lower log levels are dropped before transmission. Transponder never puts tokens, keys, or message content into log or panic messages (an invariant enforced in review; see AGENTS.md), so none reach GlitchTip. TLS trusts bundled roots, so reporting does not depend on the runtime's system CA store. A malformed DSN fails startup rather than silently disabling reporting.

## How It Works

1. **Subscribe**: Transponder connects to configured Nostr relays and subscribes to `kind:1059` (gift-wrapped) events addressed to its public key.

2. **Unwrap**: When an event arrives, it unwraps the NIP-59 gift wrap to extract the inner `kind:446` notification trigger.

3. **Decrypt**: Each encrypted token in the request is decrypted using ECDH + HKDF + ChaCha20-Poly1305. The adopted domain-separation values are defined by the [Marmot push-notifications feature](https://github.com/marmot-protocol/marmot/blob/master/features/push-notifications.md); see [Protocol Status](#protocol-status) for the current compatibility gap.

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
- **Use secret files or a secrets manager** for sensitive values in production
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
- **Relay TLS enforcement**: ClearNet relay URLs must use `wss://`; `ws://` requires an explicit local-development opt-in
- **Health endpoint exposure**: Keep the default localhost bind (`127.0.0.1:8080`) unless an internal proxy, VPN, or load balancer needs it
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

# Run with verbose Transponder logging without dependency debug chatter
RUST_LOG=info,transponder=debug,nostr_relay_pool=info,reqwest=warn,hyper_util=warn,h2=warn cargo run -- --config config/local.toml

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

- [Marmot Protocol](https://github.com/marmot-protocol/marmot) - Adopted privacy-preserving group-messaging specification
- [Marmot Push Notifications](https://github.com/marmot-protocol/marmot/blob/master/features/push-notifications.md) - Adopted push-notification feature and interop surface
- [MIP Coverage](https://github.com/marmot-protocol/marmot/blob/master/mip-coverage.md) - Historical mapping from deprecated MIPs to adopted spec surfaces
- [NIP-59](https://github.com/nostr-protocol/nips/blob/master/59.md) - Gift wrap specification

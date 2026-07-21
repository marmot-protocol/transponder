# AGENTS.md

## Project Overview

Transponder is a privacy-preserving push notification server targeting the adopted [Marmot push-notifications feature](https://github.com/marmot-protocol/marmot/blob/master/features/push-notifications.md) and [Nostr transport binding](https://github.com/marmot-protocol/marmot/blob/master/transports/nostr.md). It listens for gift-wrapped Nostr events (kind 1059) on configured relays, decrypts notification triggers, and dispatches content-free push notifications to APNs and FCM. APNs delivery is silent by default and may use the opt-in, product-neutral `generic_alert` mode.

The Marmot repository's adopted surface documents are normative. The MIP-era documents are deprecated; use [mip-coverage.md](https://github.com/marmot-protocol/marmot/blob/master/mip-coverage.md) only as a historical map. The current source implements the `marmot-push-v1` server surface and must retain exact wire compatibility with those adopted documents.

The maintained MIP-05 line is [`release/mip05-v1`](https://github.com/marmot-protocol/transponder/tree/release/mip05-v1), anchored by [`transponder-mip05-v1.0.0`](https://github.com/marmot-protocol/transponder/releases/tag/transponder-mip05-v1.0.0). Target MIP-05-only fixes to that branch; `master` is the Marmot Push v1 line.

Key properties:
- **No persisted secrets or message/user content**: Device tokens, trigger plaintext, content hashes, message content, group identifiers, and recipient linkage are never persisted.
- **Privacy-preserving**: Cannot learn message content, sender/recipient identities, or group membership
- **Nostr-native**: Subscribes to relays for incoming events (not an HTTP server for notifications)
- **Multi-network**: Supports both ClearNet and Tor (.onion) relays

## Git Worktrees

When working on tasks that require separate git worktrees (e.g., any time you're working on a distinct task like an issue or bug fix), always create them in the `trees/` directory at the project root. This keeps worktrees organized and separated from the main working directory.

## Build Commands

```bash
# Install dependencies and build
cargo build

# Build release binary
cargo build --release

# Run the server (requires config)
cargo run -- --config config/default.toml

# Run with environment variable overrides
TRANSPONDER_SERVER_PRIVATE_KEY=<hex_key> cargo run -- --config config/default.toml
```

## Test Commands

```bash
# Run all tests
cargo test

# Run tests with output
cargo test -- --nocapture

# Run specific test module
cargo test crypto::
cargo test push::
cargo test config::

# Check code without building
cargo check

# Run clippy lints
cargo clippy -- -D warnings

# Format code
cargo fmt

# Run test coverage (requires cargo-llvm-cov)
cargo install cargo-llvm-cov
rustup component add llvm-tools-preview
cargo llvm-cov --html
```

## Code Style

- Use `rustfmt` for formatting (run `cargo fmt` before committing when working outside the `just ci` flow)
- Follow Rust API guidelines: https://rust-lang.github.io/api-guidelines/
- Use `thiserror` for error types in library code
- Use `anyhow` for error propagation in main/tests
- Prefer `tracing` macros over `println!` for any output
- All public items must have documentation comments
- Use `#[must_use]` on functions that return values that shouldn't be ignored
- Run `cargo clippy -- -D warnings` and fix all warnings before committing

## Architecture

```
src/
├── main.rs           # Entry point, CLI args, initialization, event loop
├── config.rs         # Configuration loading (TOML + env vars)
├── error.rs          # Error types using thiserror
├── shutdown.rs       # Graceful shutdown handling (SIGTERM/SIGINT)
├── crypto/
│   ├── mod.rs        # Module exports
│   ├── token.rs      # Marmot push-token decryption (ECDH + HKDF + ChaCha20-Poly1305)
│   └── nip59.rs      # NIP-59 gift wrap/seal handling
├── nostr/
│   ├── mod.rs        # Module exports
│   ├── client.rs     # Relay connections (ClearNet + Tor via nostr-sdk)
│   └── events.rs     # Notification-trigger processing, replay protection, and admission
├── push/
│   ├── mod.rs        # Module exports
│   ├── apns.rs       # APNs HTTP/2 client with JWT token auth
│   ├── fcm.rs        # FCM v1 API client with OAuth2
│   └── dispatcher.rs # Push routing with semaphore-based concurrency (100 max)
├── server/
│   ├── mod.rs        # Module exports
│   └── health.rs     # Health check HTTP endpoints (/health, /ready, /metrics)
└── metrics.rs        # Prometheus metrics collection
```

## Key Implementation Details

### Marmot Push Token Decryption (crypto/token.rs)
- Uses ECDH with secp256k1 for key agreement
- HKDF-SHA256 uses salt `marmot-push-token-v1` and info `marmot-push-token-encryption`
- ChaCha20-Poly1305 for authenticated encryption
- Length-prefixed plaintext: platform byte, u16 big-endian token length, device token, ignored random padding
- Platform byte: 0x01 = APNs, 0x02 = FCM

### Event Processing (nostr/events.rs)
- Replay protection retains `SHA-256` hashes of decoded kind `446` content in memory for minutes; it never keys on outer gift-wrap IDs or persists trigger state
- The parser requires `["v", "marmot-push-v1"]` as the rumor's only tag and standard padded base64 content
- Silently ignores invalid, stale, or replayed notification triggers as local push hygiene under the adopted feature
- Concurrent push dispatch (doesn't wait for completion)

### Rate Limiting (rate_limiter.rs)
- Uses per-minute and per-hour sliding windows with bounded key cardinality
- `max_rate_limit_cache_size` is an aggregate tracked-key budget per limiter
- Large caches are sharded for lock locality; admission is stripe-local, so a key can be rejected when its stripe has no safe victim even if sibling stripes have free capacity

### Push Dispatcher (push/dispatcher.rs)
- Semaphore limits concurrent outbound requests to 100
- Spawns tasks for each notification (fire-and-forget)
- Graceful shutdown waits for in-flight requests

### Health Server (server/health.rs)
- `/health` - Always returns 200 OK (liveness)
- `/ready` - Returns 200 if relays connected AND at least one push service configured
- `/metrics` - Prometheus metrics endpoint (when metrics enabled)

### Metrics (metrics.rs)
- All metrics prefixed with `transponder_`
- Event processing: received, processed, deduplicated, failed counts
- Push notifications: dispatched, success, failed (by platform/reason), queue size, retries
- Push client: request duration histogram, response status codes, auth token refreshes
- Relay connections: connected/configured counts by type (clearnet/onion)
- Server info: start time, version
- **Security**: No sensitive data (tokens, user IDs, relay URLs) in metrics

## Security Considerations

- **Never log device tokens or private keys** - these are sensitive
- **`ERROR` logs and panics are forwarded to GlitchTip.** Transponder-target `error!` events, plus any panic, are sent to the error reporter (see `src/telemetry.rs`; panics go through Sentry's global hook and are *not* target-scoped, so they can originate anywhere). Never interpolate a device token, encrypted blob, private key, recipient identity, or a raw `reqwest::Error` (whose APNs URL contains the device token) into an `error!`, `panic!`, `expect`, or `unwrap` message - fail or log with a redacted id or status instead. The same rule already governs `warn!`/`debug!`, but for anything reportable it is a hard privacy boundary, not just hygiene. As a mechanical backstop, `scrub_event` (`src/telemetry.rs` + `src/redaction.rs`) redacts secret-shaped substrings (64+ char hex runs, `/3/device/<hex>` paths, `wss://` URLs, `.onion` hosts, `nsec1` keys) from every outgoing event — this catches dependency panics, which are not target-scoped. The backstop does not relax the no-secrets rule.
- **Never persist device tokens, trigger plaintext, trigger/content hashes, group identifiers, or recipient linkage.** The adopted feature permits only short-lived in-memory trigger/content-hash retention needed to dispatch and suppress immediate replay.
- **Silently ignore invalid, stale, and replayed notification triggers** under the adopted push-notification feature
- Use `tracing` at debug level for push results, never include user-identifying info
- All credentials should come from environment variables or config files, never hardcoded
- The server private key enables decryption of all tokens - protect it carefully

## Key Dependencies

| Crate | Purpose |
|-------|---------|
| `nostr-sdk` | Nostr protocol client with built-in Tor support via arti |
| `chacha20poly1305` | ChaCha20-Poly1305 AEAD encryption |
| `hmac`, `sha2` | HKDF-SHA256 key derivation (manual extract/expand so the PRK is zeroizable; `hkdf` remains a dev-dependency for the test-vector encryption side) |
| `secp256k1` | ECDH key agreement |
| `reqwest` | HTTP client for APNs/FCM |
| `jsonwebtoken` | JWT auth for APNs and FCM OAuth |
| `axum` | Health check HTTP server |
| `tokio` | Async runtime |
| `tracing` | Structured logging |
| `config` | Configuration loading with env overrides |
| `prometheus` | Prometheus metrics collection |
| `sentry` | GlitchTip/Sentry error and panic reporting |
| `rustls` | Installs the `ring` crypto provider for sentry's `rustls-no-provider` transport (keeps the build off `aws-lc-rs`) |

## Configuration

Config uses TOML files with environment variable overrides. Pattern: `TRANSPONDER_<SECTION>_<KEY>`

Required configuration:
- `server.private_key` - 64-character hex string (secp256k1 private key)
- At least one relay in `relays.clearnet` or `relays.onion`
- At least one push service enabled (`apns.enabled` or `fcm.enabled`)

Example environment overrides:
```bash
TRANSPONDER_SERVER_PRIVATE_KEY=abc123...
TRANSPONDER_APNS_ENABLED=true
TRANSPONDER_APNS_KEY_ID=ABCD123456
TRANSPONDER_RELAYS_CLEARNET='["wss://relay.example.com"]'
```

## PR Guidelines

- Run `just ci` before every commit; this is the standard pre-commit gate for formatting, linting, tests, and audit checks
- If `just ci` fails, fix the issues before committing
- Run `cargo fmt` before committing when working outside the `just ci` flow
- Run `cargo clippy -- -D warnings` and fix all warnings
- All tests must pass (`cargo test`)
- Include tests for new functionality
- Update documentation for public API changes
- Commit messages should describe the "why" not just the "what"
- Don't commit credentials or private keys

## Common Tasks

### Adding a new configuration option
1. Add field to appropriate struct in `config.rs`
2. Add default value in `AppConfig::load()` and `AppConfig::from_env()`
3. Add to `config/default.toml`
4. Update README.md configuration reference

### Adding a new push service
1. Create new client in `push/` directory
2. Add configuration struct in `config.rs`
3. Initialize in `main.rs`
4. Add to `PushDispatcher` with new platform type

### Debugging relay connections
```bash
RUST_LOG=info,transponder=debug,nostr_relay_pool=info,reqwest=warn,hyper_util=warn,h2=warn TRANSPONDER_LOGGING_FORMAT=pretty cargo run -- --config config/local.toml
```

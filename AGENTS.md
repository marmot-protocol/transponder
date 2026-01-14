# AGENTS.md

## Project Overview

Transponder is a privacy-preserving push notification server implementing the [Marmot MIP-05 specification](https://github.com/marmot-protocol/marmot/blob/master/05.md). It listens for gift-wrapped Nostr events (kind 1059) on configured relays, decrypts notification requests, and dispatches silent push notifications to APNs and FCM.

Key properties:
- **Stateless**: No persistent storage of tokens or user data (required by spec for privacy)
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

- Use `rustfmt` for formatting (run `cargo fmt` before committing)
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
│   ├── token.rs      # MIP-05 token decryption (ECDH + HKDF + ChaCha20-Poly1305)
│   └── nip59.rs      # NIP-59 gift wrap/seal handling
├── nostr/
│   ├── mod.rs        # Module exports
│   ├── client.rs     # Relay connections (ClearNet + Tor via nostr-sdk)
│   └── events.rs     # Event processing with 5-minute deduplication
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

### Monitoring Stack

```
monitoring/
├── prometheus/
│   └── prometheus.yml    # Prometheus scrape config (targets transponder:8080)
└── grafana/
    └── provisioning/
        └── datasources/
            └── datasource.yml  # Auto-provisions Prometheus datasource
```

## Key Implementation Details

### Token Decryption (crypto/token.rs)
- Uses ECDH with secp256k1 for key agreement
- HKDF-SHA256 with salt "mip05-v1" and info "mip05-token-encryption"
- ChaCha20-Poly1305 for authenticated encryption
- PKCS#7 padding removal from decrypted payload
- Platform byte: 0x01 = APNs, 0x02 = FCM

### Event Processing (nostr/events.rs)
- 5-minute deduplication window using event IDs
- Silently ignores invalid tokens per MIP-05 spec
- Concurrent push dispatch (doesn't wait for completion)

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
- **No persistent storage** - the spec requires stateless operation for privacy
- **Silently ignore invalid/expired tokens** (per MIP-05 spec)
- Use `tracing` at debug level for push results, never include user-identifying info
- All credentials should come from environment variables or config files, never hardcoded
- The server private key enables decryption of all tokens - protect it carefully

## Key Dependencies

| Crate | Purpose |
|-------|---------|
| `nostr-sdk` | Nostr protocol client with built-in Tor support via arti |
| `chacha20poly1305` | ChaCha20-Poly1305 AEAD encryption |
| `hkdf`, `sha2` | HKDF key derivation |
| `secp256k1` | ECDH key agreement |
| `reqwest` | HTTP client for APNs/FCM |
| `jsonwebtoken` | JWT auth for APNs and FCM OAuth |
| `axum` | Health check HTTP server |
| `tokio` | Async runtime |
| `tracing` | Structured logging |
| `config` | Configuration loading with env overrides |
| `prometheus` | Prometheus metrics collection |

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

- Run `cargo fmt` before committing
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
TRANSPONDER_LOGGING_LEVEL=debug TRANSPONDER_LOGGING_FORMAT=pretty cargo run -- --config config/local.toml
```

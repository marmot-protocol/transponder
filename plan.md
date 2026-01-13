# Transponder - MIP-05 Notification Server Implementation Plan

## Overview

Transponder is a privacy-preserving push notification server implementing the [Marmot MIP-05 specification](https://github.com/marmot-protocol/marmot/blob/master/05.md). It listens for gift-wrapped Nostr events on configured relays (ClearNet and/or Tor), decrypts notification requests, and dispatches silent push notifications to APNs (Apple) and FCM (Google).

### Key Properties

- **Stateless**: No persistent storage of tokens or user data
- **Privacy-preserving**: Cannot learn message content, sender/recipient identities, or group membership
- **Nostr-native**: Operates by subscribing to relays for incoming events
- **Multi-network**: Supports both ClearNet and Tor (.onion) relays

---

## Architecture

```
                    ┌─────────────────┐
                    │  Nostr Relays   │
                    │ (ClearNet/Tor)  │
                    └────────┬────────┘
                             │ kind:1059 (gift-wrapped)
                             ▼
                    ┌─────────────────┐
                    │   Transponder   │
                    │                 │
                    │ ┌─────────────┐ │
                    │ │ NIP-59      │ │
                    │ │ Unwrapper   │ │
                    │ └──────┬──────┘ │
                    │        │        │
                    │ ┌──────▼──────┐ │
                    │ │ Token       │ │
                    │ │ Decryptor   │ │
                    │ └──────┬──────┘ │
                    │        │        │
                    │ ┌──────▼──────┐ │
                    │ │ Push        │ │
                    │ │ Dispatcher  │ │
                    │ └─────────────┘ │
                    └────────┬────────┘
                             │
              ┌──────────────┼──────────────┐
              ▼              ▼              ▼
         ┌────────┐    ┌─────────┐    ┌─────────┐
         │  APNs  │    │   FCM   │    │ Health  │
         │        │    │  v1 API │    │ HTTP    │
         └────────┘    └─────────┘    └─────────┘
```

---

## Implementation Phases

### Phase 1: Project Setup & Core Infrastructure

#### 1.1 Project Initialization
- [ ] Initialize Cargo project with binary target
- [ ] Set up directory structure:
  ```
  transponder/
  ├── Cargo.toml
  ├── Cargo.lock
  ├── config/
  │   └── default.toml          # Default configuration
  ├── src/
  │   ├── main.rs               # Entry point
  │   ├── config.rs             # Configuration loading
  │   ├── error.rs              # Error types
  │   ├── crypto/
  │   │   ├── mod.rs
  │   │   ├── token.rs          # Token decryption (ECDH + HKDF + ChaCha20-Poly1305)
  │   │   └── nip59.rs          # Gift wrap/seal handling
  │   ├── nostr/
  │   │   ├── mod.rs
  │   │   ├── client.rs         # Relay connections
  │   │   ├── events.rs         # Event types (kind 446, 1059)
  │   │   └── subscription.rs   # Subscription management
  │   ├── push/
  │   │   ├── mod.rs
  │   │   ├── apns.rs           # APNs client
  │   │   ├── fcm.rs            # FCM v1 client
  │   │   └── dispatcher.rs     # Push routing logic
  │   ├── server/
  │   │   ├── mod.rs
  │   │   └── health.rs         # Health check HTTP server
  │   └── shutdown.rs           # Graceful shutdown handling
  ├── Dockerfile
  ├── docker-compose.yml
  └── README.md
  ```

#### 1.2 Dependencies (Cargo.toml)
```toml
[package]
name = "transponder"
version = "0.1.0"
edition = "2021"
rust-version = "1.75"

[dependencies]
# Async runtime
tokio = { version = "1.49", features = ["full", "signal"] }

# Nostr
nostr-sdk = { version = "0.44", features = ["tor"] }  # Includes Tor support via arti

# Cryptography
chacha20poly1305 = "0.10.1"
hkdf = "0.12.4"
sha2 = "0.10.9"
secp256k1 = { version = "0.31", features = ["rand-std"] }

# Push notifications
reqwest = { version = "0.13", features = ["json", "rustls-tls"] }
jsonwebtoken = "10"  # For APNs JWT and FCM OAuth

# Configuration
config = "0.15"
serde = { version = "1.0", features = ["derive"] }
toml = "0.9"

# Logging
tracing = "0.1.44"
tracing-subscriber = { version = "0.3.22", features = ["json", "env-filter"] }

# HTTP server (for health checks)
axum = "0.8"

# Utilities
thiserror = "2"
anyhow = "1.0"
base64 = "0.22"
hex = "0.4.3"
bytes = "1.11"

[dev-dependencies]
tokio-test = "0.4.5"
```

#### 1.3 Configuration System
- [ ] Define configuration schema:
  ```toml
  # config/default.toml

  [server]
  # Server's Nostr private key (hex or nsec)
  private_key = ""

  [relays]
  # ClearNet relays to subscribe to
  clearnet = [
    "wss://relay.damus.io",
    "wss://nos.lol"
  ]

  # Tor/onion relays (requires tor feature)
  onion = []

  # Reconnection settings
  reconnect_interval_secs = 5
  max_reconnect_attempts = 10

  [apns]
  enabled = true
  # Authentication method: "certificate" or "token"
  auth_method = "token"

  # For token auth (.p8 key)
  key_id = ""
  team_id = ""
  private_key_path = ""

  # For certificate auth (.p12)
  certificate_path = ""
  certificate_password = ""

  # Environment: "production" or "sandbox"
  environment = "production"

  [fcm]
  enabled = true
  # Path to service account JSON file
  service_account_path = ""
  # FCM project ID
  project_id = ""

  [health]
  enabled = true
  bind_address = "0.0.0.0:8080"

  [logging]
  # Level: "trace", "debug", "info", "warn", "error", "off"
  level = "info"
  # Format: "json" or "pretty"
  format = "json"
  ```

- [ ] Implement config loading with environment variable overrides
  - Pattern: `TRANSPONDER_<SECTION>_<KEY>` (e.g., `TRANSPONDER_SERVER_PRIVATE_KEY`)

#### 1.4 Logging Infrastructure
- [ ] Set up tracing-subscriber with configurable output
- [ ] Support JSON format for production
- [ ] Support pretty format for development
- [ ] Support disabling logging entirely (`level = "off"`)
- [ ] Add span context for request tracing

#### 1.5 Error Handling
- [ ] Define error types using thiserror:
  ```rust
  #[derive(Debug, thiserror::Error)]
  pub enum Error {
      #[error("Configuration error: {0}")]
      Config(#[from] config::ConfigError),

      #[error("Crypto error: {0}")]
      Crypto(String),

      #[error("Nostr error: {0}")]
      Nostr(#[from] nostr_sdk::client::Error),

      #[error("APNs error: {0}")]
      Apns(String),

      #[error("FCM error: {0}")]
      Fcm(String),

      #[error("Invalid token: {0}")]
      InvalidToken(String),
  }
  ```

---

### Phase 2: Cryptographic Operations

#### 2.1 Token Decryption
- [ ] Implement encrypted token parsing:
  ```rust
  pub struct EncryptedToken {
      ephemeral_pubkey: [u8; 32],  // First 32 bytes
      nonce: [u8; 12],              // Next 12 bytes
      ciphertext: [u8; 236],        // Remaining bytes (220 + 16 auth tag)
  }
  ```

- [ ] Implement ECDH key derivation:
  ```rust
  // shared_x = secp256k1_ecdh(server_privkey, ephemeral_pubkey)
  // prk = HKDF-Extract(salt="mip05-v1", IKM=shared_x)
  // encryption_key = HKDF-Expand(prk, "mip05-token-encryption", 32)
  ```

- [ ] Implement ChaCha20-Poly1305 decryption with empty AAD

- [ ] Implement padded payload parsing:
  ```rust
  pub struct TokenPayload {
      platform: Platform,  // 0x01 = APNs, 0x02 = FCM
      device_token: Vec<u8>,
  }

  pub enum Platform {
      Apns,
      Fcm,
  }
  ```

#### 2.2 NIP-59 Gift Wrap Handling
- [ ] Implement gift wrap (kind 1059) decryption using nostr-sdk
- [ ] Implement seal (kind 13) decryption and signature verification
- [ ] Implement rumor (kind 446) extraction and validation
- [ ] Verify that rumor pubkey matches seal pubkey

#### 2.3 Cryptographic Test Suite
- [ ] Unit tests for ECDH key derivation
- [ ] Unit tests for HKDF with MIP-05 parameters
- [ ] Unit tests for ChaCha20-Poly1305 decryption
- [ ] Unit tests for padded payload parsing
- [ ] Integration tests with test vectors from MIP-05 (if available)
- [ ] Test invalid token handling (malformed, wrong size, auth failure)

---

### Phase 3: Nostr Integration

#### 3.1 Relay Client
- [ ] Initialize nostr-sdk client with server keypair
- [ ] Configure ClearNet relay connections
- [ ] Configure Tor relay connections (nostr-sdk has built-in arti support)
- [ ] Implement connection management with auto-reconnect
- [ ] Handle relay disconnections gracefully

#### 3.2 Event Subscription
- [ ] Subscribe to kind 1059 events with `p` tag matching server pubkey:
  ```rust
  let filter = Filter::new()
      .kind(Kind::GiftWrap)
      .pubkey(server_pubkey)
      .since(Timestamp::now());
  ```

- [ ] Handle incoming events asynchronously
- [ ] Deduplicate events seen from multiple relays

#### 3.3 Kind 10050 Inbox Relay Publication
- [ ] Generate and publish kind 10050 event advertising inbox relays
- [ ] Periodically refresh the kind 10050 event

---

### Phase 4: Push Notification Clients

#### 4.1 APNs Client
- [ ] Implement HTTP/2 client for APNs
- [ ] Support token-based authentication (JWT with .p8 key):
  ```rust
  // JWT Header
  { "alg": "ES256", "kid": "<key_id>" }

  // JWT Claims
  { "iss": "<team_id>", "iat": <timestamp> }
  ```

- [ ] Support certificate-based authentication (.p12)
- [ ] Implement APNs endpoints:
  - Production: `https://api.push.apple.com`
  - Sandbox: `https://api.sandbox.push.apple.com`

- [ ] Construct silent notification payload:
  ```json
  {
    "aps": {
      "content-available": 1
    }
  }
  ```

- [ ] Handle APNs response codes:
  - 200: Success
  - 400: Bad request
  - 403: Auth error
  - 410: Token no longer valid (device unregistered)

- [ ] Implement token caching and refresh for JWT auth

#### 4.2 FCM v1 Client
- [ ] Implement OAuth2 authentication with service account
- [ ] Implement FCM v1 API endpoint:
  ```
  POST https://fcm.googleapis.com/v1/projects/{project_id}/messages:send
  ```

- [ ] Construct silent notification payload:
  ```json
  {
    "message": {
      "token": "<device_token>",
      "android": {
        "priority": "high"
      },
      "data": {
        "content_available": "true"
      }
    }
  }
  ```

- [ ] Handle FCM response codes and error types
- [ ] Implement access token caching and refresh

#### 4.3 Push Dispatcher
- [ ] Route decrypted tokens to appropriate push service based on platform byte
- [ ] Implement concurrent push sending using semaphore-based concurrency control:
  ```rust
  // Limit concurrent outbound requests to avoid overwhelming push services
  let semaphore = Arc::new(Semaphore::new(100));

  for token in tokens {
      let permit = semaphore.clone().acquire_owned().await?;
      let client = self.http_client.clone();

      tokio::spawn(async move {
          // Send push, ignore errors (per spec: silently ignore invalid tokens)
          let _ = send_push(&client, token).await;
          drop(permit);  // Release permit when done
      });
  }
  ```
- [ ] Stateless design: no persistent job queue (aligns with MIP-05 privacy requirements)
- [ ] Silently ignore invalid/expired tokens (per spec)
- [ ] Log push results at debug level (no user-identifying info)

---

### Phase 5: Server Runtime

#### 5.1 Main Event Loop
- [ ] Initialize all components (config, crypto, nostr client, push clients)
- [ ] Start relay subscriptions
- [ ] Process incoming events:
  ```rust
  async fn process_event(&self, event: Event) -> Result<()> {
      // 1. Unwrap gift wrap
      let seal = self.unwrap_gift_wrap(&event)?;

      // 2. Decrypt and verify seal
      let rumor = self.decrypt_seal(&seal)?;

      // 3. Validate kind 446
      if rumor.kind != Kind::Custom(446) {
          return Ok(()); // Silently ignore
      }

      // 4. Parse and decrypt tokens
      let tokens = self.parse_tokens(&rumor.content)?;

      // 5. Dispatch push notifications
      self.dispatch_notifications(tokens).await?;

      Ok(())
  }
  ```

#### 5.2 Health Check Server
- [ ] Implement HTTP server with axum
- [ ] `/health` endpoint - basic liveness check
- [ ] `/ready` endpoint - checks relay connections and push service connectivity
- [ ] Bind to configurable address

#### 5.3 Graceful Shutdown
- [ ] Handle SIGTERM and SIGINT signals
- [ ] Stop accepting new events from relays
- [ ] Wait for in-flight push notifications to complete (with 10-second timeout)
- [ ] Close relay connections cleanly
- [ ] Shutdown health check server

---

### Phase 6: Testing & Quality

#### 6.1 Unit Tests
- [ ] Crypto module tests
- [ ] Config parsing tests
- [ ] Token decryption tests
- [ ] NIP-59 unwrapping tests

#### 6.2 Integration Tests
- [ ] Full event processing flow with mock relays
- [ ] APNs client tests with sandbox
- [ ] FCM client tests with test project

#### 6.3 End-to-End Tests
- [ ] Test with real Nostr relays (testnet)
- [ ] Test ClearNet relay connectivity
- [ ] Test Tor relay connectivity
- [ ] Verify push delivery to test devices

---

### Phase 7: Deployment

#### 7.1 Docker Support
- [ ] Multi-stage Dockerfile:
  ```dockerfile
  # Build stage
  FROM rust:1.75-alpine AS builder
  RUN apk add --no-cache musl-dev openssl-dev
  WORKDIR /app
  COPY . .
  RUN cargo build --release

  # Runtime stage
  FROM alpine:3.19
  RUN apk add --no-cache ca-certificates
  COPY --from=builder /app/target/release/transponder /usr/local/bin/
  COPY config/default.toml /etc/transponder/config.toml
  EXPOSE 8080
  ENTRYPOINT ["transponder"]
  ```

- [ ] docker-compose.yml for local development
- [ ] Volume mounts for config and credentials

#### 7.2 Documentation
- [ ] README with setup instructions
- [ ] Configuration reference
- [ ] Deployment guide
- [ ] Security considerations

---

## Open Questions & Decisions

### Resolved
1. **Crate Type**: Standalone binary
2. **Async Runtime**: Tokio
3. **Configuration**: Config file + environment variable overrides
4. **Logging**: Configurable (JSON/pretty/off) using tracing
5. **Tor Support**: Use nostr-sdk's built-in Tor support (arti)
6. **APNs Auth**: Support both certificate and token-based authentication
7. **FCM API**: FCM v1 API with OAuth2 service account auth
8. **Health Checks**: HTTP endpoint for /health and /ready
9. **Project Name**: transponder

### Resolved (continued)
10. **Metrics**: No Prometheus metrics - health endpoint only
11. **Rate Limiting**: Rely on relay-level spam protection initially; revisit if needed
12. **Event Deduplication Window**: 5 minutes
13. **Concurrent Push Sending**: 100 concurrent outbound requests using semaphore-based concurrency

---

## Security Considerations

### Key Management
- Server private key must be kept secure
- Use environment variables or secrets manager for credentials
- Never log private keys or device tokens

### Network Security
- TLS for all outbound connections
- Verify relay TLS certificates
- Consider running Tor for enhanced privacy

### Operational Security
- Minimal logging (no user-identifying data)
- No persistent storage of tokens
- Regular key rotation for APNs/FCM credentials

### Test Coverage
- Ensure extremely high degree of test coverage using rust test coverage tools

---

## Dependencies Graph

```
Phase 1 (Setup)
    │
    ├──► Phase 2 (Crypto) ──► Phase 3 (Nostr) ──┐
    │                                            │
    └──► Phase 4 (Push) ────────────────────────┼──► Phase 5 (Runtime)
                                                 │
                                                 ▼
                                            Phase 6 (Testing)
                                                 │
                                                 ▼
                                            Phase 7 (Deploy)
```

Phases 2, 3, and 4 can be worked on in parallel after Phase 1 is complete.

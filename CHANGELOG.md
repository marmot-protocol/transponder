# Changelog

## Unreleased

### Added

- Added opt-in, product-neutral APNs `generic_alert` and `mutable_alert` payload modes with configurable title/body copy and optional `apns-collapse-id` coalescing. `mutable_alert` sets Apple's `mutable-content` flag so an iOS Notification Service Extension can replace the fallback alert. Configuration rejects empty alerts, oversized serialized payloads, overlong collapse identifiers, and invalid header values at startup.
- Optional error and panic reporting to a GlitchTip (Sentry-compatible) instance, enabled by setting `glitchtip.dsn` (or `TRANSPONDER_GLITCHTIP_DSN`). Only Transponder's own `ERROR` events and panics are sent, over a self-contained TLS transport (bundled roots, no system CA store dependency); dependency-crate errors and lower log levels are dropped, and Transponder never logs or panics with secret material.

### Fixed

- Drain every admitted push notification before closing the outbound concurrency semaphore during graceful shutdown, preventing a backlogged queue from being silently shed.
- Protect in-flight Marmot Push deduplication reservations from LRU eviction so a waiting relay redelivery cannot re-acquire and dispatch the same trigger concurrently.
- Reject invalid APNs `environment` configuration values at startup instead of silently routing pushes to the sandbox gateway; only `production` and `sandbox` are accepted ([#143](https://github.com/marmot-protocol/transponder/pull/143)).
- Limit each notification event to at most 100 encrypted tokens before base64 decoding, preventing oversized events from forcing unbounded token blob allocation and rate-limit work ([#38](https://github.com/marmot-protocol/transponder/pull/38)).
- Validate configuration at load time so misconfiguration fails loudly at startup with a named-field error instead of silently coercing or detonating later: `server.max_dedup_cache_size`, `server.max_rate_limit_cache_size`, and `server.max_tokens_per_event` now reject `0`; `health.bind_address` must parse as a socket address; `logging.format` accepts only `json`/`pretty` (unknown values, including `off`, are rejected — silence console logs with `logging.level = "off"`); and `relays.onion` entries must be `ws://`/`wss://` URLs with a `.onion` host. Change-detection for the kind-10050 inbox relay list now normalizes URLs through `RelayUrl` and selects the newest event by `created_at`, avoiding spurious republishes.

### Changed

- Updated MIP-05 token handling for the expanded 1084-byte encrypted token format and variable-length APNs/FCM device tokens introduced in [marmot-protocol/mdk#254](https://github.com/marmot-protocol/mdk/pull/254) ([#40](https://github.com/marmot-protocol/transponder/pull/40)).
- Centralized configuration defaults on the serde `default_*` functions as the single source of truth, removing the parallel `set_default` ladder that could silently drift out of sync.

### Security

- Changed `generate-keys` to hide the private key by default, write secrets with `0600` file permissions via `--output`, and require `--show-private-key` for explicit display, addressing marmot-security#77 ([#51](https://github.com/marmot-protocol/transponder/pull/51)).
- Removed the unwrapped notification sender public key from event processing state and trace logs, addressing marmot-security#79.
- Store the server secp256k1 secret key in zeroizing memory and erase temporary `SecretKey` values used during token decryption, addressing the long-term key retention risk reported in marmot-security#24 ([#36](https://github.com/marmot-protocol/transponder/pull/36)).
- Changed the default health server bind address to localhost and documented internal-only exposure for the unauthenticated health, readiness, and metrics endpoints ([#39](https://github.com/marmot-protocol/transponder/pull/39)).
- Redacted FCM service account private keys from debug output and zeroized the service account JSON buffer after loading [#35](https://github.com/marmot-protocol/transponder/pull/35)
- Zeroized the server Nostr private key in config state and shortened the lifetime of resolved key material during startup ([#37](https://github.com/marmot-protocol/transponder/pull/37)).
- Refused to start when the server `private_key_file` grants group or other read access (mode `& 0o077`), mirroring the `0600` the `generate-keys` write path enforces, so an accidentally world-readable key file is rejected instead of loaded silently.
- Kept the inline server private key (`server.private_key` / `TRANSPONDER_SERVER_PRIVATE_KEY`) out of the `config` crate's un-zeroized `Value` tree by resolving it through a dedicated `Zeroizing` path before the rest of the configuration is parsed.

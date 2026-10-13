# Changelog

## 0.2.1 - 2026-10-13

### Added

- Added `relays.tor_data_dir` / `TRANSPONDER_RELAYS_TOR_DATA_DIR` to select a private writable root for Arti's network cache and state. Read-only containers must mount a writable directory owned by the runtime user; keeping this state across restarts preserves Tor guard selection.

### Changed

- Migrated to `nostr-sdk` 0.45.4 and `nostr` 0.45.5 while retaining optional embedded Tor support through a direct Arti 0.47 transport ([#401](https://github.com/marmot-protocol/transponder/pull/401)). Onion connections share a lazily initialized Tor client and wait for bootstrap; failed onion connections never fall back to ClearNet. Build with `--features tor` to enable Tor. Marmot Push v1 wire compatibility is unchanged.
- Vendored a narrowly patched Nostr SDK snapshot to expose its fallible notification receiver, preserving detection and recovery when relay notifications overflow.
- Raised the minimum supported Rust version to 1.95 and updated the Docker builder accordingly ([#392](https://github.com/marmot-protocol/transponder/pull/392)).
- Retired maintenance of the historical MIP-05 line. Existing MIP-05 services and clients should migrate to `marmot-push-v1`; the historical branch and immutable release remain available for reference ([#393](https://github.com/marmot-protocol/transponder/pull/393)).

### Fixed

- Re-subscribe live gift-wrap notifications on relays that require NIP-42 authentication, with relay-local recovery, duplicate-close suppression, and bounded retry backoff ([#387](https://github.com/marmot-protocol/transponder/pull/387)).
- Reuse still-valid provider credentials after transient proactive refresh failures, and scale refresh margins to short credential lifetimes ([#394](https://github.com/marmot-protocol/transponder/pull/394), [#395](https://github.com/marmot-protocol/transponder/pull/395)).
- Preserve configured relay lists when environment overrides contain only empty entries ([#396](https://github.com/marmot-protocol/transponder/pull/396)).
- Preserve file-configured GlitchTip DSNs in Docker Compose unless an explicit environment override is supplied; an explicit blank override disables reporting ([#398](https://github.com/marmot-protocol/transponder/pull/398)).
- Bound configured rates to limit admitted-hit storage growth and clarify shared global rate-limit sizing ([#399](https://github.com/marmot-protocol/transponder/pull/399)).
- Keep push-task panic metrics and capacity gauges accurate when a task unwinds ([#400](https://github.com/marmot-protocol/transponder/pull/400)).
- Pass the Docker Tor build argument into the builder stage, preserving Tor-enabled image builds ([#401](https://github.com/marmot-protocol/transponder/pull/401)).
- Allow coverage checks on fork pull requests to succeed without permission to post a PR comment ([#391](https://github.com/marmot-protocol/transponder/pull/391)).

### Security

- Updated Nostr, TLS, and cache dependencies to address security advisories and restored the dependency audit gate ([#390](https://github.com/marmot-protocol/transponder/pull/390), [#393](https://github.com/marmot-protocol/transponder/pull/393), [#401](https://github.com/marmot-protocol/transponder/pull/401)).
- Preserve relay URL redaction beside bearer credentials in outgoing error reports ([#397](https://github.com/marmot-protocol/transponder/pull/397)).

## 0.2.0 - 2026-07-26

### Added

- Added opt-in, product-neutral APNs `generic_alert` and `mutable_alert` payload modes with configurable title/body copy and optional `apns-collapse-id` coalescing. `mutable_alert` sets Apple's `mutable-content` flag so an iOS Notification Service Extension configured by the app can replace the fallback alert. For enabled APNs configurations, startup validation rejects empty alerts, oversized serialized payloads, overlong collapse identifiers, and invalid header values.
- Optional error and panic reporting to a GlitchTip (Sentry-compatible) instance, enabled by setting `glitchtip.dsn` (or `TRANSPONDER_GLITCHTIP_DSN`). Only Transponder's own `ERROR` events and panics are sent, over a self-contained TLS transport (bundled roots, no system CA store dependency); dependency-crate errors and lower log levels are dropped, and Transponder never logs or panics with secret material.

### Fixed

- Bound each provider's delivery-health failure score so `/ready` recovers after a fixed number of processed requests instead of remaining at 503 in proportion to the duration and traffic volume of a prior outage ([#372](https://github.com/marmot-protocol/transponder/issues/372)).
- Drain every admitted push notification before closing the outbound concurrency semaphore during graceful shutdown, preventing a backlogged queue from being silently shed.
- Protect in-flight Marmot Push deduplication reservations from LRU eviction so a waiting relay redelivery cannot re-acquire and dispatch the same trigger concurrently.
- Made the deduplication reservation lifecycle unwind-safe: the owning task now holds an RAII guard, so a panic (or a task dropped mid-processing) gives the reservation up instead of stranding the content hash in flight forever. Previously such a reservation was never evicted or expired, every later delivery of that content blocked on it permanently while holding an event-processing permit, and enough redeliveries could exhaust the permit pool into a silent notification outage ([#370](https://github.com/marmot-protocol/transponder/issues/370)).
- Reject invalid APNs `environment` configuration values at startup instead of silently routing pushes to the sandbox gateway; only `production` and `sandbox` are accepted ([#143](https://github.com/marmot-protocol/transponder/pull/143)).
- Limit each notification trigger to the adopted Marmot Push v1 maximum of 32 encrypted-token or padding chunks before base64 decoding, reducing the earlier 100-token safety cap so configuration cannot admit protocol-invalid oversized triggers ([#38](https://github.com/marmot-protocol/transponder/pull/38)).
- Validate configuration at load time so misconfiguration fails loudly at startup with a named-field error instead of silently coercing or detonating later: `server.max_dedup_cache_size`, `server.max_rate_limit_cache_size`, and `server.max_tokens_per_event` now reject `0`; `health.bind_address` must parse as a socket address; `logging.format` accepts only `json`/`pretty` (unknown values, including `off`, are rejected — silence console logs with `logging.level = "off"`); and `relays.onion` entries must be `ws://`/`wss://` URLs with a `.onion` host. Change-detection for the kind-10050 inbox relay list now normalizes URLs through `RelayUrl` and selects the newest event by `created_at`, avoiding spurious republishes.

### Changed

- Updated MIP-05 token handling for the expanded 1084-byte encrypted token format and variable-length APNs/FCM device tokens introduced in [marmot-protocol/mdk#254](https://github.com/marmot-protocol/mdk/pull/254) ([#40](https://github.com/marmot-protocol/transponder/pull/40)).
- Centralized configuration defaults on the serde `default_*` functions as the single source of truth, removing the parallel `set_default` ladder that could silently drift out of sync.

### Security

- Redact truncated or unterminated PEM private keys from GlitchTip events by scrubbing from the private-key BEGIN marker through the end of the captured text when no END marker is present ([#376](https://github.com/marmot-protocol/transponder/issues/376)).
- Changed `generate-keys` to hide the private key by default, write secrets with `0600` file permissions via `--output`, and require `--show-private-key` for explicit display, addressing marmot-security#77 ([#51](https://github.com/marmot-protocol/transponder/pull/51)).
- Removed the unwrapped notification sender public key from event processing state and trace logs, addressing marmot-security#79.
- Store the server secp256k1 secret key in zeroizing memory and erase temporary `SecretKey` values used during token decryption, addressing the long-term key retention risk reported in marmot-security#24 ([#36](https://github.com/marmot-protocol/transponder/pull/36)).
- Changed the default health server bind address to localhost and documented internal-only exposure for the unauthenticated health, readiness, and metrics endpoints ([#39](https://github.com/marmot-protocol/transponder/pull/39)).
- Redacted FCM service account private keys from debug output and zeroized the service account JSON buffer after loading [#35](https://github.com/marmot-protocol/transponder/pull/35)
- Zeroized the server Nostr private key in config state and shortened the lifetime of resolved key material during startup ([#37](https://github.com/marmot-protocol/transponder/pull/37)).
- Refused to start when the server `private_key_file` grants group or other read access (mode `& 0o077`), mirroring the `0600` the `generate-keys` write path enforces, so an accidentally world-readable key file is rejected instead of loaded silently.
- Kept the inline server private key (`server.private_key` / `TRANSPONDER_SERVER_PRIVATE_KEY`) out of the `config` crate's un-zeroized `Value` tree by resolving it through a dedicated `Zeroizing` path before the rest of the configuration is parsed.

# Changelog

## Unreleased

### Fixed

- Limit each notification event to at most 100 encrypted tokens before base64 decoding, preventing oversized events from forcing unbounded token blob allocation and rate-limit work ([#38](https://github.com/marmot-protocol/transponder/pull/38)).

### Security

- Changed the default health server bind address to localhost and documented internal-only exposure for the unauthenticated health, readiness, and metrics endpoints ([#39](https://github.com/marmot-protocol/transponder/pull/39)).
- Redacted FCM service account private keys from debug output and zeroized the service account JSON buffer after loading [#35](https://github.com/marmot-protocol/transponder/pull/35)

# Changelog

## Unreleased

### Fixed

- Limit each notification event to at most 100 encrypted tokens before base64 decoding, preventing oversized events from forcing unbounded token blob allocation and rate-limit work ([#38](https://github.com/marmot-protocol/transponder/pull/38)).

### Changed

- Updated MIP-05 token handling for the expanded 1084-byte encrypted token format and variable-length APNs/FCM device tokens introduced in [marmot-protocol/mdk#254](https://github.com/marmot-protocol/mdk/pull/254) ([#40](https://github.com/marmot-protocol/transponder/pull/40)).

### Security

- Store the server secp256k1 secret key in zeroizing memory and erase temporary `SecretKey` values used during token decryption, addressing the long-term key retention risk reported in marmot-security#24 ([#36](https://github.com/marmot-protocol/transponder/pull/36)).
- Changed the default health server bind address to localhost and documented internal-only exposure for the unauthenticated health, readiness, and metrics endpoints ([#39](https://github.com/marmot-protocol/transponder/pull/39)).
- Redacted FCM service account private keys from debug output and zeroized the service account JSON buffer after loading [#35](https://github.com/marmot-protocol/transponder/pull/35)
- Zeroized the server Nostr private key in config state and shortened the lifetime of resolved key material during startup ([#37](https://github.com/marmot-protocol/transponder/pull/37)).

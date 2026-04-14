# Changelog

## Unreleased

### Security

- Store the server secp256k1 secret key in zeroizing memory and erase temporary `SecretKey` values used during token decryption, addressing the long-term key retention risk reported in marmot-security#24 ([#36](https://github.com/marmot-protocol/transponder/pull/36)).
- Changed the default health server bind address to localhost and documented internal-only exposure for the unauthenticated health, readiness, and metrics endpoints ([#39](https://github.com/marmot-protocol/transponder/pull/39)).
- Redacted FCM service account private keys from debug output and zeroized the service account JSON buffer after loading [#35](https://github.com/marmot-protocol/transponder/pull/35)

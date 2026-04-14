# Changelog

All notable changes to this project will be documented in this file.

## Unreleased

### Security

- Changed the default health server bind address to localhost and documented internal-only exposure for the unauthenticated health, readiness, and metrics endpoints ([#39](https://github.com/marmot-protocol/transponder/pull/39)).
- Redacted FCM service account private keys from debug output and zeroized the service account JSON buffer after loading [#35](https://github.com/marmot-protocol/transponder/pull/35)

# Changelog

## Unreleased

### Fixed

- Limit each notification event to at most 100 encrypted tokens before base64 decoding, preventing oversized events from forcing unbounded token blob allocation and rate-limit work.

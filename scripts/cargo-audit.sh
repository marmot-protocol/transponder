#!/usr/bin/env bash
set -euo pipefail

# These ignores are limited to the optional Tor relay dependency path.
# The default Transponder build does not enable the `tor` feature.
#
# RUSTSEC-2023-0071 (`rsa`):
# - The advisory is about private-key timing leakage.
# - Arti's `tor-llcrypto` source notes that Tor clients do not need RSA private keys.
#
# RUSTSEC-2025-0009 / RUSTSEC-2025-0010 (`ring`):
# - These come from `x509-signature` via Arti's rustls runtime compatibility layer.
# - They remain upstream in the optional Tor graph.
#
# RUSTSEC-2024-0384 (`instant`) / RUSTSEC-2024-0436 (`paste`):
# - Unmaintained warnings in the same optional Tor dependency tree.
#
# These ignores cover the nostr-sdk 0.44 line, which the default build uses.
# Every nostr / nostr-relay-pool security advisory against 0.44 is fixed in the
# locked patch releases (nostr >= 0.44.8, nostr-relay-pool >= 0.44.3); only
# informational warnings without a 0.44.x fix remain. nostr-sdk 0.45 folds the
# pool into the SDK but drops the `tor` (Arti) and `nip59` features, so moving
# to it means replacing onion-relay support rather than bumping a version
# (tracked in https://github.com/marmot-protocol/transponder/issues/389).
#
# RUSTSEC-2026-0243 (`nostr-relay-pool`) / RUSTSEC-2026-0237 (`nostr-relay-builder`):
# - Unmaintained warnings; upstream points at nostr-sdk 0.45 (see above).
# - `nostr-relay-builder` is a dev-dependency (`MockRelay` in health tests) only.
#
# RUSTSEC-2026-0253 (`lru` 0.16):
# - Unsound only if a cached key's `Drop` panics and the panic is caught.
# - The 0.16 copy is pinned by `nostr-database`, whose in-memory tracker keys on
#   `EventId` (a plain 32-byte array with no `Drop`).
# - Transponder's own caches use the patched `lru` 0.18 line.
#
# Use `cargo audit` directly if you want the unfiltered raw report.

exec cargo audit \
  --ignore RUSTSEC-2023-0071 \
  --ignore RUSTSEC-2024-0384 \
  --ignore RUSTSEC-2024-0436 \
  --ignore RUSTSEC-2025-0009 \
  --ignore RUSTSEC-2025-0010 \
  --ignore RUSTSEC-2026-0237 \
  --ignore RUSTSEC-2026-0243 \
  --ignore RUSTSEC-2026-0253

#!/usr/bin/env bash
set -euo pipefail

# Remaining exceptions belong to the optional embedded-Arti graph, not the
# default server. Keep the unfiltered report available through just audit-strict.
#
# RUSTSEC-2023-0071 (`rsa`): private-key timing leakage. Arti's tor-llcrypto
# explicitly notes that Tor clients never need RSA private keys; this server
# enables onion-service-client, not onion-service-service.
#
# RUSTSEC-2024-0436 (`paste`): unmaintained macro dependency of Arti.
#
# RUSTSEC-2025-0141 (`bincode`): unmaintained optional dependency of
# typed-index-collections, locked through Arti. Its `bincode` feature is not
# enabled in either server build (cargo tree --features tor -i bincode is empty).
#
# SDK 0.45 and Arti 0.47 remove the retired relay crates, lru 0.16, instant,
# and old ring/x509-signature path; their previous ignores have been removed.

exec cargo audit \
  --ignore RUSTSEC-2023-0071 \
  --ignore RUSTSEC-2024-0436 \
  --ignore RUSTSEC-2025-0141

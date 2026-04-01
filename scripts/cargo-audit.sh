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
# Use `cargo audit` directly if you want the unfiltered raw report.

exec cargo audit \
  --ignore RUSTSEC-2023-0071 \
  --ignore RUSTSEC-2024-0384 \
  --ignore RUSTSEC-2024-0436 \
  --ignore RUSTSEC-2025-0009 \
  --ignore RUSTSEC-2025-0010

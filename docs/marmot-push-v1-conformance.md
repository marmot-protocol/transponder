# Marmot Push v1 Conformance

Transponder 0.2.0 targets the adopted Marmot protocol at commit
[`dedeaf429a6f52a4f1c62f3e992be012dab61b7b`](https://github.com/marmot-protocol/marmot/tree/dedeaf429a6f52a4f1c62f3e992be012dab61b7b).
The normative server surfaces are:

- [`features/push-notifications.md`](https://github.com/marmot-protocol/marmot/blob/dedeaf429a6f52a4f1c62f3e992be012dab61b7b/features/push-notifications.md)
- [`transports/nostr.md`](https://github.com/marmot-protocol/marmot/blob/dedeaf429a6f52a4f1c62f3e992be012dab61b7b/transports/nostr.md)

Client interoperability was checked against MDK commit
[`1d6b9f1d65f8deb897d15a4e300a2443c9179e86`](https://github.com/marmot-protocol/mdk/tree/1d6b9f1d65f8deb897d15a4e300a2443c9179e86),
whose `marmot-app` notification implementation emits the adopted token and rumor formats.

## Implemented Wire Contract

- NIP-59 kind `1059` gift wrap containing a kind `13` seal and unsigned kind `446` rumor
- exactly one rumor tag: `["v", "marmot-push-v1"]`
- RFC 4648 standard padded base64 content, with no encoding tag
- 1 to 32 concatenated chunks, each exactly `1084` decoded bytes and containing either an encrypted token or optional random padding
- ECDH over secp256k1 followed by HKDF-SHA256 with salt `marmot-push-token-v1` and info `marmot-push-token-encryption`
- ChaCha20-Poly1305 token encryption with the fixed-size platform, length, token, and padding plaintext layout
- short-lived in-memory replay suppression keyed by SHA-256 of decoded kind `446` content

## Live-Only Relay Delivery

Push hints are advisory and are not a message-recovery mechanism. Transponder
opens a fresh, unregistered subscription for every relay connection with kind
`1059`, the server public-key tag, the full NIP-59 timestamp-randomization
window, and `limit:0`. Event processing begins only after the matching EOSE.
Stored events returned before EOSE and events from superseded subscription IDs
are ignored.

Consequently, push hints published while Transponder is offline or a relay is
disconnected are intentionally not recovered. Normal Marmot message
synchronization is unaffected: clients still fetch the underlying messages
from their relays after waking or reconnecting. `dedup_retention_secs` remains
solely the short-lived, in-memory decoded-content-hash replay window and does
not control relay subscription history.

## Executable Evidence

The independent test-side encoder in `src/test_vectors.rs` constructs full Marmot Push v1 triggers and NIP-59 envelopes. It is exercised through the event processor and provider mocks. The production decoder is additionally covered by:

- the fixed HKDF vector in `crypto::token::tests::marmot_push_v1_hkdf_conformance_vector`
- positive and negative kind/tag/base64/token-size cases in `crypto::nip59::tests`
- rewrapping and decoded-content-hash replay cases in `nostr::events::processor::tests`
- live-only filter, EOSE admission, reconnect rotation, and mock-relay backlog cases in `nostr::client::tests` and `app::tests`
- end-to-end application startup, dispatch, and shutdown cases in `app::tests`

Run the release gate with:

```bash
just ci
cargo build --release
```

At the pinned MDK commit, the corresponding client-side contract is exercised by:

```bash
cargo test -p marmot-app notifications::tests::
```

That suite covers APNs and FCM token encryption, raw shared-point X-coordinate derivation, the 32-chunk trigger ceiling, concatenated-token base64, and the exact version-only kind `446` rumor inside NIP-59.

MIP-05 is intentionally not accepted by this line. Its historical implementation remains on `release/mip05-v1` and in the immutable `transponder-mip05-v1.0.0` release.

# Marmot Push v1 Conformance

This release candidate targets the adopted Marmot protocol at commit
[`7f2f5fac4b0e8648d820b20d27d670a6c139e717`](https://github.com/marmot-protocol/marmot/tree/7f2f5fac4b0e8648d820b20d27d670a6c139e717).
The normative server surfaces are:

- [`features/push-notifications.md`](https://github.com/marmot-protocol/marmot/blob/7f2f5fac4b0e8648d820b20d27d670a6c139e717/features/push-notifications.md)
- [`transports/nostr.md`](https://github.com/marmot-protocol/marmot/blob/7f2f5fac4b0e8648d820b20d27d670a6c139e717/transports/nostr.md)

Client interoperability was checked against MDK commit
[`479e868f5a58d4b794270ddee498ea69a52d767f`](https://github.com/marmot-protocol/mdk/tree/479e868f5a58d4b794270ddee498ea69a52d767f),
whose `marmot-app` notification implementation emits the adopted token and rumor formats.

## Implemented Wire Contract

- NIP-59 kind `1059` gift wrap containing a kind `13` seal and unsigned kind `446` rumor
- exactly one rumor tag: `["v", "marmot-push-v1"]`
- RFC 4648 standard padded base64 content, with no encoding tag
- one or more concatenated encrypted tokens, each exactly `1084` decoded bytes
- ECDH over secp256k1 followed by HKDF-SHA256 with salt `marmot-push-token-v1` and info `marmot-push-token-encryption`
- ChaCha20-Poly1305 token encryption with the fixed-size platform, length, token, and padding plaintext layout
- short-lived in-memory replay suppression keyed by SHA-256 of decoded kind `446` content

## Executable Evidence

The independent test-side encoder in `src/test_vectors.rs` constructs full Marmot Push v1 triggers and NIP-59 envelopes. It is exercised through the event processor and provider mocks. The production decoder is additionally covered by:

- the fixed HKDF vector in `crypto::token::tests::marmot_push_v1_hkdf_conformance_vector`
- positive and negative kind/tag/base64/token-size cases in `crypto::nip59::tests`
- rewrapping and decoded-content-hash replay cases in `nostr::events::processor::tests`
- end-to-end application startup, dispatch, and shutdown cases in `app::tests`

Run the release-candidate gate with:

```bash
just ci
cargo build --release
```

At the pinned MDK commit, the corresponding client-side contract is exercised by:

```bash
cargo test -p marmot-app notifications::tests::
```

That suite covers APNs and FCM token encryption, raw shared-point X-coordinate derivation, concatenated-token base64, and the exact version-only kind `446` rumor inside NIP-59.

MIP-05 is intentionally not accepted by this line. Its historical implementation remains on `release/mip05-v1` and in the immutable `transponder-mip05-v1.0.0` release.

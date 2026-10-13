# Transponder SDK patch

Source: crates.io `nostr-sdk` 0.45.4, upstream commit
`3140cc74e40f5c1a7b777419e069e2998202f211` in
https://github.com/nostrdevkit/nostr. Upstream MIT license is preserved.

The only Rust source change is the additive
`Client::notification_receiver() -> broadcast::Receiver<ClientNotification>`
method in `src/client/mod.rs`. It returns the same underlying receiver used by
`Client::notifications()` without the stream wrapper that discards `Lagged`.
Transponder must detect notification loss because a lost EOSE or CLOSED message
requires invalidating current subscription IDs and installing new live-only REQs.
All event validation, admission, authentication, and SDK deduplication remain upstream.

Remove this vendored patch when an upstream release provides a notification API
that preserves loss reporting. To upgrade, replace the published source snapshot,
reapply this method, and run the notification-overflow and subscription regression
tests. `Cargo.toml` uses a `[patch.crates-io]` entry so every SDK consumer resolves
to the same source. The root SDK version is pinned exactly so a registry patch
release cannot silently bypass the loss-reporting extension.

//! Mechanical, conservative redaction of secret-shaped substrings.
//!
//! The primary privacy guarantee is discipline at first-party log/error sites
//! ("never log secrets", AGENTS.md) plus the first-party target scope on the
//! GlitchTip tracing path. This module is the mechanical backstop for the one
//! path that discipline provably does not cover: panic payloads originating in
//! dependencies, which Sentry's global hook captures without target scoping
//! (applied in [`crate::telemetry`]'s `scrub_event`).
//!
//! The patterns are deliberately conservative — over-redaction is preferred to
//! leaking — and cover the secret shapes transponder handles:
//!
//! - APNs device-token URL paths (`/3/device/<hex>`)
//! - Nostr bech32 secret keys (`nsec1…`)
//! - `wss://` relay URLs (the host can identify a private relay)
//! - `.onion` hostnames
//! - Long hex runs (64+ chars: device tokens, keys, event ids)

use std::borrow::Cow;
use std::sync::LazyLock;

use regex::Regex;

/// Replacement patterns, applied in order.
///
/// Order matters: the APNs path pattern runs before the generic hex-run
/// pattern so device tokens shorter than 64 hex chars are still caught when
/// they appear in a request URL, and `wss://` runs before `.onion` so an onion
/// relay URL is redacted as a whole.
static REDACTIONS: LazyLock<[(Regex, &'static str); 5]> = LazyLock::new(|| {
    [
        (
            Regex::new(r"(?i)/3/device/[0-9a-f]+").expect("static redaction regex is valid"),
            "/3/device/[REDACTED]",
        ),
        (
            Regex::new(r"(?i)nsec1[0-9a-z]+").expect("static redaction regex is valid"),
            "[REDACTED-NSEC]",
        ),
        (
            Regex::new(r#"(?i)wss://[^\s"']+"#).expect("static redaction regex is valid"),
            "wss://[REDACTED]",
        ),
        (
            Regex::new(r#"(?i)[^\s/:"']+\.onion"#).expect("static redaction regex is valid"),
            "[REDACTED].onion",
        ),
        (
            Regex::new(r"(?i)[0-9a-f]{64,}").expect("static redaction regex is valid"),
            "[REDACTED-HEX]",
        ),
    ]
});

/// Redact secret-shaped substrings from `input`.
///
/// Returns the input untouched (borrowed, no allocation) when no pattern
/// matches — the common case for ordinary error and panic messages.
pub(crate) fn redact(input: &str) -> Cow<'_, str> {
    if !REDACTIONS
        .iter()
        .any(|(pattern, _)| pattern.is_match(input))
    {
        return Cow::Borrowed(input);
    }

    let mut output = input.to_owned();
    for (pattern, replacement) in REDACTIONS.iter() {
        output = pattern.replace_all(&output, *replacement).into_owned();
    }
    Cow::Owned(output)
}

/// Redact secret-shaped substrings in place, leaving clean strings untouched.
pub(crate) fn redact_in_place(value: &mut String) {
    let redacted = match redact(value) {
        Cow::Borrowed(_) => return,
        Cow::Owned(redacted) => redacted,
    };
    *value = redacted;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_runs_of_64_or_more_chars_are_redacted() {
        let token = "a1b2".repeat(16); // 64 hex chars
        let input = format!("delivery failed for token {token} after 3 tries");

        let output = redact(&input);

        assert!(!output.contains(&token));
        assert_eq!(
            output,
            "delivery failed for token [REDACTED-HEX] after 3 tries"
        );
    }

    #[test]
    fn uppercase_hex_runs_are_redacted() {
        let token = "A1B2C3D4".repeat(8); // 64 hex chars
        let output = redact(&token);
        assert_eq!(output, "[REDACTED-HEX]");
    }

    #[test]
    fn short_hex_runs_pass_through() {
        // 63 hex chars: below the conservative threshold, kept verbatim so
        // ordinary ids (short hashes, status codes) stay debuggable.
        let input = format!("request id {}", "f".repeat(63));
        assert_eq!(redact(&input), input.as_str());
    }

    #[test]
    fn apns_device_paths_are_redacted_even_when_the_token_is_short() {
        // 32 hex chars — too short for the generic hex rule; the URL-path rule
        // must catch it on its own.
        let input = "https://api.push.apple.com/3/device/0a1B2c3D4e5F60718293a4b5c6d7e8f9 -> 410";

        let output = redact(input);

        assert!(!output.contains("0a1B2c3D4e5F60718293a4b5c6d7e8f9"));
        assert_eq!(
            output,
            "https://api.push.apple.com/3/device/[REDACTED] -> 410"
        );
    }

    #[test]
    fn wss_relay_urls_are_redacted() {
        let input = "connect to wss://relay.example.com/v1?auth=abc timed out";

        let output = redact(input);

        assert!(!output.contains("relay.example.com"));
        assert_eq!(output, "connect to wss://[REDACTED] timed out");
    }

    #[test]
    fn onion_hostnames_are_redacted() {
        let input = "GET http://vwxyz234abcdefgh.onion/path failed";

        let output = redact(input);

        assert!(!output.contains("vwxyz234abcdefgh"));
        assert_eq!(output, "GET http://[REDACTED].onion/path failed");
    }

    #[test]
    fn nsec_keys_are_redacted() {
        let input = "loaded key nsec1qyfxxqmxq8gcrqvpsxqcrqvpsxqcrqvps from env";

        let output = redact(input);

        assert!(!output.contains("nsec1q"));
        assert_eq!(output, "loaded key [REDACTED-NSEC] from env");
    }

    #[test]
    fn multiple_patterns_in_one_message_are_all_redacted() {
        let token = "ab".repeat(32); // 64 hex chars
        let input =
            format!("panicked: wss://relay.onionhost123456.onion failed; retry token {token}");

        let output = redact(&input);

        assert!(!output.contains("onionhost123456"));
        assert!(!output.contains(&token));
        assert_eq!(
            output,
            "panicked: wss://[REDACTED] failed; retry token [REDACTED-HEX]"
        );
    }

    #[test]
    fn clean_text_is_returned_borrowed_and_unchanged() {
        let input = "connection refused (os error 111) after 2 retries";

        let output = redact(input);

        assert!(matches!(output, Cow::Borrowed(_)));
        assert_eq!(output, input);
    }

    #[test]
    fn redact_in_place_rewrites_only_dirty_strings() {
        let mut dirty = format!("token {}", "0f".repeat(32));
        redact_in_place(&mut dirty);
        assert_eq!(dirty, "token [REDACTED-HEX]");

        let mut clean = String::from("push dispatch failed with status 503");
        redact_in_place(&mut clean);
        assert_eq!(clean, "push dispatch failed with status 503");
    }
}

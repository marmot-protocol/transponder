//! Error and panic reporting to a GlitchTip (Sentry-compatible) instance.
//!
//! Reporting is opt-in: it activates only when a DSN is configured. Transponder's
//! own `ERROR` events are forwarded — first-party only, see `glitchtip_layer` —
//! together with panics, which Sentry's global hook captures from anywhere in the
//! process (not just first-party code). First-party message content is kept clean
//! by the "never log secrets" invariant in AGENTS.md; because the panic hook is
//! not target-scoped, every outgoing event additionally passes through the
//! mechanical redaction backstop in `scrub_event` (see [`crate::redaction`]).

use std::sync::Arc;

use anyhow::{Context, Result};
use sentry::integrations::tracing::EventFilter;
use sentry::protocol::{Context as SentryContext, Value};
use sentry::{Transport, TransportFactory, TransportOptions};
use tracing::{Level, Subscriber};
use tracing_subscriber::Layer;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::registry::LookupSpan;

use crate::config::GlitchtipConfig;
use crate::redaction;

/// Initialize GlitchTip reporting from configuration.
///
/// Returns `Ok(None)` when no DSN is configured, leaving reporting disabled.
/// When a DSN is set, returns a guard that must be held for the lifetime of the
/// process; dropping it flushes any buffered events. A malformed DSN is a hard
/// startup error rather than a silent no-op, so a misconfiguration surfaces
/// immediately instead of quietly dropping telemetry.
pub fn init(config: &GlitchtipConfig) -> Result<Option<sentry::ClientInitGuard>> {
    let dsn = config.dsn.trim();
    if dsn.is_empty() {
        return Ok(None);
    }

    let dsn: sentry::types::Dsn = dsn.parse().context("Invalid GlitchTip DSN")?;

    let guard = sentry::init(sentry::ClientOptions {
        dsn: Some(dsn),
        release: sentry::release_name!(),
        environment: Some(config.environment.clone().into()),
        traces_sample_rate: config.traces_sample_rate,
        // Never attach request/user PII. This is the default; set explicitly so
        // the intent survives future edits.
        send_default_pii: false,
        before_send: Some(Arc::new(scrub_event)),
        // Send over a transport whose TLS trusts the bundled webpki roots, so
        // error reporting does not depend on the runtime image shipping a system
        // CA store — the same posture as the app's own reqwest client.
        transport: Some(Arc::new(GlitchtipTransportFactory)),
        // `default_integrations` stays enabled (via `..Default::default()`); it
        // registers the panic hook that captures panics. Session tracking is
        // deliberately not compiled in — the `release-health` feature is left
        // off in Cargo.toml.
        ..Default::default()
    });

    Ok(Some(guard))
}

/// Sentry transport factory whose HTTP client trusts the bundled webpki roots.
///
/// reqwest 0.13 (sentry's transport client) verifies TLS against the OS trust
/// store by default; on the distroless runtime that store may be absent, which
/// would make GlitchTip delivery fail silently. Injecting a client built with
/// the bundled Mozilla roots keeps reporting self-contained.
struct GlitchtipTransportFactory;

impl TransportFactory for GlitchtipTransportFactory {
    fn create_transport_with_options(&self, options: TransportOptions) -> Arc<dyn Transport> {
        Arc::new(
            sentry::transports::ReqwestHttpTransportOptions::from(options)
                .with_client(glitchtip_http_client())
                .build(),
        )
    }
}

/// Build the GlitchTip HTTP client: rustls with the `ring` provider, trusting
/// only the bundled webpki root certificates (no dependency on a system CA
/// store). The explicit provider keeps this off `aws-lc-rs` and independent of
/// any process-wide default.
fn glitchtip_http_client() -> reqwest13::Client {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let tls_config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("ring provider supports the default TLS protocol versions")
    .with_root_certificates(roots)
    .with_no_client_auth();

    reqwest13::Client::builder()
        .tls_backend_preconfigured(tls_config)
        .build()
        .expect("building the GlitchTip HTTP client should not fail")
}

/// Tracing layer that forwards events to GlitchTip.
///
/// Captures **only** `ERROR` events emitted by transponder's own code; every
/// other level and every dependency-crate event is dropped before it can reach
/// GlitchTip. The target scope is the privacy boundary: dependency errors
/// (`reqwest`, `hyper`, `nostr_sdk`, `tungstenite`, …) routinely embed URLs, and
/// the APNs request URL carries a device token. Restricting capture to the
/// `transponder` target — whose `ERROR` sites are audited to carry no secret
/// material — keeps that data out of the sink.
///
/// The layer is a no-op when no client is initialized, so it is always safe to
/// attach whether or not GlitchTip is configured.
pub(crate) fn glitchtip_layer<S>() -> impl Layer<S>
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    sentry::integrations::tracing::layer()
        .event_filter(|metadata| capture_decision(*metadata.level(), metadata.target()))
        // Independent of the console `EnvFilter`/`RUST_LOG`: only `ERROR` events
        // are ever handed to this layer, and they always are.
        .with_filter(LevelFilter::ERROR)
}

/// The GlitchTip capture policy: forward only first-party `ERROR` events as
/// events; drop everything else. This is the privacy boundary — dependency-crate
/// events and non-error levels never reach the sink. (`glitchtip_layer` also
/// pre-filters to `ERROR` via `with_filter`; this stays self-contained so the
/// policy is correct regardless of that.)
fn capture_decision(level: Level, target: &str) -> EventFilter {
    if level == Level::ERROR && is_first_party_target(target) {
        EventFilter::Event
    } else {
        EventFilter::Ignore
    }
}

/// Whether a tracing target belongs to transponder's own crate.
///
/// This is the privacy boundary for error reporting: only first-party events are
/// forwarded, so dependency-crate messages (which can embed relay URLs or the
/// APNs device-token URL) never reach GlitchTip. Matches the crate root and any
/// of its modules, but not an unrelated crate whose name merely begins with
/// `transponder`.
fn is_first_party_target(target: &str) -> bool {
    target == "transponder" || target.starts_with("transponder::")
}

/// Scrub every outgoing event immediately before it is sent.
///
/// This runs for both tracing-captured errors and panic events, so it is the one
/// choke point that sees everything leaving the process. It drops the hostname
/// (which can reveal deployment topology) and mechanically redacts secret-shaped
/// substrings (see [`crate::redaction`]) from the event message, log-entry
/// fields, exception values, tags, generic contexts, and extra values.
///
/// The redaction is a backstop, not the primary guarantee: first-party sites
/// still must never put secrets in `error!`/`panic!`/`expect`/`unwrap` messages
/// (see AGENTS.md). The backstop exists for the one path that discipline cannot
/// reach — panics raised inside dependencies, which the global panic hook
/// forwards without target scoping.
fn scrub_event(
    mut event: sentry::protocol::Event<'static>,
) -> Option<sentry::protocol::Event<'static>> {
    event.server_name = None;

    if let Some(message) = event.message.as_mut() {
        redaction::redact_in_place(message);
    }

    if let Some(logentry) = event.logentry.as_mut() {
        redaction::redact_in_place(&mut logentry.message);
        for param in &mut logentry.params {
            if let sentry::protocol::Value::String(text) = param {
                redaction::redact_in_place(text);
            }
        }
    }

    for exception in &mut event.exception.values {
        if let Some(value) = exception.value.as_mut() {
            redaction::redact_in_place(value);
        }
    }

    for tag in event.tags.values_mut() {
        redaction::redact_in_place(tag);
    }

    for context in event.contexts.values_mut() {
        redact_context(context);
    }

    for value in event.extra.values_mut() {
        redact_value(value);
    }

    Some(event)
}

fn redact_context(context: &mut SentryContext) {
    if let SentryContext::Other(fields) = context {
        for value in fields.values_mut() {
            redact_value(value);
        }
    }
}

fn redact_value(value: &mut Value) {
    match value {
        Value::String(text) => redaction::redact_in_place(text),
        Value::Array(values) => {
            for value in values {
                redact_value(value);
            }
        }
        Value::Object(fields) => {
            for value in fields.values_mut() {
                redact_value(value);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_with_dsn(dsn: &str) -> GlitchtipConfig {
        GlitchtipConfig {
            dsn: dsn.to_string(),
            environment: "test".to_string(),
            traces_sample_rate: 0.0,
        }
    }

    #[test]
    fn init_is_disabled_without_a_dsn() {
        let guard = init(&config_with_dsn("")).expect("an empty DSN should disable, not error");
        assert!(guard.is_none());
    }

    #[test]
    fn init_treats_a_whitespace_dsn_as_disabled() {
        let guard = init(&config_with_dsn("   \n\t ")).expect("a blank DSN should disable");
        assert!(guard.is_none());
    }

    #[test]
    fn init_rejects_a_malformed_dsn() {
        // `expect_err` is unavailable here: `ClientInitGuard` is not `Debug`, so
        // inspect the error through `.err()` instead.
        let error = init(&config_with_dsn("not-a-valid-dsn"))
            .err()
            .expect("a malformed DSN must fail loudly");
        assert!(error.to_string().contains("Invalid GlitchTip DSN"));
    }

    // `EventFilter` is a bitflags type without `PartialEq`, so compare `.bits()`.
    #[test]
    fn capture_decision_forwards_first_party_errors() {
        let event = EventFilter::Event.bits();
        assert_eq!(capture_decision(Level::ERROR, "transponder").bits(), event);
        assert_eq!(
            capture_decision(Level::ERROR, "transponder::push::retry").bits(),
            event
        );
    }

    #[test]
    fn capture_decision_drops_non_errors_and_third_party() {
        let ignore = EventFilter::Ignore.bits();
        // Lower levels are dropped even from first-party code (they may carry
        // tokens/URLs per AGENTS.md).
        assert_eq!(capture_decision(Level::WARN, "transponder").bits(), ignore);
        assert_eq!(
            capture_decision(Level::INFO, "transponder::nostr::client").bits(),
            ignore
        );
        // Dependency-crate errors never reach the sink, even at ERROR level.
        assert_eq!(capture_decision(Level::ERROR, "reqwest").bits(), ignore);
        assert_eq!(
            capture_decision(Level::ERROR, "hyper::client::conn").bits(),
            ignore
        );
    }

    #[test]
    fn first_party_targets_are_captured() {
        assert!(is_first_party_target("transponder"));
        assert!(is_first_party_target("transponder::push::retry"));
        assert!(is_first_party_target("transponder::nostr::client"));
    }

    #[test]
    fn third_party_and_lookalike_targets_are_excluded() {
        assert!(!is_first_party_target("nostr_sdk"));
        assert!(!is_first_party_target("reqwest"));
        assert!(!is_first_party_target("hyper::client::conn"));
        // A crate whose name merely starts with "transponder" is not first-party.
        assert!(!is_first_party_target("transponderx"));
        assert!(!is_first_party_target("transponder_utils"));
    }

    #[test]
    fn glitchtip_http_client_builds_with_bundled_roots() {
        // Exercises the load-bearing transport path: a rustls config using the
        // `ring` provider + bundled webpki roots, injected into a reqwest client.
        // Hermetic — constructs the client, makes no network call.
        let _client = glitchtip_http_client();
    }

    #[test]
    fn scrub_event_drops_the_server_name() {
        let event = sentry::protocol::Event {
            server_name: Some("internal-host-01".into()),
            ..Default::default()
        };

        let scrubbed = scrub_event(event).expect("the scrubber keeps the event");

        assert!(scrubbed.server_name.is_none());
    }

    #[test]
    fn scrub_event_redacts_a_device_token_url_in_the_message() {
        // The shape of a dependency panic that embeds an APNs request URL.
        let event = sentry::protocol::Event {
            message: Some(
                "request to https://api.push.apple.com/3/device/0a1b2c3d4e5f60718293a4b5c6d7e8f9 \
                 failed"
                    .into(),
            ),
            ..Default::default()
        };

        let scrubbed = scrub_event(event).expect("the scrubber keeps the event");

        let message = scrubbed.message.expect("the message is kept");
        assert!(!message.contains("0a1b2c3d4e5f60718293a4b5c6d7e8f9"));
        assert!(message.contains("/3/device/[REDACTED]"));
    }

    #[test]
    fn scrub_event_redacts_exception_values_and_log_entries() {
        let hex_token = "ab".repeat(32); // 64 hex chars
        let event = sentry::protocol::Event {
            logentry: Some(sentry::protocol::LogEntry {
                message: format!("relay wss://relay.example.com/ws dropped; token {hex_token}"),
                params: vec![
                    sentry::protocol::Value::String("key nsec1qs0v6yz2mwqzzz9".into()),
                    sentry::protocol::Value::from(42),
                ],
            }),
            exception: sentry::protocol::Values {
                values: vec![sentry::protocol::Exception {
                    ty: "panic".into(),
                    value: Some(format!("connect to abcdefgh23456789.onion: {hex_token}")),
                    ..Default::default()
                }],
            },
            ..Default::default()
        };

        let scrubbed = scrub_event(event).expect("the scrubber keeps the event");

        let logentry = scrubbed.logentry.expect("the log entry is kept");
        assert!(!logentry.message.contains("relay.example.com"));
        assert!(!logentry.message.contains(&hex_token));
        assert!(logentry.message.contains("wss://[REDACTED]"));
        assert_eq!(
            logentry.params[0],
            sentry::protocol::Value::String("key [REDACTED-NSEC]".into())
        );
        // Non-string params pass through untouched.
        assert_eq!(logentry.params[1], sentry::protocol::Value::from(42));

        let exception = &scrubbed.exception.values[0];
        let value = exception.value.as_deref().expect("the value is kept");
        assert!(!value.contains("abcdefgh23456789"));
        assert!(!value.contains(&hex_token));
        assert!(value.contains("[REDACTED].onion"));
        assert!(value.contains("[REDACTED-HEX]"));
    }

    #[test]
    fn scrub_event_redacts_structured_tags_contexts_and_extra_values() {
        let mut context_fields = sentry::protocol::Map::new();
        context_fields.insert(
            "relay".to_string(),
            sentry::protocol::Value::String("wss://secretrelay23456789.onion".into()),
        );
        context_fields.insert(
            "nested".to_string(),
            sentry::protocol::Value::Array(vec![sentry::protocol::Value::Object({
                let mut fields = sentry::protocol::value::Map::new();
                fields.insert(
                    "key".to_string(),
                    sentry::protocol::Value::String("nsec1qs0v6yz2mwqzzz9".into()),
                );
                fields
            })]),
        );

        let mut extra = sentry::protocol::Map::new();
        extra.insert(
            "transport".to_string(),
            sentry::protocol::Value::String(
                "https://api.push.apple.com/3/device/0a1b2c3d4e5f60718293a4b5c6d7e8f9".into(),
            ),
        );

        let event = sentry::protocol::Event {
            tags: sentry::protocol::Map::from_iter([(
                "relay".to_string(),
                "wss://tagrelay23456789.onion".to_string(),
            )]),
            contexts: sentry::protocol::Map::from_iter([(
                "Rust Tracing Fields".to_string(),
                sentry::protocol::Context::Other(context_fields),
            )]),
            extra,
            ..Default::default()
        };

        let scrubbed = scrub_event(event).expect("the scrubber keeps the event");

        let tag = scrubbed.tags.get("relay").expect("the tag is kept");
        assert_eq!(tag, "wss://[REDACTED]");

        let sentry::protocol::Context::Other(fields) = scrubbed
            .contexts
            .get("Rust Tracing Fields")
            .expect("the context is kept")
        else {
            panic!("structured tracing fields should stay in an Other context");
        };
        assert_eq!(
            fields.get("relay"),
            Some(&sentry::protocol::Value::String("wss://[REDACTED]".into()))
        );
        let nested = fields
            .get("nested")
            .expect("the nested context value is kept");
        assert_eq!(
            nested,
            &sentry::protocol::Value::Array(vec![sentry::protocol::Value::Object({
                let mut fields = sentry::protocol::value::Map::new();
                fields.insert(
                    "key".to_string(),
                    sentry::protocol::Value::String("[REDACTED-NSEC]".into()),
                );
                fields
            })])
        );

        let extra_value = scrubbed
            .extra
            .get("transport")
            .expect("the extra value is kept");
        assert_eq!(
            extra_value,
            &sentry::protocol::Value::String(
                "https://api.push.apple.com/3/device/[REDACTED]".into()
            )
        );
    }

    #[test]
    fn scrub_event_leaves_clean_messages_untouched() {
        let event = sentry::protocol::Event {
            message: Some("push dispatch failed with status 503".into()),
            exception: sentry::protocol::Values {
                values: vec![sentry::protocol::Exception {
                    ty: "panic".into(),
                    value: Some("index out of bounds: the len is 3".into()),
                    ..Default::default()
                }],
            },
            ..Default::default()
        };

        let scrubbed = scrub_event(event).expect("the scrubber keeps the event");

        assert_eq!(
            scrubbed.message.as_deref(),
            Some("push dispatch failed with status 503")
        );
        assert_eq!(
            scrubbed.exception.values[0].value.as_deref(),
            Some("index out of bounds: the len is 3")
        );
    }
}

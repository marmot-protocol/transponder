//! Health check HTTP server.
//!
//! Provides `/health` (liveness) and `/ready` (readiness) endpoints, plus the
//! Prometheus `/metrics` endpoint.
//!
//! `/metrics` availability is governed by `metrics.enabled`, independent of
//! `health.enabled`: disabling the health endpoints does not silence the
//! metrics endpoint (both share the `health.bind_address` listener). The
//! listener is hardened with a per-request timeout, a request-body cap, and a
//! metrics-route concurrency limit. It must stay loopback-bound or behind an
//! access-controlled proxy that enforces connection and header-read timeouts:
//! all routes are unauthenticated, and tower request layers do not cover idle
//! connections that have not completed their headers.

use std::sync::Arc;
use std::time::Duration;

use axum::{Json, Router, extract::State, http::StatusCode, response::IntoResponse, routing::get};
use prometheus::{Encoder, TextEncoder};
use serde::Serialize;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tower::limit::GlobalConcurrencyLimitLayer;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::timeout::TimeoutLayer;
use tracing::{error, info, warn};

use crate::config::HealthConfig;
use crate::error::Result;
use crate::metrics::Metrics;
use crate::nostr::client::RelayClient;
use crate::push::PushDispatcher;

/// Per-request timeout for the health/metrics listener.
///
/// Bounds slow-request (slowloris-style) holds on the unauthenticated port; a
/// few seconds is generous for handlers that do only cached reads and a
/// registry gather/encode.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// Maximum accepted request-body size.
///
/// None of the health/metrics endpoints take a request body, so anything
/// beyond a trivial allowance is rejected with `413 Payload Too Large`.
const MAX_REQUEST_BODY_BYTES: usize = 1024;

/// Maximum concurrently processed metrics requests.
///
/// Scrapes are isolated from health probes so registry-rendering load cannot
/// starve liveness/readiness and cause self-inflicted restarts.
const MAX_CONCURRENT_REQUESTS: usize = 32;

/// Health check response.
#[derive(Debug, Serialize)]
#[cfg_attr(test, derive(serde::Deserialize))]
struct HealthResponse {
    status: String,
}

/// Readiness check response.
#[derive(Debug, Serialize)]
#[cfg_attr(test, derive(serde::Deserialize))]
struct ReadyResponse {
    status: String,
    relays_connected: bool,
    apns_configured: bool,
    fcm_configured: bool,
    apns_delivering: bool,
    fcm_delivering: bool,
}

/// Shared state for health check handlers.
struct HealthState {
    relay_client: Arc<RelayClient>,
    push_dispatcher: Arc<PushDispatcher>,
    metrics: Metrics,
}

/// Health check HTTP server.
pub struct HealthServer {
    config: HealthConfig,
    relay_client: Arc<RelayClient>,
    push_dispatcher: Arc<PushDispatcher>,
    metrics: Metrics,
}

impl HealthServer {
    /// Create a new health server.
    pub fn new(
        config: HealthConfig,
        relay_client: Arc<RelayClient>,
        push_dispatcher: Arc<PushDispatcher>,
        metrics: Metrics,
    ) -> Self {
        Self {
            config,
            relay_client,
            push_dispatcher,
            metrics,
        }
    }

    /// Bind the health server listener, or return `None` when nothing is
    /// served.
    ///
    /// Binding is split from [`Self::serve`] so startup can fail fast on a
    /// bind failure — almost always a permanent misconfiguration (port in
    /// use, bad `health.bind_address`) — instead of running indefinitely
    /// with dead `/health`, `/ready`, and `/metrics` endpoints.
    ///
    /// A listener is bound when the health endpoints are enabled OR a metrics
    /// collector exists: `/metrics` availability follows `metrics.enabled`,
    /// independent of `health.enabled`, so disabling the health endpoints
    /// cannot silently strand a running collector without a scrape endpoint.
    /// Only when both are disabled is nothing bound.
    pub async fn bind(&self) -> Result<Option<TcpListener>> {
        let serve_health = self.config.enabled;
        let serve_metrics = self.metrics.is_enabled();

        if !serve_health && !serve_metrics {
            info!("Health server and metrics disabled; not binding a listener");
            return Ok(None);
        }

        if !serve_health {
            warn!(
                address = %self.config.bind_address,
                "Health endpoints disabled but metrics are enabled; serving only /metrics"
            );
        }

        let listener = TcpListener::bind(&self.config.bind_address)
            .await
            .map_err(|e| {
                std::io::Error::new(
                    e.kind(),
                    format!(
                        "Failed to bind health server to '{}': {}",
                        self.config.bind_address, e
                    ),
                )
            })?;
        info!(address = %self.config.bind_address, "Health server listening");

        Ok(Some(listener))
    }

    /// Serve on a previously bound listener until shutdown is signaled.
    ///
    /// A `None` listener means both the health endpoints and metrics are
    /// disabled; the task then just waits for the shutdown signal so its exit
    /// is always an expected, supervised event.
    ///
    /// Routes are mounted by flag: `/health` + `/ready` when `health.enabled`,
    /// `/metrics` whenever a metrics collector exists (see [`Self::bind`]).
    pub async fn serve(
        &self,
        listener: Option<TcpListener>,
        mut shutdown: watch::Receiver<bool>,
    ) -> Result<()> {
        let Some(listener) = listener else {
            // Nothing to serve: wait for shutdown.
            let _ = shutdown.changed().await;
            return Ok(());
        };

        let state = Arc::new(HealthState {
            relay_client: self.relay_client.clone(),
            push_dispatcher: self.push_dispatcher.clone(),
            metrics: self.metrics.clone(),
        });

        let mut router = Router::new();
        if self.config.enabled {
            router = router
                .route("/health", get(health_handler))
                .route("/ready", get(ready_handler));
        }
        if self.metrics.is_enabled() {
            router = router.route(
                "/metrics",
                get(metrics_handler)
                    .layer(GlobalConcurrencyLimitLayer::new(MAX_CONCURRENT_REQUESTS)),
            );
        }

        // Hardening layers: bound how long any request may run, reject
        // request bodies (these endpoints take none), and cap concurrent
        // in-flight requests on this unauthenticated listener. axum applies
        // the last-added layer outermost, so requests flow
        // timeout -> body limit -> concurrency cap -> route.
        let app = router
            .layer(RequestBodyLimitLayer::new(MAX_REQUEST_BODY_BYTES))
            .layer(TimeoutLayer::with_status_code(
                StatusCode::REQUEST_TIMEOUT,
                REQUEST_TIMEOUT,
            ))
            .with_state(state);

        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = shutdown.changed().await;
                info!("Health server shutting down");
            })
            .await?;

        Ok(())
    }

    /// Run the health server until shutdown is signaled.
    ///
    /// Test-only convenience combining [`Self::bind`] and [`Self::serve`];
    /// production startup calls them separately so a bind failure aborts
    /// startup before any relay work begins.
    #[cfg(test)]
    pub async fn run(&self, shutdown: watch::Receiver<bool>) -> Result<()> {
        let listener = self.bind().await?;
        self.serve(listener, shutdown).await
    }
}

/// Liveness check handler.
async fn health_handler() -> impl IntoResponse {
    Json(HealthResponse {
        status: "ok".to_string(),
    })
}

/// Readiness check handler.
///
/// `/ready` reports whether this process can currently deliver notifications.
/// It returns `200` only when ALL of the following hold:
///
/// 1. **Relays connected** — at least one relay connection, read from the
///    cached status snapshot maintained by the background status refresher
///    (and by startup polling). The probe itself is side-effect-free: it
///    performs no relay-pool enumeration, takes no write locks, and rewrites
///    no gauges.
/// 2. **Push configured** — at least one push provider (APNs/FCM) is
///    configured.
/// 3. **Providers delivering** — at least one configured provider has a healthy
///    delivery score. A single-provider outage does not depool a dual-provider
///    instance that can still deliver the other platform. This signal is
///    passive: it is derived from real send outcomes and never probes the
///    providers, so a revoked APNs key or expired FCM service account flips
///    readiness once the failure streak is observed on live traffic.
///
/// Not reflected: per-relay coverage (a single connected relay of many is
/// still "connected"), push-queue saturation, and delivery latency. With no
/// push traffic, the delivery-health signal retains its last observed state.
async fn ready_handler(State(state): State<Arc<HealthState>>) -> impl IntoResponse {
    let relays_connected = state.relay_client.is_connected().await;
    let apns_configured = state.push_dispatcher.has_apns();
    let fcm_configured = state.push_dispatcher.has_fcm();
    let apns_delivering = apns_configured && state.push_dispatcher.is_apns_delivering();
    let fcm_delivering = fcm_configured && state.push_dispatcher.is_fcm_delivering();

    let push_configured = apns_configured || fcm_configured;
    let providers_delivering = apns_delivering || fcm_delivering;

    let is_ready = relays_connected && push_configured && providers_delivering;

    let response = ReadyResponse {
        status: if is_ready { "ready" } else { "not_ready" }.to_string(),
        relays_connected,
        apns_configured,
        fcm_configured,
        apns_delivering,
        fcm_delivering,
    };

    if is_ready {
        (StatusCode::OK, Json(response))
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, Json(response))
    }
}

/// Prometheus metrics handler.
async fn metrics_handler(State(state): State<Arc<HealthState>>) -> impl IntoResponse {
    if !state.metrics.is_enabled() {
        return (
            StatusCode::NOT_FOUND,
            [("content-type", "text/plain")],
            vec![],
        );
    }

    let metric_families = state.metrics.gather();
    let encoder = TextEncoder::new();
    let mut buffer = vec![];

    if let Err(e) = encoder.encode(&metric_families, &mut buffer) {
        error!(error = %e, "Failed to encode metrics");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            [("content-type", "text/plain")],
            b"Failed to encode metrics".to_vec(),
        );
    }

    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4")],
        buffer,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RelayConfig;
    use nostr_sdk::prelude::*;
    use std::time::Duration;

    async fn wait_for_server_response(client: &reqwest::Client, url: String) -> reqwest::Response {
        for _ in 0..50 {
            match client.get(&url).send().await {
                Ok(response) => return response,
                Err(error) if error.is_connect() => {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                Err(error) => panic!("request to health test server failed: {error}"),
            }
        }

        panic!("health test server did not accept connections at {url}");
    }

    #[tokio::test]
    #[should_panic(expected = "health test server did not accept connections")]
    async fn wait_for_server_response_times_out_if_server_never_starts() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let client = reqwest::Client::new();
        let _ = wait_for_server_response(&client, format!("http://{addr}/health")).await;
    }

    async fn test_health_server(config: HealthConfig) -> HealthServer {
        let keys = Keys::generate();
        let relay_config = RelayConfig {
            clearnet: vec![],
            allow_unencrypted_clearnet_relays: true,
            onion: vec![],
            reconnect_interval_secs: 5,
            max_reconnect_attempts: 10,
            connection_timeout_secs: 5,
        };

        let relay_client = Arc::new(RelayClient::new(keys, relay_config).await.unwrap());
        let push_dispatcher = Arc::new(PushDispatcher::new(None, None));
        HealthServer::new(config, relay_client, push_dispatcher, Metrics::disabled())
    }

    #[tokio::test]
    async fn bind_returns_none_when_disabled() {
        let server = test_health_server(HealthConfig {
            enabled: false,
            bind_address: "127.0.0.1:0".to_string(),
        })
        .await;

        let listener = server.bind().await.unwrap();

        assert!(listener.is_none());
    }

    #[tokio::test]
    async fn bind_returns_listener_on_the_configured_address() {
        let server = test_health_server(HealthConfig {
            enabled: true,
            bind_address: "127.0.0.1:0".to_string(),
        })
        .await;

        let listener = server.bind().await.unwrap();

        let listener = listener.expect("enabled health server must bind a listener");
        assert!(listener.local_addr().unwrap().ip().is_loopback());
    }

    #[tokio::test]
    async fn bind_fails_fast_when_the_port_is_taken() {
        // Occupy a port, then ask the health server to bind the same one.
        let occupied = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = occupied.local_addr().unwrap();

        let server = test_health_server(HealthConfig {
            enabled: true,
            bind_address: addr.to_string(),
        })
        .await;

        let error = server
            .bind()
            .await
            .expect_err("binding an occupied port must fail");

        assert!(
            error.to_string().contains("Failed to bind health server"),
            "error should carry bind context, got: {error}"
        );
    }

    #[tokio::test]
    async fn serve_without_listener_waits_for_shutdown() {
        let server = test_health_server(HealthConfig {
            enabled: false,
            bind_address: "127.0.0.1:0".to_string(),
        })
        .await;

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let serve = server.serve(None, shutdown_rx);
        tokio::pin!(serve);

        // Still parked while no shutdown has been signaled.
        let pending = tokio::time::timeout(Duration::from_millis(10), &mut serve).await;
        assert!(pending.is_err());

        shutdown_tx.send(true).unwrap();

        let result = tokio::time::timeout(Duration::from_secs(1), &mut serve)
            .await
            .expect("disabled health task must exit on shutdown");
        assert!(result.is_ok());
    }

    #[test]
    fn test_health_response_serialization() {
        let response = HealthResponse {
            status: "ok".to_string(),
        };
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("ok"));
    }

    #[test]
    fn test_ready_response_serialization() {
        let response = ReadyResponse {
            status: "ready".to_string(),
            relays_connected: true,
            apns_configured: true,
            fcm_configured: false,
            apns_delivering: true,
            fcm_delivering: true,
        };
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("ready"));
        assert!(json.contains("relays_connected"));
        assert!(json.contains("apns_delivering"));
        assert!(json.contains("fcm_delivering"));
    }

    #[tokio::test]
    async fn test_health_endpoint() {
        use nostr_relay_builder::MockRelay;

        // Start mock relay
        let mock = MockRelay::run().await.unwrap();
        let relay_url = mock.url().await;

        let keys = Keys::generate();
        let relay_config = RelayConfig {
            clearnet: vec![relay_url.to_string()],
            allow_unencrypted_clearnet_relays: true,
            onion: vec![],
            reconnect_interval_secs: 5,
            max_reconnect_attempts: 10,
            connection_timeout_secs: 5,
        };

        let relay_client = Arc::new(RelayClient::new(keys, relay_config).await.unwrap());
        let push_dispatcher = Arc::new(PushDispatcher::new(None, None));

        // Find a free port
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let config = HealthConfig {
            enabled: true,
            bind_address: addr.to_string(),
        };

        let server = HealthServer::new(config, relay_client, push_dispatcher, Metrics::disabled());

        // Create shutdown channel
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        // Spawn server
        let server_handle = tokio::spawn(async move { server.run(shutdown_rx).await });

        let client = reqwest::Client::new();
        let response = wait_for_server_response(&client, format!("http://{}/health", addr)).await;

        assert_eq!(response.status(), 200);
        let body: HealthResponse = response.json().await.unwrap();
        assert_eq!(body.status, "ok");

        // Shutdown
        shutdown_tx.send(true).unwrap();
        let _ = tokio::time::timeout(Duration::from_secs(2), server_handle).await;
    }

    #[tokio::test]
    async fn test_ready_endpoint_not_ready() {
        use nostr_relay_builder::MockRelay;

        // Start mock relay
        let mock = MockRelay::run().await.unwrap();
        let relay_url = mock.url().await;

        let keys = Keys::generate();
        let relay_config = RelayConfig {
            clearnet: vec![relay_url.to_string()],
            allow_unencrypted_clearnet_relays: true,
            onion: vec![],
            reconnect_interval_secs: 5,
            max_reconnect_attempts: 10,
            connection_timeout_secs: 5,
        };

        // Client not connected, no push services
        let relay_client = Arc::new(RelayClient::new(keys, relay_config).await.unwrap());
        let push_dispatcher = Arc::new(PushDispatcher::new(None, None));

        // Find a free port
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let config = HealthConfig {
            enabled: true,
            bind_address: addr.to_string(),
        };

        let server = HealthServer::new(config, relay_client, push_dispatcher, Metrics::disabled());

        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let server_handle = tokio::spawn(async move { server.run(shutdown_rx).await });

        let client = reqwest::Client::new();
        let response = wait_for_server_response(&client, format!("http://{}/ready", addr)).await;

        // Should be 503 because no relays connected and no push services
        assert_eq!(response.status(), 503);
        let body: ReadyResponse = response.json().await.unwrap();
        assert_eq!(body.status, "not_ready");
        assert!(!body.relays_connected);
        assert!(!body.apns_configured);
        assert!(!body.fcm_configured);
        assert!(!body.apns_delivering);
        assert!(!body.fcm_delivering);

        shutdown_tx.send(true).unwrap();
        let _ = tokio::time::timeout(Duration::from_secs(2), server_handle).await;
    }

    #[tokio::test]
    async fn test_server_disabled() {
        use nostr_relay_builder::MockRelay;

        let mock = MockRelay::run().await.unwrap();
        let relay_url = mock.url().await;

        let keys = Keys::generate();
        let relay_config = RelayConfig {
            clearnet: vec![relay_url.to_string()],
            allow_unencrypted_clearnet_relays: true,
            onion: vec![],
            reconnect_interval_secs: 5,
            max_reconnect_attempts: 10,
            connection_timeout_secs: 5,
        };

        let relay_client = Arc::new(RelayClient::new(keys, relay_config).await.unwrap());
        let push_dispatcher = Arc::new(PushDispatcher::new(None, None));

        let config = HealthConfig {
            enabled: false, // Disabled
            bind_address: "127.0.0.1:0".to_string(),
        };

        let server = HealthServer::new(config, relay_client, push_dispatcher, Metrics::disabled());

        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let server_handle = tokio::spawn(async move { server.run(shutdown_rx).await });

        // Server should just wait for shutdown when disabled
        tokio::time::sleep(Duration::from_millis(50)).await;
        shutdown_tx.send(true).unwrap();

        let result = tokio::time::timeout(Duration::from_secs(2), server_handle)
            .await
            .expect("Server should complete")
            .expect("Server task should not panic");

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_bind_error_contains_address() {
        use nostr_relay_builder::MockRelay;

        let mock = MockRelay::run().await.unwrap();
        let relay_url = mock.url().await;

        let keys = Keys::generate();
        let relay_config = RelayConfig {
            clearnet: vec![relay_url.to_string()],
            allow_unencrypted_clearnet_relays: true,
            onion: vec![],
            reconnect_interval_secs: 5,
            max_reconnect_attempts: 10,
            connection_timeout_secs: 5,
        };

        let relay_client = Arc::new(RelayClient::new(keys, relay_config).await.unwrap());
        let push_dispatcher = Arc::new(PushDispatcher::new(None, None));

        // Use an invalid bind address to trigger an error
        let invalid_address = "999.999.999.999:9999";
        let config = HealthConfig {
            enabled: true,
            bind_address: invalid_address.to_string(),
        };

        let server = HealthServer::new(config, relay_client, push_dispatcher, Metrics::disabled());

        let (_shutdown_tx, shutdown_rx) = watch::channel(false);

        let result = server.run(shutdown_rx).await;

        assert!(result.is_err());
        let error_message = result.unwrap_err().to_string();
        assert!(
            error_message.contains(invalid_address),
            "Error message '{}' should contain the bind address '{}'",
            error_message,
            invalid_address
        );
        assert!(
            error_message.contains("Failed to bind health server"),
            "Error message '{}' should contain context about the health server",
            error_message
        );
    }

    #[tokio::test]
    async fn test_metrics_endpoint() {
        use crate::metrics::Metrics;

        let keys = Keys::generate();
        let relay_config = RelayConfig {
            clearnet: vec![],
            allow_unencrypted_clearnet_relays: false,
            onion: vec![],
            reconnect_interval_secs: 5,
            max_reconnect_attempts: 1,
            connection_timeout_secs: 1,
        };
        let relay_client = Arc::new(RelayClient::new(keys, relay_config).await.unwrap());
        let push_dispatcher = Arc::new(PushDispatcher::new(None, None));
        let metrics = Metrics::new().unwrap();
        metrics.init_server_info("0.0.0");
        let metrics = metrics;

        // Find a free port
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let config = HealthConfig {
            enabled: true,
            bind_address: addr.to_string(),
        };

        let server = HealthServer::new(config, relay_client, push_dispatcher, metrics);

        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let server_task = tokio::spawn(async move {
            server.run(shutdown_rx).await.unwrap();
        });

        let client = reqwest::Client::new();
        let response = wait_for_server_response(&client, format!("http://{}/metrics", addr)).await;

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.text().await.unwrap();
        assert!(body.contains("transponder_server_info"));

        // Shutdown
        let _ = shutdown_tx.send(true);
        let _ = server_task.await;
    }

    #[tokio::test]
    async fn test_metrics_endpoint_disabled() {
        let keys = Keys::generate();
        let relay_config = RelayConfig {
            clearnet: vec![],
            allow_unencrypted_clearnet_relays: false,
            onion: vec![],
            reconnect_interval_secs: 5,
            max_reconnect_attempts: 1,
            connection_timeout_secs: 1,
        };
        let relay_client = Arc::new(RelayClient::new(keys, relay_config).await.unwrap());
        let push_dispatcher = Arc::new(PushDispatcher::new(None, None));
        let metrics = Metrics::disabled();

        // Find a free port
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let config = HealthConfig {
            enabled: true,
            bind_address: addr.to_string(),
        };

        let server = HealthServer::new(config, relay_client, push_dispatcher, metrics);

        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let server_task = tokio::spawn(async move {
            server.run(shutdown_rx).await.unwrap();
        });

        let client = reqwest::Client::new();
        let response = wait_for_server_response(&client, format!("http://{}/metrics", addr)).await;

        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        // Shutdown
        let _ = shutdown_tx.send(true);
        let _ = server_task.await;
    }

    #[tokio::test]
    async fn test_ready_endpoint_ready() {
        use crate::config::ApnsConfig;
        use crate::push::ApnsClient;
        use nostr_relay_builder::MockRelay;

        // Start mock relay
        let mock = MockRelay::run().await.unwrap();
        let relay_url = mock.url().await;

        let keys = Keys::generate();
        let relay_config = RelayConfig {
            clearnet: vec![relay_url.to_string()],
            allow_unencrypted_clearnet_relays: true,
            onion: vec![],
            reconnect_interval_secs: 5,
            max_reconnect_attempts: 10,
            connection_timeout_secs: 5,
        };

        // Create relay client and connect it
        let relay_client = Arc::new(RelayClient::new(keys, relay_config).await.unwrap());
        // Connect to the relay so is_connected() returns true
        relay_client.connect().await.unwrap();

        // Create mock APNs client that is configured
        let apns_config = ApnsConfig {
            enabled: true,
            key_id: "KEY123".to_string(),
            team_id: "TEAM456".to_string(),
            private_key_path: String::new(),
            environment: crate::config::ApnsEnvironment::Sandbox,
            bundle_id: "com.example.app".to_string(),
            payload_mode: Default::default(),
            alert_title: String::new(),
            alert_body: String::new(),
            collapse_id: String::new(),
        };
        let apns_client = ApnsClient::mock(apns_config, true);
        let push_dispatcher = Arc::new(PushDispatcher::new(Some(apns_client), None));

        // Find a free port
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let config = HealthConfig {
            enabled: true,
            bind_address: addr.to_string(),
        };

        let server = HealthServer::new(config, relay_client, push_dispatcher, Metrics::disabled());

        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let server_handle = tokio::spawn(async move { server.run(shutdown_rx).await });

        let client = reqwest::Client::new();
        let response = wait_for_server_response(&client, format!("http://{}/ready", addr)).await;

        // Should be 200 OK because relays are connected, APNs is configured,
        // and no delivery-failure streak has been observed.
        assert_eq!(response.status(), 200);
        let body: ReadyResponse = response.json().await.unwrap();
        assert_eq!(body.status, "ready");
        assert!(body.relays_connected);
        assert!(body.apns_configured);
        assert!(!body.fcm_configured);
        assert!(body.apns_delivering);
        assert!(!body.fcm_delivering);

        shutdown_tx.send(true).unwrap();
        let _ = tokio::time::timeout(Duration::from_secs(2), server_handle).await;
    }

    #[tokio::test]
    async fn test_ready_stays_ready_when_one_of_two_providers_stops_delivering() {
        use crate::config::{ApnsConfig, FcmConfig};
        use crate::crypto::Platform;
        use crate::push::dispatcher::DELIVERY_FAILURE_STREAK_THRESHOLD;
        use crate::push::{ApnsClient, FcmClient};
        use nostr_relay_builder::MockRelay;

        let mock = MockRelay::run().await.unwrap();
        let relay_url = mock.url().await;

        let keys = Keys::generate();
        let relay_config = RelayConfig {
            clearnet: vec![relay_url.to_string()],
            allow_unencrypted_clearnet_relays: true,
            onion: vec![],
            reconnect_interval_secs: 5,
            max_reconnect_attempts: 10,
            connection_timeout_secs: 5,
        };

        let relay_client = Arc::new(RelayClient::new(keys, relay_config).await.unwrap());
        relay_client.connect().await.unwrap();

        let apns_config = ApnsConfig {
            enabled: true,
            key_id: "KEY123".to_string(),
            team_id: "TEAM456".to_string(),
            private_key_path: String::new(),
            environment: crate::config::ApnsEnvironment::Sandbox,
            bundle_id: "com.example.app".to_string(),
            payload_mode: Default::default(),
            alert_title: String::new(),
            alert_body: String::new(),
            collapse_id: String::new(),
        };
        let apns_client = ApnsClient::mock(apns_config, true);
        let fcm_client = FcmClient::mock(
            FcmConfig {
                enabled: true,
                service_account_path: String::new(),
                project_id: "test-project".to_string(),
            },
            true,
        );
        let push_dispatcher = Arc::new(PushDispatcher::new(Some(apns_client), Some(fcm_client)));

        // Simulate a sustained hard-failure streak (e.g. a revoked APNs key
        // rejecting every send) as the dispatcher would record it.
        for _ in 0..DELIVERY_FAILURE_STREAK_THRESHOLD {
            push_dispatcher
                .delivery_health()
                .record_hard_failure(Platform::Apns);
        }

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let config = HealthConfig {
            enabled: true,
            bind_address: addr.to_string(),
        };

        let server = HealthServer::new(config, relay_client, push_dispatcher, Metrics::disabled());

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let server_handle = tokio::spawn(async move { server.run(shutdown_rx).await });

        let client = reqwest::Client::new();
        let response = wait_for_server_response(&client, format!("http://{}/ready", addr)).await;

        // APNs is down, but the same instance can still deliver FCM traffic.
        assert_eq!(response.status(), 200);
        let body: ReadyResponse = response.json().await.unwrap();
        assert_eq!(body.status, "ready");
        assert!(body.relays_connected);
        assert!(body.apns_configured);
        assert!(!body.apns_delivering);
        assert!(body.fcm_configured);
        assert!(body.fcm_delivering);

        shutdown_tx.send(true).unwrap();
        let _ = tokio::time::timeout(Duration::from_secs(2), server_handle).await;
    }

    #[tokio::test]
    async fn test_metrics_served_when_health_endpoints_disabled() {
        use crate::metrics::Metrics;

        let keys = Keys::generate();
        let relay_config = RelayConfig {
            clearnet: vec![],
            allow_unencrypted_clearnet_relays: false,
            onion: vec![],
            reconnect_interval_secs: 5,
            max_reconnect_attempts: 1,
            connection_timeout_secs: 1,
        };
        let relay_client = Arc::new(RelayClient::new(keys, relay_config).await.unwrap());
        let push_dispatcher = Arc::new(PushDispatcher::new(None, None));
        let metrics = Metrics::new().unwrap();
        metrics.init_server_info("0.0.0");

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let config = HealthConfig {
            enabled: false, // health endpoints off, metrics still enabled
            bind_address: addr.to_string(),
        };

        let server = HealthServer::new(config, relay_client, push_dispatcher, metrics);

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let server_handle = tokio::spawn(async move { server.run(shutdown_rx).await });

        let client = reqwest::Client::new();
        let response = wait_for_server_response(&client, format!("http://{}/metrics", addr)).await;

        // /metrics must be reachable even though the health endpoints are off.
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.text().await.unwrap();
        assert!(body.contains("transponder_server_info"));

        // The health endpoints themselves stay unmounted.
        let health = client
            .get(format!("http://{}/health", addr))
            .send()
            .await
            .unwrap();
        assert_eq!(health.status(), StatusCode::NOT_FOUND);
        let ready = client
            .get(format!("http://{}/ready", addr))
            .send()
            .await
            .unwrap();
        assert_eq!(ready.status(), StatusCode::NOT_FOUND);

        shutdown_tx.send(true).unwrap();
        let _ = tokio::time::timeout(Duration::from_secs(2), server_handle).await;
    }

    #[tokio::test]
    async fn bind_returns_listener_when_metrics_enabled_and_health_disabled() {
        use crate::metrics::Metrics;

        let keys = Keys::generate();
        let relay_config = RelayConfig {
            clearnet: vec![],
            allow_unencrypted_clearnet_relays: true,
            onion: vec![],
            reconnect_interval_secs: 5,
            max_reconnect_attempts: 10,
            connection_timeout_secs: 5,
        };
        let relay_client = Arc::new(RelayClient::new(keys, relay_config).await.unwrap());
        let push_dispatcher = Arc::new(PushDispatcher::new(None, None));

        let server = HealthServer::new(
            HealthConfig {
                enabled: false,
                bind_address: "127.0.0.1:0".to_string(),
            },
            relay_client,
            push_dispatcher,
            Metrics::new().unwrap(),
        );

        let listener = server.bind().await.unwrap();

        assert!(
            listener.is_some(),
            "metrics.enabled must bind a listener even with health.enabled=false"
        );
    }

    #[tokio::test]
    async fn bind_returns_none_without_attempting_when_nothing_is_served() {
        // An unbindable address proves no bind is attempted when both the
        // health endpoints and metrics are disabled: bind() would fail if it
        // tried to create a listener.
        let server = test_health_server(HealthConfig {
            enabled: false,
            bind_address: "999.999.999.999:9999".to_string(),
        })
        .await;

        let listener = server.bind().await.unwrap();

        assert!(listener.is_none());
    }

    #[tokio::test]
    async fn test_metrics_handler_returns_not_found_without_metrics() {
        let keys = Keys::generate();
        let relay_config = RelayConfig {
            clearnet: vec![],
            allow_unencrypted_clearnet_relays: false,
            onion: vec![],
            reconnect_interval_secs: 5,
            max_reconnect_attempts: 1,
            connection_timeout_secs: 1,
        };
        let relay_client = Arc::new(RelayClient::new(keys, relay_config).await.unwrap());
        let push_dispatcher = Arc::new(PushDispatcher::new(None, None));

        let state = Arc::new(HealthState {
            relay_client,
            push_dispatcher,
            metrics: Metrics::disabled(),
        });

        // Defensive guard: the route is only mounted when a collector exists,
        // but the handler still answers 404 rather than panicking if invoked
        // without one.
        let response = metrics_handler(State(state)).await.into_response();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_request_body_limit_rejects_oversized_bodies() {
        use nostr_relay_builder::MockRelay;

        let mock = MockRelay::run().await.unwrap();
        let relay_url = mock.url().await;

        let keys = Keys::generate();
        let relay_config = RelayConfig {
            clearnet: vec![relay_url.to_string()],
            allow_unencrypted_clearnet_relays: true,
            onion: vec![],
            reconnect_interval_secs: 5,
            max_reconnect_attempts: 10,
            connection_timeout_secs: 5,
        };

        let relay_client = Arc::new(RelayClient::new(keys, relay_config).await.unwrap());
        let push_dispatcher = Arc::new(PushDispatcher::new(None, None));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let config = HealthConfig {
            enabled: true,
            bind_address: addr.to_string(),
        };

        let server = HealthServer::new(config, relay_client, push_dispatcher, Metrics::disabled());

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let server_handle = tokio::spawn(async move { server.run(shutdown_rx).await });

        let client = reqwest::Client::new();
        // Wait until the listener is up before sending the oversized request.
        let _ = wait_for_server_response(&client, format!("http://{}/health", addr)).await;

        let response = client
            .get(format!("http://{}/health", addr))
            .body(vec![0u8; MAX_REQUEST_BODY_BYTES + 1])
            .send()
            .await
            .unwrap();

        // Health endpoints take no request bodies; oversized ones are
        // rejected outright by the body-limit layer.
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);

        shutdown_tx.send(true).unwrap();
        let _ = tokio::time::timeout(Duration::from_secs(2), server_handle).await;
    }
}

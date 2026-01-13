//! Health check HTTP server.
//!
//! Provides `/health` (liveness) and `/ready` (readiness) endpoints.

use std::sync::Arc;

use axum::{Json, Router, extract::State, http::StatusCode, response::IntoResponse, routing::get};
use serde::Serialize;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tracing::info;

use crate::config::HealthConfig;
use crate::error::Result;
use crate::nostr::client::RelayClient;
use crate::push::PushDispatcher;

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
}

/// Shared state for health check handlers.
struct HealthState {
    relay_client: Arc<RelayClient>,
    push_dispatcher: Arc<PushDispatcher>,
}

/// Health check HTTP server.
pub struct HealthServer {
    config: HealthConfig,
    relay_client: Arc<RelayClient>,
    push_dispatcher: Arc<PushDispatcher>,
}

impl HealthServer {
    /// Create a new health server.
    pub fn new(
        config: HealthConfig,
        relay_client: Arc<RelayClient>,
        push_dispatcher: Arc<PushDispatcher>,
    ) -> Self {
        Self {
            config,
            relay_client,
            push_dispatcher,
        }
    }

    /// Run the health server until shutdown is signaled.
    pub async fn run(&self, mut shutdown: watch::Receiver<bool>) -> Result<()> {
        if !self.config.enabled {
            info!("Health server disabled");
            // Wait for shutdown
            let _ = shutdown.changed().await;
            return Ok(());
        }

        let state = Arc::new(HealthState {
            relay_client: self.relay_client.clone(),
            push_dispatcher: self.push_dispatcher.clone(),
        });

        let app = Router::new()
            .route("/health", get(health_handler))
            .route("/ready", get(ready_handler))
            .with_state(state);

        let listener = TcpListener::bind(&self.config.bind_address).await?;
        info!(address = %self.config.bind_address, "Health server listening");

        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = shutdown.changed().await;
                info!("Health server shutting down");
            })
            .await?;

        Ok(())
    }
}

/// Liveness check handler.
async fn health_handler() -> impl IntoResponse {
    Json(HealthResponse {
        status: "ok".to_string(),
    })
}

/// Readiness check handler.
async fn ready_handler(State(state): State<Arc<HealthState>>) -> impl IntoResponse {
    let relays_connected = state.relay_client.is_connected().await;
    let apns_configured = state.push_dispatcher.has_apns();
    let fcm_configured = state.push_dispatcher.has_fcm();

    let is_ready = relays_connected && (apns_configured || fcm_configured);

    let response = ReadyResponse {
        status: if is_ready { "ready" } else { "not_ready" }.to_string(),
        relays_connected,
        apns_configured,
        fcm_configured,
    };

    if is_ready {
        (StatusCode::OK, Json(response))
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, Json(response))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RelayConfig;
    use nostr_sdk::prelude::*;
    use std::time::Duration;

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
        };
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("ready"));
        assert!(json.contains("relays_connected"));
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
            onion: vec![],
            reconnect_interval_secs: 5,
            max_reconnect_attempts: 10,
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

        let server = HealthServer::new(config, relay_client, push_dispatcher);

        // Create shutdown channel
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        // Spawn server
        let server_handle = tokio::spawn(async move { server.run(shutdown_rx).await });

        // Give server time to start
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Test health endpoint
        let client = reqwest::Client::new();
        let response = client
            .get(format!("http://{}/health", addr))
            .send()
            .await
            .unwrap();

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
            onion: vec![],
            reconnect_interval_secs: 5,
            max_reconnect_attempts: 10,
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

        let server = HealthServer::new(config, relay_client, push_dispatcher);

        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let server_handle = tokio::spawn(async move { server.run(shutdown_rx).await });

        tokio::time::sleep(Duration::from_millis(100)).await;

        let client = reqwest::Client::new();
        let response = client
            .get(format!("http://{}/ready", addr))
            .send()
            .await
            .unwrap();

        // Should be 503 because no relays connected and no push services
        assert_eq!(response.status(), 503);
        let body: ReadyResponse = response.json().await.unwrap();
        assert_eq!(body.status, "not_ready");
        assert!(!body.relays_connected);
        assert!(!body.apns_configured);
        assert!(!body.fcm_configured);

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
            onion: vec![],
            reconnect_interval_secs: 5,
            max_reconnect_attempts: 10,
        };

        let relay_client = Arc::new(RelayClient::new(keys, relay_config).await.unwrap());
        let push_dispatcher = Arc::new(PushDispatcher::new(None, None));

        let config = HealthConfig {
            enabled: false, // Disabled
            bind_address: "127.0.0.1:0".to_string(),
        };

        let server = HealthServer::new(config, relay_client, push_dispatcher);

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
}

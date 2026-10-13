//! Opt-in verification against an operator-supplied live onion relay.

#![cfg(feature = "tor")]

use std::time::Duration;

use nostr_sdk::prelude::*;
use transponder::config::RelayConfig;
use transponder::nostr::client::RelayClient;

#[tokio::test]
#[ignore = "requires Tor connectivity and TRANSPONDER_TEST_ONION_RELAY"]
async fn live_onion_relay_delivers_eose() {
    let relay = std::env::var("TRANSPONDER_TEST_ONION_RELAY")
        .expect("set TRANSPONDER_TEST_ONION_RELAY to a reachable onion relay");
    let data = tempfile::tempdir().unwrap();
    let config: RelayConfig = serde_json::from_value(serde_json::json!({
        "onion": [relay],
        "tor_data_dir": data.path().to_string_lossy(),
        "connection_timeout_secs": 180,
        "reconnect_interval_secs": 2,
    }))
    .unwrap();
    let keys = Keys::generate();
    let client = RelayClient::new(keys.clone(), config).await.unwrap();
    let mut notifications = client.notifications();
    let connected = client.connect().await;
    if connected.is_err() {
        client.disconnect().await.unwrap();
        panic!("live Tor relay did not connect within the startup deadline");
    }
    let subscribed = client.subscribe(keys.public_key()).await;
    assert!(
        subscribed.is_ok(),
        "live Tor subscription could not be installed"
    );
    let eose = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let ClientNotification::Message { message, .. } = notifications.recv().await.unwrap()
                && matches!(*message, RelayMessage::EndOfStoredEvents(_))
            {
                break;
            }
        }
    })
    .await;
    client.disconnect().await.unwrap();
    assert!(eose.is_ok(), "live Tor relay did not deliver EOSE");
}

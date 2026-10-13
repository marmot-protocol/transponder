//! The SDK's default stream hides lag. The patched receiver must expose it so
//! the application can invalidate subscription state after a dropped EOSE.

use std::num::NonZeroUsize;
use std::time::Duration;

use nostr_sdk::local_relay::MockRelay;
use nostr_sdk::prelude::*;
use tokio::sync::broadcast::error::RecvError;
use transponder::config::RelayConfig;
use transponder::nostr::client::RelayClient;

#[tokio::test]
async fn inbox_relay_publication_uses_nip17_wire_tags() {
    let mock = MockRelay::run().await.unwrap();
    let url = mock.url().await;
    let config: RelayConfig = serde_json::from_value(serde_json::json!({
        "clearnet": [url.as_str()], "allow_unencrypted_clearnet_relays": true,
        "connection_timeout_secs": 5,
    }))
    .unwrap();
    let keys = Keys::generate();
    let client = RelayClient::new(keys.clone(), config).await.unwrap();
    client.connect().await.unwrap();
    client.publish_inbox_relays().await.unwrap();
    let events = client
        .inner()
        .fetch_events(
            Filter::new()
                .kind(Kind::Custom(10050))
                .author(keys.public_key())
                .limit(1),
        )
        .timeout(Duration::from_secs(5))
        .await
        .unwrap();
    let event = events.first().expect("inbox relay publication must exist");
    // Independent NIP-17 reader, rather than Transponder's own change detector.
    let relays = nip17::extract_relay_list(event).collect::<Vec<_>>();
    assert_eq!(relays, vec![url.clone()]);
    assert_eq!(
        event.tags.as_slice()[0].as_slice(),
        &["relay".to_owned(), url.to_string()]
    );
    client.disconnect().await.unwrap();
    mock.shutdown();
}

#[tokio::test]
async fn sdk_notification_receiver_reports_overflow() {
    let mock = MockRelay::run().await.unwrap();
    let client = Client::builder()
        .notification_channel_size(NonZeroUsize::MIN)
        .build();
    client.add_relay(mock.url().await).await.unwrap();
    let connected = client.try_connect().timeout(Duration::from_secs(5)).await;
    assert!(!connected.success.is_empty());
    let mut slow = client.notification_receiver();
    let mut witness = client.notification_receiver();
    for index in 0..4 {
        let id = SubscriptionId::new(format!("overflow-{index}"));
        client
            .send_msg(ClientMessage::req(id.clone(), Filter::new().limit(0)))
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let ClientNotification::Message { message, .. } = witness.recv().await.unwrap()
                    && let RelayMessage::EndOfStoredEvents(received) = *message
                    && received.as_ref() == &id
                {
                    break;
                }
            }
        })
        .await
        .unwrap();
    }
    assert!(matches!(slow.recv().await, Err(RecvError::Lagged(skipped)) if skipped > 0));
    client.shutdown().await;
    mock.shutdown();
}

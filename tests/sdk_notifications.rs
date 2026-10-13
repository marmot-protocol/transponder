//! The SDK's default stream hides lag. The patched receiver must expose it so
//! the application can invalidate subscription state after a dropped EOSE.

use std::num::NonZeroUsize;
use std::time::Duration;

use nostr_sdk::local_relay::MockRelay;
use nostr_sdk::prelude::*;
use tokio::sync::broadcast::error::RecvError;

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

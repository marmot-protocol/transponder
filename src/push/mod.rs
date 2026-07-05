//! Push notification clients and dispatching.

pub mod apns;
pub mod dispatcher;
pub mod fcm;
pub mod retry;

pub use apns::ApnsClient;
pub use dispatcher::PushDispatcher;
pub use fcm::FcmClient;

use serde::de::DeserializeOwned;

/// Maximum number of bytes read from a provider error response before JSON
/// parsing.
///
/// Legitimate APNs/FCM error payloads are tiny (a `reason`/`status` plus a
/// short message). The response body is provider/network-controlled and the
/// HTTP client imposes no size cap, so a hostile or buggy endpoint could stream
/// an arbitrarily large body on an error status. Reading only a bounded prefix
/// keeps a single failing request from buffering an unbounded body into memory.
const MAX_ERROR_BODY_BYTES: usize = 8 * 1024;

/// Read at most [`MAX_ERROR_BODY_BYTES`] of a provider error response and
/// deserialize the bounded prefix as JSON.
///
/// If the server declares a body larger than the cap, the helper returns before
/// reading it. Otherwise the body is streamed chunk by chunk and reading stops
/// as soon as the cap is reached, so the full body is never buffered. Returns
/// `None` when the body is unreadable, exceeds the cap, or does not parse (e.g.
/// an empty or non-JSON body, or a JSON document truncated by the cap), letting
/// callers fall back to their default status-derived classification.
async fn parse_bounded_error_body<T: DeserializeOwned>(
    mut response: reqwest::Response,
) -> Option<T> {
    if response
        .content_length()
        .is_some_and(|len| len > MAX_ERROR_BODY_BYTES as u64)
    {
        return None;
    }

    let mut body = Vec::new();

    loop {
        match response.chunk().await {
            Ok(Some(chunk)) => {
                if body.len() + chunk.len() > MAX_ERROR_BODY_BYTES {
                    // The body is larger than any legitimate provider error
                    // payload; stop reading and fall back to the default.
                    return None;
                }
                body.extend_from_slice(&chunk);
            }
            Ok(None) => break,
            Err(_) => return None,
        }
    }

    serde_json::from_slice(&body).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[derive(Debug, Deserialize, PartialEq, Eq)]
    struct TestError {
        reason: String,
    }

    async fn parse_body(body: String) -> Option<TestError> {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(400).set_body_string(body))
            .expect(1)
            .mount(&mock_server)
            .await;

        let response = reqwest::Client::new()
            .get(mock_server.uri())
            .send()
            .await
            .unwrap();

        parse_bounded_error_body::<TestError>(response).await
    }

    #[tokio::test]
    async fn test_parses_small_error_body() {
        let parsed = parse_body(r#"{"reason":"BadDeviceToken"}"#.to_string()).await;
        assert_eq!(
            parsed,
            Some(TestError {
                reason: "BadDeviceToken".to_string()
            })
        );
    }

    #[tokio::test]
    async fn test_returns_none_for_non_json_body() {
        let parsed = parse_body("not json at all".to_string()).await;
        assert_eq!(parsed, None);
    }

    #[tokio::test]
    async fn test_returns_none_for_empty_body() {
        let parsed = parse_body(String::new()).await;
        assert_eq!(parsed, None);
    }

    #[tokio::test]
    async fn test_oversized_body_falls_back_without_parsing_whole_body() {
        // A hostile/buggy endpoint returns a valid-JSON error whose `reason`
        // value alone is far larger than any legitimate payload. The helper
        // must refuse to buffer/parse the whole body and fall back to `None`
        // rather than materializing the multi-megabyte string.
        let padding = "A".repeat(4 * 1024 * 1024);
        let huge_body = format!(r#"{{"reason":"{padding}"}}"#);
        assert!(huge_body.len() > MAX_ERROR_BODY_BYTES);

        let parsed = parse_body(huge_body).await;
        assert_eq!(parsed, None);
    }

    #[tokio::test]
    async fn test_body_at_limit_is_still_parsed() {
        // A body up to the cap is read and parsed normally.
        let reason_len = MAX_ERROR_BODY_BYTES - r#"{"reason":""}"#.len();
        let reason = "A".repeat(reason_len);
        let body = format!(r#"{{"reason":"{reason}"}}"#);
        assert_eq!(body.len(), MAX_ERROR_BODY_BYTES);

        let parsed = parse_body(body).await;
        assert_eq!(parsed, Some(TestError { reason }));
    }
}

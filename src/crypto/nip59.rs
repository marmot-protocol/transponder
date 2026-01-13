//! NIP-59 Gift Wrap handling for Nostr events.
//!
//! Implements the gift wrap protocol for extracting kind 446 notification requests
//! from encrypted Nostr events.

use nostr_sdk::nips::nip59::UnwrappedGift;
use nostr_sdk::prelude::*;

use crate::error::{Error, Result};

/// Kind for MIP-05 notification requests (rumor inside seal).
pub const KIND_NOTIFICATION_REQUEST: u16 = 446;

/// Handler for NIP-59 gift wrap operations.
#[derive(Clone)]
pub struct Nip59Handler {
    keys: Keys,
}

impl Nip59Handler {
    /// Create a new NIP-59 handler with the given server keys.
    pub fn new(keys: Keys) -> Self {
        Self { keys }
    }

    /// Get the server's public key.
    #[must_use]
    #[allow(dead_code)]
    pub fn public_key(&self) -> PublicKey {
        self.keys.public_key()
    }

    /// Unwrap a gift-wrapped event and extract the notification request rumor.
    ///
    /// Process:
    /// 1. Verify the event is kind 1059 (gift wrap)
    /// 2. Decrypt the gift wrap to get the seal
    /// 3. Verify the seal is kind 13
    /// 4. Decrypt the seal to get the rumor
    /// 5. Verify the rumor is kind 446
    /// 6. Return the rumor content (encrypted tokens)
    pub async fn unwrap(&self, event: &Event) -> Result<UnwrappedNotification> {
        // Verify this is a gift wrap event
        if event.kind != Kind::GiftWrap {
            return Err(Error::Crypto(format!(
                "Expected gift wrap (kind 1059), got kind {}",
                event.kind.as_u16()
            )));
        }

        // Decrypt the gift wrap to get the rumor (nostr-sdk handles seal internally)
        let unwrapped = UnwrappedGift::from_gift_wrap(&self.keys, event)
            .await
            .map_err(|e| Error::Crypto(format!("Failed to extract rumor: {e}")))?;

        // Verify the rumor is kind 446 (notification request)
        if unwrapped.rumor.kind.as_u16() != KIND_NOTIFICATION_REQUEST {
            return Err(Error::Crypto(format!(
                "Expected notification request (kind 446), got kind {}",
                unwrapped.rumor.kind.as_u16()
            )));
        }

        // Extract the sender's public key
        let sender_pubkey = unwrapped.sender;

        // The content contains the encrypted tokens
        let content = unwrapped.rumor.content.clone();

        Ok(UnwrappedNotification {
            sender_pubkey,
            content,
            created_at: unwrapped.rumor.created_at,
        })
    }
}

/// Unwrapped notification request data.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct UnwrappedNotification {
    /// Public key of the sender.
    pub sender_pubkey: PublicKey,
    /// Content containing encrypted tokens (base64-encoded).
    pub content: String,
    /// When the rumor was created.
    pub created_at: Timestamp,
}

impl UnwrappedNotification {
    /// Parse the encrypted tokens from the content.
    ///
    /// The content is expected to be a JSON array of base64-encoded tokens.
    pub fn parse_tokens(&self) -> Result<Vec<Vec<u8>>> {
        use base64::prelude::*;

        // Parse JSON array of base64 strings
        let token_strings: Vec<String> = serde_json::from_str(&self.content)
            .map_err(|e| Error::InvalidToken(format!("Failed to parse token array: {e}")))?;

        // Decode each base64 token
        let mut tokens = Vec::with_capacity(token_strings.len());
        for token_str in token_strings {
            let token_bytes = BASE64_STANDARD
                .decode(&token_str)
                .map_err(|e| Error::InvalidToken(format!("Failed to decode token: {e}")))?;
            tokens.push(token_bytes);
        }

        Ok(tokens)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handler_creation() {
        let keys = Keys::generate();
        let handler = Nip59Handler::new(keys.clone());
        assert_eq!(handler.public_key(), keys.public_key());
    }

    #[test]
    fn test_parse_tokens() {
        use base64::prelude::*;

        let token1 = vec![0x01, 0x02, 0x03];
        let token2 = vec![0x04, 0x05, 0x06];

        let content = format!(
            "[\"{}\", \"{}\"]",
            BASE64_STANDARD.encode(&token1),
            BASE64_STANDARD.encode(&token2)
        );

        let notification = UnwrappedNotification {
            sender_pubkey: Keys::generate().public_key(),
            content,
            created_at: Timestamp::now(),
        };

        let tokens = notification.parse_tokens().unwrap();
        assert_eq!(tokens.len(), 2);
        assert_eq!(tokens[0], token1);
        assert_eq!(tokens[1], token2);
    }

    #[test]
    fn test_parse_invalid_json() {
        let notification = UnwrappedNotification {
            sender_pubkey: Keys::generate().public_key(),
            content: "not json".to_string(),
            created_at: Timestamp::now(),
        };

        assert!(notification.parse_tokens().is_err());
    }

    #[test]
    fn test_parse_invalid_base64() {
        let notification = UnwrappedNotification {
            sender_pubkey: Keys::generate().public_key(),
            content: "[\"not valid base64!!!\"]".to_string(),
            created_at: Timestamp::now(),
        };

        assert!(notification.parse_tokens().is_err());
    }

    #[test]
    fn test_parse_empty_token_array() {
        let notification = UnwrappedNotification {
            sender_pubkey: Keys::generate().public_key(),
            content: "[]".to_string(),
            created_at: Timestamp::now(),
        };

        let tokens = notification.parse_tokens().unwrap();
        assert!(tokens.is_empty());
    }

    #[test]
    fn test_parse_single_token() {
        use base64::prelude::*;

        let token = vec![0xde, 0xad, 0xbe, 0xef];
        let content = format!("[\"{}\"]", BASE64_STANDARD.encode(&token));

        let notification = UnwrappedNotification {
            sender_pubkey: Keys::generate().public_key(),
            content,
            created_at: Timestamp::now(),
        };

        let tokens = notification.parse_tokens().unwrap();
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0], token);
    }

    #[test]
    fn test_parse_many_tokens() {
        use base64::prelude::*;

        let token_data: Vec<Vec<u8>> = (0..10).map(|i| vec![i; 32]).collect();
        let encoded: Vec<String> = token_data
            .iter()
            .map(|t| BASE64_STANDARD.encode(t))
            .collect();
        let content = format!(
            "[{}]",
            encoded
                .iter()
                .map(|s| format!("\"{}\"", s))
                .collect::<Vec<_>>()
                .join(", ")
        );

        let notification = UnwrappedNotification {
            sender_pubkey: Keys::generate().public_key(),
            content,
            created_at: Timestamp::now(),
        };

        let tokens = notification.parse_tokens().unwrap();
        assert_eq!(tokens.len(), 10);
        for (i, token) in tokens.iter().enumerate() {
            assert_eq!(token, &vec![i as u8; 32]);
        }
    }

    #[test]
    fn test_parse_tokens_not_array() {
        // JSON object instead of array
        let notification = UnwrappedNotification {
            sender_pubkey: Keys::generate().public_key(),
            content: r#"{"token": "abc"}"#.to_string(),
            created_at: Timestamp::now(),
        };

        let result = notification.parse_tokens();
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Failed to parse token array")
        );
    }

    #[test]
    fn test_parse_tokens_number_array() {
        // Array of numbers instead of strings
        let notification = UnwrappedNotification {
            sender_pubkey: Keys::generate().public_key(),
            content: "[1, 2, 3]".to_string(),
            created_at: Timestamp::now(),
        };

        let result = notification.parse_tokens();
        assert!(result.is_err());
    }
}

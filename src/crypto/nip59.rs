//! NIP-59 Gift Wrap handling for Nostr events.
//!
//! Implements the gift wrap protocol for extracting kind 446 notification requests
//! from encrypted Nostr events.

use nostr_sdk::nips::nip59::UnwrappedGift;
use nostr_sdk::prelude::*;

use crate::crypto::token::ENCRYPTED_TOKEN_SIZE;
use crate::error::{Error, Result};

/// Kind for MIP-05 notification requests (rumor inside seal).
pub const KIND_NOTIFICATION_REQUEST: u16 = 446;

const TAG_VERSION: &str = "v";
const TAG_ENCODING: &str = "encoding";
const VERSION_MIP05_V1: &str = "mip05-v1";
const ENCODING_BASE64: &str = "base64";

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
    /// 6. Return the rumor metadata and content
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

        let rumor = unwrapped.rumor;

        Ok(UnwrappedNotification {
            sender_pubkey,
            content: rumor.content,
            tags: rumor.tags,
            created_at: rumor.created_at,
        })
    }
}

/// Unwrapped notification request data.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct UnwrappedNotification {
    /// Public key of the sender.
    pub sender_pubkey: PublicKey,
    /// Content containing encrypted tokens as a single base64 blob.
    pub content: String,
    /// Rumor tags used for versioning and content encoding validation.
    pub tags: Tags,
    /// When the rumor was created.
    pub created_at: Timestamp,
}

impl UnwrappedNotification {
    fn require_tag_value(&self, tag_name: &str, expected_value: &str) -> Result<()> {
        let mut found_tag = false;

        for tag in self
            .tags
            .iter()
            .filter(|tag| tag.kind() == TagKind::custom(tag_name))
        {
            found_tag = true;

            match tag.content() {
                Some(value) if value == expected_value => continue,
                Some(value) => {
                    return Err(Error::InvalidToken(format!(
                        "Unsupported {tag_name} tag value: {value}"
                    )));
                }
                None => {
                    return Err(Error::InvalidToken(format!(
                        "Missing value for required {tag_name} tag"
                    )));
                }
            }
        }

        if !found_tag {
            return Err(Error::InvalidToken(format!(
                "Missing required {tag_name} tag"
            )));
        }

        Ok(())
    }

    /// Parse the encrypted tokens from the content.
    ///
    /// The content is expected to be a single RFC 4648 standard base64 string
    /// containing one or more concatenated encrypted tokens.
    pub fn parse_tokens(&self) -> Result<Vec<Vec<u8>>> {
        use base64::prelude::*;

        self.require_tag_value(TAG_VERSION, VERSION_MIP05_V1)?;
        self.require_tag_value(TAG_ENCODING, ENCODING_BASE64)?;

        let decoded = BASE64_STANDARD
            .decode(&self.content)
            .map_err(|e| Error::InvalidToken(format!("Failed to decode token blob: {e}")))?;

        if decoded.is_empty() {
            return Err(Error::InvalidToken(
                "Notification request contains no encrypted tokens".to_string(),
            ));
        }

        if decoded.len() % ENCRYPTED_TOKEN_SIZE != 0 {
            return Err(Error::InvalidToken(format!(
                "Decoded token blob length {} is not a multiple of {ENCRYPTED_TOKEN_SIZE}",
                decoded.len()
            )));
        }

        Ok(decoded
            .chunks(ENCRYPTED_TOKEN_SIZE)
            .map(|chunk| chunk.to_vec())
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::prelude::*;

    fn valid_tags() -> Tags {
        Tags::parse([
            [TAG_VERSION, VERSION_MIP05_V1],
            [TAG_ENCODING, ENCODING_BASE64],
        ])
        .unwrap()
    }

    fn notification(content: String) -> UnwrappedNotification {
        UnwrappedNotification {
            sender_pubkey: Keys::generate().public_key(),
            content,
            tags: valid_tags(),
            created_at: Timestamp::now(),
        }
    }

    #[test]
    fn test_handler_creation() {
        let keys = Keys::generate();
        let handler = Nip59Handler::new(keys.clone());
        assert_eq!(handler.public_key(), keys.public_key());
    }

    #[test]
    fn test_parse_tokens() {
        let token1 = vec![0x01; ENCRYPTED_TOKEN_SIZE];
        let token2 = vec![0x02; ENCRYPTED_TOKEN_SIZE];
        let mut concatenated = token1.clone();
        concatenated.extend_from_slice(&token2);

        let notification = notification(BASE64_STANDARD.encode(&concatenated));

        let tokens = notification.parse_tokens().unwrap();
        assert_eq!(tokens.len(), 2);
        assert_eq!(tokens[0], token1);
        assert_eq!(tokens[1], token2);
    }

    #[test]
    fn test_parse_rejects_missing_version_tag() {
        let notification = UnwrappedNotification {
            sender_pubkey: Keys::generate().public_key(),
            content: BASE64_STANDARD.encode(vec![0x01; ENCRYPTED_TOKEN_SIZE]),
            tags: Tags::parse([[TAG_ENCODING, ENCODING_BASE64]]).unwrap(),
            created_at: Timestamp::now(),
        };

        let result = notification.parse_tokens();
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Missing required v tag")
        );
    }

    #[test]
    fn test_parse_invalid_base64() {
        let notification = notification("not valid base64!!!".to_string());

        let result = notification.parse_tokens();
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Failed to decode token blob")
        );
    }

    #[test]
    fn test_parse_empty_token_blob() {
        let notification = notification(String::new());

        let result = notification.parse_tokens();
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("no encrypted tokens")
        );
    }

    #[test]
    fn test_parse_single_token() {
        let token = vec![0xde; ENCRYPTED_TOKEN_SIZE];
        let notification = notification(BASE64_STANDARD.encode(&token));

        let tokens = notification.parse_tokens().unwrap();
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0], token);
    }

    #[test]
    fn test_parse_many_tokens() {
        let token_data: Vec<Vec<u8>> = (0..10)
            .map(|i| vec![i as u8; ENCRYPTED_TOKEN_SIZE])
            .collect();
        let concatenated: Vec<u8> = token_data.iter().flatten().copied().collect();
        let notification = notification(BASE64_STANDARD.encode(&concatenated));

        let tokens = notification.parse_tokens().unwrap();
        assert_eq!(tokens.len(), 10);
        for (i, token) in tokens.iter().enumerate() {
            assert_eq!(token, &vec![i as u8; ENCRYPTED_TOKEN_SIZE]);
        }
    }

    #[test]
    fn test_parse_rejects_invalid_blob_length() {
        let invalid_len = ENCRYPTED_TOKEN_SIZE - 1;
        let notification = notification(BASE64_STANDARD.encode(vec![0xAA; invalid_len]));

        let result = notification.parse_tokens();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not a multiple"));
    }

    #[test]
    fn test_parse_rejects_invalid_encoding_tag() {
        let notification = UnwrappedNotification {
            sender_pubkey: Keys::generate().public_key(),
            content: BASE64_STANDARD.encode(vec![0x11; ENCRYPTED_TOKEN_SIZE]),
            tags: Tags::parse([[TAG_VERSION, VERSION_MIP05_V1], [TAG_ENCODING, "hex"]]).unwrap(),
            created_at: Timestamp::now(),
        };

        let result = notification.parse_tokens();
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Unsupported encoding tag value")
        );
    }
}

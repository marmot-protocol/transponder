//! NIP-59 Gift Wrap handling for Nostr events.
//!
//! Implements the gift wrap protocol for extracting kind 446 notification requests
//! from encrypted Nostr events.

use nostr_sdk::prelude::*;

use crate::crypto::token::ENCRYPTED_TOKEN_SIZE;
use crate::error::{Error, Result};

/// Kind for MIP-05 notification requests (rumor inside seal).
pub const KIND_NOTIFICATION_REQUEST: u16 = 446;

const TAG_VERSION: &str = "v";
const TAG_ENCODING: &str = "encoding";
const VERSION_MIP05_V1: &str = "mip05-v1";
const ENCODING_BASE64: &str = "base64";

pub use crate::defaults::DEFAULT_MAX_TOKENS_PER_EVENT;

/// Maximum number of characters of attacker-controlled tag content included in
/// error messages.
const MAX_TAG_VALUE_ERROR_CHARS: usize = 32;

/// Maximum number of characters of a parse-error detail (which can embed
/// attacker-controlled decrypted plaintext) included in error messages.
const MAX_PARSE_ERROR_CHARS: usize = 128;

/// Bound and escape attacker-controlled text before embedding it in an error
/// message.
///
/// Errors from this module are logged verbatim (`warn!(error = %e, ...)` in
/// the event processor), so any decrypted gift-wrap content that reaches an
/// error string must be length-bounded and control-character-escaped to
/// prevent log injection and log-volume amplification.
fn sanitize_for_error(value: &str, max_chars: usize) -> String {
    let mut chars = value.chars();
    let mut sanitized = String::new();

    for ch in chars.by_ref().take(max_chars) {
        sanitized.extend(ch.escape_default());
    }
    if chars.next().is_some() {
        sanitized.push_str("...");
    }

    sanitized
}

fn max_encoded_token_blob_len(max_tokens: usize) -> usize {
    max_tokens
        .saturating_mul(ENCRYPTED_TOKEN_SIZE)
        .div_ceil(3)
        .saturating_mul(4)
}

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
    /// The unwrap is performed manually with nostr-sdk primitives instead of
    /// delegating to `UnwrappedGift::from_gift_wrap`, because the latter never
    /// exposes (or validates) the seal kind. Every step below is enforced in
    /// this function.
    ///
    /// Process:
    /// 1. Verify the event is kind 1059 (gift wrap)
    /// 2. Decrypt the gift wrap content (NIP-44) to get the seal event
    /// 3. Verify the seal signature and that the seal is kind 13
    /// 4. Decrypt the seal content (NIP-44) to get the rumor
    /// 5. Verify the rumor author matches the seal signer (the rumor is
    ///    unsigned, so its `pubkey` field is otherwise attacker-chosen)
    /// 6. Verify the rumor is kind 446 and return its metadata and content
    pub async fn unwrap(&self, event: &Event) -> Result<UnwrappedNotification> {
        // Step 1: verify this is a gift wrap event.
        if event.kind != Kind::GiftWrap {
            return Err(Error::Crypto(format!(
                "Expected gift wrap (kind 1059), got kind {}",
                event.kind.as_u16()
            )));
        }

        // Step 2: decrypt the gift wrap content to get the seal event.
        let seal_json = self
            .keys
            .nip44_decrypt(&event.pubkey, &event.content)
            .await
            .map_err(|e| Error::Crypto(format!("Failed to decrypt gift wrap: {e}")))?;
        // Parse-error details can embed the (attacker-controlled) decrypted
        // plaintext, so they are bounded and escaped before formatting.
        let seal = Event::from_json(&seal_json).map_err(|e| {
            Error::Crypto(format!(
                "Failed to parse seal event: {}",
                sanitize_for_error(&e.to_string(), MAX_PARSE_ERROR_CHARS)
            ))
        })?;

        // Step 3: verify the seal signature, then the seal kind. nostr-sdk's
        // `UnwrappedGift::from_gift_wrap` verifies the signature but not the
        // kind; both are enforced here.
        seal.verify()
            .map_err(|e| Error::Crypto(format!("Invalid seal: {e}")))?;
        if seal.kind != Kind::Seal {
            return Err(Error::Crypto(format!(
                "Expected seal (kind 13), got kind {}",
                seal.kind.as_u16()
            )));
        }

        // Step 4: decrypt the seal content to get the rumor.
        let rumor_json = self
            .keys
            .nip44_decrypt(&seal.pubkey, &seal.content)
            .await
            .map_err(|e| Error::Crypto(format!("Failed to decrypt seal: {e}")))?;
        let rumor = UnsignedEvent::from_json(&rumor_json).map_err(|e| {
            Error::Crypto(format!(
                "Failed to parse rumor: {}",
                sanitize_for_error(&e.to_string(), MAX_PARSE_ERROR_CHARS)
            ))
        })?;

        // Step 5: bind the rumor author to the seal signer. The rumor is
        // unsigned, so its `pubkey` is attacker-chosen; the seal signer is the
        // only authenticated identity in the wrap.
        if rumor.pubkey != seal.pubkey {
            return Err(Error::Crypto(
                "Rumor author does not match seal signer".to_string(),
            ));
        }

        // Step 6: verify the rumor is kind 446 (notification request).
        if rumor.kind.as_u16() != KIND_NOTIFICATION_REQUEST {
            return Err(Error::Crypto(format!(
                "Expected notification request (kind 446), got kind {}",
                rumor.kind.as_u16()
            )));
        }

        Ok(UnwrappedNotification {
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
    /// Content containing encrypted tokens as a single base64 blob.
    pub content: String,
    /// Rumor tags used for versioning and optional content encoding validation.
    pub tags: Tags,
    /// When the rumor was created.
    pub created_at: Timestamp,
}

/// Whether a validated tag must be present on the rumor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TagPresence {
    /// At least one tag with the given name must exist.
    Required,
    /// Zero tags with the given name is accepted.
    Optional,
}

impl UnwrappedNotification {
    /// Validate every tag named `tag_name` against `expected_value`.
    ///
    /// Each present tag must carry exactly `expected_value`. When `presence`
    /// is [`TagPresence::Required`], at least one such tag must exist; when
    /// [`TagPresence::Optional`], the tag may be absent entirely.
    ///
    /// Tag values are attacker-controlled decrypted content, so they are
    /// truncated and escaped before being embedded in error messages.
    fn validate_tag(
        &self,
        tag_name: &str,
        expected_value: &str,
        presence: TagPresence,
    ) -> Result<()> {
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
                        "Unsupported {tag_name} tag value: {}",
                        sanitize_for_error(value, MAX_TAG_VALUE_ERROR_CHARS)
                    )));
                }
                None => {
                    return Err(Error::InvalidToken(match presence {
                        TagPresence::Required => {
                            format!("Missing value for required {tag_name} tag")
                        }
                        TagPresence::Optional => format!("Missing value for {tag_name} tag"),
                    }));
                }
            }
        }

        if presence == TagPresence::Required && !found_tag {
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
    #[allow(dead_code)]
    #[must_use = "parsed tokens must be handled or parsing errors will be ignored"]
    pub fn parse_tokens(&self) -> Result<Vec<Vec<u8>>> {
        self.parse_tokens_with_limit(DEFAULT_MAX_TOKENS_PER_EVENT)
    }

    /// Parse the encrypted tokens from the content with an event-local token limit.
    ///
    /// The base64 input length is checked before decoding so oversized events
    /// are rejected before allocating a decoded token blob.
    #[must_use = "parsed tokens must be handled or parsing errors will be ignored"]
    pub fn parse_tokens_with_limit(&self, max_tokens: usize) -> Result<Vec<Vec<u8>>> {
        use base64::prelude::*;

        self.validate_tag(TAG_VERSION, VERSION_MIP05_V1, TagPresence::Required)?;
        // Zero `encoding` tags defaults to base64 (current Darkmatter / Marmot
        // spec). If present, every `encoding` tag must carry the value `base64`.
        self.validate_tag(TAG_ENCODING, ENCODING_BASE64, TagPresence::Optional)?;

        let max_encoded_len = max_encoded_token_blob_len(max_tokens);
        if self.content.len() > max_encoded_len {
            return Err(Error::InvalidToken(format!(
                "Token blob too large: exceeds maximum of {max_tokens} tokens"
            )));
        }

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

    fn exceeds_max_tokens_message(max_tokens: usize) -> String {
        format!("exceeds maximum of {max_tokens} tokens")
    }

    fn version_only_tags() -> Tags {
        Tags::parse([[TAG_VERSION, VERSION_MIP05_V1]]).unwrap()
    }

    fn valid_tags_with_encoding() -> Tags {
        Tags::parse([
            [TAG_VERSION, VERSION_MIP05_V1],
            [TAG_ENCODING, ENCODING_BASE64],
        ])
        .unwrap()
    }

    fn notification(content: String) -> UnwrappedNotification {
        UnwrappedNotification {
            content,
            tags: version_only_tags(),
            created_at: Timestamp::now(),
        }
    }

    fn notification_with_encoding(content: String) -> UnwrappedNotification {
        UnwrappedNotification {
            content,
            tags: valid_tags_with_encoding(),
            created_at: Timestamp::now(),
        }
    }

    fn contains_hex_run(input: &str, target_len: usize) -> bool {
        let mut run_len = 0;

        for ch in input.chars() {
            if ch.is_ascii_hexdigit() {
                run_len += 1;
                if run_len >= target_len {
                    return true;
                }
            } else {
                run_len = 0;
            }
        }

        false
    }

    #[test]
    fn test_unwrapped_notification_debug_excludes_sender_metadata() {
        let notification = notification(BASE64_STANDARD.encode(vec![0x01; ENCRYPTED_TOKEN_SIZE]));
        let debug = format!("{notification:?}");

        assert!(!debug.contains("sender"));
        assert!(!contains_hex_run(&debug, 64));
    }

    #[test]
    fn test_handler_creation() {
        let keys = Keys::generate();
        let handler = Nip59Handler::new(keys.clone());
        assert_eq!(handler.public_key(), keys.public_key());
    }

    /// Build a kind 446 rumor claiming the given author.
    fn notification_rumor(author: PublicKey) -> UnsignedEvent {
        EventBuilder::new(Kind::Custom(KIND_NOTIFICATION_REQUEST), "token-blob").build(author)
    }

    /// Gift-wrap the given seal JSON to `receiver` with an ephemeral key,
    /// mirroring the NIP-59 outer layer.
    async fn wrap_seal_json(receiver: &Keys, seal_json: &str) -> Event {
        let ephemeral = Keys::generate();
        let content = ephemeral
            .nip44_encrypt(&receiver.public_key(), seal_json)
            .await
            .unwrap();
        EventBuilder::new(Kind::GiftWrap, content)
            .tag(Tag::public_key(receiver.public_key()))
            .sign(&ephemeral)
            .await
            .unwrap()
    }

    /// Build a full gift wrap manually so the seal kind can be controlled.
    async fn manual_gift_wrap(
        seal_signer: &Keys,
        receiver: &Keys,
        mut rumor: UnsignedEvent,
        seal_kind: Kind,
    ) -> Event {
        rumor.ensure_id();
        let seal_content = seal_signer
            .nip44_encrypt(&receiver.public_key(), &rumor.as_json())
            .await
            .unwrap();
        let seal = EventBuilder::new(seal_kind, seal_content)
            .sign(seal_signer)
            .await
            .unwrap();
        wrap_seal_json(receiver, &seal.as_json()).await
    }

    #[tokio::test]
    async fn test_unwrap_accepts_valid_gift_wrap() {
        let server_keys = Keys::generate();
        let sender_keys = Keys::generate();
        let handler = Nip59Handler::new(server_keys.clone());

        let rumor = notification_rumor(sender_keys.public_key());
        let gift_wrap = EventBuilder::gift_wrap(
            &sender_keys,
            &server_keys.public_key(),
            rumor,
            Vec::<Tag>::new(),
        )
        .await
        .unwrap();

        let unwrapped = handler.unwrap(&gift_wrap).await.unwrap();
        assert_eq!(unwrapped.content, "token-blob");
    }

    #[tokio::test]
    async fn test_unwrap_accepts_manually_built_seal_of_kind_13() {
        // Sanity-check the manual construction against the real unwrap path,
        // so the rejection tests below fail for the intended reason only.
        let server_keys = Keys::generate();
        let sender_keys = Keys::generate();
        let handler = Nip59Handler::new(server_keys.clone());

        let rumor = notification_rumor(sender_keys.public_key());
        let gift_wrap = manual_gift_wrap(&sender_keys, &server_keys, rumor, Kind::Seal).await;

        let unwrapped = handler.unwrap(&gift_wrap).await.unwrap();
        assert_eq!(unwrapped.content, "token-blob");
    }

    #[tokio::test]
    async fn test_unwrap_rejects_non_gift_wrap_event() {
        let server_keys = Keys::generate();
        let sender_keys = Keys::generate();
        let handler = Nip59Handler::new(server_keys);

        let event = EventBuilder::text_note("not a gift wrap")
            .sign(&sender_keys)
            .await
            .unwrap();

        let error = handler.unwrap(&event).await.unwrap_err().to_string();
        assert!(error.contains("Expected gift wrap (kind 1059), got kind 1"));
    }

    #[tokio::test]
    async fn test_unwrap_rejects_gift_wrap_for_other_recipient() {
        let server_keys = Keys::generate();
        let other_keys = Keys::generate();
        let sender_keys = Keys::generate();
        let handler = Nip59Handler::new(server_keys);

        let rumor = notification_rumor(sender_keys.public_key());
        let gift_wrap = EventBuilder::gift_wrap(
            &sender_keys,
            &other_keys.public_key(),
            rumor,
            Vec::<Tag>::new(),
        )
        .await
        .unwrap();

        let error = handler.unwrap(&gift_wrap).await.unwrap_err().to_string();
        assert!(error.contains("Failed to decrypt gift wrap"));
    }

    #[tokio::test]
    async fn test_unwrap_rejects_non_event_seal_payload() {
        let server_keys = Keys::generate();
        let handler = Nip59Handler::new(server_keys.clone());

        let gift_wrap = wrap_seal_json(&server_keys, "not a seal event").await;

        let error = handler.unwrap(&gift_wrap).await.unwrap_err().to_string();
        assert!(error.contains("Failed to parse seal event"));
    }

    #[tokio::test]
    async fn test_unwrap_rejects_tampered_seal() {
        let server_keys = Keys::generate();
        let sender_keys = Keys::generate();
        let handler = Nip59Handler::new(server_keys.clone());

        let mut rumor = notification_rumor(sender_keys.public_key());
        rumor.ensure_id();
        let seal_content = sender_keys
            .nip44_encrypt(&server_keys.public_key(), &rumor.as_json())
            .await
            .unwrap();
        let seal = EventBuilder::new(Kind::Seal, seal_content)
            .sign(&sender_keys)
            .await
            .unwrap();

        // Tamper with a signed field after signing: id/signature no longer match.
        let mut seal_value: serde_json::Value = serde_json::from_str(&seal.as_json()).unwrap();
        seal_value["created_at"] = (seal.created_at.as_secs() + 1).into();
        let gift_wrap = wrap_seal_json(&server_keys, &seal_value.to_string()).await;

        let error = handler.unwrap(&gift_wrap).await.unwrap_err().to_string();
        assert!(error.contains("Invalid seal"));
    }

    #[tokio::test]
    async fn test_unwrap_rejects_seal_of_wrong_kind() {
        let server_keys = Keys::generate();
        let sender_keys = Keys::generate();
        let handler = Nip59Handler::new(server_keys.clone());

        let rumor = notification_rumor(sender_keys.public_key());
        let gift_wrap = manual_gift_wrap(&sender_keys, &server_keys, rumor, Kind::TextNote).await;

        let error = handler.unwrap(&gift_wrap).await.unwrap_err().to_string();
        assert!(error.contains("Expected seal (kind 13), got kind 1"));
    }

    #[tokio::test]
    async fn test_unwrap_rejects_undecryptable_seal_content() {
        let server_keys = Keys::generate();
        let sender_keys = Keys::generate();
        let handler = Nip59Handler::new(server_keys.clone());

        let seal = EventBuilder::new(Kind::Seal, "not a nip44 payload")
            .sign(&sender_keys)
            .await
            .unwrap();
        let gift_wrap = wrap_seal_json(&server_keys, &seal.as_json()).await;

        let error = handler.unwrap(&gift_wrap).await.unwrap_err().to_string();
        assert!(error.contains("Failed to decrypt seal"));
    }

    #[tokio::test]
    async fn test_unwrap_rejects_non_json_rumor() {
        let server_keys = Keys::generate();
        let sender_keys = Keys::generate();
        let handler = Nip59Handler::new(server_keys.clone());

        let seal_content = sender_keys
            .nip44_encrypt(&server_keys.public_key(), "not a rumor")
            .await
            .unwrap();
        let seal = EventBuilder::new(Kind::Seal, seal_content)
            .sign(&sender_keys)
            .await
            .unwrap();
        let gift_wrap = wrap_seal_json(&server_keys, &seal.as_json()).await;

        let error = handler.unwrap(&gift_wrap).await.unwrap_err().to_string();
        assert!(error.contains("Failed to parse rumor"));
    }

    #[tokio::test]
    async fn test_unwrap_rejects_forged_rumor_author() {
        let server_keys = Keys::generate();
        let sender_keys = Keys::generate();
        let impersonated_keys = Keys::generate();
        let handler = Nip59Handler::new(server_keys.clone());

        // Seal signed by the sender, but the (unsigned) rumor claims another
        // author. The rumor pubkey is attacker-chosen and must be rejected.
        let rumor = notification_rumor(impersonated_keys.public_key());
        let gift_wrap = EventBuilder::gift_wrap(
            &sender_keys,
            &server_keys.public_key(),
            rumor,
            Vec::<Tag>::new(),
        )
        .await
        .unwrap();

        let error = handler.unwrap(&gift_wrap).await.unwrap_err().to_string();
        assert!(error.contains("Rumor author does not match seal signer"));
    }

    #[tokio::test]
    async fn test_unwrap_rejects_wrong_rumor_kind() {
        let server_keys = Keys::generate();
        let sender_keys = Keys::generate();
        let handler = Nip59Handler::new(server_keys.clone());

        let rumor = EventBuilder::text_note("wrong kind").build(sender_keys.public_key());
        let gift_wrap = EventBuilder::gift_wrap(
            &sender_keys,
            &server_keys.public_key(),
            rumor,
            Vec::<Tag>::new(),
        )
        .await
        .unwrap();

        let error = handler.unwrap(&gift_wrap).await.unwrap_err().to_string();
        assert!(error.contains("Expected notification request (kind 446), got kind 1"));
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
    fn test_parse_rejects_missing_version_tag_value() {
        let notification = UnwrappedNotification {
            content: BASE64_STANDARD.encode(vec![0x01; ENCRYPTED_TOKEN_SIZE]),
            tags: Tags::from_list(vec![
                Tag::parse([TAG_VERSION]).unwrap(),
                Tag::parse([TAG_ENCODING, ENCODING_BASE64]).unwrap(),
            ]),
            created_at: Timestamp::now(),
        };

        let result = notification.parse_tokens();
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Missing value for required v tag")
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
    fn test_parse_accepts_default_max_tokens() {
        let concatenated = vec![0x42; DEFAULT_MAX_TOKENS_PER_EVENT * ENCRYPTED_TOKEN_SIZE];
        let notification = notification(BASE64_STANDARD.encode(&concatenated));

        let tokens = notification.parse_tokens().unwrap();
        assert_eq!(tokens.len(), DEFAULT_MAX_TOKENS_PER_EVENT);
    }

    #[test]
    fn test_parse_rejects_more_than_default_max_tokens_before_decode() {
        let concatenated = vec![0x42; (DEFAULT_MAX_TOKENS_PER_EVENT + 1) * ENCRYPTED_TOKEN_SIZE];
        let notification = notification(BASE64_STANDARD.encode(&concatenated));

        let result = notification.parse_tokens();
        assert!(result.is_err());
        let expected_error = exceeds_max_tokens_message(DEFAULT_MAX_TOKENS_PER_EVENT);
        assert!(result.unwrap_err().to_string().contains(&expected_error));
    }

    #[test]
    fn test_parse_tokens_with_custom_limit() {
        const MAX_TOKENS: usize = 2;

        let concatenated = vec![0x24; MAX_TOKENS * ENCRYPTED_TOKEN_SIZE];
        let within_limit = notification(BASE64_STANDARD.encode(&concatenated));

        let tokens = within_limit.parse_tokens_with_limit(MAX_TOKENS).unwrap();
        assert_eq!(tokens.len(), MAX_TOKENS);

        let concatenated = vec![0x42; (MAX_TOKENS + 1) * ENCRYPTED_TOKEN_SIZE];
        let over_limit = notification(BASE64_STANDARD.encode(&concatenated));

        let result = over_limit.parse_tokens_with_limit(MAX_TOKENS);
        assert!(result.is_err());
        let expected_error = exceeds_max_tokens_message(MAX_TOKENS);
        assert!(result.unwrap_err().to_string().contains(&expected_error));
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
    fn test_parse_succeeds_without_encoding_tag() {
        let token = vec![0x01; ENCRYPTED_TOKEN_SIZE];
        let notification = notification(BASE64_STANDARD.encode(&token));

        let tokens = notification.parse_tokens().unwrap();
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0], token);
    }

    #[test]
    fn test_parse_succeeds_with_encoding_tag() {
        let token = vec![0x01; ENCRYPTED_TOKEN_SIZE];
        let notification = notification_with_encoding(BASE64_STANDARD.encode(&token));

        let tokens = notification.parse_tokens().unwrap();
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0], token);
    }

    #[test]
    fn test_parse_rejects_malformed_encoding_tag_missing_value() {
        let notification = UnwrappedNotification {
            content: BASE64_STANDARD.encode(vec![0x01; ENCRYPTED_TOKEN_SIZE]),
            tags: Tags::from_list(vec![
                Tag::parse([TAG_VERSION, VERSION_MIP05_V1]).unwrap(),
                Tag::parse([TAG_ENCODING]).unwrap(),
            ]),
            created_at: Timestamp::now(),
        };

        let result = notification.parse_tokens();
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Missing value for encoding tag")
        );
    }

    #[test]
    fn test_parse_rejects_duplicate_conflicting_encoding_tags() {
        let notification = UnwrappedNotification {
            content: BASE64_STANDARD.encode(vec![0x01; ENCRYPTED_TOKEN_SIZE]),
            tags: Tags::from_list(vec![
                Tag::parse([TAG_VERSION, VERSION_MIP05_V1]).unwrap(),
                Tag::parse([TAG_ENCODING, ENCODING_BASE64]).unwrap(),
                Tag::parse([TAG_ENCODING, "hex"]).unwrap(),
            ]),
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

    #[test]
    fn test_parse_rejects_invalid_encoding_tag() {
        let notification = UnwrappedNotification {
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
                .contains("Unsupported encoding tag value: hex")
        );
    }

    #[test]
    fn test_tag_value_error_escapes_and_truncates_attacker_content() {
        let long_tail = "B".repeat(512);
        let injected = format!("mip05-v1\n2026-07-03 ERROR forged line {long_tail}");
        let notification = UnwrappedNotification {
            content: BASE64_STANDARD.encode(vec![0x01; ENCRYPTED_TOKEN_SIZE]),
            tags: Tags::parse([[TAG_VERSION, injected.as_str()]]).unwrap(),
            created_at: Timestamp::now(),
        };

        let message = notification.parse_tokens().unwrap_err().to_string();

        assert!(message.contains("Unsupported v tag value"));
        // The raw value must never appear: no control characters, no
        // unbounded content.
        assert!(!message.contains(&injected));
        assert!(
            !message.contains('\n'),
            "control characters must be escaped: {message:?}"
        );
        assert!(
            !message.contains(&long_tail),
            "value must be truncated: {message:?}"
        );
        // The newline survives only in escaped form, and truncation is marked.
        assert!(message.contains("\\n"));
        assert!(message.contains("..."));
    }

    #[test]
    fn test_sanitize_for_error_keeps_short_printable_values() {
        assert_eq!(sanitize_for_error("hex", 32), "hex");
    }

    #[test]
    fn test_sanitize_for_error_escapes_and_truncates() {
        let value = format!("a\nb{}", "c".repeat(64));
        assert_eq!(sanitize_for_error(&value, 8), "a\\nbccccc...");
    }

    #[test]
    fn test_sanitize_for_error_no_marker_at_exact_limit() {
        assert_eq!(sanitize_for_error("abcd", 4), "abcd");
    }
}

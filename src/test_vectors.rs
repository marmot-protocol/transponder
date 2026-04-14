//! Test vectors and utilities for testing the MIP-05 notification flow.
//!
//! This module provides:
//! - Token encryption (the inverse of what the server does for decryption)
//! - Gift-wrapped event creation for kind 446 notification requests
//! - Pre-built test scenarios for integration testing
//!
//! These utilities allow creating realistic test data that exercises the full
//! event processing pipeline from relay receipt to push dispatch.

use ::hkdf::Hkdf;
use ::secp256k1::{Parity, PublicKey, Secp256k1, SecretKey, XOnlyPublicKey};
use base64::prelude::*;
use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, KeyInit},
};
use nostr_sdk::prelude::*;
use sha2::Sha256;

use crate::crypto::token::{ENCRYPTED_TOKEN_SIZE, PLATFORM_APNS, PLATFORM_FCM};

/// MIP-05 HKDF salt for key derivation (same as in token.rs).
const HKDF_SALT: &[u8] = b"mip05-v1";

/// MIP-05 HKDF info string for token encryption key.
const HKDF_INFO: &[u8] = b"mip05-token-encryption";

/// Kind for MIP-05 notification requests.
pub const KIND_NOTIFICATION_REQUEST: u16 = 446;

const TOKEN_PLAINTEXT_SIZE: usize = 220;
const APNS_DEVICE_TOKEN_SIZE: usize = 32;
const MAX_FCM_DEVICE_TOKEN_SIZE: usize = 200;
const TAG_VERSION: &str = "v";
const TAG_ENCODING: &str = "encoding";
const VERSION_MIP05_V1: &str = "mip05-v1";
const ENCODING_BASE64: &str = "base64";

/// A test token that can be encrypted for the server.
#[derive(Debug, Clone)]
pub struct TestToken {
    /// Platform identifier (0x01 = APNs, 0x02 = FCM).
    pub platform: u8,
    /// Device token bytes.
    pub device_token: Vec<u8>,
}

#[allow(dead_code)]
impl TestToken {
    /// Create a test APNs token with a hex device token.
    #[must_use]
    pub fn apns(device_token_hex: &str) -> Self {
        Self {
            platform: PLATFORM_APNS,
            device_token: hex::decode(device_token_hex).expect("valid hex"),
        }
    }

    /// Create a test APNs token with random bytes.
    #[must_use]
    pub fn apns_random() -> Self {
        let mut device_token = vec![0u8; 32];
        getrandom::fill(&mut device_token).expect("random bytes");
        Self {
            platform: PLATFORM_APNS,
            device_token,
        }
    }

    /// Create a test FCM token with a string device token.
    #[must_use]
    pub fn fcm(device_token: &str) -> Self {
        Self {
            platform: PLATFORM_FCM,
            device_token: device_token.as_bytes().to_vec(),
        }
    }

    /// Create a test FCM token with a random string-like token.
    #[must_use]
    pub fn fcm_random() -> Self {
        let mut random_bytes = [0u8; 32];
        getrandom::fill(&mut random_bytes).expect("random bytes");
        let device_token = format!("fcm-token-{}", hex::encode(random_bytes));
        Self {
            platform: PLATFORM_FCM,
            device_token: device_token.into_bytes(),
        }
    }

    /// Get the fixed-size token plaintext used by MIP-05.
    ///
    /// Format: platform || token_length || device_token || random_padding
    fn to_plaintext(&self) -> Vec<u8> {
        match self.platform {
            PLATFORM_APNS => assert_eq!(
                self.device_token.len(),
                APNS_DEVICE_TOKEN_SIZE,
                "APNs token must be 32 bytes"
            ),
            PLATFORM_FCM => assert!(
                (1..=MAX_FCM_DEVICE_TOKEN_SIZE).contains(&self.device_token.len()),
                "FCM token must be 1..=200 bytes"
            ),
            _ => panic!("unsupported test platform"),
        }

        let token_length = self.device_token.len();
        let mut plaintext = vec![0u8; TOKEN_PLAINTEXT_SIZE];
        plaintext[0] = self.platform;
        plaintext[1..3].copy_from_slice(&(token_length as u16).to_be_bytes());
        plaintext[3..(3 + token_length)].copy_from_slice(&self.device_token);
        getrandom::fill(&mut plaintext[(3 + token_length)..]).expect("random bytes");
        plaintext
    }
}

/// Token encryptor for creating test tokens.
///
/// This is the inverse of `TokenDecryptor` - it encrypts tokens that the server
/// can then decrypt.
pub struct TokenEncryptor {
    /// Server's public key (we encrypt to this).
    server_pubkey: PublicKey,
    secp: Secp256k1<secp256k1::All>,
}

impl TokenEncryptor {
    /// Create a new token encryptor targeting the given server public key.
    #[must_use]
    pub fn new(server_pubkey: PublicKey) -> Self {
        Self {
            server_pubkey,
            secp: Secp256k1::new(),
        }
    }

    /// Create from a server's nostr Keys.
    #[must_use]
    pub fn from_keys(keys: &Keys) -> Self {
        let xonly =
            XOnlyPublicKey::from_slice(&keys.public_key().to_bytes()).expect("valid pubkey");
        let server_pubkey = PublicKey::from_x_only_public_key(xonly, Parity::Even);
        Self::new(server_pubkey)
    }

    /// Encrypt a test token.
    ///
    /// Returns the encrypted token bytes (280 bytes total).
    pub fn encrypt(&self, token: &TestToken) -> Vec<u8> {
        // Generate ephemeral keypair
        let mut ephemeral_secret_bytes = [0u8; 32];
        getrandom::fill(&mut ephemeral_secret_bytes).expect("random bytes");
        let ephemeral_secret =
            SecretKey::from_slice(&ephemeral_secret_bytes).expect("valid secret key");
        let ephemeral_pubkey = PublicKey::from_secret_key(&self.secp, &ephemeral_secret);
        let ephemeral_xonly = XOnlyPublicKey::from(ephemeral_pubkey);

        // Perform ECDH to get shared secret
        let shared_point =
            ::secp256k1::ecdh::shared_secret_point(&self.server_pubkey, &ephemeral_secret);
        let shared_x = &shared_point[..32];

        // Derive encryption key using HKDF
        let hkdf = Hkdf::<Sha256>::new(Some(HKDF_SALT), shared_x);
        let mut encryption_key = [0u8; 32];
        hkdf.expand(HKDF_INFO, &mut encryption_key)
            .expect("HKDF expansion should not fail");

        // Generate random nonce
        let mut nonce_bytes = [0u8; 12];
        getrandom::fill(&mut nonce_bytes).expect("random bytes");
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Encrypt using ChaCha20-Poly1305
        let cipher = ChaCha20Poly1305::new_from_slice(&encryption_key).expect("valid key size");
        let plaintext = token.to_plaintext();
        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_ref())
            .expect("encryption should not fail");

        // Assemble encrypted token: ephemeral_pubkey || nonce || ciphertext
        let mut encrypted = Vec::with_capacity(ENCRYPTED_TOKEN_SIZE);
        encrypted.extend_from_slice(&ephemeral_xonly.serialize()); // 32 bytes
        encrypted.extend_from_slice(&nonce_bytes); // 12 bytes
        encrypted.extend_from_slice(&ciphertext); // 236 bytes (220 + 16 tag)

        assert_eq!(encrypted.len(), ENCRYPTED_TOKEN_SIZE);
        encrypted
    }

    /// Encrypt a test token and return as base64.
    pub fn encrypt_base64(&self, token: &TestToken) -> String {
        BASE64_STANDARD.encode(self.encrypt(token))
    }
}

/// Builder for creating kind 446 notification request content.
///
/// The content is one base64 string of concatenated encrypted tokens.
pub struct NotificationContentBuilder {
    encryptor: TokenEncryptor,
    tokens: Vec<Vec<u8>>,
}

#[allow(dead_code)]
impl NotificationContentBuilder {
    /// Create a new builder targeting the given server keys.
    #[must_use]
    pub fn new(server_keys: &Keys) -> Self {
        Self {
            encryptor: TokenEncryptor::from_keys(server_keys),
            tokens: Vec::new(),
        }
    }

    /// Add an APNs token with the given hex device token.
    #[must_use]
    pub fn with_apns_token(mut self, device_token_hex: &str) -> Self {
        let token = TestToken::apns(device_token_hex);
        self.tokens.push(self.encryptor.encrypt(&token));
        self
    }

    /// Add an APNs token with random bytes.
    #[must_use]
    pub fn with_random_apns_token(mut self) -> Self {
        let token = TestToken::apns_random();
        self.tokens.push(self.encryptor.encrypt(&token));
        self
    }

    /// Add an FCM token with the given string device token.
    #[must_use]
    pub fn with_fcm_token(mut self, device_token: &str) -> Self {
        let token = TestToken::fcm(device_token);
        self.tokens.push(self.encryptor.encrypt(&token));
        self
    }

    /// Add a random FCM token.
    #[must_use]
    pub fn with_random_fcm_token(mut self) -> Self {
        let token = TestToken::fcm_random();
        self.tokens.push(self.encryptor.encrypt(&token));
        self
    }

    /// Add a pre-encrypted token (base64 encoded).
    #[must_use]
    pub fn with_raw_token(mut self, base64_token: String) -> Self {
        let token = BASE64_STANDARD
            .decode(base64_token)
            .expect("pre-encrypted token should be valid base64");
        assert_eq!(
            token.len(),
            ENCRYPTED_TOKEN_SIZE,
            "token should be 280 bytes"
        );
        self.tokens.push(token);
        self
    }

    /// Build the base64 content string.
    #[must_use]
    pub fn build(self) -> String {
        let concatenated: Vec<u8> = self.tokens.into_iter().flatten().collect();
        BASE64_STANDARD.encode(concatenated)
    }
}

/// Builder for creating gift-wrapped notification events.
///
/// Creates the full NIP-59 gift wrap structure:
/// - Kind 1059 (gift wrap) containing
/// - Kind 13 (seal) containing
/// - Kind 446 (notification request rumor)
pub struct GiftWrapBuilder {
    server_keys: Keys,
    sender_keys: Keys,
}

#[allow(dead_code)]
impl GiftWrapBuilder {
    /// Create a new gift wrap builder.
    ///
    /// # Arguments
    /// * `server_keys` - The server's keys (recipient of the gift wrap)
    /// * `sender_keys` - The sender's keys (who is sending the notification request)
    #[must_use]
    pub fn new(server_keys: Keys, sender_keys: Keys) -> Self {
        Self {
            server_keys,
            sender_keys,
        }
    }

    /// Build a gift-wrapped notification request event.
    ///
    /// # Arguments
    /// * `content` - The base64 content (concatenated encrypted tokens)
    pub async fn build(&self, content: &str) -> Event {
        // Create the kind 446 rumor (unsigned event)
        let rumor_builder = EventBuilder::new(Kind::Custom(KIND_NOTIFICATION_REQUEST), content)
            .tags([
                Tag::parse([TAG_VERSION, VERSION_MIP05_V1]).expect("valid version tag"),
                Tag::parse([TAG_ENCODING, ENCODING_BASE64]).expect("valid encoding tag"),
            ]);

        // Build the unsigned event (rumor)
        let rumor = rumor_builder.build(self.sender_keys.public_key());

        // Gift wrap it to the server using EventBuilder::gift_wrap
        // This creates the seal internally and wraps it
        EventBuilder::gift_wrap(
            &self.sender_keys,
            &self.server_keys.public_key(),
            rumor,
            Vec::<Tag>::new(),
        )
        .await
        .expect("gift wrap creation should not fail")
    }

    /// Build a gift-wrapped notification request with the given tokens.
    pub async fn build_with_tokens(&self, tokens: Vec<TestToken>) -> Event {
        let encryptor = TokenEncryptor::from_keys(&self.server_keys);
        let content = tokens
            .into_iter()
            .fold(
                NotificationContentBuilder::new(&self.server_keys),
                |builder, token| builder.with_raw_token(encryptor.encrypt_base64(&token)),
            )
            .build();
        self.build(&content).await
    }
}

/// Pre-built test scenarios for common test cases.
#[allow(dead_code)]
pub mod scenarios {
    use super::*;

    /// Create a simple notification with one APNs token.
    pub async fn single_apns_notification(
        server_keys: &Keys,
        sender_keys: &Keys,
        device_token_hex: &str,
    ) -> Event {
        let content = NotificationContentBuilder::new(server_keys)
            .with_apns_token(device_token_hex)
            .build();

        GiftWrapBuilder::new(server_keys.clone(), sender_keys.clone())
            .build(&content)
            .await
    }

    /// Create a simple notification with one FCM token.
    pub async fn single_fcm_notification(
        server_keys: &Keys,
        sender_keys: &Keys,
        device_token: &str,
    ) -> Event {
        let content = NotificationContentBuilder::new(server_keys)
            .with_fcm_token(device_token)
            .build();

        GiftWrapBuilder::new(server_keys.clone(), sender_keys.clone())
            .build(&content)
            .await
    }

    /// Create a notification with multiple tokens (mixed platforms).
    pub async fn multi_token_notification(server_keys: &Keys, sender_keys: &Keys) -> Event {
        let content = NotificationContentBuilder::new(server_keys)
            .with_random_apns_token()
            .with_random_apns_token()
            .with_random_fcm_token()
            .build();

        GiftWrapBuilder::new(server_keys.clone(), sender_keys.clone())
            .build(&content)
            .await
    }

    /// Create a notification with an empty token blob.
    pub async fn empty_notification(server_keys: &Keys, sender_keys: &Keys) -> Event {
        let content = "";

        GiftWrapBuilder::new(server_keys.clone(), sender_keys.clone())
            .build(content)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::TokenDecryptor;

    #[test]
    fn test_token_encryption_roundtrip() {
        // Generate server keys
        let server_keys = Keys::generate();
        let mut secp_secret_key =
            SecretKey::from_slice(&server_keys.secret_key().to_secret_bytes())
                .expect("valid secret key");
        let decryptor = TokenDecryptor::new(&mut secp_secret_key);
        let encryptor = TokenEncryptor::from_keys(&server_keys);

        // Create and encrypt a test token
        let test_token =
            TestToken::apns("deadbeef1234567890abcdefdeadbeef1234567890abcdefdeadbeef12345678");
        let encrypted = encryptor.encrypt(&test_token);

        // Verify size
        assert_eq!(encrypted.len(), ENCRYPTED_TOKEN_SIZE);

        // Decrypt and verify
        let payload = decryptor.decrypt_bytes(&encrypted).unwrap();
        assert_eq!(payload.platform, crate::crypto::Platform::Apns);
        assert_eq!(payload.device_token, test_token.device_token);
    }

    #[test]
    fn test_fcm_token_roundtrip() {
        let server_keys = Keys::generate();
        let mut secp_secret_key =
            SecretKey::from_slice(&server_keys.secret_key().to_secret_bytes())
                .expect("valid secret key");
        let decryptor = TokenDecryptor::new(&mut secp_secret_key);
        let encryptor = TokenEncryptor::from_keys(&server_keys);

        let test_token = TestToken::fcm("test-fcm-device-token-12345");
        let encrypted = encryptor.encrypt(&test_token);
        let payload = decryptor.decrypt_bytes(&encrypted).unwrap();

        assert_eq!(payload.platform, crate::crypto::Platform::Fcm);
        assert_eq!(
            payload.device_token_string(),
            Some("test-fcm-device-token-12345".to_string())
        );
    }

    #[test]
    fn test_notification_content_builder() {
        let server_keys = Keys::generate();

        let content = NotificationContentBuilder::new(&server_keys)
            .with_apns_token("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
            .with_fcm_token("fcm-token")
            .build();

        let decoded = BASE64_STANDARD.decode(&content).unwrap();
        assert_eq!(decoded.len(), ENCRYPTED_TOKEN_SIZE * 2);
    }

    #[tokio::test]
    async fn test_gift_wrap_creation() {
        let server_keys = Keys::generate();
        let sender_keys = Keys::generate();

        let content = NotificationContentBuilder::new(&server_keys)
            .with_random_apns_token()
            .build();

        let event = GiftWrapBuilder::new(server_keys.clone(), sender_keys.clone())
            .build(&content)
            .await;

        // Verify it's a gift wrap
        assert_eq!(event.kind, Kind::GiftWrap);

        // Verify it's addressed to the server
        let p_tag = event.tags.iter().find(|t| t.kind() == TagKind::p());
        assert!(p_tag.is_some());
    }

    #[tokio::test]
    async fn test_gift_wrap_unwrap_roundtrip() {
        use crate::crypto::Nip59Handler;

        let server_keys = Keys::generate();
        let sender_keys = Keys::generate();

        // Create notification content
        let content = NotificationContentBuilder::new(&server_keys)
            .with_apns_token("deadbeef1234567890abcdefdeadbeef1234567890abcdefdeadbeef12345678")
            .build();

        // Create gift wrap
        let gift_wrap = GiftWrapBuilder::new(server_keys.clone(), sender_keys.clone())
            .build(&content)
            .await;

        // Unwrap it
        let handler = Nip59Handler::new(server_keys.clone());
        let unwrapped = handler.unwrap(&gift_wrap).await.unwrap();

        // Verify sender
        assert_eq!(unwrapped.sender_pubkey, sender_keys.public_key());

        // Verify content is parseable
        let tokens = unwrapped.parse_tokens().unwrap();
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].len(), ENCRYPTED_TOKEN_SIZE);
    }

    #[tokio::test]
    async fn test_full_decryption_roundtrip() {
        use crate::crypto::{Nip59Handler, TokenDecryptor};

        let server_keys = Keys::generate();
        let sender_keys = Keys::generate();
        let device_token_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

        // Create gift-wrapped notification
        let gift_wrap =
            scenarios::single_apns_notification(&server_keys, &sender_keys, device_token_hex).await;

        // Process like the server would
        let nip59_handler = Nip59Handler::new(server_keys.clone());
        let mut secp_secret_key =
            SecretKey::from_slice(&server_keys.secret_key().to_secret_bytes())
                .expect("valid secret key");
        let token_decryptor = TokenDecryptor::new(&mut secp_secret_key);

        // Unwrap
        let notification = nip59_handler.unwrap(&gift_wrap).await.unwrap();

        // Parse tokens
        let token_bytes = notification.parse_tokens().unwrap();
        assert_eq!(token_bytes.len(), 1);

        // Decrypt token
        let payload = token_decryptor.decrypt_bytes(&token_bytes[0]).unwrap();
        assert_eq!(payload.platform, crate::crypto::Platform::Apns);
        assert_eq!(payload.device_token_hex(), device_token_hex);
    }
}

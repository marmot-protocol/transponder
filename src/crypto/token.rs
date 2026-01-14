//! MIP-05 token decryption implementation.
//!
//! Handles encrypted token parsing and decryption using:
//! - ECDH key agreement with secp256k1
//! - HKDF-SHA256 key derivation
//! - ChaCha20-Poly1305 authenticated encryption
//!
//! # Security
//!
//! All sensitive cryptographic material (keys, shared secrets, decrypted tokens)
//! is automatically zeroed from memory when dropped using the `zeroize` crate.

use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, KeyInit},
};
use hkdf::Hkdf;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::{Error, Result};

/// MIP-05 HKDF salt for key derivation.
const HKDF_SALT: &[u8] = b"mip05-v1";

/// MIP-05 HKDF info string for token encryption key.
const HKDF_INFO: &[u8] = b"mip05-token-encryption";

/// Expected size of the encrypted token (280 bytes total).
/// - 33 bytes: compressed ephemeral public key
/// - 12 bytes: nonce
/// - 235 bytes: ciphertext (219 payload + 16 auth tag)
pub const ENCRYPTED_TOKEN_SIZE: usize = 280;

/// Size of compressed secp256k1 public key.
const PUBKEY_SIZE: usize = 33;

/// Size of ChaCha20-Poly1305 nonce.
const NONCE_SIZE: usize = 12;

/// Platform identifier for APNs (iOS).
pub const PLATFORM_APNS: u8 = 0x01;

/// Platform identifier for FCM (Android).
pub const PLATFORM_FCM: u8 = 0x02;

/// Push notification platform.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    /// Apple Push Notification Service (iOS).
    Apns,
    /// Firebase Cloud Messaging (Android).
    Fcm,
}

impl Platform {
    /// Parse platform from byte identifier.
    pub fn from_byte(byte: u8) -> Result<Self> {
        match byte {
            PLATFORM_APNS => Ok(Platform::Apns),
            PLATFORM_FCM => Ok(Platform::Fcm),
            _ => Err(Error::InvalidToken(format!(
                "Unknown platform identifier: 0x{byte:02x}"
            ))),
        }
    }
}

/// Parsed encrypted token structure.
///
/// # Security
///
/// This struct implements `ZeroizeOnDrop` to ensure all fields are zeroed
/// when the token goes out of scope, preventing sensitive data from lingering
/// in memory.
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct EncryptedToken {
    /// Compressed ephemeral public key (33 bytes).
    pub ephemeral_pubkey: [u8; PUBKEY_SIZE],
    /// ChaCha20-Poly1305 nonce (12 bytes).
    pub nonce: [u8; NONCE_SIZE],
    /// Ciphertext including auth tag.
    pub ciphertext: Vec<u8>,
}

impl EncryptedToken {
    /// Parse an encrypted token from raw bytes.
    ///
    /// Expected format:
    /// - Bytes 0-32: Compressed ephemeral public key
    /// - Bytes 33-44: Nonce
    /// - Bytes 45-279: Ciphertext with auth tag
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() != ENCRYPTED_TOKEN_SIZE {
            return Err(Error::InvalidToken(format!(
                "Invalid token size: expected {ENCRYPTED_TOKEN_SIZE}, got {}",
                data.len()
            )));
        }

        let mut ephemeral_pubkey = [0u8; PUBKEY_SIZE];
        ephemeral_pubkey.copy_from_slice(&data[0..PUBKEY_SIZE]);

        let mut nonce = [0u8; NONCE_SIZE];
        nonce.copy_from_slice(&data[PUBKEY_SIZE..PUBKEY_SIZE + NONCE_SIZE]);

        let ciphertext = data[PUBKEY_SIZE + NONCE_SIZE..].to_vec();

        Ok(Self {
            ephemeral_pubkey,
            nonce,
            ciphertext,
        })
    }
}

/// Decrypted token payload.
///
/// # Security
///
/// This struct implements `ZeroizeOnDrop` to ensure the device token is zeroed
/// when the payload goes out of scope, preventing sensitive data from lingering
/// in memory.
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct TokenPayload {
    /// Target platform (APNs or FCM).
    #[zeroize(skip)]
    pub platform: Platform,
    /// Device token for push notification.
    pub device_token: Vec<u8>,
}

impl TokenPayload {
    /// Parse a decrypted payload, removing PKCS#7 padding.
    ///
    /// Payload format:
    /// - Byte 0: Platform identifier (0x01 = APNs, 0x02 = FCM)
    /// - Bytes 1-N: Device token
    /// - Remaining: PKCS#7 padding
    pub fn from_decrypted(data: &[u8]) -> Result<Self> {
        if data.is_empty() {
            return Err(Error::InvalidToken("Empty decrypted payload".to_string()));
        }

        // Remove PKCS#7 padding
        let padding_len = *data.last().unwrap() as usize;
        if padding_len == 0 || padding_len > data.len() {
            return Err(Error::InvalidToken("Invalid PKCS#7 padding".to_string()));
        }

        // Verify padding bytes
        for &byte in &data[data.len() - padding_len..] {
            if byte as usize != padding_len {
                return Err(Error::InvalidToken("Invalid PKCS#7 padding".to_string()));
            }
        }

        let unpadded = &data[..data.len() - padding_len];
        if unpadded.is_empty() {
            return Err(Error::InvalidToken(
                "Payload empty after removing padding".to_string(),
            ));
        }

        let platform = Platform::from_byte(unpadded[0])?;
        let device_token = unpadded[1..].to_vec();

        if device_token.is_empty() {
            return Err(Error::InvalidToken("Empty device token".to_string()));
        }

        Ok(Self {
            platform,
            device_token,
        })
    }

    /// Get the device token as a hex string (for APNs).
    #[must_use]
    pub fn device_token_hex(&self) -> String {
        hex::encode(&self.device_token)
    }

    /// Get the device token as a string (for FCM).
    #[must_use]
    pub fn device_token_string(&self) -> Option<String> {
        String::from_utf8(self.device_token.clone()).ok()
    }
}

/// Token decryptor using server's private key.
#[derive(Clone)]
pub struct TokenDecryptor {
    secret_key: SecretKey,
    #[allow(dead_code)]
    secp: Secp256k1<secp256k1::All>,
}

impl TokenDecryptor {
    /// Create a new token decryptor with the given secret key.
    ///
    /// # Arguments
    ///
    /// * `secret_key` - The server's secp256k1 secret key for ECDH key agreement
    pub fn new(secret_key: SecretKey) -> Self {
        Self {
            secret_key,
            secp: Secp256k1::new(),
        }
    }

    /// Decrypt an encrypted token.
    ///
    /// Process:
    /// 1. Parse ephemeral public key from token
    /// 2. Perform ECDH to get shared secret
    /// 3. Derive encryption key using HKDF
    /// 4. Decrypt ciphertext using ChaCha20-Poly1305
    /// 5. Parse and return the payload
    ///
    /// # Security
    ///
    /// All intermediate cryptographic material (shared secrets, derived keys,
    /// plaintext buffers) is automatically zeroed when this function returns.
    pub fn decrypt(&self, token: &EncryptedToken) -> Result<TokenPayload> {
        // Parse ephemeral public key
        let ephemeral_pubkey = PublicKey::from_slice(&token.ephemeral_pubkey)
            .map_err(|e| Error::Crypto(format!("Invalid ephemeral public key: {e}")))?;

        // Perform ECDH to get shared point (wrapped for zeroization)
        let shared_point: Zeroizing<[u8; 64]> = Zeroizing::new(
            secp256k1::ecdh::shared_secret_point(&ephemeral_pubkey, &self.secret_key),
        );

        // Use only the x-coordinate (first 32 bytes) as the shared secret
        let shared_x: Zeroizing<[u8; 32]> = {
            let mut x = [0u8; 32];
            x.copy_from_slice(&shared_point[..32]);
            Zeroizing::new(x)
        };

        // Derive encryption key using HKDF (wrapped for zeroization)
        let hkdf = Hkdf::<Sha256>::new(Some(HKDF_SALT), shared_x.as_ref());
        let encryption_key: Zeroizing<[u8; 32]> = {
            let mut key = [0u8; 32];
            hkdf.expand(HKDF_INFO, &mut key)
                .map_err(|e| Error::Crypto(format!("HKDF expansion failed: {e}")))?;
            Zeroizing::new(key)
        };

        // Decrypt using ChaCha20-Poly1305
        let cipher = ChaCha20Poly1305::new_from_slice(encryption_key.as_ref())
            .map_err(|e| Error::Crypto(format!("Failed to create cipher: {e}")))?;
        let nonce = Nonce::from_slice(&token.nonce);

        // Wrap plaintext for zeroization
        let plaintext: Zeroizing<Vec<u8>> = Zeroizing::new(
            cipher
                .decrypt(nonce, token.ciphertext.as_ref())
                .map_err(|e| Error::Crypto(format!("Decryption failed: {e}")))?,
        );

        // Parse the decrypted payload
        TokenPayload::from_decrypted(&plaintext)
    }

    /// Decrypt a token from raw bytes.
    pub fn decrypt_bytes(&self, data: &[u8]) -> Result<TokenPayload> {
        let token = EncryptedToken::from_bytes(data)?;
        self.decrypt(&token)
    }

    /// Get the public key corresponding to this decryptor's secret key.
    #[must_use]
    #[allow(dead_code)]
    pub fn public_key(&self) -> PublicKey {
        PublicKey::from_secret_key(&self.secp, &self.secret_key)
    }

    /// Get the public key as a hex string (x-only, 32 bytes).
    #[must_use]
    #[allow(dead_code)]
    pub fn public_key_hex(&self) -> String {
        let (xonly, _parity) = self.public_key().x_only_public_key();
        hex::encode(xonly.serialize())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_platform_from_byte() {
        assert_eq!(Platform::from_byte(0x01).unwrap(), Platform::Apns);
        assert_eq!(Platform::from_byte(0x02).unwrap(), Platform::Fcm);
        assert!(Platform::from_byte(0x00).is_err());
        assert!(Platform::from_byte(0x03).is_err());
    }

    #[test]
    fn test_encrypted_token_wrong_size() {
        let data = vec![0u8; 100];
        assert!(EncryptedToken::from_bytes(&data).is_err());
    }

    #[test]
    fn test_encrypted_token_correct_size() {
        let data = vec![0u8; ENCRYPTED_TOKEN_SIZE];
        let result = EncryptedToken::from_bytes(&data);
        assert!(result.is_ok());
        let token = result.unwrap();
        assert_eq!(token.ephemeral_pubkey.len(), PUBKEY_SIZE);
        assert_eq!(token.nonce.len(), NONCE_SIZE);
        assert_eq!(
            token.ciphertext.len(),
            ENCRYPTED_TOKEN_SIZE - PUBKEY_SIZE - NONCE_SIZE
        );
    }

    #[test]
    fn test_token_payload_parsing() {
        // Platform byte + device token + PKCS#7 padding (3 bytes of 0x03)
        let data = vec![0x01, 0xaa, 0xbb, 0xcc, 0x03, 0x03, 0x03];
        let payload = TokenPayload::from_decrypted(&data).unwrap();
        assert_eq!(payload.platform, Platform::Apns);
        assert_eq!(payload.device_token, vec![0xaa, 0xbb, 0xcc]);
    }

    #[test]
    fn test_token_payload_invalid_padding() {
        // Invalid padding (mismatched bytes)
        let data = vec![0x01, 0xaa, 0xbb, 0x02, 0x03];
        assert!(TokenPayload::from_decrypted(&data).is_err());
    }

    #[test]
    fn test_token_decryptor_creation() {
        use nostr_sdk::prelude::Keys;

        let keys = Keys::generate();
        let secret_bytes = keys.secret_key().to_secret_bytes();
        let secret_key = SecretKey::from_slice(&secret_bytes).unwrap();
        let decryptor = TokenDecryptor::new(secret_key);
        assert_eq!(decryptor.public_key_hex(), keys.public_key().to_hex());
    }

    #[test]
    fn test_device_token_hex() {
        let payload = TokenPayload {
            platform: Platform::Apns,
            device_token: vec![0xde, 0xad, 0xbe, 0xef],
        };
        assert_eq!(payload.device_token_hex(), "deadbeef");
    }

    #[test]
    fn test_device_token_string() {
        let payload = TokenPayload {
            platform: Platform::Fcm,
            device_token: b"test-token-123".to_vec(),
        };
        assert_eq!(
            payload.device_token_string(),
            Some("test-token-123".to_string())
        );
    }

    #[test]
    fn test_device_token_string_invalid_utf8() {
        let payload = TokenPayload {
            platform: Platform::Fcm,
            device_token: vec![0xff, 0xfe, 0x00, 0x01], // Invalid UTF-8
        };
        assert_eq!(payload.device_token_string(), None);
    }

    #[test]
    fn test_token_payload_empty_data() {
        let data: Vec<u8> = vec![];
        let result = TokenPayload::from_decrypted(&data);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("Empty decrypted payload"));
    }

    #[test]
    fn test_token_payload_fcm_platform() {
        // FCM platform byte (0x02) + device token + PKCS#7 padding (2 bytes of 0x02)
        let data = vec![0x02, 0x64, 0x65, 0x76, 0x69, 0x63, 0x65, 0x02, 0x02];
        let payload = TokenPayload::from_decrypted(&data).unwrap();
        assert_eq!(payload.platform, Platform::Fcm);
        assert_eq!(
            payload.device_token,
            vec![0x64, 0x65, 0x76, 0x69, 0x63, 0x65]
        ); // "device"
    }

    #[test]
    fn test_token_payload_padding_zero() {
        // Padding of 0 is invalid
        let data = vec![0x01, 0xaa, 0x00];
        let result = TokenPayload::from_decrypted(&data);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Invalid PKCS#7 padding")
        );
    }

    #[test]
    fn test_token_payload_padding_too_large() {
        // Padding larger than data length is invalid
        let data = vec![0x01, 0xaa, 0x10]; // 0x10 = 16, but data is only 3 bytes
        let result = TokenPayload::from_decrypted(&data);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Invalid PKCS#7 padding")
        );
    }

    #[test]
    fn test_token_payload_empty_after_padding() {
        // After removing padding, only the data would be empty (all padding)
        let data = vec![0x03, 0x03, 0x03]; // 3 bytes of 0x03 padding = empty payload
        let result = TokenPayload::from_decrypted(&data);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Payload empty after removing padding")
        );
    }

    #[test]
    fn test_token_payload_empty_device_token() {
        // Platform byte + 1 byte of padding (no device token)
        let data = vec![0x01, 0x01]; // Platform byte 0x01, then 1 byte of 0x01 padding
        let result = TokenPayload::from_decrypted(&data);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Empty device token")
        );
    }

    #[test]
    fn test_encrypted_token_parses_correctly() {
        // Create a token with specific byte patterns to verify parsing
        let mut data = vec![0u8; ENCRYPTED_TOKEN_SIZE];

        // Set ephemeral pubkey bytes (first 33)
        for (i, byte) in data.iter_mut().take(PUBKEY_SIZE).enumerate() {
            *byte = i as u8;
        }

        // Set nonce bytes (next 12)
        for (i, byte) in data
            .iter_mut()
            .skip(PUBKEY_SIZE)
            .take(NONCE_SIZE)
            .enumerate()
        {
            *byte = (i + 100) as u8;
        }

        // Set ciphertext bytes (remaining)
        let ciphertext_offset = PUBKEY_SIZE + NONCE_SIZE;
        for (i, byte) in data
            .iter_mut()
            .skip(ciphertext_offset)
            .take(ENCRYPTED_TOKEN_SIZE - ciphertext_offset)
            .enumerate()
        {
            *byte = ((ciphertext_offset + i) % 256) as u8;
        }

        let token = EncryptedToken::from_bytes(&data).unwrap();

        // Verify ephemeral pubkey and nonce were parsed correctly
        assert_eq!(&token.ephemeral_pubkey[..], &data[..PUBKEY_SIZE]);
        assert_eq!(
            &token.nonce[..],
            &data[PUBKEY_SIZE..(PUBKEY_SIZE + NONCE_SIZE)]
        );

        // Verify ciphertext
        assert_eq!(
            token.ciphertext.len(),
            ENCRYPTED_TOKEN_SIZE - PUBKEY_SIZE - NONCE_SIZE
        );
        assert_eq!(token.ciphertext, data[ciphertext_offset..].to_vec());
    }

    #[test]
    fn test_encrypted_token_too_small() {
        let data = vec![0u8; ENCRYPTED_TOKEN_SIZE - 1];
        let result = EncryptedToken::from_bytes(&data);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("Invalid token size"));
        assert!(
            err.to_string()
                .contains(&format!("{}", ENCRYPTED_TOKEN_SIZE - 1))
        );
    }

    #[test]
    fn test_encrypted_token_too_large() {
        let data = vec![0u8; ENCRYPTED_TOKEN_SIZE + 1];
        let result = EncryptedToken::from_bytes(&data);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("Invalid token size"));
    }

    #[test]
    fn test_encrypted_token_empty() {
        let data: Vec<u8> = vec![];
        let result = EncryptedToken::from_bytes(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_platform_display_coverage() {
        // Test that unknown platforms give informative error messages
        let err = Platform::from_byte(0xff).unwrap_err();
        assert!(err.to_string().contains("0xff"));

        let err = Platform::from_byte(0x00).unwrap_err();
        assert!(err.to_string().contains("0x00"));
    }
}

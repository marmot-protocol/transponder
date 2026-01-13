//! Error types for Transponder.

use thiserror::Error;

/// Main error type for Transponder operations.
#[derive(Debug, Error)]
pub enum Error {
    /// Configuration loading or parsing error.
    #[error("Configuration error: {0}")]
    Config(#[from] config::ConfigError),

    /// Cryptographic operation error.
    #[error("Crypto error: {0}")]
    Crypto(String),

    /// Nostr protocol or relay error.
    #[error("Nostr error: {0}")]
    Nostr(String),

    /// APNs push notification error.
    #[error("APNs error: {0}")]
    Apns(String),

    /// FCM push notification error.
    #[error("FCM error: {0}")]
    Fcm(String),

    /// Invalid or malformed token.
    #[error("Invalid token: {0}")]
    InvalidToken(String),

    /// IO error.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// HTTP request error.
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON serialization/deserialization error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// JWT token error.
    #[error("JWT error: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),

    /// Base64 decoding error.
    #[error("Base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),

    /// Hex decoding error.
    #[error("Hex decode error: {0}")]
    Hex(#[from] hex::FromHexError),
}

/// Result type alias using our Error type.
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display_crypto() {
        let err = Error::Crypto("test crypto error".to_string());
        assert_eq!(err.to_string(), "Crypto error: test crypto error");
    }

    #[test]
    fn test_error_display_nostr() {
        let err = Error::Nostr("relay disconnected".to_string());
        assert_eq!(err.to_string(), "Nostr error: relay disconnected");
    }

    #[test]
    fn test_error_display_apns() {
        let err = Error::Apns("bad device token".to_string());
        assert_eq!(err.to_string(), "APNs error: bad device token");
    }

    #[test]
    fn test_error_display_fcm() {
        let err = Error::Fcm("invalid registration".to_string());
        assert_eq!(err.to_string(), "FCM error: invalid registration");
    }

    #[test]
    fn test_error_display_invalid_token() {
        let err = Error::InvalidToken("malformed token data".to_string());
        assert_eq!(err.to_string(), "Invalid token: malformed token data");
    }

    #[test]
    fn test_error_from_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let err: Error = io_err.into();
        assert!(err.to_string().contains("IO error"));
        assert!(err.to_string().contains("file not found"));
    }

    #[test]
    fn test_error_from_json() {
        let json_err = serde_json::from_str::<String>("not valid json").unwrap_err();
        let err: Error = json_err.into();
        assert!(err.to_string().contains("JSON error"));
    }

    #[test]
    fn test_error_from_hex() {
        let hex_err = hex::decode("not hex!").unwrap_err();
        let err: Error = hex_err.into();
        assert!(err.to_string().contains("Hex decode error"));
    }

    #[test]
    fn test_error_from_base64() {
        use base64::prelude::*;
        let b64_err = BASE64_STANDARD.decode("not valid base64!!!").unwrap_err();
        let err: Error = b64_err.into();
        assert!(err.to_string().contains("Base64 decode error"));
    }

    #[test]
    fn test_error_debug_impl() {
        let err = Error::Crypto("test".to_string());
        let debug_str = format!("{:?}", err);
        assert!(debug_str.contains("Crypto"));
        assert!(debug_str.contains("test"));
    }
}

//! Transponder - MIP-05 Push Notification Server
//!
//! A privacy-preserving push notification server implementing the Marmot MIP-05
//! specification.

pub mod app;
pub mod config;
pub mod crypto;
pub mod defaults;
pub mod error;
pub mod metrics;
pub mod nostr;
pub mod push;
pub mod rate_limiter;
pub mod redaction;
pub mod server;
pub mod shutdown;
pub mod telemetry;

#[cfg(test)]
pub(crate) mod test_metrics;
#[cfg(test)]
pub(crate) mod test_vectors;

pub use app::run;

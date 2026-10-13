use std::borrow::Cow;

use nostr::types::RelayUrl;

use crate::error::Error;

// TODO: replace this implementation with a trait before the v1.0

/// Relay URL argument.
///
/// This type allows passing different types to methods that accept a relay URL.
#[derive(Debug, Clone)]
pub enum RelayUrlArg<'a> {
    /// An already parsed relay URL.
    Parsed(Cow<'a, RelayUrl>),
    /// A relay URL string that has to be parsed.
    String(Cow<'a, str>),
}

impl<'a> RelayUrlArg<'a> {
    /// Convert into [`RelayUrl`] without consuming self.
    #[inline]
    pub fn try_as_relay_url(&'a self) -> Result<Cow<'a, RelayUrl>, Error> {
        match self {
            Self::Parsed(url) => Ok(Cow::Borrowed(url.as_ref())),
            Self::String(s) => Ok(Cow::Owned(RelayUrl::parse(s)?)),
        }
    }

    /// Convert into [`RelayUrl`].
    #[inline]
    pub fn try_into_relay_url(self) -> Result<Cow<'a, RelayUrl>, Error> {
        match self {
            Self::Parsed(url) => Ok(url),
            Self::String(s) => Ok(Cow::Owned(RelayUrl::parse(&s)?)),
        }
    }
}

impl From<RelayUrl> for RelayUrlArg<'_> {
    fn from(url: RelayUrl) -> Self {
        Self::Parsed(Cow::Owned(url))
    }
}

impl<'a> From<&'a RelayUrl> for RelayUrlArg<'a> {
    fn from(url: &'a RelayUrl) -> Self {
        Self::Parsed(Cow::Borrowed(url))
    }
}

impl<'a> From<Cow<'a, RelayUrl>> for RelayUrlArg<'a> {
    fn from(url: Cow<'a, RelayUrl>) -> Self {
        Self::Parsed(url)
    }
}

impl From<String> for RelayUrlArg<'_> {
    fn from(s: String) -> Self {
        Self::String(Cow::Owned(s))
    }
}

impl<'a> From<&'a String> for RelayUrlArg<'a> {
    fn from(s: &'a String) -> Self {
        Self::String(Cow::Borrowed(s))
    }
}

impl<'a> From<&'a str> for RelayUrlArg<'a> {
    fn from(s: &'a str) -> Self {
        Self::String(Cow::Borrowed(s))
    }
}

impl<'a> From<Cow<'a, str>> for RelayUrlArg<'a> {
    fn from(s: Cow<'a, str>) -> Self {
        Self::String(s)
    }
}

//! Errors from configuring and running the watcher.

use std::error::Error;
use std::fmt;
use std::path::PathBuf;

use keri_cesr::crypto::error::CryptoError;
use keri_kel::{KelError, StoreError};
use keri_protocol::attachment::AttachmentError;
use keri_protocol::event::EventError;
use keri_protocol::event::timestamp::TimestampError;
use keri_protocol::prefix::PrefixError;
use keri_protocol::said::SaidError;
use keri_protocol::stream::StreamError;
use keri_watch::WatchError;

/// Why the watcher could not start, or could not handle what it was sent.
#[derive(Debug)]
#[non_exhaustive]
pub enum WatcherError {
    /// A file could not be read or written.
    File {
        /// The file.
        path: PathBuf,
        /// Underlying failure.
        source: std::io::Error,
    },
    /// The configuration is not valid TOML of the expected shape.
    Config {
        /// Underlying failure.
        source: Box<toml::de::Error>,
    },
    /// A URL the watcher is to announce is not `http` or `https`.
    Url {
        /// The URL.
        url: String,
    },
    /// An identifier in the configuration or the identity is not valid.
    Prefix {
        /// Underlying failure.
        source: PrefixError,
    },
    /// The identity's salt is not valid, or its key could not be derived or sign.
    Key {
        /// Underlying failure.
        source: CryptoError,
    },
    /// The store could not be opened, or failed.
    Store {
        /// Underlying failure.
        source: StoreError,
    },
    /// A SAID could not be written as qb64.
    Said {
        /// Underlying failure.
        source: SaidError,
    },
    /// The clock gave a time that is not a valid timestamp.
    Clock {
        /// Underlying failure.
        source: TimestampError,
    },
    /// What was sent is not a CESR stream.
    Stream {
        /// Underlying failure.
        source: StreamError,
    },
    /// What was sent to be answered is not a single query.
    NotAQuery,
    /// keri-kel failed for a reason other than refusing a message, such as the store failing.
    Kel {
        /// Underlying failure.
        source: Box<KelError>,
    },
    /// An answer could not be written.
    Answer {
        /// Underlying failure.
        source: Box<dyn Error + Send + Sync>,
    },
    /// An identifier could not be planned or tracked.
    Watch {
        /// Underlying failure.
        source: WatchError,
    },
    /// The listening address could not be bound, or serving failed.
    Serve {
        /// Underlying failure.
        source: std::io::Error,
    },
    /// Handling a request stopped before it finished.
    Interrupted,
}

impl WatcherError {
    pub(crate) fn kel(source: KelError) -> Self {
        Self::Kel {
            source: Box::new(source),
        }
    }

    pub(crate) fn answer(source: impl Into<Box<dyn Error + Send + Sync>>) -> Self {
        Self::Answer { source: source.into() }
    }
}

impl From<EventError> for WatcherError {
    fn from(source: EventError) -> Self {
        Self::answer(source)
    }
}

impl From<AttachmentError> for WatcherError {
    fn from(source: AttachmentError) -> Self {
        Self::answer(source)
    }
}

impl fmt::Display for WatcherError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::File { path, .. } => write!(formatter, "{} could not be read or written", path.display()),
            Self::Config { .. } => formatter.write_str("configuration is not valid"),
            Self::Url { url } => write!(formatter, "{url} is not an http or https URL"),
            Self::Prefix { .. } => formatter.write_str("identifier is not valid"),
            Self::Key { .. } => formatter.write_str("identity key could not be derived or sign"),
            Self::Store { .. } => formatter.write_str("store could not be opened, or failed"),
            Self::Said { .. } => formatter.write_str("SAID could not be written"),
            Self::Clock { .. } => formatter.write_str("clock gave an invalid timestamp"),
            Self::Stream { .. } => formatter.write_str("body is not a CESR stream"),
            Self::NotAQuery => formatter.write_str("body is not a single query"),
            Self::Kel { .. } => formatter.write_str("key event log processing failed"),
            Self::Answer { .. } => formatter.write_str("answer could not be written"),
            Self::Watch { .. } => formatter.write_str("identifier could not be planned or tracked"),
            Self::Serve { .. } => formatter.write_str("HTTP could not be served"),
            Self::Interrupted => formatter.write_str("request handling stopped before it finished"),
        }
    }
}

impl Error for WatcherError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::File { source, .. } | Self::Serve { source } => Some(source),
            Self::Config { source } => Some(source.as_ref()),
            Self::Prefix { source } => Some(source),
            Self::Key { source } => Some(source),
            Self::Store { source } => Some(source),
            Self::Said { source } => Some(source),
            Self::Clock { source } => Some(source),
            Self::Stream { source } => Some(source),
            Self::Url { .. } | Self::NotAQuery | Self::Interrupted => None,
            Self::Kel { source } => Some(source.as_ref()),
            Self::Answer { source } => Some(source.as_ref()),
            Self::Watch { source } => Some(source),
        }
    }
}

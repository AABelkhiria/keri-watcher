//! Failures of the watcher's decisions.

use core::fmt;
use std::error::Error;

use keri_protocol::prefix::PrefixError;

/// Why a decision could not be made.
#[derive(Debug)]
#[non_exhaustive]
pub enum WatchError {
    /// Reports to be merged are about different identifiers.
    MixedIdentifiers,
    /// An identifier could not be written as qb64.
    Prefix {
        /// Underlying prefix failure.
        source: Box<PrefixError>,
    },
}

impl WatchError {
    pub(crate) fn prefix(source: PrefixError) -> Self {
        Self::Prefix {
            source: Box::new(source),
        }
    }
}

impl fmt::Display for WatchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MixedIdentifiers => formatter.write_str("reports are about different identifiers"),
            Self::Prefix { .. } => formatter.write_str("identifier could not be written as qb64"),
        }
    }
}

impl Error for WatchError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Prefix { source } => Some(source.as_ref()),
            Self::MixedIdentifiers => None,
        }
    }
}

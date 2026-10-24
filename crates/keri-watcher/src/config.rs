//! The watcher's configuration, read from a TOML file.
//!
//! ```toml
//! listen = "127.0.0.1:5631"
//! database = "/var/lib/keri-watcher/watcher.redb"
//! # The salt the watcher's key is derived from; by default the database's path with `.salt`.
//! identity = "/var/lib/keri-watcher/watcher.salt"
//! # Keep key state notices only from the identifier itself, its witnesses, and these watchers.
//! # Without it, notices from any source are kept.
//! trusted_watchers = ["BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha"]
//! ```

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use keri_kel::NoticeTrust;
use keri_protocol::prefix::IdentifierPrefix;
use serde::Deserialize;

use crate::error::WatcherError;

/// The watcher's configuration.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// The address to serve HTTP on.
    pub listen: SocketAddr,
    /// The redb database file, created on first start.
    pub database: PathBuf,
    /// The file holding the salt the watcher's key is derived from, created on first start.
    #[serde(default)]
    pub identity: Option<PathBuf>,
    /// The watchers whose key state notices are kept besides the identifier's own and its
    /// witnesses'; without it, any source's are.
    #[serde(default)]
    pub trusted_watchers: Option<Vec<String>>,
}

impl Config {
    /// Reads the configuration from a TOML file.
    ///
    /// # Errors
    ///
    /// Returns [`WatcherError::File`] when the file cannot be read, and [`WatcherError::Config`]
    /// when it is not a valid configuration.
    pub fn load(path: &Path) -> Result<Self, WatcherError> {
        let text = std::fs::read_to_string(path).map_err(|source| WatcherError::File {
            path: path.to_path_buf(),
            source,
        })?;
        Self::parse(&text)
    }

    /// Parses the configuration from TOML text.
    ///
    /// # Errors
    ///
    /// Returns [`WatcherError::Config`] when it is not a valid configuration.
    pub fn parse(text: &str) -> Result<Self, WatcherError> {
        toml::from_str(text).map_err(|source| WatcherError::Config {
            source: Box::new(source),
        })
    }

    /// Returns the file holding the identity's salt.
    #[must_use]
    pub fn identity_path(&self) -> PathBuf {
        self.identity
            .clone()
            .unwrap_or_else(|| self.database.with_extension("salt"))
    }

    /// Returns whose key state notices to keep.
    ///
    /// # Errors
    ///
    /// Returns [`WatcherError::Prefix`] for a trusted watcher that is not a valid identifier.
    pub fn trust(&self) -> Result<NoticeTrust, WatcherError> {
        let Some(watchers) = &self.trusted_watchers else {
            return Ok(NoticeTrust::AnySource);
        };
        watchers
            .iter()
            .map(|watcher| IdentifierPrefix::from_qb64(watcher).map_err(|source| WatcherError::Prefix { source }))
            .collect::<Result<_, _>>()
            .map(NoticeTrust::Watchers)
    }
}

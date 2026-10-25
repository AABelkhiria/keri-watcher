//! The watcher's configuration, read from a TOML file.
//!
//! ```toml
//! listen = "127.0.0.1:5631"
//! # The URLs the watcher announces in its OOBI, `http` or `https`.
//! urls = ["http://127.0.0.1:5631"]
//! database = "/var/lib/keri-watcher/watcher.redb"
//! # The salt the watcher's key is derived from; by default the database's path with `.salt`.
//! identity = "/var/lib/keri-watcher/watcher.salt"
//! # Keep key state notices only from the identifier itself, its witnesses, and these watchers.
//! # Without it, notices from any source are kept.
//! trusted_watchers = ["BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha"]
//! # How often to poll an observed identifier's witnesses while its log changes; 0 disables
//! # polling. 60 by default.
//! poll_interval_seconds = 60
//! # How long to wait for a witness's answer. 5 by default.
//! witness_timeout_seconds = 5
//! # How long an escrowed event, receipt, reply or query waits before it is dropped. 3600 by
//! # default.
//! escrow_timeout_seconds = 3600
//! ```

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use keri_kel::NoticeTrust;
use keri_protocol::event::reply::route::Scheme;
use keri_protocol::prefix::IdentifierPrefix;
use keri_watch::PollPolicy;
use serde::Deserialize;

use crate::error::WatcherError;

/// The watcher's configuration.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// The address to serve HTTP on.
    pub listen: SocketAddr,
    /// The URLs the watcher announces in its OOBI.
    #[serde(default)]
    pub urls: Vec<String>,
    /// The redb database file, created on first start.
    pub database: PathBuf,
    /// The file holding the salt the watcher's key is derived from, created on first start.
    #[serde(default)]
    pub identity: Option<PathBuf>,
    /// The watchers whose key state notices are kept besides the identifier's own and its
    /// witnesses'; without it, any source's are.
    #[serde(default)]
    pub trusted_watchers: Option<Vec<String>>,
    /// How often, in seconds, to poll an observed identifier's witnesses while its log changes;
    /// zero disables polling.
    #[serde(default = "default_poll_interval")]
    pub poll_interval_seconds: u64,
    /// How long, in seconds, to wait for a witness's answer.
    #[serde(default = "default_witness_timeout")]
    pub witness_timeout_seconds: u64,
    /// How long, in seconds, an escrowed event, receipt, reply or query waits before it is dropped.
    #[serde(default = "default_escrow_timeout")]
    pub escrow_timeout_seconds: u64,
}

const fn default_poll_interval() -> u64 {
    60
}

const fn default_witness_timeout() -> u64 {
    5
}

const fn default_escrow_timeout() -> u64 {
    3600
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

    /// Returns how often to poll an observed identifier's witnesses.
    #[must_use]
    pub const fn poll_policy(&self) -> PollPolicy {
        PollPolicy::new(Duration::from_secs(self.poll_interval_seconds))
    }

    /// Returns how long to wait for a witness's answer.
    #[must_use]
    pub const fn witness_timeout(&self) -> Duration {
        Duration::from_secs(self.witness_timeout_seconds)
    }

    /// Returns how long an escrowed event, receipt, reply or query waits before it is dropped.
    #[must_use]
    pub const fn escrow_timeout(&self) -> Duration {
        Duration::from_secs(self.escrow_timeout_seconds)
    }

    /// Returns the URLs the watcher announces, each with its scheme.
    ///
    /// # Errors
    ///
    /// Returns [`WatcherError::Url`] for a URL that is not `http` or `https`.
    pub fn locations(&self) -> Result<Vec<(Scheme, String)>, WatcherError> {
        self.urls
            .iter()
            .map(|url| {
                let scheme = url
                    .split_once("://")
                    .and_then(|(scheme, _)| scheme.parse::<Scheme>().ok())
                    .filter(|scheme| matches!(scheme, Scheme::Http | Scheme::Https))
                    .ok_or_else(|| WatcherError::Url { url: url.clone() })?;
                Ok((scheme, url.clone()))
            })
            .collect()
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

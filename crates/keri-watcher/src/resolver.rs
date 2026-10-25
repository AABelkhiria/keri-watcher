//! Resolving the OOBIs registrations carry.
//!
//! A `/watcher/{watcher}/add` registration may carry an OOBI for the identifier it asks the watcher
//! to observe, and keri-kel queues it. The resolver fetches each queued OOBI and ingests what it
//! serves: from a keripy witness, the identifier's log and the witnesses' location replies, which is
//! what the watcher needs to observe the identifier.
//!
//! As keripy's `Oobiery` does, an OOBI answered `200` is resolved once its body is ingested, one
//! answered `404` is asked again after [`RETRY_DELAY`], at most [`MAX_RETRIES`] times, and one
//! answered with any other status fails. A request that times out or cannot be sent is asked again
//! as a `404` is. A body that is not a CESR stream fails, and only `http` and `https` URLs are
//! fetched.
//!
//! What became of each OOBI is remembered while the watcher runs, not in its database: after a
//! restart each queued OOBI is resolved once more, and ingesting again what was ingested before
//! changes nothing.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tracing::{info, warn};

use crate::error::WatcherError;
use crate::status::Counter;
use crate::watcher::{Ingested, Watcher, blocking};
use crate::witness::WitnessClient;

/// How long to wait before asking again for an OOBI that was not found.
pub const RETRY_DELAY: Duration = Duration::from_secs(30);

/// How many times an OOBI that was not found is asked for again before it fails.
pub const MAX_RETRIES: u32 = 3;

/// How often the resolver reads the queue.
pub const INTERVAL: Duration = Duration::from_secs(5);

/// What became of an OOBI.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Resolution {
    /// It was fetched and what it serves was ingested.
    Resolved(Ingested),
    /// It was not found, or could not be fetched; it is asked for again later.
    Retrying {
        /// How many times it was asked for again, this time included.
        retries: u32,
    },
    /// It is not an `http` or `https` URL, its server refused it, it serves no CESR stream, or it
    /// was asked for again too many times.
    Failed,
}

impl Resolution {
    /// Returns what became of the OOBI, as a metric label.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Resolved(_) => "resolved",
            Self::Retrying { .. } => "retrying",
            Self::Failed => "failed",
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct Waiting {
    retries: u32,
    due: Duration,
}

/// Resolves the OOBIs registrations queue.
#[derive(Debug)]
pub struct Resolver<C> {
    watcher: Arc<Watcher>,
    client: C,
    timeout: Duration,
    waiting: HashMap<String, Waiting>,
    settled: HashSet<String>,
}

impl<C: WitnessClient> Resolver<C> {
    /// Makes a resolver fetching OOBIs through `client`, giving each request `timeout`.
    #[must_use]
    pub fn new(watcher: Arc<Watcher>, client: C, timeout: Duration) -> Self {
        Self {
            watcher,
            client,
            timeout,
            waiting: HashMap::new(),
            settled: HashSet::new(),
        }
    }

    /// Runs one round at `now`, the time since the clock origin: fetches each queued OOBI neither
    /// settled nor waiting to be asked for again, returning what became of each.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Watcher::oobis`], and those of [`Watcher::ingest`] other than
    /// [`WatcherError::Stream`].
    pub async fn round(&mut self, now: Duration) -> Result<Vec<(String, Resolution)>, WatcherError> {
        let queued = {
            let watcher = Arc::clone(&self.watcher);
            blocking(move || watcher.oobis()).await?
        };
        let mut resolutions = Vec::new();
        for url in queued {
            if self.settled.contains(&url) {
                continue;
            }
            let retries = match self.waiting.get(&url) {
                Some(waiting) if waiting.due > now => continue,
                Some(waiting) => waiting.retries,
                None => 0,
            };
            let resolution = self.resolve(&url, retries).await?;
            self.watcher.status().count(Counter::Oobi(resolution.label()), 1);
            if let Resolution::Retrying { retries } = resolution {
                self.waiting.insert(
                    url.clone(),
                    Waiting {
                        retries,
                        due: now.saturating_add(RETRY_DELAY),
                    },
                );
            } else {
                self.waiting.remove(&url);
                self.settled.insert(url.clone());
            }
            resolutions.push((url, resolution));
        }
        Ok(resolutions)
    }

    async fn resolve(&self, url: &str, retries: u32) -> Result<Resolution, WatcherError> {
        if !(url.starts_with("http://") || url.starts_with("https://")) {
            return Ok(Resolution::Failed);
        }
        let again = if retries < MAX_RETRIES {
            Resolution::Retrying { retries: retries + 1 }
        } else {
            Resolution::Failed
        };
        let Ok(Ok(fetched)) = tokio::time::timeout(self.timeout, self.client.get(url.to_owned())).await else {
            return Ok(again);
        };
        match fetched.status {
            200 => {}
            404 => return Ok(again),
            _ => return Ok(Resolution::Failed),
        }
        let watcher = Arc::clone(&self.watcher);
        match blocking(move || watcher.ingest(&fetched.body)).await {
            Ok(ingested) => Ok(Resolution::Resolved(ingested)),
            Err(WatcherError::Stream { .. }) => Ok(Resolution::Failed),
            Err(error) => Err(error),
        }
    }

    /// Resolves until the task is dropped, logging what became of each OOBI and rounds that fail.
    pub async fn run(mut self) {
        let origin = Instant::now();
        loop {
            match self.round(origin.elapsed()).await {
                Ok(resolutions) => {
                    for (url, resolution) in resolutions {
                        match resolution {
                            Resolution::Resolved(ingested) => info!(%url, ?ingested, "OOBI resolved"),
                            Resolution::Retrying { retries } => info!(%url, retries, "OOBI not found yet"),
                            Resolution::Failed => warn!(%url, "OOBI failed"),
                        }
                    }
                }
                Err(error) => warn!(%error, "OOBI round failed"),
            }
            tokio::time::sleep(INTERVAL).await;
        }
    }
}

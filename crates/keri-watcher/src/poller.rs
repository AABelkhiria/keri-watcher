//! Polling the observed identifiers: the loop that decides when to observe each.
//!
//! Each round reads which identifiers registrations ask the watcher to observe, starts or stops
//! planning polls for them, and observes those due. Between rounds the poller sleeps until the
//! next identifier is due, waking at least every [`REFRESH`] to pick up new registrations.

use std::sync::Arc;
use std::time::{Duration, Instant};

use keri_protocol::prefix::IdentifierPrefix;
use keri_watch::{PollPlanner, PollPolicy};
use tracing::{debug, warn};

use crate::error::WatcherError;
use crate::observe::{Observation, Observer};
use crate::watcher::{Watcher, blocking};
use crate::witness::WitnessClient;

/// The longest the poller sleeps before reading the registrations again.
pub const REFRESH: Duration = Duration::from_secs(10);

/// Polls the observed identifiers' witnesses.
#[derive(Debug)]
pub struct Poller<C> {
    watcher: Arc<Watcher>,
    observer: Observer<C>,
    planner: PollPlanner,
    observing: Vec<IdentifierPrefix>,
}

impl<C: WitnessClient> Poller<C> {
    /// Makes a poller observing through `observer`, as `policy` plans.
    #[must_use]
    pub fn new(watcher: Arc<Watcher>, observer: Observer<C>, policy: PollPolicy) -> Self {
        Self {
            watcher,
            observer,
            planner: PollPlanner::new(policy),
            observing: Vec::new(),
        }
    }

    /// Returns the observer, with the witnesses' health.
    #[must_use]
    pub const fn observer(&self) -> &Observer<C> {
        &self.observer
    }

    /// Runs one round at `now`, the time since the clock origin: reads the registrations, and
    /// observes each identifier due, returning what each observation found.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Watcher::observed`] and [`Observer::observe`], and
    /// [`WatcherError::Watch`] for an identifier that cannot be written as qb64.
    pub async fn round(&mut self, now: Duration) -> Result<Vec<(IdentifierPrefix, Observation)>, WatcherError> {
        let observed = {
            let watcher = Arc::clone(&self.watcher);
            blocking(move || watcher.observed()).await?
        };
        let watch = |source| WatcherError::Watch { source };
        for identifier in &self.observing {
            if !observed.contains(identifier) {
                self.planner.forget(identifier).map_err(watch)?;
            }
        }
        for identifier in &observed {
            self.planner.observe(identifier, now).map_err(watch)?;
        }
        self.observing = observed;

        let mut observations = Vec::new();
        for identifier in self.planner.due(now) {
            let observation = self.observer.observe(&identifier, now).await?;
            let changed = matches!(observation, Observation::Updated { .. });
            self.planner.polled(&identifier, now, changed).map_err(watch)?;
            observations.push((identifier, observation));
        }
        Ok(observations)
    }

    /// Polls until the task is dropped, logging rounds that fail.
    pub async fn run(mut self) {
        let origin = Instant::now();
        loop {
            let now = origin.elapsed();
            match self.round(now).await {
                Ok(observations) => {
                    for (identifier, observation) in observations {
                        debug!(%identifier, ?observation, "observed");
                    }
                }
                Err(error) => warn!(%error, "poll round failed"),
            }
            let now = origin.elapsed();
            let wait = self
                .planner
                .next_due(now)
                .map_or(REFRESH, |due| due.saturating_sub(now).min(REFRESH));
            tokio::time::sleep(wait).await;
        }
    }
}

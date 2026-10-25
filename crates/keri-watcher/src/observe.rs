//! Bringing one observed identifier's log up to date from its witnesses.
//!
//! The watcher asks each of the identifier's witnesses for its key state, healthiest first, and
//! offers each answer to keri-kel, which verifies the witness's signature and keeps the notice as
//! it keeps any. The notices kept are merged: when the witnesses agree on a state the watcher's log
//! has not reached, it fetches the log from a witness reporting that state and ingests it, asking
//! from the first event it lacks and, should that not bring it up to date, from the beginning.
//!
//! Witnesses reporting different events at the same sequence number, or an event other than the one
//! the watcher holds, are recorded as duplicity, and nothing is fetched.
//!
//! A witness the watcher has no URL for is skipped. A witness that does not answer within the
//! timeout, or answers with a server error, counts as a failure for its health; one that answers
//! `404` does not hold the identifier's latest event fully witnessed, and reports nothing.

use std::sync::Arc;
use std::time::{Duration, Instant};

use keri_protocol::event::key_state::KeyStateRecord;
use keri_protocol::prefix::IdentifierPrefix;
use keri_protocol::said::Said;
use keri_watch::{HealthPolicy, Merged, Report, WitnessHealth, merge};
use tracing::{debug, info, warn};

use crate::error::WatcherError;
use crate::watcher::{Notice, Watcher, Witnessed, blocking};
use crate::witness::{Fetched, WitnessClient, key_state_url, log_url};

/// What observing an identifier found.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Observation {
    /// The watcher holds no log for the identifier, so it does not know its witnesses.
    Unknown,
    /// No witness reported the identifier's key state.
    Silent,
    /// The witnesses report nothing the watcher's log lacks.
    UpToDate {
        /// The watcher's latest sequence number.
        sequence_number: u128,
    },
    /// The log was fetched and brought up to date.
    Updated {
        /// The latest sequence number before.
        from: u128,
        /// The latest sequence number after.
        to: u128,
    },
    /// The witnesses report events no witness reporting them served.
    Behind {
        /// The watcher's latest sequence number.
        sequence_number: u128,
        /// The sequence number the witnesses report.
        reported: u128,
    },
    /// Witnesses report different events at the same sequence number.
    Duplicitous {
        /// The lowest sequence number they disagree at.
        sequence_number: u128,
        /// Each witness reporting at it, with the event it reports.
        conflicting: Vec<(IdentifierPrefix, Said)>,
    },
    /// Witnesses report events other than those in the watcher's log.
    Contradicted {
        /// The witnesses.
        witnesses: Vec<IdentifierPrefix>,
    },
}

/// Observes identifiers through their witnesses, keeping track of each witness's health.
#[derive(Debug)]
pub struct Observer<C> {
    watcher: Arc<Watcher>,
    client: C,
    health: WitnessHealth,
    timeout: Duration,
}

impl<C: WitnessClient> Observer<C> {
    /// Makes an observer asking witnesses through `client`, giving each request `timeout`.
    #[must_use]
    pub fn new(watcher: Arc<Watcher>, client: C, timeout: Duration) -> Self {
        Self {
            watcher,
            client,
            health: WitnessHealth::new(HealthPolicy::default()),
            timeout,
        }
    }

    /// Returns how each witness has answered.
    #[must_use]
    pub const fn health(&self) -> &WitnessHealth {
        &self.health
    }

    /// Brings `identifier`'s log up to date from its witnesses, `now` being the time since the
    /// clock origin the health records are kept against.
    ///
    /// # Errors
    ///
    /// Returns [`WatcherError::Kel`] when the store fails, and [`WatcherError::Watch`] or
    /// [`WatcherError::Prefix`] for an identifier that cannot be written as qb64.
    pub async fn observe(&mut self, identifier: &IdentifierPrefix, now: Duration) -> Result<Observation, WatcherError> {
        let held = {
            let (watcher, identifier) = (Arc::clone(&self.watcher), identifier.clone());
            blocking(move || watcher.witnessed(&identifier)).await?
        };
        let Some(Witnessed {
            sequence_number: local,
            witnesses,
        }) = held
        else {
            return Ok(Observation::Unknown);
        };
        let (reports, contradicting) = self.reports(identifier, &witnesses, now).await?;
        if !contradicting.is_empty() {
            let witnesses: Vec<IdentifierPrefix> = contradicting.iter().map(|(witness, _)| witness.clone()).collect();
            warn!(%identifier, ?witnesses, "witnesses contradict the log");
            let watcher = Arc::clone(&self.watcher);
            blocking(move || {
                for (witness, state) in &contradicting {
                    watcher.record_contradiction(witness, state)?;
                }
                Ok(())
            })
            .await?;
            return Ok(Observation::Contradicted { witnesses });
        }
        let merged = merge(&reports).map_err(|source| WatcherError::Watch { source })?;
        let target = match &merged {
            Merged::Silent => return Ok(Observation::Silent),
            Merged::Duplicitous {
                sequence_number,
                conflicting,
            } => {
                warn!(%identifier, sequence_number, ?conflicting, "witnesses report duplicity");
                let (watcher, identifier, at, reported) = (
                    Arc::clone(&self.watcher),
                    identifier.clone(),
                    *sequence_number,
                    conflicting.clone(),
                );
                blocking(move || watcher.record_duplicity(&identifier, at, &reported)).await?;
                return Ok(Observation::Duplicitous {
                    sequence_number: *sequence_number,
                    conflicting: conflicting.clone(),
                });
            }
            Merged::Agreed { state, .. } => state.sequence_number(),
        };
        let Some(missing) = merged.missing(Some(local)) else {
            return Ok(Observation::UpToDate { sequence_number: local });
        };
        for source in merged.sources() {
            let Some(url) = url_of(&witnesses, source) else {
                continue;
            };
            let reached = self
                .fetch(identifier, source, &url, (*missing.start(), target), now)
                .await?;
            if let Some(to) = reached.filter(|reached| *reached >= target) {
                info!(%identifier, from = local, to, "log updated");
                return Ok(Observation::Updated { from: local, to });
            }
        }
        Ok(Observation::Behind {
            sequence_number: local,
            reported: target,
        })
    }

    /// Asks each witness for its key state, healthiest first, returning the states the witnesses
    /// whose notices were kept report, and the witnesses that contradict the log with the states
    /// they report.
    async fn reports(
        &mut self,
        identifier: &IdentifierPrefix,
        witnesses: &[(IdentifierPrefix, Option<String>)],
        now: Duration,
    ) -> Result<(Vec<Report>, Vec<(IdentifierPrefix, KeyStateRecord)>), WatcherError> {
        let listed: Vec<IdentifierPrefix> = witnesses.iter().map(|(witness, _)| witness.clone()).collect();
        let mut reports = Vec::new();
        let mut contradicting = Vec::new();
        for witness in self
            .health
            .priority_order(&listed, now)
            .map_err(|source| WatcherError::Watch { source })?
        {
            let Some(url) = url_of(witnesses, &witness) else {
                debug!(%witness, "no location for witness");
                continue;
            };
            let Some(answer) = self.ask(&witness, key_state_url(&url, identifier)?, now).await? else {
                continue;
            };
            if answer.status != 200 {
                debug!(%witness, status = answer.status, "no key state");
                continue;
            }
            let notice = {
                let (watcher, identifier, witness) = (Arc::clone(&self.watcher), identifier.clone(), witness.clone());
                blocking(move || watcher.accept_notice(&identifier, &witness, &answer.body)).await?
            };
            match notice {
                Notice::Accepted(state) => reports.push((witness, *state)),
                Notice::Contradicting(state) => contradicting.push((witness, *state)),
                Notice::Refused(error) => debug!(%witness, %error, "key state notice refused"),
                Notice::Unexpected => debug!(%witness, "answer is not a key state notice"),
            }
        }
        Ok((reports, contradicting))
    }

    /// Fetches the log from the witness at `url` and ingests it, asking from first-seen ordinal
    /// `from` and then, should the log not reach `target`, from the beginning. Returns the latest
    /// sequence number reached, or `None` when the witness did not serve the log.
    async fn fetch(
        &mut self,
        identifier: &IdentifierPrefix,
        witness: &IdentifierPrefix,
        url: &str,
        (from, target): (u128, u128),
        now: Duration,
    ) -> Result<Option<u128>, WatcherError> {
        let starts: &[u128] = if from == 0 { &[0] } else { &[from, 0] };
        let mut reached = None;
        for &from in starts {
            let Some(answer) = self.ask(witness, log_url(url, identifier, from)?, now).await? else {
                break;
            };
            if answer.status != 200 {
                debug!(%witness, status = answer.status, "no log");
                break;
            }
            let ingested = {
                let (watcher, identifier) = (Arc::clone(&self.watcher), identifier.clone());
                blocking(move || {
                    watcher.ingest(&answer.body)?;
                    watcher.witnessed(&identifier)
                })
                .await
            };
            match ingested {
                Ok(held) => reached = held.map(|held| held.sequence_number).max(reached),
                Err(error @ WatcherError::Stream { .. }) => {
                    debug!(%witness, %error, "log is not a CESR stream");
                    break;
                }
                Err(error) => return Err(error),
            }
            if reached.is_some_and(|reached| reached >= target) {
                break;
            }
        }
        Ok(reached)
    }

    /// Asks a witness, recording how it answered: `None` when it did not.
    async fn ask(
        &mut self,
        witness: &IdentifierPrefix,
        url: String,
        now: Duration,
    ) -> Result<Option<Fetched>, WatcherError> {
        let started = Instant::now();
        let answered = tokio::time::timeout(self.timeout, self.client.get(url)).await;
        match answered {
            Ok(Ok(fetched)) if fetched.status < 500 => {
                self.health
                    .succeeded(witness, started.elapsed())
                    .map_err(|source| WatcherError::Watch { source })?;
                Ok(Some(fetched))
            }
            failed => {
                match failed {
                    Ok(Ok(fetched)) => debug!(%witness, status = fetched.status, "witness failed"),
                    Ok(Err(error)) => debug!(%witness, %error, "witness unreachable"),
                    Err(_) => debug!(%witness, "witness timed out"),
                }
                self.health
                    .failed(witness, now)
                    .map_err(|source| WatcherError::Watch { source })?;
                Ok(None)
            }
        }
    }
}

fn url_of(witnesses: &[(IdentifierPrefix, Option<String>)], witness: &IdentifierPrefix) -> Option<String> {
    witnesses
        .iter()
        .find(|(listed, _)| listed == witness)
        .and_then(|(_, url)| url.clone())
}

//! Which witnesses answer well, and the order to ask them in.
//!
//! A watcher asks an identifier's witnesses for its key state, every healthy one at once, and then
//! for the events it is missing, one at a time until one answers. [`WitnessHealth`] remembers how
//! each witness has answered: a smoothed response time, an exponential moving average, and its
//! failures. A witness that has failed several times in a row is unhealthy, but becomes worth one
//! more try once a cooldown has passed since its last failure, so a witness that recovers is not
//! shunned for good; a single success makes it healthy again.
//!
//! [`WitnessHealth::priority_order`] orders the witnesses to ask: healthy ones first, the fastest
//! first and those never measured after the measured ones, then unhealthy ones, the fewest
//! consecutive failures first. Ties keep the order given, which for an identifier's witnesses is
//! the order its key state lists them.
//!
//! This is the application's choice, not KERI's; it follows the health tracking keriox's watcher
//! describes. Times are [`Duration`]s from a clock origin the caller chooses, as in
//! [`crate::poll`].

use core::time::Duration;
use std::collections::BTreeMap;

use keri_protocol::prefix::IdentifierPrefix;

use crate::error::WatchError;

/// When a witness counts as healthy, and how its response time is smoothed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HealthPolicy {
    smoothing: u32,
    failures: u32,
    cooldown: Duration,
}

impl Default for HealthPolicy {
    /// Smooths response times with a weight of one fifth for each new one, counts a witness
    /// unhealthy after three failures in a row, and tries it again a minute after its last.
    fn default() -> Self {
        Self {
            smoothing: 5,
            failures: 3,
            cooldown: Duration::from_secs(60),
        }
    }
}

impl HealthPolicy {
    /// Sets the smoothing: each new response time weighs one `smoothing`th of the average. One
    /// keeps only the latest.
    #[must_use]
    pub const fn smoothing(mut self, smoothing: u32) -> Self {
        self.smoothing = smoothing;
        self
    }

    /// Sets how many failures in a row make a witness unhealthy.
    #[must_use]
    pub const fn failures(mut self, failures: u32) -> Self {
        self.failures = failures;
        self
    }

    /// Sets how long after its last failure an unhealthy witness is worth another try.
    #[must_use]
    pub const fn cooldown(mut self, cooldown: Duration) -> Self {
        self.cooldown = cooldown;
        self
    }
}

/// How one witness has answered.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WitnessRecord {
    witness: IdentifierPrefix,
    average: Option<Duration>,
    consecutive_failures: u32,
    successes: u64,
    failures: u64,
    last_failure: Option<Duration>,
}

impl WitnessRecord {
    /// Returns the witness.
    #[must_use]
    pub const fn witness(&self) -> &IdentifierPrefix {
        &self.witness
    }

    /// Returns the smoothed response time, once the witness has answered.
    #[must_use]
    pub const fn average(&self) -> Option<Duration> {
        self.average
    }

    /// Returns how many times in a row the witness has failed.
    #[must_use]
    pub const fn consecutive_failures(&self) -> u32 {
        self.consecutive_failures
    }

    /// Returns how many times the witness has answered.
    #[must_use]
    pub const fn successes(&self) -> u64 {
        self.successes
    }

    /// Returns how many times the witness has failed.
    #[must_use]
    pub const fn failures(&self) -> u64 {
        self.failures
    }

    fn is_healthy(&self, policy: &HealthPolicy, now: Duration) -> bool {
        self.consecutive_failures < policy.failures.max(1)
            || self
                .last_failure
                .is_none_or(|last| now.saturating_sub(last) >= policy.cooldown)
    }
}

/// How each witness has answered.
#[derive(Clone, Debug, Default)]
pub struct WitnessHealth {
    policy: HealthPolicy,
    witnesses: BTreeMap<String, WitnessRecord>,
}

impl WitnessHealth {
    /// Health tracking under `policy`, with nothing recorded yet.
    #[must_use]
    pub const fn new(policy: HealthPolicy) -> Self {
        Self {
            policy,
            witnesses: BTreeMap::new(),
        }
    }

    /// Records that `witness` answered in `response_time`.
    ///
    /// # Errors
    ///
    /// Returns [`WatchError::Prefix`] for a witness that cannot be written as qb64.
    pub fn succeeded(&mut self, witness: &IdentifierPrefix, response_time: Duration) -> Result<(), WatchError> {
        let smoothing = u128::from(self.policy.smoothing.max(1));
        let record = self.record(witness)?;
        record.average = Some(record.average.map_or(response_time, |average| {
            // average + (sample - average) / smoothing, in nanoseconds.
            let average = average.as_nanos();
            let sample = response_time.as_nanos();
            let smoothed = if sample >= average {
                average.saturating_add((sample - average) / smoothing)
            } else {
                average.saturating_sub((average - sample) / smoothing)
            };
            u64::try_from(smoothed).map_or(Duration::MAX, Duration::from_nanos)
        }));
        record.consecutive_failures = 0;
        record.successes = record.successes.saturating_add(1);
        Ok(())
    }

    /// Records that `witness` failed to answer at `now`: a timeout, a refused connection, or a
    /// reply that does not parse.
    ///
    /// # Errors
    ///
    /// Returns [`WatchError::Prefix`] for a witness that cannot be written as qb64.
    pub fn failed(&mut self, witness: &IdentifierPrefix, now: Duration) -> Result<(), WatchError> {
        let record = self.record(witness)?;
        record.consecutive_failures = record.consecutive_failures.saturating_add(1);
        record.failures = record.failures.saturating_add(1);
        record.last_failure = Some(now);
        Ok(())
    }

    /// Returns whether `witness` is worth asking at `now`: it has not failed too often in a row, or
    /// its cooldown has passed. A witness never seen is healthy.
    ///
    /// # Errors
    ///
    /// Returns [`WatchError::Prefix`] for a witness that cannot be written as qb64.
    pub fn is_healthy(&self, witness: &IdentifierPrefix, now: Duration) -> Result<bool, WatchError> {
        Ok(self
            .witnesses
            .get(&key(witness)?)
            .is_none_or(|record| record.is_healthy(&self.policy, now)))
    }

    /// Orders `witnesses` to ask at `now`: healthy ones first, the fastest first and those never
    /// measured after the measured ones, then unhealthy ones, the fewest consecutive failures
    /// first. Ties keep the order given.
    ///
    /// # Errors
    ///
    /// Returns [`WatchError::Prefix`] for a witness that cannot be written as qb64.
    pub fn priority_order(
        &self,
        witnesses: &[IdentifierPrefix],
        now: Duration,
    ) -> Result<Vec<IdentifierPrefix>, WatchError> {
        let mut ranked = witnesses
            .iter()
            .map(|witness| {
                let record = self.witnesses.get(&key(witness)?);
                let healthy = record.is_none_or(|record| record.is_healthy(&self.policy, now));
                let rank = match (healthy, record.and_then(WitnessRecord::average)) {
                    (true, Some(average)) => (0, 0, average),
                    (true, None) => (1, 0, Duration::ZERO),
                    (false, _) => (2, record.map_or(0, WitnessRecord::consecutive_failures), Duration::ZERO),
                };
                Ok((rank, witness.clone()))
            })
            .collect::<Result<Vec<_>, WatchError>>()?;
        ranked.sort_by_key(|(rank, _)| *rank);
        Ok(ranked.into_iter().map(|(_, witness)| witness).collect())
    }

    /// Returns what is recorded for each witness, for a health report.
    pub fn records(&self) -> impl Iterator<Item = &WitnessRecord> {
        self.witnesses.values()
    }

    fn record(&mut self, witness: &IdentifierPrefix) -> Result<&mut WitnessRecord, WatchError> {
        Ok(self.witnesses.entry(key(witness)?).or_insert_with(|| WitnessRecord {
            witness: witness.clone(),
            average: None,
            consecutive_failures: 0,
            successes: 0,
            failures: 0,
            last_failure: None,
        }))
    }
}

fn key(identifier: &IdentifierPrefix) -> Result<String, WatchError> {
    identifier.qb64().map_err(WatchError::prefix)
}

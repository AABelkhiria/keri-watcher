//! When each observed identifier is due to be polled.
//!
//! A watcher asks an observed identifier's witnesses for its key state from time to time. Polling a
//! log that changes often keeps the watcher current; polling one that has not changed in an hour
//! as often wastes the witnesses' time. [`PollPolicy`] sets the rate: the base interval while the
//! log is changing, growing linearly once the log has been stable for a while, up to a multiple of
//! the base for a log stable for an hour or more. A subscribed identifier, one a client is
//! following closely, is always polled at the base interval. This cadence is the application's
//! choice, not KERI's; it follows the one keriox's watcher describes.
//!
//! [`PollPlanner`] tracks the observed identifiers and, given the time, says which are due: those
//! never polled first, then the most overdue. The caller reports each poll, and whether the log
//! changed, with [`PollPlanner::polled`].
//!
//! Times are [`Duration`]s from a clock origin the caller chooses: a monotonic clock in
//! production, a fixed one in tests. The planner keeps no state across restarts; after one,
//! every identifier is due at once.

use core::time::Duration;
use std::collections::BTreeMap;

use keri_protocol::prefix::IdentifierPrefix;

use crate::error::WatchError;

/// How often observed identifiers are polled.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PollPolicy {
    base: Duration,
    settling: Duration,
    settled: Duration,
    slowdown: u32,
}

impl PollPolicy {
    /// Polls every `base`, slowing while a log is stable: from the base interval for a log changed
    /// in the last minute, to ten times it for a log stable for an hour. A zero `base` disables
    /// polling.
    #[must_use]
    pub const fn new(base: Duration) -> Self {
        Self {
            base,
            settling: Duration::from_secs(60),
            settled: Duration::from_secs(3600),
            slowdown: 10,
        }
    }

    /// Sets how long a log must be stable before polling slows.
    #[must_use]
    pub const fn settling(mut self, settling: Duration) -> Self {
        self.settling = settling;
        self
    }

    /// Sets how long a log must be stable for polling to reach its slowest.
    #[must_use]
    pub const fn settled(mut self, settled: Duration) -> Self {
        self.settled = settled;
        self
    }

    /// Sets the slowest interval as a multiple of the base; one never slows.
    #[must_use]
    pub const fn slowdown(mut self, slowdown: u32) -> Self {
        self.slowdown = slowdown;
        self
    }

    /// Returns the base interval.
    #[must_use]
    pub const fn base(&self) -> Duration {
        self.base
    }

    /// Returns whether polling is disabled, by a zero base interval.
    #[must_use]
    pub const fn is_disabled(&self) -> bool {
        self.base.is_zero()
    }

    /// Returns the interval for a log that has been stable for `stable`, or for a subscribed
    /// identifier.
    #[must_use]
    pub fn interval(&self, stable: Duration, subscribed: bool) -> Duration {
        let slowest = self.base.saturating_mul(self.slowdown.max(1));
        if subscribed || stable <= self.settling {
            return self.base;
        }
        if stable >= self.settled || self.settled <= self.settling {
            return slowest;
        }
        // Linear from the base interval when settling ends to the slowest when settled.
        let progress = stable.saturating_sub(self.settling).as_nanos();
        let span = self.settled.saturating_sub(self.settling).as_nanos();
        let extra = slowest.saturating_sub(self.base).as_nanos();
        let added = extra.saturating_mul(progress) / span.max(1);
        u64::try_from(added).map_or(slowest, |added| self.base.saturating_add(Duration::from_nanos(added)))
    }
}

/// One observed identifier's polling history.
#[derive(Clone, Debug)]
struct Observed {
    identifier: IdentifierPrefix,
    since: Duration,
    last_polled: Option<Duration>,
    last_changed: Option<Duration>,
    subscribed: bool,
}

impl Observed {
    /// When this identifier is next due, or `None` when it has never been polled.
    fn due_at(&self, policy: &PollPolicy) -> Option<Duration> {
        let last_polled = self.last_polled?;
        let stable = last_polled.saturating_sub(self.last_changed.unwrap_or(self.since));
        Some(last_polled.saturating_add(policy.interval(stable, self.subscribed)))
    }
}

/// The observed identifiers, and when each is due to be polled.
#[derive(Clone, Debug)]
pub struct PollPlanner {
    policy: PollPolicy,
    observed: BTreeMap<String, Observed>,
}

impl PollPlanner {
    /// A planner observing nothing yet.
    #[must_use]
    pub const fn new(policy: PollPolicy) -> Self {
        Self {
            policy,
            observed: BTreeMap::new(),
        }
    }

    /// Returns the policy.
    #[must_use]
    pub const fn policy(&self) -> &PollPolicy {
        &self.policy
    }

    /// Starts observing `identifier` from `now`. Observing an identifier already observed changes
    /// nothing.
    ///
    /// # Errors
    ///
    /// Returns [`WatchError::Prefix`] for an identifier that cannot be written as qb64.
    pub fn observe(&mut self, identifier: &IdentifierPrefix, now: Duration) -> Result<(), WatchError> {
        self.observed.entry(key(identifier)?).or_insert_with(|| Observed {
            identifier: identifier.clone(),
            since: now,
            last_polled: None,
            last_changed: None,
            subscribed: false,
        });
        Ok(())
    }

    /// Stops observing `identifier`, and returns whether it was observed.
    ///
    /// # Errors
    ///
    /// Returns [`WatchError::Prefix`] for an identifier that cannot be written as qb64.
    pub fn forget(&mut self, identifier: &IdentifierPrefix) -> Result<bool, WatchError> {
        Ok(self.observed.remove(&key(identifier)?).is_some())
    }

    /// Marks an observed identifier as subscribed, always polled at the base interval, or no
    /// longer. Returns whether it is observed.
    ///
    /// # Errors
    ///
    /// Returns [`WatchError::Prefix`] for an identifier that cannot be written as qb64.
    pub fn subscribe(&mut self, identifier: &IdentifierPrefix, subscribed: bool) -> Result<bool, WatchError> {
        let observed = self.observed.get_mut(&key(identifier)?);
        if let Some(observed) = observed {
            observed.subscribed = subscribed;
            return Ok(true);
        }
        Ok(false)
    }

    /// Records that `identifier` was polled at `now`, and whether its log changed. Returns whether
    /// it is observed.
    ///
    /// # Errors
    ///
    /// Returns [`WatchError::Prefix`] for an identifier that cannot be written as qb64.
    pub fn polled(&mut self, identifier: &IdentifierPrefix, now: Duration, changed: bool) -> Result<bool, WatchError> {
        let Some(observed) = self.observed.get_mut(&key(identifier)?) else {
            return Ok(false);
        };
        observed.last_polled = Some(now);
        if changed {
            observed.last_changed = Some(now);
        }
        Ok(true)
    }

    /// Returns the identifiers due at `now`: those never polled first, then the most overdue
    /// first, ties in qb64 order. Nothing is due while polling is disabled.
    #[must_use]
    pub fn due(&self, now: Duration) -> Vec<IdentifierPrefix> {
        if self.policy.is_disabled() {
            return Vec::new();
        }
        let mut due: Vec<(Option<Duration>, &Observed)> = self
            .observed
            .values()
            .map(|observed| (observed.due_at(&self.policy), observed))
            .filter(|(due_at, _)| due_at.is_none_or(|due_at| due_at <= now))
            .collect();
        // `None`, never polled, sorts first; then the earliest due, the most overdue.
        due.sort_by_key(|(due_at, _)| *due_at);
        due.into_iter()
            .map(|(_, observed)| observed.identifier.clone())
            .collect()
    }

    /// Returns when the next identifier falls due: `now` when one already is, `None` when nothing
    /// is observed or polling is disabled. A polling loop sleeps until then.
    #[must_use]
    pub fn next_due(&self, now: Duration) -> Option<Duration> {
        if self.policy.is_disabled() {
            return None;
        }
        self.observed
            .values()
            .map(|observed| observed.due_at(&self.policy).map_or(now, |due_at| due_at.max(now)))
            .min()
    }

    /// Returns how many identifiers are observed.
    #[must_use]
    pub fn len(&self) -> usize {
        self.observed.len()
    }

    /// Returns whether no identifier is observed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.observed.is_empty()
    }
}

fn key(identifier: &IdentifierPrefix) -> Result<String, WatchError> {
    identifier.qb64().map_err(WatchError::prefix)
}

//! What the watcher reports to its operators: counters its tasks keep, the witnesses' health, and
//! what it holds, which `GET /health` answers as JSON and `GET /metrics` as Prometheus text.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Instant;

use keri_watch::WitnessRecord;
use serde::{Deserialize, Serialize};

/// Something the watcher counts.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum Counter {
    /// A message keri-kel accepted, escrowed or found duplicate.
    Processed,
    /// A message keri-kel refused.
    Refused,
    /// An observation of an identifier, by what it found.
    Observed(&'static str),
    /// An OOBI asked for, by what became of it.
    Oobi(&'static str),
    /// An escrowed event, receipt, reply or query dropped for having waited too long.
    Expired,
}

impl Counter {
    fn metric(self) -> (&'static str, Option<(&'static str, &'static str)>) {
        match self {
            Self::Processed => ("keri_watcher_messages_total", Some(("outcome", "processed"))),
            Self::Refused => ("keri_watcher_messages_total", Some(("outcome", "refused"))),
            Self::Observed(found) => ("keri_watcher_observations_total", Some(("found", found))),
            Self::Oobi(outcome) => ("keri_watcher_oobis_total", Some(("outcome", outcome))),
            Self::Expired => ("keri_watcher_escrows_expired_total", None),
        }
    }
}

/// The counters and the witnesses' health, as the watcher's tasks last left them.
#[derive(Debug)]
pub(crate) struct Status {
    started: Instant,
    counters: Mutex<BTreeMap<Counter, u64>>,
    witnesses: Mutex<Vec<WitnessRecord>>,
}

impl Status {
    pub(crate) fn new() -> Self {
        Self {
            started: Instant::now(),
            counters: Mutex::new(BTreeMap::new()),
            witnesses: Mutex::new(Vec::new()),
        }
    }

    pub(crate) fn count(&self, counter: Counter, by: u64) {
        if by > 0 {
            let mut counters = lock(&self.counters);
            let count = counters.entry(counter).or_insert(0);
            *count = count.saturating_add(by);
        }
    }

    pub(crate) fn set_witnesses(&self, records: Vec<WitnessRecord>) {
        *lock(&self.witnesses) = records;
    }

    fn counters(&self) -> BTreeMap<Counter, u64> {
        lock(&self.counters).clone()
    }

    fn witnesses(&self) -> Vec<WitnessRecord> {
        lock(&self.witnesses).clone()
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    // Counters and a snapshot: a panic while one was held leaves nothing worth refusing to read.
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Reads one figure of a witness's record, as Prometheus writes it.
type Reading = fn(&WitnessRecord) -> String;

/// What the watcher holds, besides its counters.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Held {
    /// The identifiers registrations ask it to observe.
    pub observed: usize,
    /// Events waiting in the escrows.
    pub escrowed_events: usize,
    /// Receipts waiting for their event.
    pub waiting_receipts: usize,
    /// Queries waiting for the log to answer them.
    pub escrowed_queries: usize,
}

/// How one witness has answered the watcher.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WitnessReport {
    /// The witness, as qb64.
    pub witness: String,
    /// Its smoothed response time in milliseconds, once it has answered.
    pub average_milliseconds: Option<u128>,
    /// Its failures since it last answered.
    pub consecutive_failures: u32,
    /// Its answers.
    pub successes: u64,
    /// Its failures.
    pub failures: u64,
}

/// What `GET /health` answers.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Health {
    /// The watcher's identifier, as qb64.
    pub identifier: String,
    /// How long the watcher has run, in seconds.
    pub uptime_seconds: u64,
    /// What it holds.
    pub held: Held,
    /// How each witness asked has answered.
    pub witnesses: Vec<WitnessReport>,
}

impl Status {
    pub(crate) fn health(&self, identifier: String, held: Held) -> Health {
        let witnesses = self
            .witnesses()
            .iter()
            .map(|record| WitnessReport {
                witness: record.witness().to_string(),
                average_milliseconds: record.average().map(|average| average.as_millis()),
                consecutive_failures: record.consecutive_failures(),
                successes: record.successes(),
                failures: record.failures(),
            })
            .collect();
        Health {
            identifier,
            uptime_seconds: self.started.elapsed().as_secs(),
            held,
            witnesses,
        }
    }

    /// The counters, what the watcher holds and the witnesses' health, as Prometheus text.
    pub(crate) fn metrics(&self, held: Held) -> String {
        let mut text = String::new();
        let mut described = Vec::new();
        for (counter, count) in self.counters() {
            let (name, label) = counter.metric();
            if !described.contains(&name) {
                described.push(name);
                let _ = writeln!(text, "# TYPE {name} counter");
            }
            match label {
                Some((key, value)) => {
                    let _ = writeln!(text, "{name}{{{key}=\"{value}\"}} {count}");
                }
                None => {
                    let _ = writeln!(text, "{name} {count}");
                }
            }
        }
        for (name, value) in [
            ("keri_watcher_observed", held.observed),
            ("keri_watcher_escrowed_events", held.escrowed_events),
            ("keri_watcher_waiting_receipts", held.waiting_receipts),
            ("keri_watcher_escrowed_queries", held.escrowed_queries),
        ] {
            let _ = writeln!(text, "# TYPE {name} gauge\n{name} {value}");
        }
        let witnesses = self.witnesses();
        let gauges: [(&str, &str, Reading); 3] = [
            ("keri_watcher_witness_successes_total", "counter", |record| {
                record.successes().to_string()
            }),
            ("keri_watcher_witness_failures_total", "counter", |record| {
                record.failures().to_string()
            }),
            ("keri_watcher_witness_response_seconds", "gauge", |record| {
                record
                    .average()
                    .map_or_else(|| "NaN".to_owned(), |average| average.as_secs_f64().to_string())
            }),
        ];
        for (name, kind, value) in gauges {
            if witnesses.is_empty() {
                continue;
            }
            let _ = writeln!(text, "# TYPE {name} {kind}");
            for record in &witnesses {
                let _ = writeln!(text, "{name}{{witness=\"{}\"}} {}", record.witness(), value(record));
            }
        }
        text
    }
}

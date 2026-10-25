//! A KERI watcher: it keeps the key event logs it is sent, in a redb database, and answers queries
//! about them over HTTP.
//!
//! [`Config`] is read from a TOML file. [`Identity`] is the watcher's non-transferable key, derived
//! from a salt kept beside the database. [`Watcher`] processes what it is sent through keri-kel and
//! answers `logs` and `ksn` queries, and [`http::router`] serves it. [`Poller`] keeps the
//! identifiers registrations ask it to observe up to date from their witnesses, through
//! [`Observer`]. [`Resolver`] fetches the OOBIs registrations carry, and [`sweeper`] drops what has
//! waited too long in the escrows.
//!
//! | Route | |
//! |---|---|
//! | `POST /`, `PUT /` | Ingests a CESR stream: events, receipts, replies and queries |
//! | `POST /query` | Answers one query: a log replay, or the key state signed by the watcher |
//! | `GET /oobi/{aid}[/{role}[/{eid}]]` | Answers the watcher's own OOBI: where it can be reached, signed by it |
//! | `GET /health` | Answers with the watcher's identifier, what it holds and its witnesses' health |
//! | `GET /metrics` | Answers with the watcher's counters and gauges as Prometheus text |
//! | `GET /duplicity/{aid}` | Answers with the duplicity recorded for an identifier |

#![forbid(unsafe_code)]

pub mod config;
pub mod error;
pub mod http;
pub mod identity;
pub mod observe;
pub mod poller;
pub mod resolver;
pub mod status;
pub mod sweeper;
pub mod watcher;
pub mod witness;

pub use config::Config;
pub use error::WatcherError;
pub use identity::Identity;
pub use keri_store_redb::Sighting;
pub use observe::{Observation, Observer};
pub use poller::Poller;
pub use resolver::{Resolution, Resolver};
pub use status::{Health, Held, WitnessReport};
pub use watcher::{Clock, Ingested, Notice, QueryOutcome, Swept, Watcher, Witnessed, system_clock};
pub use witness::{Fetched, HttpClient, WitnessClient};

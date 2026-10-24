//! A KERI watcher: it keeps the key event logs it is sent, in a redb database, and answers queries
//! about them over HTTP.
//!
//! [`Config`] is read from a TOML file. [`Identity`] is the watcher's non-transferable key, derived
//! from a salt kept beside the database. [`Watcher`] processes what it is sent through keri-kel and
//! answers `logs` and `ksn` queries, and [`http::router`] serves it:
//!
//! | Route | |
//! |---|---|
//! | `POST /` | Ingests a CESR stream: events, receipts, replies and queries |
//! | `POST /query` | Answers one query: a log replay, or the key state signed by the watcher |
//! | `GET /health` | Answers with the watcher's identifier |

#![forbid(unsafe_code)]

pub mod config;
pub mod error;
pub mod http;
pub mod identity;
pub mod watcher;

pub use config::Config;
pub use error::WatcherError;
pub use identity::Identity;
pub use watcher::{Clock, Ingested, QueryOutcome, Watcher, system_clock};

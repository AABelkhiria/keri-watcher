//! A KERI watcher's decisions, as pure functions over explicit inputs.
//!
//! [`poll`] decides when each observed identifier is due to be polled, [`health`] which of its
//! witnesses to ask first, and [`reports`] what their answers say and which events to fetch. Nothing here reads a clock,
//! a network or a store: the caller supplies the time and the facts, and acts on the decision.

#![forbid(unsafe_code)]

pub mod error;
pub mod health;
pub mod poll;
pub mod reports;

pub use error::WatchError;
pub use health::{HealthPolicy, WitnessHealth, WitnessRecord};
pub use poll::{PollPlanner, PollPolicy};
pub use reports::{Merged, Report, merge};

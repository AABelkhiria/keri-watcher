//! A KERI watcher's decisions, as pure functions over explicit inputs.
//!
//! [`poll`] decides when each observed identifier is due to be polled. Nothing here reads a clock,
//! a network or a store: the caller supplies the time and the facts, and acts on the decision.

#![forbid(unsafe_code)]

pub mod error;
pub mod poll;

pub use error::WatchError;
pub use poll::{PollPlanner, PollPolicy};

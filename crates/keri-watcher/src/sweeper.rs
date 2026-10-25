//! Sweeping the escrows: what keri-kel holds back waits until what it lacks arrives, but not for
//! ever.
//!
//! Every [`INTERVAL`], the sweeper drops what has waited longer than the configured timeout, then
//! retries the rest, as [`Watcher::sweep`] does. keripy gives each escrow its own timeout, an hour
//! for most, twenty minutes for out-of-order events and five for queries; here one timeout applies to
//! all.

use std::sync::Arc;
use std::time::Duration;

use tracing::{debug, warn};

use crate::watcher::{Watcher, blocking};

/// How often the escrows are swept.
pub const INTERVAL: Duration = Duration::from_secs(60);

/// Sweeps the escrows until the task is dropped, dropping what has waited longer than `timeout`.
pub async fn run(watcher: Arc<Watcher>, timeout: Duration) {
    let mut ticks = tokio::time::interval(INTERVAL);
    ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticks.tick().await;
        let watcher = Arc::clone(&watcher);
        match blocking(move || watcher.sweep(timeout)).await {
            Ok(swept) => debug!(?swept, "escrows swept"),
            Err(error) => warn!(%error, "escrow sweep failed"),
        }
    }
}

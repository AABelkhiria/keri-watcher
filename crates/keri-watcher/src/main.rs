//! Runs a KERI watcher: `keri-watcher <config.toml>`.
//!
//! Logs go to standard error, filtered by `RUST_LOG`, `info` by default.

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use keri_watcher::{Config, HttpClient, Observer, Poller, Watcher, WatcherError, http};
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with_writer(std::io::stderr)
        .init();
    let mut arguments = std::env::args_os().skip(1);
    let (Some(path), None) = (arguments.next(), arguments.next()) else {
        error!("usage: keri-watcher <config.toml>");
        return ExitCode::FAILURE;
    };
    match run(PathBuf::from(path)).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(failed) => {
            error!(error = %failed, source = ?std::error::Error::source(&failed), "watcher stopped");
            ExitCode::FAILURE
        }
    }
}

async fn run(path: PathBuf) -> Result<(), WatcherError> {
    let config = Config::load(&path)?;
    let watcher = Watcher::open(&config)?;
    let prefix = watcher
        .identity()
        .prefix()
        .qb64()
        .map_err(|source| WatcherError::Prefix { source })?;
    let listener = tokio::net::TcpListener::bind(config.listen)
        .await
        .map_err(|source| WatcherError::Serve { source })?;
    info!(%prefix, listen = %config.listen, "watcher started");
    let watcher = Arc::new(watcher);
    let policy = config.poll_policy();
    let poller = (!policy.is_disabled())
        .then(|| {
            let observer = Observer::new(Arc::clone(&watcher), HttpClient::new()?, config.witness_timeout());
            Ok::<_, WatcherError>(tokio::spawn(Poller::new(Arc::clone(&watcher), observer, policy).run()))
        })
        .transpose()?;
    let served = axum::serve(listener, http::router(watcher))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
        .map_err(|source| WatcherError::Serve { source });
    if let Some(poller) = poller {
        poller.abort();
    }
    served
}

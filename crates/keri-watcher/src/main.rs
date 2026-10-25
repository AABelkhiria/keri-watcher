//! Runs a KERI watcher: `keri-watcher <config.toml>`.
//!
//! Logs go to standard error, filtered by `RUST_LOG`, `info` by default.

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use keri_watcher::{Config, HttpClient, Observer, Poller, Resolver, Watcher, WatcherError, http, sweeper};
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
    let client = HttpClient::new()?;
    let mut tasks = vec![
        tokio::spawn(Resolver::new(Arc::clone(&watcher), client.clone(), config.witness_timeout()).run()),
        tokio::spawn(sweeper::run(Arc::clone(&watcher), config.escrow_timeout())),
    ];
    let policy = config.poll_policy();
    if !policy.is_disabled() {
        let observer = Observer::new(Arc::clone(&watcher), client, config.witness_timeout());
        tasks.push(tokio::spawn(Poller::new(Arc::clone(&watcher), observer, policy).run()));
    }
    let served = axum::serve(listener, http::router(watcher))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
        .map_err(|source| WatcherError::Serve { source });
    for task in tasks {
        task.abort();
    }
    served
}

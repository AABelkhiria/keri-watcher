//! Asking witnesses for what they hold, over HTTP.
//!
//! keripy's witnesses answer two GET requests the watcher needs: `/ksn?pre={identifier}` with a
//! `/ksn/{witness}` reply the witness signed, reporting the identifier's key state, and
//! `/log?pre={identifier}&fn={ordinal}` with the identifier's events from that first-seen ordinal,
//! as their log replay writes them. Both answer `404` until the witness holds the identifier's
//! latest event fully witnessed.
//!
//! [`WitnessClient`] is the one request the watcher makes, so tests can script the witnesses;
//! [`HttpClient`] makes it over the network.

use std::error::Error;
use std::future::Future;

use axum::body::Bytes;
use http_body_util::{BodyExt, Empty, Limited};
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use keri_protocol::prefix::IdentifierPrefix;

use crate::error::WatcherError;

/// The largest answer read from a witness: a log replay of some thousands of events.
pub const RESPONSE_LIMIT: usize = 16 * 1024 * 1024;

/// Why a witness could not be asked.
pub type ClientError = Box<dyn Error + Send + Sync>;

/// A witness's answer: the HTTP status and the body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Fetched {
    /// The HTTP status code.
    pub status: u16,
    /// The body.
    pub body: Vec<u8>,
}

/// Sends a GET request to a witness.
pub trait WitnessClient: Send + Sync + 'static {
    /// Gets `url`.
    fn get(&self, url: String) -> impl Future<Output = Result<Fetched, ClientError>> + Send;
}

/// Returns the URL that asks the witness at `base` for `identifier`'s key state.
///
/// # Errors
///
/// Returns [`WatcherError::Prefix`] for an identifier that cannot be written as qb64.
pub fn key_state_url(base: &str, identifier: &IdentifierPrefix) -> Result<String, WatcherError> {
    Ok(format!("{}/ksn?pre={}", base.trim_end_matches('/'), qb64(identifier)?))
}

/// Returns the URL that asks the witness at `base` for `identifier`'s events from first-seen
/// ordinal `from`.
///
/// # Errors
///
/// Returns [`WatcherError::Prefix`] for an identifier that cannot be written as qb64.
pub fn log_url(base: &str, identifier: &IdentifierPrefix, from: u128) -> Result<String, WatcherError> {
    Ok(format!(
        "{}/log?pre={}&fn={from:x}",
        base.trim_end_matches('/'),
        qb64(identifier)?
    ))
}

fn qb64(identifier: &IdentifierPrefix) -> Result<String, WatcherError> {
    identifier.qb64().map_err(|source| WatcherError::Prefix { source })
}

/// Asks witnesses over HTTP or HTTPS, trusting the platform's certificate roots.
#[derive(Clone)]
pub struct HttpClient {
    client: Client<HttpsConnector<HttpConnector>, Empty<Bytes>>,
}

impl HttpClient {
    /// Builds a client, reading the platform's certificate roots.
    ///
    /// # Errors
    ///
    /// Returns [`WatcherError::Serve`] when the platform's trust store cannot be read.
    pub fn new() -> Result<Self, WatcherError> {
        let https = hyper_rustls::HttpsConnectorBuilder::new()
            .with_native_roots()
            .map_err(|source| WatcherError::Serve { source })?
            .https_or_http()
            .enable_all_versions()
            .build();
        Ok(Self {
            client: Client::builder(TokioExecutor::new()).build(https),
        })
    }
}

impl WitnessClient for HttpClient {
    async fn get(&self, url: String) -> Result<Fetched, ClientError> {
        let response = self.client.get(url.parse()?).await?;
        let status = response.status().as_u16();
        let body = Limited::new(response.into_body(), RESPONSE_LIMIT)
            .collect()
            .await?
            .to_bytes()
            .to_vec();
        Ok(Fetched { status, body })
    }
}

impl std::fmt::Debug for HttpClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("HttpClient").finish_non_exhaustive()
    }
}

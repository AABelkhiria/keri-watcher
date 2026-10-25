//! The watcher's HTTP routes.
//!
//! | Route | Answers |
//! |---|---|
//! | `POST /` | `204` once the stream is processed, whatever keri-kel made of each message; `400` when the body is not a CESR stream |
//! | `POST /query` | `200` with the answer as `application/cesr`; `404` when the log does not hold what the query asks for yet; `400` when the body is not a single query or keri-kel refuses it; `501` for a mailbox |
//! | `GET /health` | `200` with the watcher's identifier |
//!
//! Anything else that fails answers `500`, and is logged. keri-kel and redb block, so each request
//! is handled on tokio's blocking pool.

use std::sync::Arc;

use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use tracing::{debug, error};

use crate::error::WatcherError;
use crate::watcher::{QueryOutcome, Watcher, blocking};

/// The media type of a CESR stream.
pub const CESR: &str = "application/cesr";

/// Returns the router serving `watcher`.
pub fn router(watcher: Arc<Watcher>) -> Router {
    Router::new()
        .route("/", post(ingest))
        .route("/query", post(query))
        .route("/health", get(health))
        .with_state(watcher)
}

async fn ingest(State(watcher): State<Arc<Watcher>>, body: Bytes) -> Response {
    match blocking(move || watcher.ingest(&body)).await {
        Ok(ingested) => {
            debug!(?ingested, "stream ingested");
            StatusCode::NO_CONTENT.into_response()
        }
        Err(error) => failure(&error),
    }
}

async fn query(State(watcher): State<Arc<Watcher>>, body: Bytes) -> Response {
    match blocking(move || watcher.query(&body)).await {
        Ok(QueryOutcome::Answered(answer)) => ([(header::CONTENT_TYPE, CESR)], answer).into_response(),
        Ok(QueryOutcome::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Ok(QueryOutcome::Mailbox) => StatusCode::NOT_IMPLEMENTED.into_response(),
        Ok(QueryOutcome::Refused(error)) => (StatusCode::BAD_REQUEST, error.to_string()).into_response(),
        Err(error) => failure(&error),
    }
}

async fn health(State(watcher): State<Arc<Watcher>>) -> Response {
    match watcher.identity().prefix().qb64() {
        Ok(prefix) => prefix.into_response(),
        Err(error) => failure(&WatcherError::Prefix { source: error }),
    }
}

fn failure(failed: &WatcherError) -> Response {
    match failed {
        WatcherError::Stream { .. } | WatcherError::NotAQuery => {
            (StatusCode::BAD_REQUEST, failed.to_string()).into_response()
        }
        _ => {
            error!(error = %failed, source = ?std::error::Error::source(failed), "request failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

//! The watcher's HTTP routes.
//!
//! | Route | Answers |
//! |---|---|
//! | `POST /`, `PUT /` | `204` once the stream is processed, whatever keri-kel made of each message; `400` when the body is not a CESR stream |
//! | `POST /query` | `200` with the answer as `application/cesr`; `404` when the log does not hold what the query asks for yet; `400` when the body is not a single query or keri-kel refuses it; `501` for a mailbox |
//! | `GET /oobi/{aid}`, `/oobi/{aid}/{role}`, `/oobi/{aid}/{role}/{eid}` | `200` with the watcher's `/loc/scheme` replies as `application/json+cesr`, when `aid`, and `eid` if given, are the watcher's own; `404` otherwise |
//! | `GET /health` | `200` with the watcher's identifier, what it holds and its witnesses' health, as JSON |
//! | `GET /metrics` | `200` with the watcher's counters and gauges as Prometheus text |
//! | `GET /duplicity/{aid}` | `200` with the duplicity recorded for `aid`, as JSON, empty when there is none; `404` when `aid` is not an identifier |
//!
//! keripy posts one message at a time, its attachments in a `CESR-ATTACHMENT` header, and puts a
//! whole stream as the body; both are taken, as is a whole stream posted. A header's attachments
//! follow the body.
//!
//! Anything else that fails answers `500`, and is logged. keri-kel and redb block, so each request
//! is handled on tokio's blocking pool.

use std::sync::Arc;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderName, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use keri_protocol::prefix::IdentifierPrefix;
use serde::Serialize;
use tracing::{debug, error};

use crate::error::WatcherError;
use crate::watcher::{QueryOutcome, Watcher, blocking};

/// The media type of a CESR stream.
pub const CESR: &str = "application/cesr";

/// The media type keripy serves an OOBI's CESR stream as, and requires when resolving one.
pub const OOBI_CESR: &str = "application/json+cesr";

/// The header naming the identifier an OOBI answers for, keripy's `KERI-AID`.
pub const OOBI_AID: HeaderName = HeaderName::from_static("keri-aid");

/// The media type of Prometheus text.
pub const PROMETHEUS: &str = "text/plain; version=0.0.4";

/// The header keripy puts a posted message's attachments in.
pub const CESR_ATTACHMENT: HeaderName = HeaderName::from_static("cesr-attachment");

/// Returns the router serving `watcher`.
pub fn router(watcher: Arc<Watcher>) -> Router {
    Router::new()
        .route("/", post(ingest).put(ingest))
        .route("/query", post(query))
        .route("/oobi/{aid}", get(oobi))
        .route("/oobi/{aid}/{role}", get(oobi_role))
        .route("/oobi/{aid}/{role}/{eid}", get(oobi_endpoint))
        .route("/health", get(health))
        .route("/metrics", get(metrics))
        .route("/duplicity/{aid}", get(duplicity))
        .with_state(watcher)
}

async fn ingest(State(watcher): State<Arc<Watcher>>, headers: HeaderMap, body: Bytes) -> Response {
    let stream = with_attachments(&headers, body);
    match blocking(move || watcher.ingest(&stream)).await {
        Ok(ingested) => {
            debug!(?ingested, "stream ingested");
            StatusCode::NO_CONTENT.into_response()
        }
        Err(error) => failure(&error),
    }
}

async fn query(State(watcher): State<Arc<Watcher>>, headers: HeaderMap, body: Bytes) -> Response {
    let stream = with_attachments(&headers, body);
    match blocking(move || watcher.query(&stream)).await {
        Ok(QueryOutcome::Answered(answer)) => ([(header::CONTENT_TYPE, CESR)], answer).into_response(),
        Ok(QueryOutcome::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Ok(QueryOutcome::Mailbox) => StatusCode::NOT_IMPLEMENTED.into_response(),
        Ok(QueryOutcome::Refused(error)) => (StatusCode::BAD_REQUEST, error.to_string()).into_response(),
        Err(error) => failure(&error),
    }
}

async fn oobi(State(watcher): State<Arc<Watcher>>, Path(aid): Path<String>) -> Response {
    answer_oobi(watcher, aid, None).await
}

async fn oobi_role(State(watcher): State<Arc<Watcher>>, Path((aid, _)): Path<(String, String)>) -> Response {
    answer_oobi(watcher, aid, None).await
}

async fn oobi_endpoint(
    State(watcher): State<Arc<Watcher>>,
    Path((aid, _, eid)): Path<(String, String, String)>,
) -> Response {
    answer_oobi(watcher, aid, Some(eid)).await
}

/// Answers an OOBI for `aid`, naming endpoint `eid`, whatever role it names: the watcher plays one.
async fn answer_oobi(watcher: Arc<Watcher>, aid: String, eid: Option<String>) -> Response {
    let (Ok(identifier), Ok(endpoint)) = (
        IdentifierPrefix::from_qb64(&aid),
        eid.as_deref().map(IdentifierPrefix::from_qb64).transpose(),
    ) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    match blocking(move || watcher.oobi(&identifier, endpoint.as_ref())).await {
        Ok(Some(stream)) => ([(header::CONTENT_TYPE, OOBI_CESR.to_owned()), (OOBI_AID, aid)], stream).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => failure(&error),
    }
}

async fn health(State(watcher): State<Arc<Watcher>>) -> Response {
    match blocking(move || watcher.health()).await {
        Ok(health) => json(&health),
        Err(error) => failure(&error),
    }
}

async fn metrics(State(watcher): State<Arc<Watcher>>) -> Response {
    match blocking(move || watcher.metrics()).await {
        Ok(text) => ([(header::CONTENT_TYPE, PROMETHEUS)], text).into_response(),
        Err(error) => failure(&error),
    }
}

/// One sequence number duplicity was seen at, as `GET /duplicity/{aid}` answers it.
#[derive(Serialize)]
struct Duplicity {
    sequence_number: u128,
    reported: Vec<Reported>,
}

/// One source's event, as `GET /duplicity/{aid}` answers it.
#[derive(Serialize)]
struct Reported {
    said: String,
    source: String,
    first_seen: String,
}

async fn duplicity(State(watcher): State<Arc<Watcher>>, Path(aid): Path<String>) -> Response {
    let Ok(identifier) = IdentifierPrefix::from_qb64(&aid) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    match blocking(move || watcher.duplicity(&identifier)).await {
        Ok(recorded) => {
            let answer: Vec<Duplicity> = recorded
                .into_iter()
                .map(|(sequence_number, sightings)| Duplicity {
                    sequence_number,
                    reported: sightings
                        .into_iter()
                        .map(|sighting| Reported {
                            said: sighting.said,
                            source: sighting.source,
                            first_seen: sighting.first_seen.into_string(),
                        })
                        .collect(),
                })
                .collect();
            json(&answer)
        }
        Err(error) => failure(&error),
    }
}

fn json(value: &impl Serialize) -> Response {
    match serde_json::to_vec(value) {
        Ok(body) => ([(header::CONTENT_TYPE, "application/json")], body).into_response(),
        Err(error) => failure(&WatcherError::answer(error)),
    }
}

/// The body, followed by the attachments a `CESR-ATTACHMENT` header carries.
fn with_attachments(headers: &HeaderMap, body: Bytes) -> Vec<u8> {
    let mut stream = Vec::from(body);
    if let Some(attachments) = headers.get(CESR_ATTACHMENT) {
        stream.extend_from_slice(attachments.as_bytes());
    }
    stream
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

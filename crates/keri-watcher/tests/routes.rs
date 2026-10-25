//! The watcher's routes, served in process on an in-memory database with a fixed clock: what is
//! ingested is kept, and queries are answered with messages another `Kevery` accepts.

use std::error::Error;
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderValue, Request, StatusCode, header};
use chrono::{DateTime, Utc};
use http_body_util::BodyExt;
use keri_cesr::crypto::digest::{Digest, DigestAlgorithm};
use keri_cesr::crypto::signer::{SignaturePlacement, Signer};
use keri_cesr::crypto::verifier::KeyTransferability;
use keri_kel::{Kevery, Processed};
use keri_protocol::attachment::{ReceiptCouple, SignatureSeal, SignedMessageBuilder};
use keri_protocol::event::KeyEvent;
use keri_protocol::event::inception::InceptionBuilder;
use keri_protocol::event::interaction::InteractionBuilder;
use keri_protocol::event::query::{QueryArguments, QueryBuilder};
use keri_protocol::event::reply::route::{Role, Scheme};
use keri_protocol::event::timestamp::Timestamp;
use keri_protocol::prefix::{IdentifierPrefix, PrefixDerivation};
use keri_protocol::serialization::{Sad, SadValue};
use keri_protocol::stream::{Message, parse_stream};
use keri_store_redb::RedbStore;
use keri_watcher::{HttpClient, Identity, Watcher, WitnessClient, http};
use tower::ServiceExt;

const STAMP: &str = "2021-01-01T00:00:00.000000+00:00";

type Failure = Box<dyn Error>;

fn signer(seed: u8, transferability: KeyTransferability) -> Result<Signer, Failure> {
    Ok(Signer::from_seed(&[seed; 32], transferability)?)
}

fn prefix(signer: &Signer) -> Result<IdentifierPrefix, Failure> {
    Ok(IdentifierPrefix::from_qb64(&signer.verifier().qb64()?)?)
}

fn digest(signer: &Signer) -> Result<Digest, Failure> {
    Ok(Digest::derive(
        DigestAlgorithm::Blake3_256,
        &signer.verifier().qb64_bytes()?,
    ))
}

fn signed(event: &KeyEvent, key: &Signer) -> Result<Vec<u8>, Failure> {
    let message = SignedMessageBuilder::new(event.serialized())
        .controller_signatures(vec![key.sign_indexed(event.raw(), SignaturePlacement::both_lists(0))?])
        .build()?;
    Ok(message.into_bytes())
}

/// A watcher whose key is derived from seed 30, on an in-memory database, at [`STAMP`].
fn watcher() -> Result<(Router, IdentifierPrefix), Failure> {
    announcing(Vec::new())
}

/// The watcher of [`watcher`], announcing these URLs.
fn announcing(locations: Vec<(Scheme, String)>) -> Result<(Router, IdentifierPrefix), Failure> {
    let identity = Identity::from_signer(signer(30, KeyTransferability::NonTransferable)?)?;
    let id = identity.prefix().clone();
    let kevery = Kevery::with_store(RedbStore::in_memory()?);
    let at: DateTime<Utc> = STAMP.parse()?;
    let watcher = Watcher::new(identity, kevery, Box::new(move || at)).announcing(locations);
    Ok((http::router(Arc::new(watcher)), id))
}

/// A controller with an inception and two interactions.
struct Controller {
    key: Signer,
    identifier: IdentifierPrefix,
    events: Vec<KeyEvent>,
}

fn controller() -> Result<Controller, Failure> {
    let key = signer(1, KeyTransferability::Transferable)?;
    let inception = InceptionBuilder::new(vec![key.verifier().clone()])
        .next_key_digests(vec![digest(&signer(2, KeyTransferability::Transferable)?)?])
        .prefix_derivation(PrefixDerivation::Blake3_256)
        .build()?;
    let identifier = inception.identifier().clone();
    let first = InteractionBuilder::new(identifier.clone(), inception.said(), 1).build()?;
    let second = InteractionBuilder::new(identifier.clone(), first.said(), 2).build()?;
    Ok(Controller {
        key,
        identifier,
        events: vec![inception, first, second],
    })
}

/// A query on `route` about `identifier`, signed by a transferable requester, or by the
/// non-transferable key of seed 50.
fn query(route: &str, arguments: QueryArguments, transferable: bool) -> Result<Vec<u8>, Failure> {
    let query = QueryBuilder::new(route, Timestamp::parse(STAMP)?)
        .query(arguments.into_sad()?)
        .build()?;
    let builder = SignedMessageBuilder::new(query.serialized());
    let builder = if transferable {
        let requester = signer(40, KeyTransferability::Transferable)?;
        builder
            .controller_signatures(vec![
                requester.sign_indexed(query.raw(), SignaturePlacement::both_lists(0))?,
            ])
            .seal(SignatureSeal::Last {
                identifier: prefix(&requester)?,
            })
    } else {
        let requester = signer(50, KeyTransferability::NonTransferable)?;
        builder.receipt_couples(vec![ReceiptCouple::new(
            requester.verifier().clone(),
            requester.sign_unindexed(query.raw())?,
        )?])
    };
    Ok(builder.build()?.into_bytes())
}

async fn send(router: &Router, method: &str, path: &str, body: Vec<u8>) -> Result<(StatusCode, Vec<u8>), Failure> {
    let request = Request::builder()
        .method(method)
        .uri(path)
        .header(header::CONTENT_TYPE, http::CESR)
        .body(Body::from(body))?;
    let response = router.clone().oneshot(request).await?;
    let status = response.status();
    let body = response.into_body().collect().await?.to_bytes().to_vec();
    Ok((status, body))
}

async fn ingest(router: &Router, controller: &Controller) -> Result<(), Failure> {
    let mut stream = Vec::new();
    for event in &controller.events {
        stream.extend(signed(event, &controller.key)?);
    }
    let (status, _) = send(router, "POST", "/", stream).await?;
    assert_eq!(status, StatusCode::NO_CONTENT);
    Ok(())
}

#[tokio::test]
async fn health_names_the_watcher() -> Result<(), Failure> {
    let (router, id) = watcher()?;
    let (status, body) = send(&router, "GET", "/health", Vec::new()).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(String::from_utf8(body)?, id.qb64()?);
    Ok(())
}

#[tokio::test]
async fn a_log_ingested_is_replayed_whole() -> Result<(), Failure> {
    let (router, id) = watcher()?;
    let controller = controller()?;
    ingest(&router, &controller).await?;
    let arguments = QueryArguments::new(controller.identifier.clone(), id);
    let (status, body) = send(&router, "POST", "/query", query("logs", arguments, true)?).await?;
    assert_eq!(status, StatusCode::OK);

    let now = Timestamp::parse(STAMP)?;
    let mut elsewhere = Kevery::new();
    let replayed = parse_stream(&body)?;
    assert_eq!(replayed.len(), controller.events.len());
    for message in &replayed {
        assert_eq!(elsewhere.process(message, &now)?, Processed::Accepted);
    }
    let kever = elsewhere.kever(&controller.identifier)?.ok_or("log not replayed")?;
    assert_eq!(kever.sequence_number(), 2);
    Ok(())
}

#[tokio::test]
async fn key_state_is_answered_with_a_notice_the_watcher_signed() -> Result<(), Failure> {
    let (router, id) = watcher()?;
    let controller = controller()?;
    ingest(&router, &controller).await?;
    let arguments = QueryArguments::new(controller.identifier.clone(), id.clone());
    let (status, body) = send(&router, "POST", "/query", query("ksn", arguments, false)?).await?;
    assert_eq!(status, StatusCode::OK);

    let now = Timestamp::parse(STAMP)?;
    let mut elsewhere = Kevery::new();
    assert_eq!(
        elsewhere.process(&Message::from_bytes(&body)?, &now)?,
        Processed::KeyStateAccepted
    );
    let notice = elsewhere
        .key_state_notice(&controller.identifier, &id)?
        .ok_or("notice not kept")?;
    assert_eq!(notice.state().sequence_number(), 2);
    Ok(())
}

#[tokio::test]
async fn a_query_the_log_cannot_answer_yet_is_not_found() -> Result<(), Failure> {
    let (router, id) = watcher()?;
    let controller = controller()?;
    let arguments = QueryArguments::new(controller.identifier.clone(), id);
    let (status, _) = send(&router, "POST", "/query", query("ksn", arguments, true)?).await?;
    assert_eq!(status, StatusCode::NOT_FOUND);
    Ok(())
}

#[tokio::test]
async fn what_cannot_be_answered_is_told_apart() -> Result<(), Failure> {
    let (router, id) = watcher()?;
    let controller = controller()?;
    ingest(&router, &controller).await?;

    // keri-kel refuses a query it can neither answer nor escrow.
    let unknown = QueryArguments::new(prefix(&signer(60, KeyTransferability::Transferable)?)?, id.clone());
    let (status, _) = send(&router, "POST", "/query", query("ksn", unknown, false)?).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let mut topics = Sad::new();
    topics.insert("/receipt", SadValue::integer(0)?)?;
    let mailbox = QueryArguments::new(controller.identifier.clone(), id).topics(topics);
    let (status, _) = send(&router, "POST", "/query", query("mbx", mailbox, true)?).await?;
    assert_eq!(status, StatusCode::NOT_IMPLEMENTED);

    let event = controller.events.first().ok_or("no inception")?;
    let (status, _) = send(&router, "POST", "/query", signed(event, &controller.key)?).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, _) = send(&router, "POST", "/", b"not a stream".to_vec()).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    Ok(())
}

#[tokio::test]
async fn the_http_client_reads_a_served_answer() -> Result<(), Failure> {
    let (router, id) = watcher()?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let server = tokio::spawn(async move { axum::serve(listener, router).await });

    let client = HttpClient::new()?;
    let health = client
        .get(format!("http://{address}/health"))
        .await
        .map_err(|error| error.to_string())?;
    assert_eq!(health.status, 200);
    assert_eq!(String::from_utf8(health.body)?, id.qb64()?);
    let missing = client
        .get(format!("http://{address}/nowhere"))
        .await
        .map_err(|error| error.to_string())?;
    assert_eq!(missing.status, 404);
    server.abort();
    Ok(())
}

#[tokio::test]
async fn the_watchers_oobi_tells_where_it_is_reached_and_that_it_controls_itself() -> Result<(), Failure> {
    let urls = [
        (Scheme::Http, "http://w.example:5631".to_owned()),
        (Scheme::Https, "https://w.example".to_owned()),
    ];
    let (router, id) = announcing(urls.to_vec())?;
    let aid = id.qb64()?;
    for path in [
        format!("/oobi/{aid}"),
        format!("/oobi/{aid}/controller"),
        format!("/oobi/{aid}/watcher/{aid}"),
    ] {
        let request = Request::builder().uri(path.as_str()).body(Body::empty())?;
        let response = router.clone().oneshot(request).await?;
        assert_eq!(response.status(), StatusCode::OK, "{path}");
        let headers = response.headers();
        assert_eq!(
            headers.get(header::CONTENT_TYPE).map(HeaderValue::as_bytes),
            Some(http::OOBI_CESR.as_bytes())
        );
        assert_eq!(
            headers.get(http::OOBI_AID).map(HeaderValue::as_bytes),
            Some(aid.as_bytes())
        );
        let body = response.into_body().collect().await?.to_bytes();

        let (mut kevery, now) = (Kevery::new(), Timestamp::parse(STAMP)?);
        let processed = parse_stream(&body)?
            .iter()
            .map(|message| kevery.process(message, &now))
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(
            processed,
            vec![
                Processed::LocationAccepted,
                Processed::LocationAccepted,
                Processed::EndRoleAccepted
            ]
        );
        assert!(
            kevery
                .end_role(&id, Role::Controller, &id)?
                .is_some_and(|record| record.allowed())
        );
        for (scheme, url) in &urls {
            assert_eq!(
                kevery.location(&id, *scheme)?.map(|location| location.url().to_owned()),
                Some(url.clone())
            );
        }
    }
    Ok(())
}

#[tokio::test]
async fn only_the_watchers_own_oobi_is_answered() -> Result<(), Failure> {
    let (router, id) = announcing(vec![(Scheme::Http, "http://w.example:5631".to_owned())])?;
    let aid = id.qb64()?;
    let other = prefix(&signer(31, KeyTransferability::NonTransferable)?)?.qb64()?;
    for path in [
        format!("/oobi/{other}"),
        format!("/oobi/{aid}/watcher/{other}"),
        "/oobi/nope".to_owned(),
    ] {
        let (status, _) = send(&router, "GET", &path, Vec::new()).await?;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path}");
    }
    let (silent, _) = watcher()?;
    let (status, _) = send(&silent, "GET", &format!("/oobi/{aid}"), Vec::new()).await?;
    assert_eq!(status, StatusCode::NOT_FOUND);
    Ok(())
}

/// Splits a message into its event, the body keripy posts, and its attachments, the header it
/// posts them in.
fn split(message: &[u8]) -> Result<(Vec<u8>, String), Failure> {
    let event = Message::from_bytes(message)?.event().raw().len();
    let (body, attachments) = message
        .split_at_checked(event)
        .ok_or("message shorter than its event")?;
    Ok((body.to_vec(), String::from_utf8(attachments.to_vec())?))
}

async fn post_split(router: &Router, path: &str, message: &[u8]) -> Result<(StatusCode, Vec<u8>), Failure> {
    let (body, attachments) = split(message)?;
    let request = Request::builder()
        .method("POST")
        .uri(path)
        .header(header::CONTENT_TYPE, "application/cesr+json")
        .header(http::CESR_ATTACHMENT, attachments)
        .body(Body::from(body))?;
    let response = router.clone().oneshot(request).await?;
    let status = response.status();
    Ok((status, response.into_body().collect().await?.to_bytes().to_vec()))
}

#[tokio::test]
async fn messages_are_taken_as_keripy_posts_and_puts_them() -> Result<(), Failure> {
    let controller = controller()?;
    let mut stream = Vec::new();
    for event in &controller.events {
        stream.extend(signed(event, &controller.key)?);
    }

    let (put, id) = watcher()?;
    let (status, _) = send(&put, "PUT", "/", stream).await?;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (posted, _) = watcher()?;
    for event in &controller.events {
        let (status, _) = post_split(&posted, "/", &signed(event, &controller.key)?).await?;
        assert_eq!(status, StatusCode::NO_CONTENT);
    }

    let now = Timestamp::parse(STAMP)?;
    for router in [&put, &posted] {
        let arguments = QueryArguments::new(controller.identifier.clone(), id.clone());
        let (status, body) = post_split(router, "/query", &query("ksn", arguments, false)?).await?;
        assert_eq!(status, StatusCode::OK);
        let mut elsewhere = Kevery::new();
        elsewhere.process(&Message::from_bytes(&body)?, &now)?;
        let notice = elsewhere
            .key_state_notice(&controller.identifier, &id)?
            .ok_or("notice not kept")?;
        assert_eq!(notice.state().sequence_number(), 2);
    }
    Ok(())
}

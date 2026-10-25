//! Observing identifiers through scripted witnesses: what each witness, and each OOBI, answers is
//! set by the test, and the watcher, on an in-memory database with a clock the test sets, decides
//! what to fetch and keep.

use std::collections::HashMap;
use std::error::Error;
use std::future::Future;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::{DateTime, TimeDelta, Utc};
use http_body_util::BodyExt;
use tower::ServiceExt;

use keri_cesr::crypto::digest::{Digest, DigestAlgorithm};
use keri_cesr::crypto::signer::{SignaturePlacement, Signer};
use keri_cesr::crypto::verifier::KeyTransferability;
use keri_cesr::sequence::SequenceNumber;
use keri_kel::Kevery;
use keri_protocol::attachment::{ReceiptCouple, SignatureSeal, SignedMessageBuilder};
use keri_protocol::event::KeyEvent;
use keri_protocol::event::inception::InceptionBuilder;
use keri_protocol::event::interaction::InteractionBuilder;
use keri_protocol::event::reply::ReplyMessage;
use keri_protocol::event::reply::route::{LocationScheme, ReplyRoute, RouteAction, Scheme, WatcherObservation};
use keri_protocol::event::timestamp::Timestamp;
use keri_protocol::prefix::{IdentifierPrefix, PrefixDerivation};
use keri_protocol::serialization::Sad;
use keri_protocol::stream::Message;
use keri_store_redb::RedbStore;
use keri_watch::PollPolicy;
use keri_watcher::witness::{ClientError, key_state_url, log_url};
use keri_watcher::{
    Fetched, Health, Identity, Ingested, Observation, Observer, Poller, Resolution, Resolver, Sighting, Swept, Watcher,
    WitnessClient, http,
};

const STAMP: &str = "2021-01-01T00:00:00.000000+00:00";
const TIMEOUT: Duration = Duration::from_secs(5);

type Failure = Box<dyn Error>;

fn signer(seed: u8, transferability: KeyTransferability) -> Result<Signer, Failure> {
    Ok(Signer::from_seed(&[seed; 32], transferability)?)
}

fn prefix(signer: &Signer) -> Result<IdentifierPrefix, Failure> {
    Ok(IdentifierPrefix::from_qb64(&signer.verifier().qb64()?)?)
}

/// Witnesses that answer what the test scripted for each URL, and fail for any other.
#[derive(Clone, Default)]
struct Script {
    answers: Arc<Mutex<HashMap<String, Fetched>>>,
}

impl Script {
    fn answer(&self, url: String, status: u16, body: Vec<u8>) {
        self.answers
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(url, Fetched { status, body });
    }
}

impl WitnessClient for Script {
    fn get(&self, url: String) -> impl Future<Output = Result<Fetched, ClientError>> + Send {
        let answers = self.answers.lock().unwrap_or_else(PoisonError::into_inner);
        let answer = answers
            .get(&url)
            .cloned()
            .ok_or_else(|| format!("{url} unreachable").into());
        std::future::ready(answer)
    }
}

/// A controller witnessed by two witnesses, with the events it signed, each carrying both
/// witnesses' signatures, and a second interaction at sequence number 1 contradicting the first.
struct World {
    key: Signer,
    witnesses: [Signer; 2],
    identifier: IdentifierPrefix,
    events: Vec<KeyEvent>,
    contradicting: KeyEvent,
}

const URLS: [&str; 2] = ["http://w0.example:5642/", "http://w1.example:5643"];

fn world() -> Result<World, Failure> {
    let key = signer(1, KeyTransferability::Transferable)?;
    let next = signer(2, KeyTransferability::Transferable)?;
    let witnesses = [
        signer(31, KeyTransferability::NonTransferable)?,
        signer(32, KeyTransferability::NonTransferable)?,
    ];
    let inception = InceptionBuilder::new(vec![key.verifier().clone()])
        .next_key_digests(vec![Digest::derive(
            DigestAlgorithm::Blake3_256,
            &next.verifier().qb64_bytes()?,
        )])
        .witnesses(vec![prefix(&witnesses[0])?, prefix(&witnesses[1])?])
        .witness_threshold(2)
        .prefix_derivation(PrefixDerivation::Blake3_256)
        .build()?;
    let identifier = inception.identifier().clone();
    let first = InteractionBuilder::new(identifier.clone(), inception.said(), 1).build()?;
    let second = InteractionBuilder::new(identifier.clone(), first.said(), 2).build()?;
    let mut anchor = Sad::new();
    anchor.insert("i", identifier.qb64()?)?;
    let contradicting = InteractionBuilder::new(identifier.clone(), inception.said(), 1)
        .anchors(vec![anchor])
        .build()?;
    Ok(World {
        key,
        witnesses,
        identifier,
        events: vec![inception, first, second],
        contradicting,
    })
}

impl World {
    fn witness(&self, index: usize) -> Result<(&Signer, IdentifierPrefix, &'static str), Failure> {
        let witness = self.witnesses.get(index).ok_or("no such witness")?;
        let url = URLS.get(index).ok_or("no such url")?;
        Ok((witness, prefix(witness)?, url))
    }

    /// An event signed by the controller and both witnesses.
    fn signed(&self, event: &KeyEvent) -> Result<Vec<u8>, Failure> {
        let witnessed = self
            .witnesses
            .iter()
            .zip(0..)
            .map(|(witness, index)| witness.sign_indexed(event.raw(), SignaturePlacement::both_lists(index)))
            .collect::<Result<Vec<_>, _>>()?;
        let message = SignedMessageBuilder::new(event.serialized())
            .controller_signatures(vec![
                self.key.sign_indexed(event.raw(), SignaturePlacement::both_lists(0))?,
            ])
            .witness_signatures(witnessed)
            .build()?;
        Ok(message.into_bytes())
    }

    /// A reply signed by witness `index`.
    fn by_witness(&self, index: usize, reply: &ReplyMessage) -> Result<Vec<u8>, Failure> {
        let (witness, ..) = self.witness(index)?;
        let couple = ReceiptCouple::new(witness.verifier().clone(), witness.sign_unindexed(reply.raw())?)?;
        Ok(SignedMessageBuilder::new(reply.serialized())
            .receipt_couples(vec![couple])
            .build()?
            .into_bytes())
    }

    /// Both witnesses' locations.
    fn locations(&self) -> Result<Vec<u8>, Failure> {
        let mut stream = Vec::new();
        for index in 0..2 {
            let (_, id, url) = self.witness(index)?;
            let reply = ReplyRoute::LocationScheme(LocationScheme::new(id, Scheme::Http, url)?)
                .to_reply(Timestamp::parse(STAMP)?)?;
            stream.extend(self.by_witness(index, &reply)?);
        }
        Ok(stream)
    }

    /// Witness `index`'s key state notice, after the events given.
    fn notice(&self, index: usize, events: &[&KeyEvent]) -> Result<Vec<u8>, Failure> {
        let now = Timestamp::parse(STAMP)?;
        let mut kevery = Kevery::new();
        for event in events {
            kevery.process(&Message::from_bytes(&self.signed(event)?)?, &now)?;
        }
        let state = kevery.kever(&self.identifier)?.ok_or("no state")?.state()?;
        let (_, id, _) = self.witness(index)?;
        let reply = ReplyRoute::KeyStateNotice {
            source: id,
            state: Box::new(state),
        }
        .to_reply(now)?;
        self.by_witness(index, &reply)
    }

    /// The controller's registration asking `watcher` to observe it, with an OOBI for it.
    fn registration(&self, watcher: &IdentifierPrefix, oobi: Option<&str>) -> Result<Vec<u8>, Failure> {
        let mut observation = WatcherObservation::new(self.identifier.clone(), self.identifier.clone());
        if let Some(oobi) = oobi {
            observation = observation.oobi(oobi);
        }
        let reply = ReplyRoute::WatcherObservation {
            watcher: watcher.clone(),
            action: RouteAction::Add,
            observation,
        }
        .to_reply(Timestamp::parse(STAMP)?)?;
        let inception = self.events.first().ok_or("no inception")?;
        Ok(SignedMessageBuilder::new(reply.serialized())
            .controller_signatures(vec![
                self.key.sign_indexed(reply.raw(), SignaturePlacement::both_lists(0))?,
            ])
            .seal(SignatureSeal::Event {
                identifier: self.identifier.clone(),
                sequence_number: SequenceNumber::new(0),
                said: inception.said(),
            })
            .build()?
            .into_bytes())
    }

    /// Scripts witness `index` to report the state after `events` and serve them as its log.
    fn serve(&self, script: &Script, index: usize, events: &[&KeyEvent]) -> Result<(), Failure> {
        let (_, _, url) = self.witness(index)?;
        script.answer(key_state_url(url, &self.identifier)?, 200, self.notice(index, events)?);
        let mut log = Vec::new();
        for event in events {
            log.extend(self.signed(event)?);
        }
        script.answer(log_url(url, &self.identifier, 0)?, 200, log.clone());
        let mut rest = Vec::new();
        for event in events.iter().skip(1) {
            rest.extend(self.signed(event)?);
        }
        script.answer(log_url(url, &self.identifier, 1)?, 200, rest);
        Ok(())
    }

    fn event(&self, sequence_number: usize) -> Result<&KeyEvent, Failure> {
        Ok(self.events.get(sequence_number).ok_or("no such event")?)
    }
}

/// What the watcher records of these sources reporting these events, at [`STAMP`].
fn sightings(reported: &[(IdentifierPrefix, &KeyEvent)]) -> Result<Vec<Sighting>, Failure> {
    reported
        .iter()
        .map(|(source, event)| {
            Ok(Sighting {
                said: event.said().qb64()?,
                source: source.qb64()?,
                first_seen: Timestamp::parse(STAMP)?,
            })
        })
        .collect()
}

/// A clock the test sets, starting at [`STAMP`].
#[derive(Clone)]
struct Time(Arc<Mutex<DateTime<Utc>>>);

impl Time {
    fn new() -> Result<Self, Failure> {
        Ok(Self(Arc::new(Mutex::new(STAMP.parse()?))))
    }

    fn advance(&self, by: TimeDelta) {
        let mut at = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        *at += by;
    }

    fn now(&self) -> DateTime<Utc> {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// A watcher on an in-memory database, reading `time`.
fn empty_watcher(time: &Time) -> Result<Arc<Watcher>, Failure> {
    let identity = Identity::from_signer(signer(30, KeyTransferability::NonTransferable)?)?;
    let kevery = Kevery::with_store(RedbStore::in_memory()?);
    let time = time.clone();
    Ok(Arc::new(Watcher::new(identity, kevery, Box::new(move || time.now()))))
}

/// A watcher holding the controller's events up to `held` and the witnesses' locations.
fn watcher(world: &World, held: &[&KeyEvent]) -> Result<Arc<Watcher>, Failure> {
    let watcher = empty_watcher(&Time::new()?)?;
    let mut stream = world.locations()?;
    for event in held {
        stream.extend(world.signed(event)?);
    }
    watcher.ingest(&stream)?;
    Ok(watcher)
}

fn latest(watcher: &Watcher, identifier: &IdentifierPrefix) -> Result<Option<u128>, Failure> {
    Ok(watcher.witnessed(identifier)?.map(|held| held.sequence_number))
}

#[tokio::test]
async fn a_log_behind_its_witnesses_is_fetched() -> Result<(), Failure> {
    let world = world()?;
    let all: Vec<&KeyEvent> = world.events.iter().collect();
    let watcher = watcher(&world, &[world.event(0)?])?;
    let script = Script::default();
    world.serve(&script, 0, &all)?;
    world.serve(&script, 1, &all)?;
    let mut observer = Observer::new(Arc::clone(&watcher), script, TIMEOUT);

    let found = observer.observe(&world.identifier, Duration::ZERO).await?;
    assert_eq!(found, Observation::Updated { from: 0, to: 2 });
    assert_eq!(latest(&watcher, &world.identifier)?, Some(2));
    let again = observer.observe(&world.identifier, Duration::from_secs(1)).await?;
    assert_eq!(again, Observation::UpToDate { sequence_number: 2 });
    Ok(())
}

#[tokio::test]
async fn an_unreachable_witness_is_passed_over() -> Result<(), Failure> {
    let world = world()?;
    let all: Vec<&KeyEvent> = world.events.iter().collect();
    let watcher = watcher(&world, &[world.event(0)?])?;
    let script = Script::default();
    world.serve(&script, 1, &all)?;
    let mut observer = Observer::new(Arc::clone(&watcher), script, TIMEOUT);

    let found = observer.observe(&world.identifier, Duration::ZERO).await?;
    assert_eq!(found, Observation::Updated { from: 0, to: 2 });
    let (_, unreachable, _) = world.witness(0)?;
    let record = observer
        .health()
        .records()
        .find(|record| record.witness() == &unreachable)
        .ok_or("no record of the unreachable witness")?;
    assert_eq!(record.consecutive_failures(), 1);
    Ok(())
}

#[tokio::test]
async fn witnesses_that_hold_nothing_leave_the_log_as_it_is() -> Result<(), Failure> {
    let world = world()?;
    let watcher = watcher(&world, &[world.event(0)?])?;
    let script = Script::default();
    for index in 0..2 {
        let (_, _, url) = world.witness(index)?;
        script.answer(key_state_url(url, &world.identifier)?, 404, Vec::new());
    }
    let mut observer = Observer::new(Arc::clone(&watcher), script, TIMEOUT);
    assert_eq!(
        observer.observe(&world.identifier, Duration::ZERO).await?,
        Observation::Silent
    );

    let stranger = prefix(&signer(60, KeyTransferability::Transferable)?)?;
    assert_eq!(observer.observe(&stranger, Duration::ZERO).await?, Observation::Unknown);
    Ok(())
}

#[tokio::test]
async fn a_witness_that_reports_more_than_it_serves_leaves_the_log_behind() -> Result<(), Failure> {
    let world = world()?;
    let all: Vec<&KeyEvent> = world.events.iter().collect();
    let watcher = watcher(&world, &[world.event(0)?])?;
    let script = Script::default();
    for index in 0..2 {
        let (_, _, url) = world.witness(index)?;
        script.answer(key_state_url(url, &world.identifier)?, 200, world.notice(index, &all)?);
        script.answer(log_url(url, &world.identifier, 1)?, 404, Vec::new());
    }
    let mut observer = Observer::new(Arc::clone(&watcher), script, TIMEOUT);
    assert_eq!(
        observer.observe(&world.identifier, Duration::ZERO).await?,
        Observation::Behind {
            sequence_number: 0,
            reported: 2
        }
    );
    Ok(())
}

#[tokio::test]
async fn witnesses_reporting_different_events_are_duplicitous() -> Result<(), Failure> {
    let world = world()?;
    let watcher = watcher(&world, &[world.event(0)?])?;
    let script = Script::default();
    world.serve(&script, 0, &[world.event(0)?, world.event(1)?])?;
    world.serve(&script, 1, &[world.event(0)?, &world.contradicting])?;
    let mut observer = Observer::new(Arc::clone(&watcher), script, TIMEOUT);

    let found = observer.observe(&world.identifier, Duration::ZERO).await?;
    let Observation::Duplicitous {
        sequence_number,
        conflicting,
    } = found
    else {
        return Err(format!("not duplicitous: {found:?}").into());
    };
    assert_eq!(sequence_number, 1);
    assert_eq!(conflicting.len(), 2);
    assert_eq!(latest(&watcher, &world.identifier)?, Some(0));

    let recorded = sightings(&[
        (world.witness(0)?.1, world.event(1)?),
        (world.witness(1)?.1, &world.contradicting),
    ])?;
    assert_eq!(watcher.duplicity(&world.identifier)?, vec![(1, recorded.clone())]);
    observer.observe(&world.identifier, Duration::from_secs(60)).await?;
    assert_eq!(watcher.duplicity(&world.identifier)?, vec![(1, recorded.clone())]);

    let served: serde_json::Value =
        serde_json::from_slice(&get(&watcher, &format!("/duplicity/{}", world.identifier.qb64()?)).await?)?;
    let reported: Vec<serde_json::Value> = recorded
        .iter()
        .map(|sighting| {
            serde_json::json!({
                "said": sighting.said,
                "source": sighting.source,
                "first_seen": STAMP,
            })
        })
        .collect();
    assert_eq!(
        served,
        serde_json::json!([{ "sequence_number": 1, "reported": reported }])
    );
    Ok(())
}

#[tokio::test]
async fn a_witness_reporting_another_event_than_the_logs_contradicts_it() -> Result<(), Failure> {
    let world = world()?;
    let watcher = watcher(&world, &[world.event(0)?, world.event(1)?])?;
    let script = Script::default();
    world.serve(&script, 0, &[world.event(0)?, &world.contradicting])?;
    let mut observer = Observer::new(Arc::clone(&watcher), script, TIMEOUT);

    let (_, contradicting, _) = world.witness(0)?;
    assert_eq!(
        observer.observe(&world.identifier, Duration::ZERO).await?,
        Observation::Contradicted {
            witnesses: vec![contradicting]
        }
    );
    assert_eq!(latest(&watcher, &world.identifier)?, Some(1));
    assert_eq!(
        watcher.duplicity(&world.identifier)?,
        vec![(
            1,
            sightings(&[
                (watcher.identity().prefix().clone(), world.event(1)?),
                (world.witness(0)?.1, &world.contradicting),
            ])?
        )]
    );
    Ok(())
}

#[tokio::test]
async fn the_poller_observes_what_registrations_ask_for_when_due() -> Result<(), Failure> {
    let world = world()?;
    let all: Vec<&KeyEvent> = world.events.iter().collect();
    let watcher = watcher(&world, &[world.event(0)?])?;
    let script = Script::default();
    world.serve(&script, 0, &all)?;
    world.serve(&script, 1, &all)?;
    let observer = Observer::new(Arc::clone(&watcher), script, TIMEOUT);
    let mut poller = Poller::new(Arc::clone(&watcher), observer, PollPolicy::new(Duration::from_secs(60)));

    assert_eq!(poller.round(Duration::ZERO).await?, Vec::new());
    watcher.ingest(&world.registration(watcher.identity().prefix(), None)?)?;
    assert_eq!(
        poller.round(Duration::from_secs(1)).await?,
        vec![(world.identifier.clone(), Observation::Updated { from: 0, to: 2 })]
    );
    assert_eq!(poller.round(Duration::from_secs(30)).await?, Vec::new());
    assert_eq!(
        poller.round(Duration::from_secs(61)).await?,
        vec![(world.identifier.clone(), Observation::UpToDate { sequence_number: 2 })]
    );

    let health: Health = serde_json::from_slice(&get(&watcher, "/health").await?)?;
    assert_eq!(health.held.observed, 1);
    let mut asked: Vec<(String, u64)> = health
        .witnesses
        .iter()
        .map(|report| (report.witness.clone(), report.successes))
        .collect();
    asked.sort();
    let mut expected = vec![(world.witness(0)?.1.qb64()?, 3), (world.witness(1)?.1.qb64()?, 2)];
    expected.sort();
    assert_eq!(asked, expected);
    let metrics = String::from_utf8(get(&watcher, "/metrics").await?)?;
    for line in [
        "keri_watcher_observations_total{found=\"updated\"} 1",
        "keri_watcher_observations_total{found=\"up_to_date\"} 1",
        "keri_watcher_observed 1",
    ] {
        assert!(
            metrics.lines().any(|written| written == line),
            "{line} missing from\n{metrics}"
        );
    }
    Ok(())
}

/// What the watcher's router answers to `GET path`, which must be `200`.
async fn get(watcher: &Arc<Watcher>, path: &str) -> Result<Vec<u8>, Failure> {
    let request = Request::builder().uri(path).body(Body::empty())?;
    let response = http::router(Arc::clone(watcher)).oneshot(request).await?;
    if response.status() != StatusCode::OK {
        return Err(format!("{path} answered {}", response.status()).into());
    }
    Ok(response.into_body().collect().await?.to_bytes().to_vec())
}

const OOBI: &str = "http://w0.example:5642/oobi/controller/witness";

/// Resolves, in one round, a registration's OOBI that answers `status` with `body`, or does not
/// answer.
async fn resolve_once(oobi: &str, answer: Option<(u16, Vec<u8>)>) -> Result<Vec<(String, Resolution)>, Failure> {
    let world = world()?;
    let watcher = empty_watcher(&Time::new()?)?;
    watcher.ingest(&world.signed(world.event(0)?)?)?;
    watcher.ingest(&world.registration(watcher.identity().prefix(), Some(oobi))?)?;
    let script = Script::default();
    if let Some((status, body)) = answer {
        script.answer(oobi.to_owned(), status, body);
    }
    let mut resolver = Resolver::new(watcher, script, TIMEOUT);
    Ok(resolver.round(Duration::ZERO).await?)
}

#[tokio::test]
async fn an_oobi_resolved_brings_the_log_and_the_witnesses_locations() -> Result<(), Failure> {
    let world = world()?;
    let all: Vec<&KeyEvent> = world.events.iter().collect();
    let watcher = empty_watcher(&Time::new()?)?;
    watcher.ingest(&world.signed(world.event(0)?)?)?;
    watcher.ingest(&world.registration(watcher.identity().prefix(), Some(OOBI))?)?;
    let script = Script::default();
    let mut served = world.signed(world.event(0)?)?;
    served.extend(world.locations()?);
    script.answer(OOBI.to_owned(), 200, served);
    world.serve(&script, 0, &all)?;
    world.serve(&script, 1, &all)?;
    let mut resolver = Resolver::new(Arc::clone(&watcher), script.clone(), TIMEOUT);
    let observer = Observer::new(Arc::clone(&watcher), script, TIMEOUT);
    let mut poller = Poller::new(Arc::clone(&watcher), observer, PollPolicy::new(Duration::from_secs(60)));

    assert_eq!(
        poller.round(Duration::ZERO).await?,
        vec![(world.identifier.clone(), Observation::Silent)]
    );
    assert_eq!(
        resolver.round(Duration::ZERO).await?,
        vec![(
            OOBI.to_owned(),
            Resolution::Resolved(Ingested {
                processed: 3,
                refused: 0,
                unescrowed: 0
            })
        )]
    );
    assert_eq!(resolver.round(Duration::from_secs(60)).await?, Vec::new());
    assert_eq!(
        poller.round(Duration::from_secs(61)).await?,
        vec![(world.identifier.clone(), Observation::Updated { from: 0, to: 2 })]
    );
    Ok(())
}

#[tokio::test]
async fn an_oobi_not_found_is_asked_again_then_fails() -> Result<(), Failure> {
    let world = world()?;
    let watcher = empty_watcher(&Time::new()?)?;
    watcher.ingest(&world.signed(world.event(0)?)?)?;
    watcher.ingest(&world.registration(watcher.identity().prefix(), Some(OOBI))?)?;
    let script = Script::default();
    script.answer(OOBI.to_owned(), 404, Vec::new());
    let mut resolver = Resolver::new(watcher, script, TIMEOUT);

    let outcome = |resolution| vec![(OOBI.to_owned(), resolution)];
    assert_eq!(
        resolver.round(Duration::ZERO).await?,
        outcome(Resolution::Retrying { retries: 1 })
    );
    assert_eq!(resolver.round(Duration::from_secs(29)).await?, Vec::new());
    assert_eq!(
        resolver.round(Duration::from_secs(30)).await?,
        outcome(Resolution::Retrying { retries: 2 })
    );
    assert_eq!(
        resolver.round(Duration::from_secs(60)).await?,
        outcome(Resolution::Retrying { retries: 3 })
    );
    assert_eq!(
        resolver.round(Duration::from_secs(90)).await?,
        outcome(Resolution::Failed)
    );
    assert_eq!(resolver.round(Duration::from_secs(600)).await?, Vec::new());
    Ok(())
}

#[tokio::test]
async fn an_unreachable_oobi_is_asked_again() -> Result<(), Failure> {
    assert_eq!(
        resolve_once(OOBI, None).await?,
        vec![(OOBI.to_owned(), Resolution::Retrying { retries: 1 })]
    );
    Ok(())
}

#[tokio::test]
async fn an_oobi_refused_serving_no_stream_or_not_over_http_fails() -> Result<(), Failure> {
    for (oobi, status, body) in [
        (OOBI, 500, Vec::new()),
        (OOBI, 200, b"not a stream".to_vec()),
        ("ftp://w0.example/oobi", 200, Vec::new()),
    ] {
        assert_eq!(
            resolve_once(oobi, Some((status, body))).await?,
            vec![(oobi.to_owned(), Resolution::Failed)]
        );
    }
    Ok(())
}

#[test]
fn escrows_that_wait_too_long_are_dropped() -> Result<(), Failure> {
    let world = world()?;
    let time = Time::new()?;
    let watcher = empty_watcher(&time)?;
    let mut stream = world.locations()?;
    stream.extend(world.signed(world.event(0)?)?);
    stream.extend(world.signed(world.event(2)?)?);
    watcher.ingest(&stream)?;
    let hour = Duration::from_secs(3600);

    time.advance(TimeDelta::minutes(59));
    assert_eq!(watcher.sweep(hour)?, Swept::default());
    time.advance(TimeDelta::minutes(2));
    assert_eq!(
        watcher.sweep(hour)?,
        Swept {
            expired: 1,
            unescrowed: 0
        }
    );
    watcher.ingest(&world.signed(world.event(1)?)?)?;
    assert_eq!(latest(&watcher, &world.identifier)?, Some(1));
    Ok(())
}

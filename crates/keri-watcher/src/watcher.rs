//! What the watcher does with what it is sent: every message goes through a keri-kel [`Kevery`]
//! on the redb store, and queries are answered from what it holds.
//!
//! A message keri-kel refuses is logged and skipped; the rest of the stream is still processed.
//! Escrows are processed after each stream, and swept by [`Watcher::sweep`]. A query answered only
//! once its escrow is processed has no one to send the answer to yet, so the answer is logged and
//! dropped.

use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use chrono::{DateTime, TimeDelta, Utc};

use keri_kel::{Answer, KelError, Kevery, Processed};
use keri_protocol::attachment::SignedMessageBuilder;
use keri_protocol::event::Timestamp;
use keri_protocol::event::key_state::KeyStateRecord;
use keri_protocol::event::kind::EventKind;
use keri_protocol::event::reply::ReplyMessage;
use keri_protocol::event::reply::route::{EndRole, LocationScheme, ReplyRoute, Role, RouteAction, Scheme};
use keri_protocol::prefix::IdentifierPrefix;
use keri_protocol::said::Said;
use keri_protocol::stream::{Message, parse_stream};
use keri_store_redb::{RedbStore, Sighting};
use tracing::{debug, info};

use crate::config::Config;
use crate::error::WatcherError;
use crate::identity::Identity;

/// Where the watcher reads the time from.
pub type Clock = Box<dyn Fn() -> DateTime<Utc> + Send + Sync>;

/// Reads the system clock.
#[must_use]
pub fn system_clock() -> DateTime<Utc> {
    Utc::now()
}

/// What became of the messages in a stream.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Ingested {
    /// Messages keri-kel accepted, escrowed or found duplicate.
    pub processed: usize,
    /// Messages keri-kel refused.
    pub refused: usize,
    /// Escrowed messages processed after the stream.
    pub unescrowed: usize,
}

/// What a sweep of the escrows did.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Swept {
    /// Escrowed events, receipts, replies and queries dropped for having waited too long.
    pub expired: usize,
    /// Escrowed events accepted.
    pub unescrowed: usize,
}

/// What a query is answered with.
#[derive(Debug)]
pub enum QueryOutcome {
    /// The answer, as a CESR stream: the replayed events, or a key state notice signed by the
    /// watcher.
    Answered(Vec<u8>),
    /// The log does not hold what the query asks for yet.
    NotFound,
    /// The query asks for a mailbox, which the watcher does not serve.
    Mailbox,
    /// keri-kel refused the query.
    Refused(KelError),
}

/// What the watcher holds of an identifier: its latest sequence number, and its witnesses with the
/// URL each can be reached at, when one is known.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Witnessed {
    /// The latest sequence number accepted.
    pub sequence_number: u128,
    /// The current witnesses, each with its `https` URL, else its `http` one.
    pub witnesses: Vec<(IdentifierPrefix, Option<String>)>,
}

/// What became of a witness's key state notice.
#[derive(Debug)]
pub enum Notice {
    /// It was kept: the witness reports this state.
    Accepted(Box<KeyStateRecord>),
    /// It is not a single `/ksn/{witness}` reply from that witness about that identifier.
    Unexpected,
    /// The witness reports this state, whose latest event is not the one the watcher holds at
    /// that sequence number; keri-kel did not keep it.
    Contradicting(Box<KeyStateRecord>),
    /// keri-kel did not keep it.
    Refused(KelError),
}

/// A watcher: its identity, the URLs it announces, its key event logs, and its clock.
pub struct Watcher {
    identity: Identity,
    locations: Vec<(Scheme, String)>,
    kevery: Mutex<Kevery<RedbStore>>,
    clock: Clock,
}

impl Watcher {
    /// Opens the watcher `config` describes: its identity and its database, both created on first
    /// start.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Identity::load_or_create`], [`Config::locations`] and
    /// [`Config::trust`], and [`WatcherError::Store`] when the database cannot be opened.
    pub fn open(config: &Config) -> Result<Self, WatcherError> {
        let identity = Identity::load_or_create(&config.identity_path())?;
        let locations = config.locations()?;
        let store = RedbStore::create(&config.database).map_err(|source| WatcherError::Store { source })?;
        let kevery = Kevery::with_store(store).trusting(config.trust()?);
        Ok(Self::new(identity, kevery, Box::new(system_clock)).announcing(locations))
    }

    /// Makes a watcher of an identity, a [`Kevery`] and a clock, announcing no URL.
    #[must_use]
    pub fn new(identity: Identity, kevery: Kevery<RedbStore>, clock: Clock) -> Self {
        Self {
            identity,
            locations: Vec::new(),
            kevery: Mutex::new(kevery),
            clock,
        }
    }

    /// Announces these URLs in the watcher's OOBI, each with its scheme.
    #[must_use]
    pub fn announcing(mut self, locations: Vec<(Scheme, String)>) -> Self {
        self.locations = locations;
        self
    }

    /// Returns the watcher's identity.
    #[must_use]
    pub const fn identity(&self) -> &Identity {
        &self.identity
    }

    /// Processes every message in a CESR stream, then the escrows.
    ///
    /// # Errors
    ///
    /// Returns [`WatcherError::Stream`] when `stream` is not a CESR stream, and
    /// [`WatcherError::Kel`] when keri-kel fails for a reason other than refusing a message.
    pub fn ingest(&self, stream: &[u8]) -> Result<Ingested, WatcherError> {
        let messages = parse_stream(stream).map_err(|source| WatcherError::Stream { source })?;
        let now = self.now()?;
        let mut kevery = self.kevery();
        let mut ingested = Ingested::default();
        for message in &messages {
            match kevery.process(message, &now) {
                Ok(processed) => {
                    debug!(said = message.event().said(), ?processed, "processed");
                    ingested.processed += 1;
                }
                Err(error @ KelError::Store { .. }) => return Err(WatcherError::kel(error)),
                Err(error) => {
                    debug!(said = message.event().said(), %error, "refused");
                    ingested.refused += 1;
                }
            }
        }
        ingested.unescrowed = kevery.process_escrows(&now).map_err(WatcherError::kel)?;
        drop_answers(&mut kevery);
        Ok(ingested)
    }

    /// Answers one query.
    ///
    /// # Errors
    ///
    /// Returns [`WatcherError::Stream`] when `stream` is not a CESR stream,
    /// [`WatcherError::NotAQuery`] when it is not a single query, [`WatcherError::Kel`] when
    /// keri-kel fails for a reason other than refusing it, and [`WatcherError::Answer`] when the
    /// answer cannot be written.
    pub fn query(&self, stream: &[u8]) -> Result<QueryOutcome, WatcherError> {
        let message = single_query(stream)?;
        let now = self.now()?;
        let answered = {
            let mut kevery = self.kevery();
            let processed = match kevery.process(&message, &now) {
                Ok(processed) => processed,
                Err(error @ KelError::Store { .. }) => return Err(WatcherError::kel(error)),
                Err(error) => return Ok(QueryOutcome::Refused(error)),
            };
            let said = message.event().said();
            let mut answers = kevery.take_answers();
            let answered = answers
                .iter()
                .position(|answered| answered.query().said() == said)
                .map(|position| answers.swap_remove(position));
            if answered.is_none() {
                debug!(?said, ?processed, "query not answered");
            }
            answered
        };
        let Some(answered) = answered else {
            return Ok(QueryOutcome::NotFound);
        };
        match answered.into_answer() {
            Answer::Replay { events, delegator, .. } => {
                let mut replay = Vec::new();
                for logged in events.iter().chain(&delegator) {
                    replay.extend(logged.replay().map_err(WatcherError::answer)?);
                }
                Ok(QueryOutcome::Answered(replay))
            }
            Answer::KeyState(state) => {
                let reply = ReplyRoute::KeyStateNotice {
                    source: self.identity.prefix().clone(),
                    state,
                }
                .to_reply(now)?;
                Ok(QueryOutcome::Answered(self.signed(&reply)?))
            }
            Answer::Mailbox { .. } => Ok(QueryOutcome::Mailbox),
            // An answer kind keri-kel adds later is not served until the watcher learns it.
            _ => Ok(QueryOutcome::NotFound),
        }
    }

    /// Answers an OOBI for `identifier`, naming `endpoint` when it names one, with replies the
    /// watcher signs now: a `/loc/scheme` reply for each URL it announces, and an `/end/role/add`
    /// reply naming itself its own `controller`, which keripy looks for to reach it. Returns `None`
    /// for an OOBI of any other identifier or endpoint, or when the watcher announces no URL.
    ///
    /// # Errors
    ///
    /// Returns [`WatcherError::Answer`] when a reply cannot be written, and
    /// [`WatcherError::Key`] when the watcher's key cannot sign.
    pub fn oobi(
        &self,
        identifier: &IdentifierPrefix,
        endpoint: Option<&IdentifierPrefix>,
    ) -> Result<Option<Vec<u8>>, WatcherError> {
        let own = self.identity.prefix();
        if identifier != own || endpoint.is_some_and(|endpoint| endpoint != own) || self.locations.is_empty() {
            return Ok(None);
        }
        let now = self.now()?;
        let mut stream = Vec::new();
        for (scheme, url) in &self.locations {
            let reply = ReplyRoute::LocationScheme(LocationScheme::new(own.clone(), *scheme, url.clone())?)
                .to_reply(now.clone())?;
            stream.extend(self.signed(&reply)?);
        }
        let role = ReplyRoute::EndRole {
            action: RouteAction::Add,
            end_role: EndRole::new(own.clone(), Role::Controller, own.clone()),
        }
        .to_reply(now)?;
        stream.extend(self.signed(&role)?);
        Ok(Some(stream))
    }

    /// Drops what has waited in the escrows longer than `timeout`, then retries the rest.
    ///
    /// # Errors
    ///
    /// Returns [`WatcherError::Kel`] when the store fails.
    pub fn sweep(&self, timeout: Duration) -> Result<Swept, WatcherError> {
        let at = (self.clock)();
        let now = timestamp(at)?;
        let cutoff = TimeDelta::from_std(timeout)
            .ok()
            .and_then(|timeout| at.checked_sub_signed(timeout));
        let mut kevery = self.kevery();
        let expired = match cutoff {
            Some(cutoff) => kevery.expire_escrows(&timestamp(cutoff)?).map_err(WatcherError::kel)?,
            None => 0,
        };
        let unescrowed = kevery.process_escrows(&now).map_err(WatcherError::kel)?;
        drop_answers(&mut kevery);
        Ok(Swept { expired, unescrowed })
    }

    /// Returns the OOBIs registrations queued for resolution.
    ///
    /// # Errors
    ///
    /// Returns [`WatcherError::Kel`] when the store fails.
    pub fn oobis(&self) -> Result<Vec<String>, WatcherError> {
        self.kevery().oobis().map_err(WatcherError::kel)
    }

    /// Returns the identifiers the watcher is asked to observe: those a registration added and no
    /// later one cut.
    ///
    /// # Errors
    ///
    /// Returns [`WatcherError::Kel`] when the store fails.
    pub fn observed(&self) -> Result<Vec<IdentifierPrefix>, WatcherError> {
        let observations = self
            .kevery()
            .observations(self.identity.prefix())
            .map_err(WatcherError::kel)?;
        let mut observed: Vec<IdentifierPrefix> = Vec::new();
        for (_, identifier, record) in observations {
            if record.enabled() && !observed.contains(&identifier) {
                observed.push(identifier);
            }
        }
        Ok(observed)
    }

    /// Returns what the watcher holds of `identifier`, or `None` when it holds no log for it.
    ///
    /// # Errors
    ///
    /// Returns [`WatcherError::Kel`] when the store fails.
    pub fn witnessed(&self, identifier: &IdentifierPrefix) -> Result<Option<Witnessed>, WatcherError> {
        let kevery = self.kevery();
        let Some(kever) = kevery.kever(identifier).map_err(WatcherError::kel)? else {
            return Ok(None);
        };
        let mut witnesses = Vec::new();
        for witness in kever.witnesses() {
            let mut url = None;
            for scheme in [Scheme::Https, Scheme::Http] {
                if let Some(location) = kevery.location(witness, scheme).map_err(WatcherError::kel)? {
                    url = Some(location.url().to_owned());
                    break;
                }
            }
            witnesses.push((witness.clone(), url));
        }
        Ok(Some(Witnessed {
            sequence_number: kever.sequence_number(),
            witnesses,
        }))
    }

    /// Offers a witness's answer to a key state request: a `/ksn/{witness}` reply about
    /// `identifier`, which keri-kel verifies and keeps as it keeps any notice.
    ///
    /// # Errors
    ///
    /// Returns [`WatcherError::Kel`] when keri-kel fails for a reason other than refusing it.
    pub fn accept_notice(
        &self,
        identifier: &IdentifierPrefix,
        witness: &IdentifierPrefix,
        answer: &[u8],
    ) -> Result<Notice, WatcherError> {
        let Ok(message) = Message::from_bytes(answer) else {
            return Ok(Notice::Unexpected);
        };
        let route =
            ReplyMessage::from_serialized(message.event().clone()).and_then(|reply| ReplyRoute::from_reply(&reply));
        let state = match route {
            Ok(ReplyRoute::KeyStateNotice { source, state })
                if &source == witness && state.identifier() == identifier =>
            {
                state
            }
            _ => return Ok(Notice::Unexpected),
        };
        let now = self.now()?;
        match self.kevery().process(&message, &now) {
            Ok(Processed::KeyStateAccepted) => Ok(Notice::Accepted(state)),
            Ok(processed) => {
                debug!(?processed, "key state notice not kept");
                Ok(Notice::Unexpected)
            }
            Err(KelError::KeyStateMismatch) => Ok(Notice::Contradicting(state)),
            Err(error @ KelError::Store { .. }) => Err(WatcherError::kel(error)),
            Err(error) => Ok(Notice::Refused(error)),
        }
    }

    /// Records that these sources report different events at `sequence_number` of `identifier`,
    /// returning how many of them were not recorded before.
    ///
    /// # Errors
    ///
    /// Returns [`WatcherError::Prefix`] or [`WatcherError::Said`] for one that cannot be written as
    /// qb64, and [`WatcherError::Store`] when the store fails.
    pub fn record_duplicity(
        &self,
        identifier: &IdentifierPrefix,
        sequence_number: u128,
        reported: &[(IdentifierPrefix, Said)],
    ) -> Result<usize, WatcherError> {
        let now = self.now()?;
        let sightings = reported
            .iter()
            .map(|(source, said)| {
                Ok(Sighting {
                    said: said.qb64().map_err(|source| WatcherError::Said { source })?,
                    source: qb64(source)?,
                    first_seen: now.clone(),
                })
            })
            .collect::<Result<Vec<_>, WatcherError>>()?;
        self.kevery()
            .store()
            .record_duplicity(&qb64(identifier)?, sequence_number, &sightings)
            .map_err(|source| WatcherError::Store { source })
    }

    /// Records that `witness` reports `state`, whose latest event is not the one the watcher holds:
    /// the watcher's own identifier stands for its log. Returns how many of the two were not
    /// recorded before.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Watcher::record_duplicity`], and [`WatcherError::Kel`] when the
    /// store fails.
    pub fn record_contradiction(
        &self,
        witness: &IdentifierPrefix,
        state: &KeyStateRecord,
    ) -> Result<usize, WatcherError> {
        let identifier = state.identifier();
        let sequence_number = state.sequence_number();
        let held = self
            .kevery()
            .logged(identifier, sequence_number)
            .map_err(WatcherError::kel)?
            .and_then(|logged| logged.event().said().map(Said::from_qb64))
            .transpose()
            .map_err(|source| WatcherError::Said { source })?;
        let mut reported = vec![(witness.clone(), state.said())];
        if let Some(held) = held {
            reported.insert(0, (self.identity.prefix().clone(), held));
        }
        self.record_duplicity(identifier, sequence_number, &reported)
    }

    /// Returns the duplicity recorded for `identifier`, by sequence number.
    ///
    /// # Errors
    ///
    /// Returns [`WatcherError::Prefix`] for an identifier that cannot be written as qb64, and
    /// [`WatcherError::Store`] when the store fails.
    pub fn duplicity(&self, identifier: &IdentifierPrefix) -> Result<Vec<(u128, Vec<Sighting>)>, WatcherError> {
        self.kevery()
            .store()
            .duplicity(&qb64(identifier)?)
            .map_err(|source| WatcherError::Store { source })
    }

    /// A reply signed by the watcher.
    fn signed(&self, reply: &ReplyMessage) -> Result<Vec<u8>, WatcherError> {
        Ok(SignedMessageBuilder::new(reply.serialized())
            .receipt_couples(vec![self.identity.sign(reply.raw())?])
            .build()?
            .into_bytes())
    }

    fn now(&self) -> Result<Timestamp, WatcherError> {
        timestamp((self.clock)())
    }

    fn kevery(&self) -> MutexGuard<'_, Kevery<RedbStore>> {
        // Kevery's state is in its store, written a transaction at a time, so a panic while it was
        // held leaves nothing half-done.
        self.kevery.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Runs blocking work, keri-kel's and redb's, on tokio's blocking pool.
pub(crate) async fn blocking<T: Send + 'static>(
    work: impl FnOnce() -> Result<T, WatcherError> + Send + 'static,
) -> Result<T, WatcherError> {
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|_| WatcherError::Interrupted)?
}

fn qb64(identifier: &IdentifierPrefix) -> Result<String, WatcherError> {
    identifier.qb64().map_err(|source| WatcherError::Prefix { source })
}

fn timestamp(at: DateTime<Utc>) -> Result<Timestamp, WatcherError> {
    Timestamp::parse(&at.format("%Y-%m-%dT%H:%M:%S%.6f+00:00").to_string())
        .map_err(|source| WatcherError::Clock { source })
}

fn single_query(stream: &[u8]) -> Result<Message, WatcherError> {
    let mut messages = parse_stream(stream)
        .map_err(|source| WatcherError::Stream { source })?
        .into_iter();
    let (Some(message), None) = (messages.next(), messages.next()) else {
        return Err(WatcherError::NotAQuery);
    };
    if message.event().event_kind().ok().flatten() != Some(EventKind::Query) {
        return Err(WatcherError::NotAQuery);
    }
    Ok(message)
}

fn drop_answers(kevery: &mut Kevery<RedbStore>) {
    for answered in kevery.take_answers() {
        info!(
            query = answered.query().said(),
            requester = ?answered.requester(),
            "answer to an escrowed query dropped"
        );
    }
}

impl std::fmt::Debug for Watcher {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Watcher")
            .field("identity", &self.identity)
            .finish_non_exhaustive()
    }
}

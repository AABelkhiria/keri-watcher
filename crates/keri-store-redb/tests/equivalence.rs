//! A `Kevery` on the redb store behaves exactly as one on keri-kel's in-memory store: offered the
//! same messages in the same order, it reaches the same outcomes and holds the same state; and what
//! it holds is still there after the database is closed and opened again.

use std::error::Error;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

use keri_cesr::crypto::digest::{Digest, DigestAlgorithm};
use keri_cesr::crypto::signer::{SignaturePlacement, Signer};
use keri_cesr::crypto::verifier::KeyTransferability;
use keri_kel::{Kevery, MemoryStore, Store};
use keri_protocol::attachment::{ReceiptCouple, SignatureSeal, SignedMessageBuilder};
use keri_protocol::event::KeyEvent;
use keri_protocol::event::inception::InceptionBuilder;
use keri_protocol::event::interaction::InteractionBuilder;
use keri_protocol::event::query::{QueryArguments, QueryBuilder};
use keri_protocol::event::receipt::ReceiptBuilder;
use keri_protocol::event::reply::route::{LocationScheme, ReplyRoute, Scheme};
use keri_protocol::event::rotation::RotationBuilder;
use keri_protocol::event::timestamp::Timestamp;
use keri_protocol::prefix::{IdentifierPrefix, PrefixDerivation};
use keri_protocol::serialization::Sad;
use keri_protocol::stream::Message;
use keri_store_redb::RedbStore;
use proptest::{prelude::*, test_runner::TestCaseError};

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

fn signed(event: &KeyEvent, key: &Signer, witnesses: &[(u32, &Signer)]) -> Result<Message, Failure> {
    let mut builder = SignedMessageBuilder::new(event.serialized())
        .controller_signatures(vec![key.sign_indexed(event.raw(), SignaturePlacement::both_lists(0))?]);
    let signatures = witnesses
        .iter()
        .map(|(index, witness)| witness.sign_indexed(event.raw(), SignaturePlacement::both_lists(*index)))
        .collect::<Result<Vec<_>, _>>()?;
    if !signatures.is_empty() {
        builder = builder.witness_signatures(signatures);
    }
    Ok(Message::from_bytes(builder.build()?.as_bytes())?)
}

fn receipt(event: &KeyEvent, index: u32, witness: &Signer) -> Result<Message, Failure> {
    let receipt = ReceiptBuilder::new(event.identifier().clone(), event.sequence_number(), event.said()).build()?;
    let signature = witness.sign_indexed(event.raw(), SignaturePlacement::both_lists(index))?;
    let message = SignedMessageBuilder::new(receipt.serialized())
        .witness_signatures(vec![signature])
        .build()?;
    Ok(Message::from_bytes(message.as_bytes())?)
}

/// Messages about one witnessed identifier, offered in random orders: its events with and without
/// witness signatures, witness receipts, a contradicting event, a recovery rotation, a key state
/// notice and a location from a witness, and a key state query.
struct Pool {
    identifiers: Vec<IdentifierPrefix>,
    messages: Vec<Message>,
}

fn pool() -> Result<Pool, Failure> {
    let keys = [
        signer(1, KeyTransferability::Transferable)?,
        signer(2, KeyTransferability::Transferable)?,
        signer(3, KeyTransferability::Transferable)?,
    ];
    let witnesses = [
        signer(30, KeyTransferability::NonTransferable)?,
        signer(31, KeyTransferability::NonTransferable)?,
    ];
    let [k0, k1, k2] = &keys;
    let [w0, w1] = &witnesses;
    let inception = InceptionBuilder::new(vec![k0.verifier().clone()])
        .next_key_digests(vec![digest(k1)?])
        .witnesses(vec![prefix(w0)?, prefix(w1)?])
        .witness_threshold(1)
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
    let rotation = RotationBuilder::new(identifier.clone(), second.said(), 3, vec![k1.verifier().clone()])
        .next_key_digests(vec![digest(k2)?])
        .witnesses(vec![prefix(w0)?, prefix(w1)?])
        .witness_threshold(1)
        .build()?;
    let recovery = RotationBuilder::new(identifier.clone(), first.said(), 2, vec![k1.verifier().clone()])
        .next_key_digests(vec![digest(k2)?])
        .witnesses(vec![prefix(w0)?, prefix(w1)?])
        .witness_threshold(1)
        .build()?;

    let now = Timestamp::parse(STAMP)?;
    let mut scratch = Kevery::new();
    scratch.process(&signed(&inception, k0, &[(0, w0)])?, &now)?;
    let state = scratch.kever(&identifier)?.ok_or("no state")?.state()?;
    let notice = ReplyRoute::KeyStateNotice {
        source: prefix(w0)?,
        state: Box::new(state),
    }
    .to_reply(now.clone())?;
    let location = ReplyRoute::LocationScheme(LocationScheme::new(prefix(w0)?, Scheme::Http, "http://w0.example/")?)
        .to_reply(now.clone())?;
    let couple = |raw: &[u8]| -> Result<ReceiptCouple, Failure> {
        Ok(ReceiptCouple::new(w0.verifier().clone(), w0.sign_unindexed(raw)?)?)
    };
    let replied = |reply: &keri_protocol::event::reply::ReplyMessage| -> Result<Message, Failure> {
        let message = SignedMessageBuilder::new(reply.serialized())
            .receipt_couples(vec![couple(reply.raw())?])
            .build()?;
        Ok(Message::from_bytes(message.as_bytes())?)
    };
    let requester = signer(40, KeyTransferability::Transferable)?;
    let query = QueryBuilder::new("ksn", now)
        .query(QueryArguments::new(identifier.clone(), prefix(w0)?).into_sad()?)
        .build()?;
    let asked = SignedMessageBuilder::new(query.serialized())
        .controller_signatures(vec![
            requester.sign_indexed(query.raw(), SignaturePlacement::both_lists(0))?,
        ])
        .seal(SignatureSeal::Last {
            identifier: prefix(&requester)?,
        })
        .build()?;

    Ok(Pool {
        identifiers: vec![identifier, prefix(w0)?, prefix(w1)?],
        messages: vec![
            signed(&inception, k0, &[])?,
            signed(&inception, k0, &[(0, w0)])?,
            receipt(&inception, 1, w1)?,
            signed(&first, k0, &[])?,
            receipt(&first, 0, w0)?,
            signed(&second, k0, &[(1, w1)])?,
            signed(&contradicting, k0, &[(0, w0)])?,
            signed(&rotation, k1, &[(0, w0)])?,
            signed(&recovery, k1, &[(1, w1)])?,
            replied(&notice)?,
            replied(&location)?,
            Message::from_bytes(asked.as_bytes())?,
        ],
    })
}

/// Everything a `Kevery` holds that a caller can see, for comparing two of them.
fn held<S: Store>(kevery: &mut Kevery<S>, identifiers: &[IdentifierPrefix]) -> Result<String, Failure> {
    let mut seen = Vec::new();
    for identifier in identifiers {
        seen.push(format!("{:?}", kevery.kever(identifier)?));
        for sequence_number in 0..5 {
            seen.push(format!("{:?}", kevery.logged(identifier, sequence_number)?));
        }
        seen.push(format!("{:?}", kevery.superseded(identifier)?));
        let mut notices = kevery.key_state_notices(identifier)?;
        notices.sort_by_cached_key(|(source, _)| source.qb64().unwrap_or_default());
        seen.push(format!("{notices:?}"));
        seen.push(format!("{:?}", kevery.locations(identifier)?));
    }
    let mut oobis = kevery.oobis()?;
    oobis.sort();
    seen.push(format!(
        "{} {} {} {} {oobis:?} {:?}",
        kevery.escrowed_event_count()?,
        kevery.waiting_receipt_count()?,
        kevery.escrowed_reply_count()?,
        kevery.escrowed_query_count()?,
        kevery.take_answers()
    ));
    Ok(seen.join("\n"))
}

/// Offers the same messages to both, comparing outcomes and what is held after each.
fn compare(order: &[usize], pool: &Pool) -> Result<(), Failure> {
    let now = Timestamp::parse(STAMP)?;
    let mut memory = Kevery::with_store(MemoryStore::new());
    let mut redb = Kevery::with_store(RedbStore::in_memory()?);
    for index in order {
        let Some(message) = pool.messages.get(*index) else {
            continue;
        };
        let expected = format!("{:?}", memory.process(message, &now));
        assert_eq!(format!("{:?}", redb.process(message, &now)), expected);
        assert_eq!(redb.process_escrows(&now)?, memory.process_escrows(&now)?);
        assert_eq!(
            held(&mut redb, &pool.identifiers)?,
            held(&mut memory, &pool.identifiers)?
        );
    }
    Ok(())
}

#[test]
fn the_whole_pool_in_order() -> Result<(), Failure> {
    let pool = pool()?;
    let order: Vec<usize> = (0..pool.messages.len()).collect();
    compare(&order, &pool)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    /// Whatever the order, the redb store and the in-memory store agree after every message.
    #[test]
    fn any_order_agrees(order in prop::collection::vec(0_usize..12, 0..30)) {
        let pool = pool().map_err(|error| TestCaseError::fail(error.to_string()))?;
        compare(&order, &pool).map_err(|error| TestCaseError::fail(error.to_string()))?;
    }
}

static DATABASES: AtomicU32 = AtomicU32::new(0);

/// A database file of its own, removed when dropped.
struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let number = DATABASES.fetch_add(1, Ordering::Relaxed);
        Self(std::env::temp_dir().join(format!("keri-store-redb-{}-{number}.redb", std::process::id())))
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[test]
fn what_is_held_survives_closing_the_database() -> Result<(), Failure> {
    let pool = pool()?;
    let now = Timestamp::parse(STAMP)?;
    let scratch = Scratch::new();
    let (first, rest) = pool.messages.split_at(6);
    let mut memory = Kevery::new();
    let mut redb = Kevery::with_store(RedbStore::create(&scratch.0)?);
    for message in first {
        memory.process(message, &now)?;
        memory.process_escrows(&now)?;
        redb.process(message, &now)?;
        redb.process_escrows(&now)?;
    }
    let before = held(&mut memory, &pool.identifiers)?;
    assert_eq!(held(&mut redb, &pool.identifiers)?, before);
    drop(redb);

    let mut reopened = Kevery::with_store(RedbStore::create(&scratch.0)?);
    assert_eq!(held(&mut reopened, &pool.identifiers)?, before);
    for message in rest {
        let expected = format!("{:?}", memory.process(message, &now));
        assert_eq!(format!("{:?}", reopened.process(message, &now)), expected);
        assert_eq!(reopened.process_escrows(&now)?, memory.process_escrows(&now)?);
    }
    assert_eq!(
        held(&mut reopened, &pool.identifiers)?,
        held(&mut memory, &pool.identifiers)?
    );
    Ok(())
}

/// The pool exercises the store: offered in order, and in an order where the notice is kept and the
/// recovery supersedes an event, the redb store accepts, escrows, receipts, keeps aside, keeps and
/// refuses replies, and answers.
#[test]
fn the_pool_exercises_the_store() -> Result<(), Failure> {
    let pool = pool()?;
    let now = Timestamp::parse(STAMP)?;
    let outcomes = |order: &[usize]| -> Result<(Vec<String>, Kevery<RedbStore>), Failure> {
        let mut kevery = Kevery::with_store(RedbStore::in_memory()?);
        let mut outcomes = Vec::new();
        for index in order {
            let message = pool.messages.get(*index).ok_or("no message")?;
            outcomes.push(format!("{:?}", kevery.process(message, &now)));
            kevery.process_escrows(&now)?;
        }
        Ok((outcomes, kevery))
    };
    let (in_order, _) = outcomes(&(0..pool.messages.len()).collect::<Vec<_>>())?;
    assert_eq!(
        in_order,
        [
            "Ok(Escrowed(PartiallyWitnessed))",
            "Ok(Accepted)",
            "Ok(Receipted)",
            "Ok(Escrowed(PartiallyWitnessed))",
            "Ok(Escrowed(UnverifiedReceipt))",
            "Ok(Accepted)",
            "Ok(Escrowed(LikelyDuplicitous))",
            "Ok(Accepted)",
            "Ok(Escrowed(LikelyDuplicitous))",
            "Err(StaleKeyState)",
            "Ok(LocationAccepted)",
            "Ok(Answered)",
        ]
    );
    let (recovered, kevery) = outcomes(&[1, 9, 3, 4, 5, 8])?;
    assert_eq!(
        recovered,
        [
            "Ok(Accepted)",
            "Ok(KeyStateAccepted)",
            "Ok(Escrowed(PartiallyWitnessed))",
            "Ok(Escrowed(UnverifiedReceipt))",
            "Ok(Accepted)",
            "Ok(Accepted)",
        ]
    );
    let identifier = pool.identifiers.first().ok_or("no identifier")?;
    assert_eq!(
        kevery.superseded(identifier)?.len(),
        1,
        "the recovery superseded an event"
    );
    Ok(())
}

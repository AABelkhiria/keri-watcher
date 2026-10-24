//! Starting a watcher from its configuration: the identity and the database are created on first
//! start and found again on the next.

use std::error::Error;
use std::path::{Path, PathBuf};

use keri_cesr::crypto::digest::{Digest, DigestAlgorithm};
use keri_cesr::crypto::signer::{SignaturePlacement, Signer};
use keri_cesr::crypto::verifier::KeyTransferability;
use keri_kel::NoticeTrust;
use keri_protocol::attachment::{ReceiptCouple, SignedMessageBuilder};
use keri_protocol::event::inception::InceptionBuilder;
use keri_protocol::event::query::{QueryArguments, QueryBuilder};
use keri_protocol::event::timestamp::Timestamp;
use keri_protocol::prefix::{IdentifierPrefix, PrefixDerivation};
use keri_watcher::{Config, QueryOutcome, Watcher, WatcherError};

type Failure = Box<dyn Error>;

/// A directory of its own, removed when dropped.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Result<Self, Failure> {
        let path = std::env::temp_dir().join(format!("keri-watcher-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&path)?;
        Ok(Self(path))
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn config(directory: &Path) -> Result<Config, Failure> {
    Ok(Config::parse(&format!(
        "listen = \"127.0.0.1:5631\"\ndatabase = \"{}\"\n",
        directory.join("watcher.redb").display()
    ))?)
}

#[test]
fn the_configuration_defaults_the_identity_and_the_trust() -> Result<(), Failure> {
    let config = Config::parse("listen = \"127.0.0.1:5631\"\ndatabase = \"/data/watcher.redb\"\n")?;
    assert_eq!(config.identity_path(), PathBuf::from("/data/watcher.salt"));
    assert_eq!(config.trust()?, NoticeTrust::AnySource);

    let watcher = Signer::from_seed(&[31; 32], KeyTransferability::NonTransferable)?;
    let watcher = IdentifierPrefix::from_qb64(&watcher.verifier().qb64()?)?;
    let config = Config::parse(&format!(
        "listen = \"[::1]:5631\"\ndatabase = \"watcher.redb\"\nidentity = \"key.salt\"\ntrusted_watchers = [\"{}\"]\n",
        watcher.qb64()?
    ))?;
    assert_eq!(config.identity_path(), PathBuf::from("key.salt"));
    assert_eq!(config.trust()?, NoticeTrust::Watchers(vec![watcher]));
    Ok(())
}

#[test]
fn a_configuration_with_mistakes_is_refused() {
    let unknown = "listen = \"127.0.0.1:5631\"\ndatabase = \"w.redb\"\nlisten_port = 5631\n";
    assert!(matches!(Config::parse(unknown), Err(WatcherError::Config { .. })));
    assert!(matches!(
        Config::parse("database = \"w.redb\"\n"),
        Err(WatcherError::Config { .. })
    ));
    let untrusted = "listen = \"127.0.0.1:5631\"\ndatabase = \"w.redb\"\ntrusted_watchers = [\"nope\"]\n";
    assert!(matches!(
        Config::parse(untrusted).map(|config| config.trust()),
        Ok(Err(WatcherError::Prefix { .. }))
    ));
}

#[test]
fn the_identity_and_the_log_survive_a_restart() -> Result<(), Failure> {
    let scratch = Scratch::new("restart")?;
    let config = config(&scratch.0)?;
    let key = Signer::from_seed(&[1; 32], KeyTransferability::Transferable)?;
    let next = Signer::from_seed(&[2; 32], KeyTransferability::Transferable)?;
    let inception = InceptionBuilder::new(vec![key.verifier().clone()])
        .next_key_digests(vec![Digest::derive(
            DigestAlgorithm::Blake3_256,
            &next.verifier().qb64_bytes()?,
        )])
        .prefix_derivation(PrefixDerivation::Blake3_256)
        .build()?;
    let message = SignedMessageBuilder::new(inception.serialized())
        .controller_signatures(vec![
            key.sign_indexed(inception.raw(), SignaturePlacement::both_lists(0))?,
        ])
        .build()?;

    let first = Watcher::open(&config)?;
    let ingested = first.ingest(message.as_bytes())?;
    assert_eq!((ingested.processed, ingested.refused), (1, 0));
    let prefix = first.identity().prefix().clone();
    drop(first);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(config.identity_path())?.permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    let again = Watcher::open(&config)?;
    assert_eq!(again.identity().prefix(), &prefix);
    let requester = Signer::from_seed(&[50; 32], KeyTransferability::NonTransferable)?;
    let query = QueryBuilder::new("ksn", Timestamp::parse("2021-01-01T00:00:00.000000+00:00")?)
        .query(QueryArguments::new(inception.identifier().clone(), prefix).into_sad()?)
        .build()?;
    let asked = SignedMessageBuilder::new(query.serialized())
        .receipt_couples(vec![ReceiptCouple::new(
            requester.verifier().clone(),
            requester.sign_unindexed(query.raw())?,
        )?])
        .build()?;
    assert!(matches!(again.query(asked.as_bytes())?, QueryOutcome::Answered(_)));
    Ok(())
}

#[test]
fn a_salt_file_that_is_not_a_salt_is_refused() -> Result<(), Failure> {
    let scratch = Scratch::new("bad-salt")?;
    let config = config(&scratch.0)?;
    std::fs::write(config.identity_path(), "not a salt")?;
    assert!(matches!(Watcher::open(&config), Err(WatcherError::Key { .. })));
    Ok(())
}

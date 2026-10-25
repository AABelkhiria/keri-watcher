//! The duplicity a watcher records: every source's event at a sequence number, each kept once with
//! the time it was first recorded, and kept across reopening the database.

use std::error::Error;
use std::path::PathBuf;

use keri_protocol::event::timestamp::Timestamp;
use keri_store_redb::{RedbStore, Sighting};

type Failure = Box<dyn Error>;

const IDENTIFIER: &str = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao";

fn sighting(said: &str, source: &str, first_seen: &str) -> Result<Sighting, Failure> {
    Ok(Sighting {
        said: said.to_owned(),
        source: source.to_owned(),
        first_seen: Timestamp::parse(first_seen)?,
    })
}

/// A database file of its own, removed when dropped.
struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[test]
fn each_source_and_event_is_kept_once_with_when_it_was_first_seen() -> Result<(), Failure> {
    let first = "2021-01-01T00:00:00.000000+00:00";
    let later = "2021-01-01T01:00:00.000000+00:00";
    let scratch = Scratch(std::env::temp_dir().join(format!("keri-store-redb-dups-{}.redb", std::process::id())));
    let store = RedbStore::create(&scratch.0)?;
    assert_eq!(store.duplicity(IDENTIFIER)?, Vec::new());

    let reported = [sighting("Ea", "Bw0", first)?, sighting("Eb", "Bw1", first)?];
    assert_eq!(store.record_duplicity(IDENTIFIER, 1, &reported)?, 2);
    let again = [sighting("Ea", "Bw0", later)?, sighting("Eb", "Bw2", later)?];
    assert_eq!(store.record_duplicity(IDENTIFIER, 1, &again)?, 1);
    assert_eq!(store.record_duplicity(IDENTIFIER, 16, &reported)?, 2);
    assert_eq!(store.record_duplicity("Eother", 1, &reported)?, 2);
    drop(store);

    let store = RedbStore::create(&scratch.0)?;
    assert_eq!(
        store.duplicity(IDENTIFIER)?,
        vec![
            (
                1,
                vec![
                    sighting("Ea", "Bw0", first)?,
                    sighting("Eb", "Bw1", first)?,
                    sighting("Eb", "Bw2", later)?,
                ]
            ),
            (16, reported.to_vec()),
        ]
    );
    Ok(())
}

//! A [`keri_kel::Store`] on [redb](https://www.redb.org), an embedded key-value database.
//!
//! [`RedbStore`] keeps everything a [`keri_kel::Kevery`] holds in one database file, one table per
//! kind of record, named after keripy's tables so a dump reads like keripy's:
//!
//! | Table | Key | Holds |
//! |---|---|---|
//! | `kevers` | identifier | its key state |
//! | `kels` | identifier, sequence number | its accepted events |
//! | `sups` | identifier, order superseded | events recovery rotations superseded |
//! | `escrows` | identifier, SAID | events waiting to be decided |
//! | `arrivals` | `next` | the next escrow arrival number |
//! | `receipts` | order held | receipt signatures waiting for their event |
//! | `ksns` | identifier, source | key state notices kept |
//! | `ends` | controller, role, endpoint | end roles kept |
//! | `locs` | endpoint, scheme | locations kept |
//! | `obvs` | controller, watcher, observed | watcher registrations kept |
//! | `oobis` | URL | OOBIs queued for resolution |
//! | `rpes` | SAID | replies waiting |
//! | `qnfs` | requester, SAID | queries waiting |
//! | `dups` | identifier, sequence number | the events reported where duplicity was seen |
//!
//! Keys are their parts joined by `.`, as keripy joins its keys; a sequence number or an order is
//! 32 hexadecimal digits, so a range scan reads a log in sequence order. Values are records as
//! [`keri_kel::Record`] writes them, readable JSON.
//!
//! Beside what a `Kevery` holds, the store keeps the duplicity a watcher sees, which keri-kel does
//! not: [`RedbStore::record_duplicity`] and [`RedbStore::duplicity`].
//!
//! Each store method is one transaction: accepting an event, with moving the events it supersedes
//! aside, commits together, but the several writes one message causes do not.

#![forbid(unsafe_code)]

mod duplicity;

pub use duplicity::Sighting;

use std::path::Path;

use keri_kel::{
    EndRoleRecord, Escrow, EscrowStore, EscrowedEvent, EscrowedQuery, EscrowedReply, KelStore, Kever, KeyStateNotice,
    LocationRecord, LoggedEvent, ObservationRecord, ReceiptStore, Record, ReplyStore, StoreError, WaitingReceipt,
};
use keri_protocol::event::timestamp::Timestamp;
use redb::backends::InMemoryBackend;
use redb::{Database, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition, WriteTransaction};

type Table = TableDefinition<'static, &'static str, &'static [u8]>;

const KEVERS: Table = TableDefinition::new("kevers");
const KELS: Table = TableDefinition::new("kels");
const SUPERSEDED: Table = TableDefinition::new("sups");
const ESCROWS: Table = TableDefinition::new("escrows");
const ARRIVALS: Table = TableDefinition::new("arrivals");
const RECEIPTS: Table = TableDefinition::new("receipts");
const NOTICES: Table = TableDefinition::new("ksns");
const END_ROLES: Table = TableDefinition::new("ends");
const LOCATIONS: Table = TableDefinition::new("locs");
const OBSERVATIONS: Table = TableDefinition::new("obvs");
const OOBIS: Table = TableDefinition::new("oobis");
const REPLIES: Table = TableDefinition::new("rpes");
const QUERIES: Table = TableDefinition::new("qnfs");
const DUPLICITY: Table = TableDefinition::new("dups");

const TABLES: [Table; 14] = [
    KEVERS,
    KELS,
    SUPERSEDED,
    ESCROWS,
    ARRIVALS,
    RECEIPTS,
    NOTICES,
    END_ROLES,
    LOCATIONS,
    OBSERVATIONS,
    OOBIS,
    REPLIES,
    QUERIES,
    DUPLICITY,
];

/// A [`keri_kel::Store`] in a redb database.
#[derive(Debug)]
pub struct RedbStore {
    database: Database,
}

impl RedbStore {
    /// Opens the database at `path`, creating it if there is none.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when the file cannot be opened or created.
    pub fn create(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        Self::ready(Database::create(path).map_err(StoreError::new)?)
    }

    /// A database held in memory, gone when the store is dropped.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when the database cannot be set up.
    pub fn in_memory() -> Result<Self, StoreError> {
        Self::ready(
            Database::builder()
                .create_with_backend(InMemoryBackend::new())
                .map_err(StoreError::new)?,
        )
    }

    /// Creates every table, so reading one never meets a table that does not exist yet.
    fn ready(database: Database) -> Result<Self, StoreError> {
        let transaction = database.begin_write().map_err(StoreError::new)?;
        for table in TABLES {
            transaction.open_table(table).map_err(StoreError::new)?;
        }
        transaction.commit().map_err(StoreError::new)?;
        Ok(Self { database })
    }

    fn get<T: Record>(&self, table: Table, key: &str) -> Result<Option<T>, StoreError> {
        let transaction = self.database.begin_read().map_err(StoreError::new)?;
        let table = transaction.open_table(table).map_err(StoreError::new)?;
        let Some(value) = table.get(key).map_err(StoreError::new)? else {
            return Ok(None);
        };
        T::from_bytes(value.value()).map(Some).map_err(StoreError::new)
    }

    /// Every entry whose key starts with `prefix`, in key order, with the rest of its key.
    fn scan<T: Record>(&self, table: Table, prefix: &str) -> Result<Vec<(String, T)>, StoreError> {
        let transaction = self.database.begin_read().map_err(StoreError::new)?;
        let table = transaction.open_table(table).map_err(StoreError::new)?;
        let mut found = Vec::new();
        for entry in table.range(prefix..).map_err(StoreError::new)? {
            let (key, value) = entry.map_err(StoreError::new)?;
            let Some(rest) = key.value().strip_prefix(prefix) else {
                break;
            };
            found.push((rest.to_owned(), T::from_bytes(value.value()).map_err(StoreError::new)?));
        }
        Ok(found)
    }

    fn write(&self, change: impl FnOnce(&WriteTransaction) -> Result<(), StoreError>) -> Result<(), StoreError> {
        let transaction = self.database.begin_write().map_err(StoreError::new)?;
        change(&transaction)?;
        transaction.commit().map_err(StoreError::new)
    }

    fn put<T: Record>(&self, table: Table, key: &str, value: &T) -> Result<(), StoreError> {
        let bytes = value.to_bytes().map_err(StoreError::new)?;
        self.write(|transaction| {
            let mut table = transaction.open_table(table).map_err(StoreError::new)?;
            table.insert(key, bytes.as_slice()).map_err(StoreError::new)?;
            Ok(())
        })
    }

    fn remove(&self, table: Table, key: &str) -> Result<(), StoreError> {
        self.write(|transaction| {
            let mut table = transaction.open_table(table).map_err(StoreError::new)?;
            table.remove(key).map_err(StoreError::new)?;
            Ok(())
        })
    }

    fn count(&self, table: Table) -> Result<usize, StoreError> {
        let transaction = self.database.begin_read().map_err(StoreError::new)?;
        let table = transaction.open_table(table).map_err(StoreError::new)?;
        let length = table.len().map_err(StoreError::new)?;
        usize::try_from(length).map_err(StoreError::new)
    }

    /// Removes every entry of `table` for which `stale` holds, and returns how many.
    fn expire<T: Record>(&self, table: Table, stale: impl Fn(&T) -> bool) -> Result<usize, StoreError> {
        let mut removed = 0;
        self.write(|transaction| {
            let mut table = transaction.open_table(table).map_err(StoreError::new)?;
            let mut keys = Vec::new();
            for entry in table.iter().map_err(StoreError::new)? {
                let (key, value) = entry.map_err(StoreError::new)?;
                if stale(&T::from_bytes(value.value()).map_err(StoreError::new)?) {
                    keys.push(key.value().to_owned());
                }
            }
            for key in &keys {
                table.remove(key.as_str()).map_err(StoreError::new)?;
            }
            removed = keys.len();
            Ok(())
        })?;
        Ok(removed)
    }
}

/// A key's parts joined by `.`.
fn key(parts: &[&str]) -> String {
    parts.join(".")
}

/// A number as 32 hexadecimal digits, so keys order as numbers do.
fn ordinal(number: u128) -> String {
    format!("{number:032x}")
}

fn number(text: &str) -> Result<u128, StoreError> {
    u128::from_str_radix(text, 16).map_err(StoreError::new)
}

impl KelStore for RedbStore {
    fn kever(&self, identifier: &str) -> Result<Option<Kever>, StoreError> {
        self.get(KEVERS, identifier)
    }

    fn event(&self, identifier: &str, sequence_number: u128) -> Result<Option<LoggedEvent>, StoreError> {
        self.get(KELS, &key(&[identifier, &ordinal(sequence_number)]))
    }

    fn find_event(
        &self,
        identifier: &str,
        matches: &mut dyn FnMut(&LoggedEvent) -> bool,
    ) -> Result<Option<(u128, LoggedEvent)>, StoreError> {
        for (sequence_number, event) in self.events(identifier)? {
            if matches(&event) {
                return Ok(Some((sequence_number, event)));
            }
        }
        Ok(None)
    }

    fn events(&self, identifier: &str) -> Result<Vec<(u128, LoggedEvent)>, StoreError> {
        self.scan(KELS, &key(&[identifier, ""]))?
            .into_iter()
            .map(|(sequence_number, event)| Ok((number(&sequence_number)?, event)))
            .collect()
    }

    fn superseded(&self, identifier: &str) -> Result<Vec<LoggedEvent>, StoreError> {
        Ok(self
            .scan(SUPERSEDED, &key(&[identifier, ""]))?
            .into_iter()
            .map(|(_, event)| event)
            .collect())
    }

    fn accept(
        &mut self,
        identifier: &str,
        kever: Kever,
        sequence_number: u128,
        event: LoggedEvent,
    ) -> Result<(), StoreError> {
        let superseded: Vec<(u128, LoggedEvent)> = self
            .events(identifier)?
            .into_iter()
            .filter(|(at, _)| *at >= sequence_number)
            .collect();
        let already = self.superseded(identifier)?.len();
        let kever = kever.to_bytes().map_err(StoreError::new)?;
        let event = event.to_bytes().map_err(StoreError::new)?;
        let moved = superseded
            .iter()
            .map(|(_, event)| event.to_bytes().map_err(StoreError::new))
            .collect::<Result<Vec<_>, _>>()?;
        self.write(|transaction| {
            let mut kevers = transaction.open_table(KEVERS).map_err(StoreError::new)?;
            kevers.insert(identifier, kever.as_slice()).map_err(StoreError::new)?;
            let mut kels = transaction.open_table(KELS).map_err(StoreError::new)?;
            let mut sups = transaction.open_table(SUPERSEDED).map_err(StoreError::new)?;
            // A recovery rotation supersedes the event at its sequence number and every one after.
            for (offset, ((at, _), bytes)) in superseded.iter().zip(&moved).enumerate() {
                kels.remove(key(&[identifier, &ordinal(*at)]).as_str())
                    .map_err(StoreError::new)?;
                let order = u128::try_from(already.saturating_add(offset)).map_err(StoreError::new)?;
                sups.insert(key(&[identifier, &ordinal(order)]).as_str(), bytes.as_slice())
                    .map_err(StoreError::new)?;
            }
            kels.insert(key(&[identifier, &ordinal(sequence_number)]).as_str(), event.as_slice())
                .map_err(StoreError::new)?;
            Ok(())
        })
    }

    fn update_event(&mut self, identifier: &str, sequence_number: u128, event: LoggedEvent) -> Result<(), StoreError> {
        let at = key(&[identifier, &ordinal(sequence_number)]);
        if self.get::<LoggedEvent>(KELS, &at)?.is_none() {
            return Ok(());
        }
        self.put(KELS, &at, &event)
    }
}

impl EscrowStore for RedbStore {
    fn escrowed(&self, identifier: &str, said: &str) -> Result<Option<EscrowedEvent>, StoreError> {
        self.get(ESCROWS, &key(&[identifier, said]))
    }

    fn escrowed_for(&self, reason: Escrow) -> Result<Vec<(String, String, EscrowedEvent)>, StoreError> {
        Ok(self
            .scan::<EscrowedEvent>(ESCROWS, "")?
            .into_iter()
            .filter(|(_, escrowed)| escrowed.reason() == reason)
            .filter_map(|(entry, escrowed)| {
                let (identifier, said) = entry.split_once('.')?;
                Some((identifier.to_owned(), said.to_owned(), escrowed))
            })
            .collect())
    }

    fn put_escrowed(&mut self, identifier: &str, said: &str, event: EscrowedEvent) -> Result<(), StoreError> {
        self.put(ESCROWS, &key(&[identifier, said]), &event)
    }

    fn remove_escrowed(&mut self, identifier: &str, said: &str) -> Result<(), StoreError> {
        self.remove(ESCROWS, &key(&[identifier, said]))
    }

    fn escrowed_queries(&self) -> Result<Vec<(String, String, EscrowedQuery)>, StoreError> {
        Ok(self
            .scan::<EscrowedQuery>(QUERIES, "")?
            .into_iter()
            .filter_map(|(entry, query)| {
                let (requester, said) = entry.split_once('.')?;
                Some((requester.to_owned(), said.to_owned(), query))
            })
            .collect())
    }

    fn put_escrowed_query(&mut self, requester: &str, said: &str, query: EscrowedQuery) -> Result<(), StoreError> {
        self.put(QUERIES, &key(&[requester, said]), &query)
    }

    fn remove_escrowed_query(&mut self, requester: &str, said: &str) -> Result<(), StoreError> {
        self.remove(QUERIES, &key(&[requester, said]))
    }

    fn expire_escrowed_queries(&mut self, cutoff: &Timestamp) -> Result<usize, StoreError> {
        self.expire(QUERIES, |query: &EscrowedQuery| query.since() < cutoff)
    }

    fn next_arrival(&mut self) -> Result<u64, StoreError> {
        let mut arrival = 0;
        self.write(|transaction| {
            let mut table = transaction.open_table(ARRIVALS).map_err(StoreError::new)?;
            let current = match table.get("next").map_err(StoreError::new)? {
                Some(value) => {
                    let bytes: [u8; 8] = value.value().try_into().map_err(StoreError::new)?;
                    u64::from_be_bytes(bytes)
                }
                None => 0,
            };
            arrival = current;
            table
                .insert("next", current.saturating_add(1).to_be_bytes().as_slice())
                .map_err(StoreError::new)?;
            Ok(())
        })?;
        Ok(arrival)
    }

    fn escrowed_count(&self) -> Result<usize, StoreError> {
        self.count(ESCROWS)
    }

    fn expire_escrowed(&mut self, cutoff: &Timestamp) -> Result<usize, StoreError> {
        self.expire(ESCROWS, |escrowed: &EscrowedEvent| escrowed.since() < cutoff)
    }
}

impl ReceiptStore for RedbStore {
    fn hold_receipt(&mut self, receipt: WaitingReceipt) -> Result<(), StoreError> {
        let bytes = receipt.to_bytes().map_err(StoreError::new)?;
        self.write(|transaction| {
            let mut table = transaction.open_table(RECEIPTS).map_err(StoreError::new)?;
            // The next order after the last one held keeps receipts in the order they were held.
            let next = match table.last().map_err(StoreError::new)? {
                Some((last, _)) => number(last.value())?.saturating_add(1),
                None => 0,
            };
            table
                .insert(ordinal(next).as_str(), bytes.as_slice())
                .map_err(StoreError::new)?;
            Ok(())
        })
    }

    fn take_receipts(&mut self) -> Result<Vec<WaitingReceipt>, StoreError> {
        let receipts = self
            .scan::<WaitingReceipt>(RECEIPTS, "")?
            .into_iter()
            .map(|(_, receipt)| receipt)
            .collect();
        self.write(|transaction| {
            let mut table = transaction.open_table(RECEIPTS).map_err(StoreError::new)?;
            table.retain(|_, _| false).map_err(StoreError::new)?;
            Ok(())
        })?;
        Ok(receipts)
    }

    fn receipt_count(&self) -> Result<usize, StoreError> {
        self.count(RECEIPTS)
    }

    fn expire_receipts(&mut self, cutoff: &Timestamp) -> Result<usize, StoreError> {
        self.expire(RECEIPTS, |receipt: &WaitingReceipt| receipt.received_at() < cutoff)
    }
}

impl ReplyStore for RedbStore {
    fn key_state_notice(&self, identifier: &str, source: &str) -> Result<Option<KeyStateNotice>, StoreError> {
        self.get(NOTICES, &key(&[identifier, source]))
    }

    fn key_state_notices(&self, identifier: &str) -> Result<Vec<(String, KeyStateNotice)>, StoreError> {
        self.scan(NOTICES, &key(&[identifier, ""]))
    }

    fn put_key_state_notice(
        &mut self,
        identifier: &str,
        source: &str,
        notice: KeyStateNotice,
    ) -> Result<(), StoreError> {
        self.put(NOTICES, &key(&[identifier, source]), &notice)
    }

    fn end_role(&self, controller: &str, role: &str, endpoint: &str) -> Result<Option<EndRoleRecord>, StoreError> {
        self.get(END_ROLES, &key(&[controller, role, endpoint]))
    }

    fn end_roles(&self, controller: &str) -> Result<Vec<(String, String, EndRoleRecord)>, StoreError> {
        Ok(self
            .scan::<EndRoleRecord>(END_ROLES, &key(&[controller, ""]))?
            .into_iter()
            .filter_map(|(rest, record)| {
                let (role, endpoint) = rest.split_once('.')?;
                Some((role.to_owned(), endpoint.to_owned(), record))
            })
            .collect())
    }

    fn put_end_role(
        &mut self,
        controller: &str,
        role: &str,
        endpoint: &str,
        record: EndRoleRecord,
    ) -> Result<(), StoreError> {
        self.put(END_ROLES, &key(&[controller, role, endpoint]), &record)
    }

    fn location(&self, endpoint: &str, scheme: &str) -> Result<Option<LocationRecord>, StoreError> {
        self.get(LOCATIONS, &key(&[endpoint, scheme]))
    }

    fn locations(&self, endpoint: &str) -> Result<Vec<(String, LocationRecord)>, StoreError> {
        self.scan(LOCATIONS, &key(&[endpoint, ""]))
    }

    fn put_location(&mut self, endpoint: &str, scheme: &str, record: LocationRecord) -> Result<(), StoreError> {
        self.put(LOCATIONS, &key(&[endpoint, scheme]), &record)
    }

    fn observation(
        &self,
        controller: &str,
        watcher: &str,
        observed: &str,
    ) -> Result<Option<ObservationRecord>, StoreError> {
        self.get(OBSERVATIONS, &key(&[controller, watcher, observed]))
    }

    fn observations(&self, watcher: &str) -> Result<Vec<(String, String, ObservationRecord)>, StoreError> {
        Ok(self
            .scan::<ObservationRecord>(OBSERVATIONS, "")?
            .into_iter()
            .filter_map(|(entry, record)| {
                let mut parts = entry.splitn(3, '.');
                let (controller, observing, observed) = (parts.next()?, parts.next()?, parts.next()?);
                (observing == watcher).then(|| (controller.to_owned(), observed.to_owned(), record))
            })
            .collect())
    }

    fn put_observation(
        &mut self,
        controller: &str,
        watcher: &str,
        observed: &str,
        record: ObservationRecord,
    ) -> Result<(), StoreError> {
        self.put(OBSERVATIONS, &key(&[controller, watcher, observed]), &record)
    }

    fn hold_oobi(&mut self, url: &str) -> Result<(), StoreError> {
        self.write(|transaction| {
            let mut table = transaction.open_table(OOBIS).map_err(StoreError::new)?;
            table.insert(url, [].as_slice()).map_err(StoreError::new)?;
            Ok(())
        })
    }

    fn oobis(&self) -> Result<Vec<String>, StoreError> {
        let transaction = self.database.begin_read().map_err(StoreError::new)?;
        let table = transaction.open_table(OOBIS).map_err(StoreError::new)?;
        table
            .iter()
            .map_err(StoreError::new)?
            .map(|entry| {
                let (url, _) = entry.map_err(StoreError::new)?;
                Ok(url.value().to_owned())
            })
            .collect()
    }

    fn escrowed_reply(&self, said: &str) -> Result<Option<EscrowedReply>, StoreError> {
        self.get(REPLIES, said)
    }

    fn escrowed_replies(&self) -> Result<Vec<(String, EscrowedReply)>, StoreError> {
        self.scan(REPLIES, "")
    }

    fn put_escrowed_reply(&mut self, said: &str, reply: EscrowedReply) -> Result<(), StoreError> {
        self.put(REPLIES, said, &reply)
    }

    fn remove_escrowed_reply(&mut self, said: &str) -> Result<(), StoreError> {
        self.remove(REPLIES, said)
    }

    fn expire_escrowed_replies(&mut self, cutoff: &Timestamp) -> Result<usize, StoreError> {
        self.expire(REPLIES, |reply: &EscrowedReply| reply.since() < cutoff)
    }
}

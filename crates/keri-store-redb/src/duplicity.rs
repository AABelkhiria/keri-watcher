//! The duplicity a watcher sees: at a sequence number of an identifier, the different events its
//! sources report.

use keri_kel::StoreError;
use keri_protocol::event::timestamp::Timestamp;
use redb::{ReadableDatabase, ReadableTable};
use serde::{Deserialize, Serialize};

use crate::{DUPLICITY, RedbStore, key, number, ordinal};

/// A source reporting an event at a sequence number where duplicity was seen.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Sighting {
    /// The SAID of the event reported, as qb64.
    pub said: String,
    /// Who reported it, as qb64.
    pub source: String,
    /// When it was first recorded.
    pub first_seen: Timestamp,
}

/// A sighting as the `dups` table holds it.
#[derive(Deserialize, Serialize)]
struct Mirror {
    d: String,
    i: String,
    dt: String,
}

fn write(sightings: &[Sighting]) -> Result<Vec<u8>, StoreError> {
    let mirrors: Vec<Mirror> = sightings
        .iter()
        .map(|sighting| Mirror {
            d: sighting.said.clone(),
            i: sighting.source.clone(),
            dt: sighting.first_seen.as_str().to_owned(),
        })
        .collect();
    serde_json::to_vec(&mirrors).map_err(StoreError::new)
}

fn read(bytes: &[u8]) -> Result<Vec<Sighting>, StoreError> {
    serde_json::from_slice::<Vec<Mirror>>(bytes)
        .map_err(StoreError::new)?
        .into_iter()
        .map(|mirror| {
            Ok(Sighting {
                said: mirror.d,
                source: mirror.i,
                first_seen: Timestamp::parse(&mirror.dt).map_err(StoreError::new)?,
            })
        })
        .collect()
}

impl RedbStore {
    /// Records that the sources in `sightings` report these events at `sequence_number` of
    /// `identifier`. A source already recorded reporting the same event keeps its first-seen time.
    /// Returns how many sightings were new.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when the database fails or holds a record it cannot read.
    pub fn record_duplicity(
        &self,
        identifier: &str,
        sequence_number: u128,
        sightings: &[Sighting],
    ) -> Result<usize, StoreError> {
        let at = key(&[identifier, &ordinal(sequence_number)]);
        let mut added = 0;
        self.write(|transaction| {
            let mut table = transaction.open_table(DUPLICITY).map_err(StoreError::new)?;
            let mut held = match table.get(at.as_str()).map_err(StoreError::new)? {
                Some(value) => read(value.value())?,
                None => Vec::new(),
            };
            for sighting in sightings {
                let seen = held
                    .iter()
                    .any(|kept| kept.said == sighting.said && kept.source == sighting.source);
                if !seen {
                    held.push(sighting.clone());
                    added += 1;
                }
            }
            if added > 0 {
                table
                    .insert(at.as_str(), write(&held)?.as_slice())
                    .map_err(StoreError::new)?;
            }
            Ok(())
        })?;
        Ok(added)
    }

    /// Returns the duplicity recorded for `identifier`, by sequence number.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when the database fails or holds a record it cannot read.
    pub fn duplicity(&self, identifier: &str) -> Result<Vec<(u128, Vec<Sighting>)>, StoreError> {
        let prefix = key(&[identifier, ""]);
        let transaction = self.database.begin_read().map_err(StoreError::new)?;
        let table = transaction.open_table(DUPLICITY).map_err(StoreError::new)?;
        let mut found = Vec::new();
        for entry in table.range(prefix.as_str()..).map_err(StoreError::new)? {
            let (key, value) = entry.map_err(StoreError::new)?;
            let Some(sequence_number) = key.value().strip_prefix(prefix.as_str()) else {
                break;
            };
            found.push((number(sequence_number)?, read(value.value())?));
        }
        Ok(found)
    }
}

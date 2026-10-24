//! What an identifier's witnesses report about it, merged, and what the local copy is missing.
//!
//! A watcher asks each of an identifier's witnesses for its key state and gets one report from each
//! that answers. [`merge`] combines them: the highest state the witnesses agree on, with the
//! witnesses that report it and those behind it; or duplicity, when two witnesses report different
//! events at the same sequence number, which no amount of fetching resolves. [`Merged::missing`]
//! then says which events the local copy lacks and which witnesses can serve them.
//!
//! Reports at different sequence numbers are not compared: a witness behind may simply not have
//! the later events yet, and whether its earlier event is the same as everyone else's shows only
//! once the log is fetched and validated, which is keri-kel's job.
//!
//! This is the application's choice, not KERI's; it follows how keriox's watcher brings a log up
//! to date: ask every witness for its state, take the highest, and fetch from the next local event.

use core::ops::RangeInclusive;

use keri_protocol::event::key_state::KeyStateRecord;
use keri_protocol::prefix::IdentifierPrefix;
use keri_protocol::said::Said;

use crate::error::WatchError;

/// One witness's report: the witness and the state it holds.
pub type Report = (IdentifierPrefix, KeyStateRecord);

/// The witnesses' reports about one identifier, merged.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Merged {
    /// No witness reported.
    Silent,
    /// The witnesses agree.
    Agreed {
        /// The highest state reported.
        state: Box<KeyStateRecord>,
        /// The witnesses that report it.
        reporting: Vec<IdentifierPrefix>,
        /// The witnesses that report an earlier state.
        behind: Vec<IdentifierPrefix>,
    },
    /// Witnesses report different events at the same sequence number.
    Duplicitous {
        /// The lowest sequence number they disagree at.
        sequence_number: u128,
        /// Each witness reporting at it, with the event it reports.
        conflicting: Vec<(IdentifierPrefix, Said)>,
    },
}

impl Merged {
    /// Returns the events the local copy lacks, from the one after `local`, its latest sequence
    /// number if it holds the identifier at all, to the highest agreed state, or `None` when it
    /// lacks nothing or the witnesses do not agree.
    #[must_use]
    pub fn missing(&self, local: Option<u128>) -> Option<RangeInclusive<u128>> {
        let Self::Agreed { state, .. } = self else {
            return None;
        };
        let from = local.map_or(0, |local| local.saturating_add(1));
        let to = state.sequence_number();
        (from <= to && local.is_none_or(|local| local < to)).then_some(from..=to)
    }

    /// Returns the witnesses that can serve the missing events: those reporting the highest
    /// agreed state.
    #[must_use]
    pub fn sources(&self) -> &[IdentifierPrefix] {
        match self {
            Self::Agreed { reporting, .. } => reporting,
            Self::Silent | Self::Duplicitous { .. } => &[],
        }
    }
}

/// Merges the witnesses' reports about one identifier.
///
/// # Errors
///
/// Returns [`WatchError::MixedIdentifiers`] when the reports are about different identifiers.
pub fn merge(reports: &[Report]) -> Result<Merged, WatchError> {
    let Some((_, first)) = reports.first() else {
        return Ok(Merged::Silent);
    };
    if reports
        .iter()
        .any(|(_, state)| state.identifier() != first.identifier())
    {
        return Err(WatchError::MixedIdentifiers);
    }
    // The lowest sequence number at which two reports name different events.
    let mut by_number: Vec<&Report> = reports.iter().collect();
    by_number.sort_by_key(|(_, state)| state.sequence_number());
    let conflict = by_number.windows(2).find_map(|pair| match pair {
        [(_, earlier), (_, later)]
            if earlier.sequence_number() == later.sequence_number() && earlier.said() != later.said() =>
        {
            Some(earlier.sequence_number())
        }
        _ => None,
    });
    if let Some(sequence_number) = conflict {
        let conflicting = reports
            .iter()
            .filter(|(_, state)| state.sequence_number() == sequence_number)
            .map(|(witness, state)| (witness.clone(), state.said()))
            .collect();
        return Ok(Merged::Duplicitous {
            sequence_number,
            conflicting,
        });
    }
    let highest = reports
        .iter()
        .map(|(_, state)| state.sequence_number())
        .max()
        .unwrap_or_default();
    let mut reporting = Vec::new();
    let mut behind = Vec::new();
    let mut state = first.clone();
    for (witness, reported) in reports {
        if reported.sequence_number() == highest {
            reporting.push(witness.clone());
            state = reported.clone();
        } else {
            behind.push(witness.clone());
        }
    }
    Ok(Merged::Agreed {
        state: Box::new(state),
        reporting,
        behind,
    })
}

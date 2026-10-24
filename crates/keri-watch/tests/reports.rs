//! Merging witnesses' reports about an identifier, and the events the local copy lacks.

use std::error::Error;

use keri_protocol::event::key_state::{KeyStateBuilder, KeyStateRecord, LatestEstablishment};
use keri_protocol::event::kind::EventKind;
use keri_protocol::event::timestamp::Timestamp;
use keri_protocol::prefix::IdentifierPrefix;
use keri_protocol::said::Said;
use keri_watch::{Merged, WatchError, merge};

const IDENTIFIER: &str = "EBkyBvcLsNQyvL7sqNsgPf9dqjr1HnjRxwqsx52ctU5Z";
const OTHER_IDENTIFIER: &str = "ED8-jXBLdE1A_G6M5AnzM0uw_2h4yEaHnW7_kPnycbYb";
const WITNESSES: [&str; 3] = [
    "BEMEa_5AkrPpSZTq2hXcwg2Kqge2WP05VOuODvuL3KXe",
    "BKzbDil0PwzLhobQoQTLluBavv7BU4dl51lYaffcjEmq",
    "BJEJ21X3l5ejlkYvuJXCrc6n6Gg8LzBWwHpUdRVVN7c-",
];
const SAIDS: [&str; 2] = [
    "EBkyBvcLsNQyvL7sqNsgPf9dqjr1HnjRxwqsx52ctU5Z",
    "ED8-jXBLdE1A_G6M5AnzM0uw_2h4yEaHnW7_kPnycbYb",
];

fn witnesses() -> Result<Vec<IdentifierPrefix>, Box<dyn Error>> {
    Ok(WITNESSES
        .iter()
        .map(|text| IdentifierPrefix::from_qb64(text))
        .collect::<Result<_, _>>()?)
}

/// A state of `identifier` at `sequence_number`, its latest event the `event`th SAID.
fn state(identifier: &str, sequence_number: u128, event: usize) -> Result<KeyStateRecord, Box<dyn Error>> {
    let IdentifierPrefix::Basic(signer) = IdentifierPrefix::from_qb64(WITNESSES.first().ok_or("no key")?)? else {
        return Err("not a basic prefix".into());
    };
    let said = Said::from_qb64(SAIDS.get(event).ok_or("no such event")?)?;
    let inception = Said::from_qb64(IDENTIFIER)?;
    Ok(KeyStateBuilder::new(
        IdentifierPrefix::from_qb64(identifier)?,
        sequence_number,
        said,
        if sequence_number == 0 {
            EventKind::Inception
        } else {
            EventKind::Interaction
        },
        Timestamp::parse("2021-01-01T00:00:00.000000+00:00")?,
        vec![signer.key().clone()],
        LatestEstablishment::new(0, inception),
    )
    .build()?)
}

#[test]
fn no_reports_merge_to_silence() -> Result<(), Box<dyn Error>> {
    let merged = merge(&[])?;
    assert_eq!(merged, Merged::Silent);
    assert_eq!(merged.missing(None), None);
    assert_eq!(merged.sources(), &[] as &[IdentifierPrefix]);
    Ok(())
}

#[test]
fn the_highest_state_is_taken_and_the_rest_are_behind() -> Result<(), Box<dyn Error>> {
    let witnesses = witnesses()?;
    let [first, second, third] = witnesses.as_slice() else {
        return Err("three witnesses expected".into());
    };
    let reports = vec![
        (first.clone(), state(IDENTIFIER, 1, 0)?),
        (second.clone(), state(IDENTIFIER, 3, 1)?),
        (third.clone(), state(IDENTIFIER, 3, 1)?),
    ];
    let Merged::Agreed {
        state,
        reporting,
        behind,
    } = merge(&reports)?
    else {
        return Err("the reports should agree".into());
    };
    assert_eq!(state.sequence_number(), 3);
    assert_eq!(reporting, vec![second.clone(), third.clone()]);
    assert_eq!(behind, vec![first.clone()]);
    Ok(())
}

#[test]
fn the_local_copy_lacks_the_events_after_its_latest() -> Result<(), Box<dyn Error>> {
    let witnesses = witnesses()?;
    let first = witnesses.first().ok_or("no witness")?;
    let merged = merge(&[(first.clone(), state(IDENTIFIER, 3, 0)?)])?;
    assert_eq!(
        merged.missing(None),
        Some(0..=3),
        "an unknown identifier lacks everything"
    );
    assert_eq!(merged.missing(Some(1)), Some(2..=3));
    assert_eq!(merged.missing(Some(3)), None, "a current copy lacks nothing");
    assert_eq!(merged.missing(Some(5)), None, "a copy ahead lacks nothing either");
    assert_eq!(merged.sources(), std::slice::from_ref(first));
    Ok(())
}

#[test]
fn different_events_at_one_sequence_number_are_duplicitous() -> Result<(), Box<dyn Error>> {
    let witnesses = witnesses()?;
    let [first, second, third] = witnesses.as_slice() else {
        return Err("three witnesses expected".into());
    };
    let reports = vec![
        (first.clone(), state(IDENTIFIER, 2, 0)?),
        (second.clone(), state(IDENTIFIER, 2, 1)?),
        (third.clone(), state(IDENTIFIER, 4, 0)?),
    ];
    let merged = merge(&reports)?;
    let Merged::Duplicitous {
        sequence_number,
        conflicting,
    } = &merged
    else {
        return Err("the reports should be duplicitous".into());
    };
    assert_eq!(*sequence_number, 2, "even though a later state is reported");
    let reported: Vec<&IdentifierPrefix> = conflicting.iter().map(|(witness, _)| witness).collect();
    assert_eq!(reported, vec![first, second]);
    assert_eq!(
        merged.missing(Some(0)),
        None,
        "nothing is fetched from witnesses that disagree"
    );
    assert_eq!(merged.sources(), &[] as &[IdentifierPrefix]);
    Ok(())
}

#[test]
fn reports_about_different_identifiers_are_refused() -> Result<(), Box<dyn Error>> {
    let witnesses = witnesses()?;
    let [first, second, _] = witnesses.as_slice() else {
        return Err("three witnesses expected".into());
    };
    let reports = vec![
        (first.clone(), state(IDENTIFIER, 1, 0)?),
        (second.clone(), state(OTHER_IDENTIFIER, 1, 0)?),
    ];
    assert!(matches!(merge(&reports), Err(WatchError::MixedIdentifiers)));
    Ok(())
}

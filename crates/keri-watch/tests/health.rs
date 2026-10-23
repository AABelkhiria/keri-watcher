//! Witness health: smoothed response times, failures and cooldowns, and the order to ask in.

use core::time::Duration;
use std::error::Error;

use keri_protocol::prefix::IdentifierPrefix;
use keri_watch::{HealthPolicy, WitnessHealth};
use proptest::{prelude::*, test_runner::TestCaseError};

const MINUTE: Duration = Duration::from_secs(60);
const WITNESSES: [&str; 3] = [
    "BEMEa_5AkrPpSZTq2hXcwg2Kqge2WP05VOuODvuL3KXe",
    "BKzbDil0PwzLhobQoQTLluBavv7BU4dl51lYaffcjEmq",
    "BJEJ21X3l5ejlkYvuJXCrc6n6Gg8LzBWwHpUdRVVN7c-",
];

fn witnesses() -> Result<Vec<IdentifierPrefix>, Box<dyn Error>> {
    Ok(WITNESSES
        .iter()
        .map(|text| IdentifierPrefix::from_qb64(text))
        .collect::<Result<_, _>>()?)
}

fn ms(milliseconds: u64) -> Duration {
    Duration::from_millis(milliseconds)
}

#[test]
fn response_times_are_smoothed() -> Result<(), Box<dyn Error>> {
    let witnesses = witnesses()?;
    let witness = witnesses.first().ok_or("no witness")?;
    let mut health = WitnessHealth::new(HealthPolicy::default());
    health.succeeded(witness, ms(100))?;
    // The first answer is the average; each later one moves it a fifth of the way.
    health.succeeded(witness, ms(600))?;
    let record = health.records().next().ok_or("nothing recorded")?;
    assert_eq!(record.average(), Some(ms(200)));
    health.succeeded(witness, ms(100))?;
    let record = health.records().next().ok_or("nothing recorded")?;
    assert_eq!(record.average(), Some(ms(180)));
    assert_eq!(record.successes(), 3);
    Ok(())
}

#[test]
fn three_failures_in_a_row_make_a_witness_unhealthy_until_its_cooldown() -> Result<(), Box<dyn Error>> {
    let witnesses = witnesses()?;
    let witness = witnesses.first().ok_or("no witness")?;
    let mut health = WitnessHealth::new(HealthPolicy::default());
    assert!(
        health.is_healthy(witness, Duration::ZERO)?,
        "a witness never seen is healthy"
    );
    health.failed(witness, Duration::ZERO)?;
    health.failed(witness, Duration::ZERO)?;
    assert!(health.is_healthy(witness, Duration::ZERO)?);
    health.failed(witness, Duration::from_secs(5))?;
    assert!(!health.is_healthy(witness, Duration::from_secs(5))?);
    assert!(!health.is_healthy(witness, Duration::from_secs(64))?);
    assert!(
        health.is_healthy(witness, Duration::from_secs(65))?,
        "worth a try after the cooldown"
    );
    // Failing the retry starts the cooldown again; one success restores it.
    health.failed(witness, Duration::from_secs(65))?;
    assert!(!health.is_healthy(witness, Duration::from_secs(70))?);
    health.succeeded(witness, ms(50))?;
    assert!(health.is_healthy(witness, Duration::from_secs(70))?);
    Ok(())
}

#[test]
fn healthy_fast_witnesses_are_asked_first() -> Result<(), Box<dyn Error>> {
    let witnesses = witnesses()?;
    let [slow, unmeasured, fast] = witnesses.as_slice() else {
        return Err("three witnesses expected".into());
    };
    let mut health = WitnessHealth::new(HealthPolicy::default());
    health.succeeded(slow, ms(900))?;
    health.succeeded(fast, ms(30))?;
    assert_eq!(
        health.priority_order(&witnesses, Duration::ZERO)?,
        vec![fast.clone(), slow.clone(), unmeasured.clone()]
    );
    for _ in 0..3 {
        health.failed(fast, Duration::ZERO)?;
    }
    assert_eq!(
        health.priority_order(&witnesses, Duration::ZERO)?,
        vec![slow.clone(), unmeasured.clone(), fast.clone()],
        "an unhealthy witness goes last"
    );
    assert_eq!(
        health.priority_order(&witnesses, MINUTE)?,
        vec![fast.clone(), slow.clone(), unmeasured.clone()],
        "back in its place once its cooldown has passed, ranked by its last average"
    );
    Ok(())
}

#[test]
fn a_smoothing_of_one_keeps_the_latest() -> Result<(), Box<dyn Error>> {
    let witnesses = witnesses()?;
    let witness = witnesses.first().ok_or("no witness")?;
    let mut health = WitnessHealth::new(HealthPolicy::default().smoothing(1));
    health.succeeded(witness, ms(100))?;
    health.succeeded(witness, ms(700))?;
    let record = health.records().next().ok_or("nothing recorded")?;
    assert_eq!(record.average(), Some(ms(700)));
    Ok(())
}

proptest! {
    /// Whatever happened, the order holds every witness given once, healthy ones before unhealthy
    /// ones.
    #[test]
    fn the_order_is_every_witness_healthy_first(
        events in prop::collection::vec((0_usize..3, any::<bool>(), 0_u64..2_000, 0_u64..120), 0..40),
    ) {
        let fail = |error: Box<dyn Error>| TestCaseError::fail(error.to_string());
        let witnesses = witnesses().map_err(fail)?;
        let mut health = WitnessHealth::new(HealthPolicy::default());
        let mut now = Duration::ZERO;
        for (which, answered, response, after) in events {
            now += Duration::from_secs(after);
            if let Some(witness) = witnesses.get(which) {
                let recorded = if answered {
                    health.succeeded(witness, ms(response))
                } else {
                    health.failed(witness, now)
                };
                recorded.map_err(|error| fail(error.into()))?;
            }
        }
        let order = health.priority_order(&witnesses, now).map_err(|error| fail(error.into()))?;
        prop_assert_eq!(order.len(), witnesses.len());
        for witness in &witnesses {
            prop_assert!(order.contains(witness));
        }
        let healthy = order
            .iter()
            .map(|witness| health.is_healthy(witness, now))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| fail(error.into()))?;
        prop_assert!(healthy.windows(2).all(|pair| pair.first() >= pair.last()));
    }
}

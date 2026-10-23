//! Poll planning: the interval for a log, and which observed identifiers are due when.

use core::time::Duration;
use std::error::Error;

use keri_protocol::prefix::IdentifierPrefix;
use keri_watch::{PollPlanner, PollPolicy};
use proptest::{prelude::*, test_runner::TestCaseError};

const BASE: Duration = Duration::from_secs(30);
const MINUTE: Duration = Duration::from_secs(60);
const HOUR: Duration = Duration::from_secs(3600);
const IDENTIFIERS: [&str; 3] = [
    "EBkyBvcLsNQyvL7sqNsgPf9dqjr1HnjRxwqsx52ctU5Z",
    "ED8-jXBLdE1A_G6M5AnzM0uw_2h4yEaHnW7_kPnycbYb",
    "BKzbDil0PwzLhobQoQTLluBavv7BU4dl51lYaffcjEmq",
];

fn identifiers() -> Result<Vec<IdentifierPrefix>, Box<dyn Error>> {
    Ok(IDENTIFIERS
        .iter()
        .map(|text| IdentifierPrefix::from_qb64(text))
        .collect::<Result<_, _>>()?)
}

#[test]
fn a_changing_log_is_polled_at_the_base_interval() {
    let policy = PollPolicy::new(BASE);
    assert_eq!(policy.interval(Duration::ZERO, false), BASE);
    assert_eq!(policy.interval(MINUTE, false), BASE);
}

#[test]
fn a_stable_log_is_polled_at_ten_times_the_base_interval() {
    let policy = PollPolicy::new(BASE);
    assert_eq!(policy.interval(HOUR, false), BASE * 10);
    assert_eq!(policy.interval(HOUR * 24, false), BASE * 10);
}

#[test]
fn polling_slows_linearly_between() {
    let policy = PollPolicy::new(BASE);
    // Halfway from one minute to an hour, halfway from the base interval to ten times it.
    let halfway = MINUTE + HOUR.saturating_sub(MINUTE) / 2;
    assert_eq!(policy.interval(halfway, false), BASE + BASE * 9 / 2);
}

#[test]
fn a_subscribed_identifier_is_always_polled_at_the_base_interval() {
    assert_eq!(PollPolicy::new(BASE).interval(HOUR * 24, true), BASE);
}

#[test]
fn a_slowdown_of_one_never_slows() {
    assert_eq!(PollPolicy::new(BASE).slowdown(1).interval(HOUR * 24, false), BASE);
}

#[test]
fn identifiers_never_polled_are_due_at_once() -> Result<(), Box<dyn Error>> {
    let identifiers = identifiers()?;
    let mut planner = PollPlanner::new(PollPolicy::new(BASE));
    for identifier in &identifiers {
        planner.observe(identifier, Duration::ZERO)?;
    }
    assert_eq!(planner.len(), 3);
    assert_eq!(planner.due(Duration::ZERO).len(), 3);
    assert_eq!(planner.next_due(Duration::ZERO), Some(Duration::ZERO));
    Ok(())
}

#[test]
fn a_polled_identifier_waits_its_interval() -> Result<(), Box<dyn Error>> {
    let identifiers = identifiers()?;
    let first = identifiers.first().ok_or("no identifier")?;
    let mut planner = PollPlanner::new(PollPolicy::new(BASE));
    planner.observe(first, Duration::ZERO)?;
    assert!(planner.polled(first, Duration::ZERO, true)?);
    assert_eq!(planner.due(BASE.saturating_sub(Duration::from_secs(1))), Vec::new());
    assert_eq!(planner.next_due(Duration::ZERO), Some(BASE));
    assert_eq!(planner.due(BASE), vec![first.clone()]);
    Ok(())
}

#[test]
fn a_stable_identifier_is_polled_less_often_until_it_changes() -> Result<(), Box<dyn Error>> {
    let identifiers = identifiers()?;
    let first = identifiers.first().ok_or("no identifier")?;
    let mut planner = PollPlanner::new(PollPolicy::new(BASE));
    planner.observe(first, Duration::ZERO)?;
    planner.polled(first, Duration::ZERO, true)?;
    // Unchanged for two hours: next due ten base intervals later.
    planner.polled(first, HOUR * 2, false)?;
    assert_eq!(planner.next_due(HOUR * 2), Some(HOUR * 2 + BASE * 10));
    // A change brings it back to the base interval.
    planner.polled(first, HOUR * 3, true)?;
    assert_eq!(planner.next_due(HOUR * 3), Some(HOUR * 3 + BASE));
    Ok(())
}

#[test]
fn the_most_overdue_comes_first() -> Result<(), Box<dyn Error>> {
    let identifiers = identifiers()?;
    let [first, second, third] = identifiers.as_slice() else {
        return Err("three identifiers expected".into());
    };
    let mut planner = PollPlanner::new(PollPolicy::new(BASE));
    for identifier in [first, second, third] {
        planner.observe(identifier, Duration::ZERO)?;
    }
    planner.polled(first, Duration::from_secs(10), true)?;
    planner.polled(second, Duration::ZERO, true)?;
    // The third was never polled, so it comes first; the second fell due before the first.
    assert_eq!(planner.due(MINUTE), vec![third.clone(), second.clone(), first.clone()]);
    Ok(())
}

#[test]
fn a_zero_base_interval_disables_polling() -> Result<(), Box<dyn Error>> {
    let identifiers = identifiers()?;
    let mut planner = PollPlanner::new(PollPolicy::new(Duration::ZERO));
    for identifier in &identifiers {
        planner.observe(identifier, Duration::ZERO)?;
    }
    assert!(planner.policy().is_disabled());
    assert_eq!(planner.due(HOUR), Vec::new());
    assert_eq!(planner.next_due(HOUR), None);
    Ok(())
}

#[test]
fn forgotten_and_unknown_identifiers_are_not_polled() -> Result<(), Box<dyn Error>> {
    let identifiers = identifiers()?;
    let [first, second, _] = identifiers.as_slice() else {
        return Err("three identifiers expected".into());
    };
    let mut planner = PollPlanner::new(PollPolicy::new(BASE));
    planner.observe(first, Duration::ZERO)?;
    assert!(!planner.polled(second, Duration::ZERO, true)?);
    assert!(!planner.subscribe(second, true)?);
    assert!(planner.forget(first)?);
    assert!(!planner.forget(first)?);
    assert!(planner.is_empty());
    assert_eq!(planner.due(HOUR), Vec::new());
    Ok(())
}

proptest! {
    /// The interval never shrinks as a log stays stable longer, and stays between the base
    /// interval and the slowest.
    #[test]
    fn the_interval_grows_with_stability(
        base in 1_u64..3_600,
        slowdown in 1_u32..20,
        first in 0_u64..10_000,
        later in 0_u64..10_000,
    ) {
        let base = Duration::from_secs(base);
        let policy = PollPolicy::new(base).slowdown(slowdown);
        let (earlier, later) = (first.min(later), first.max(later));
        let shorter = policy.interval(Duration::from_secs(earlier), false);
        let longer = policy.interval(Duration::from_secs(later), false);
        prop_assert!(shorter <= longer);
        prop_assert!(base <= shorter);
        prop_assert!(longer <= base * slowdown);
    }

    /// Whatever is polled when, every observed identifier falls due again no later than the
    /// slowest interval after its last poll.
    #[test]
    fn nothing_is_starved(polls in prop::collection::vec((0_usize..3, 0_u64..100_000, any::<bool>()), 0..40)) {
        let identifiers = identifiers().map_err(|error| TestCaseError::fail(error.to_string()))?;
        let policy = PollPolicy::new(BASE);
        let mut planner = PollPlanner::new(policy);
        for identifier in &identifiers {
            planner.observe(identifier, Duration::ZERO).map_err(|error| TestCaseError::fail(error.to_string()))?;
        }
        let mut now = Duration::ZERO;
        for (which, after, changed) in polls {
            now += Duration::from_secs(after);
            if let Some(identifier) = identifiers.get(which) {
                planner.polled(identifier, now, changed).map_err(|error| TestCaseError::fail(error.to_string()))?;
            }
        }
        prop_assert_eq!(planner.due(now + BASE * 10).len(), identifiers.len());
    }
}

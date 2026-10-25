//! The one test in this crate that is not ignored: that every test in a `live_*.rs` file carries
//! `#[ignore]`, checked by reading the crate's own test sources.

use std::error::Error;
use std::fs;
use std::path::Path;

fn live_sources() -> Result<Vec<(String, String)>, Box<dyn Error>> {
    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    let mut sources = Vec::new();
    for entry in fs::read_dir(&directory)? {
        let path = entry?.path();
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default()
            .to_owned();
        let rust = path
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("rs"));
        if name.starts_with("live_") && rust {
            sources.push((name, fs::read_to_string(&path)?));
        }
    }
    sources.sort();
    Ok(sources)
}

/// The attributes stacked on the item at line `index`.
fn attributes<'a>(lines: &[&'a str], index: usize) -> Vec<&'a str> {
    lines
        .iter()
        .take(index)
        .rev()
        .map(|line| line.trim())
        .take_while(|line| line.starts_with("#["))
        .collect()
}

#[test]
fn every_live_test_is_ignored() -> Result<(), Box<dyn Error>> {
    let live = live_sources()?;
    assert!(!live.is_empty(), "no live_*.rs file exists, so this guards nothing");
    let mut unguarded = Vec::new();
    for (name, source) in &live {
        let lines: Vec<&str> = source.lines().collect();
        for (index, line) in lines.iter().enumerate() {
            let trimmed = line.trim();
            if !(trimmed.starts_with("fn ") || trimmed.starts_with("async fn ")) {
                continue;
            }
            let stacked = attributes(&lines, index);
            let test = stacked.iter().any(|attribute| attribute.contains("test"));
            if test && !stacked.iter().any(|attribute| attribute.starts_with("#[ignore")) {
                unguarded.push(format!("{name}:{}: {trimmed}", index + 1));
            }
        }
    }
    assert!(
        unguarded.is_empty(),
        "these tests run kli and would run in the default suite: {unguarded:#?}"
    );
    Ok(())
}

#[test]
fn every_live_file_says_how_to_run_itself() -> Result<(), Box<dyn Error>> {
    for (name, source) in live_sources()? {
        let stem = name.strip_suffix(".rs").unwrap_or(&name);
        assert!(
            source.contains(&format!("--test {stem} -- --ignored")),
            "{name} does not say how to run itself"
        );
    }
    Ok(())
}

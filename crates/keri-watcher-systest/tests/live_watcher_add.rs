//! A keripy controller with two keripy witnesses registers with the watcher through
//! `kli watcher add`, and the watcher keeps up with its log from the witnesses.
//!
//! ```text
//! KERI_WATCHER_KLI=/path/to/venv/bin/kli DYLD_FALLBACK_LIBRARY_PATH=/opt/homebrew/lib \
//!     cargo test -p keri-watcher-systest --test live_watcher_add -- --ignored --test-threads=1
//! ```

use std::sync::Arc;
use std::time::Duration;

use keri_kel::Kevery;
use keri_protocol::event::reply::route::Scheme;
use keri_protocol::prefix::IdentifierPrefix;
use keri_store_redb::RedbStore;
use keri_watch::PollPolicy;
use keri_watcher::{
    HttpClient, Identity, Observation, Observer, Poller, Resolution, Resolver, Watcher, http, system_clock,
};
use keri_watcher_systest::{Failure, Keripy, free_port, listening};
use tokio::task::JoinHandle;

const STARTUP: Duration = Duration::from_secs(30);
const TIMEOUT: Duration = Duration::from_secs(5);

/// Starts a keripy witness named `name`, reachable over HTTP, returning its identifier and URL.
async fn witness(keripy: &mut Keripy, name: &str) -> Result<(String, String), Failure> {
    let (http, tcp) = (free_port()?, free_port()?);
    let url = format!("http://127.0.0.1:{http}/");
    keripy.run(&["init", "--name", name]).await?;
    let file = keripy.write_file(
        &format!("{name}-incept.json"),
        r#"{"transferable": false, "wits": [], "toad": 0, "icount": 1, "ncount": 0, "isith": "1", "nsith": "0"}"#,
    )?;
    let file = file.to_str().ok_or("path is not UTF-8")?;
    keripy
        .run(&["incept", "--name", name, "--alias", name, "--file", file])
        .await?;
    let identifier = keripy.identifier(name, name).await?;
    keripy
        .run(&["location", "add", "--name", name, "--alias", name, "--url", &url])
        .await?;
    // keripy's witness puts its location in its OOBI only for an end role it holds itself.
    keripy
        .run(&[
            "ends",
            "add",
            "--name",
            name,
            "--alias",
            name,
            "--role",
            "controller",
            "--eid",
            &identifier,
        ])
        .await?;
    let (http, tcp) = (http.to_string(), tcp.to_string());
    keripy.start_witness(&["--name", name, "--alias", name, "--http", &http, "--tcp", &tcp])?;
    listening(http.parse()?, STARTUP).await?;
    Ok((identifier, url))
}

/// Incepts a keripy controller named `ctl` with both witnesses and a threshold of two, returning its
/// identifier.
async fn controller(keripy: &Keripy, first: (&str, &str), second: (&str, &str)) -> Result<String, Failure> {
    let ((first, first_url), (second, second_url)) = (first, second);
    keripy.write_config(
        "ctl",
        &format!(
            r#"{{"dt": "2022-01-20T12:57:59.823350+00:00", "iurls": ["{first_url}oobi/{first}/controller", "{second_url}oobi/{second}/controller"]}}"#
        ),
    )?;
    let config_dir = keripy.config_dir();
    let config_dir = config_dir.to_str().ok_or("path is not UTF-8")?.to_owned();
    keripy
        .run(&[
            "init",
            "--name",
            "ctl",
            "--config-dir",
            &config_dir,
            "--config-file",
            "ctl",
        ])
        .await?;
    let file = keripy.write_file(
        "ctl-incept.json",
        &format!(
            r#"{{"transferable": true, "wits": ["{first}", "{second}"], "toad": 2, "icount": 1, "ncount": 1, "isith": "1", "nsith": "1"}}"#
        ),
    )?;
    let file = file.to_str().ok_or("path is not UTF-8")?;
    keripy
        .run(&["incept", "--name", "ctl", "--alias", "ctl", "--file", file])
        .await?;
    keripy.identifier("ctl", "ctl").await
}

/// Serves a watcher on a free port of `127.0.0.1`, announcing it, returning the watcher, its URL
/// and the server's task.
async fn serve_watcher(keripy: &Keripy) -> Result<(Arc<Watcher>, String, JoinHandle<std::io::Result<()>>), Failure> {
    let port = free_port()?;
    let url = format!("http://127.0.0.1:{port}");
    let identity = Identity::load_or_create(&keripy.home().join("watcher.salt"))?;
    let kevery = Kevery::with_store(RedbStore::in_memory()?);
    let watcher = Watcher::new(identity, kevery, Box::new(system_clock)).announcing(vec![(Scheme::Http, url.clone())]);
    let watcher = Arc::new(watcher);
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await?;
    let server = tokio::spawn(axum::serve(listener, http::router(Arc::clone(&watcher))).into_future());
    Ok((watcher, url, server))
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "drives keripy's kli and witnesses; run with --ignored"]
async fn a_keripy_controller_registers_and_the_watcher_keeps_up() -> Result<(), Failure> {
    let mut keripy = Keripy::new()?;
    let (first, first_url) = witness(&mut keripy, "wan").await?;
    let (second, second_url) = witness(&mut keripy, "wil").await?;

    let controller = controller(&keripy, (&first, &first_url), (&second, &second_url)).await?;
    let controller_prefix = IdentifierPrefix::from_qb64(&controller)?;

    let (watcher, url, server) = serve_watcher(&keripy).await?;
    let us = watcher.identity().prefix().qb64()?;

    // The controller learns the watcher, and an OOBI for itself to hand the watcher.
    let oobi = format!("{url}/oobi/{us}/controller");
    keripy
        .run(&[
            "oobi",
            "resolve",
            "--name",
            "ctl",
            "--oobi-alias",
            "watcher",
            "--oobi",
            &oobi,
        ])
        .await?;
    let own = format!("{first_url}oobi/{controller}/witness/{first}");
    keripy
        .run(&[
            "oobi",
            "resolve",
            "--name",
            "ctl",
            "--oobi-alias",
            "ctl",
            "--oobi",
            &own,
        ])
        .await?;
    keripy
        .run(&[
            "watcher",
            "add",
            "--name",
            "ctl",
            "--alias",
            "ctl",
            "--watcher",
            "watcher",
            "--watched",
            &controller,
        ])
        .await?;
    assert_eq!(watcher.observed()?, vec![controller_prefix.clone()]);
    assert_eq!(
        watcher.witnessed(&controller_prefix)?.map(|held| held.sequence_number),
        Some(0)
    );

    let client = HttpClient::new()?;
    let mut resolver = Resolver::new(Arc::clone(&watcher), client.clone(), TIMEOUT);
    let resolutions = resolver.round(Duration::ZERO).await?;
    assert!(
        matches!(resolutions.as_slice(), [(url, Resolution::Resolved(_))] if *url == own),
        "{resolutions:?}"
    );

    let observer = Observer::new(Arc::clone(&watcher), client, TIMEOUT);
    let mut poller = Poller::new(Arc::clone(&watcher), observer, PollPolicy::new(Duration::from_secs(1)));
    assert_eq!(
        poller.round(Duration::ZERO).await?,
        vec![(controller_prefix.clone(), Observation::UpToDate { sequence_number: 0 })]
    );
    keripy.run(&["interact", "--name", "ctl", "--alias", "ctl"]).await?;
    assert_eq!(
        poller.round(Duration::from_secs(2)).await?,
        vec![(controller_prefix, Observation::Updated { from: 0, to: 1 })]
    );
    server.abort();
    Ok(())
}

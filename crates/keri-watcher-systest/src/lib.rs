//! Opt-in system tests of the watcher against keripy: its `kli`, and witnesses `kli` starts.
//!
//! Every other test in this workspace runs on messages built in Rust. These drive keripy itself,
//! so they prove what the others cannot: that a keripy controller can resolve the watcher's OOBI
//! and register with it through `kli watcher add`, and that the watcher keeps up with a log its
//! keripy witnesses serve. They record nothing; a run is an acceptance check, not a fixture source.
//!
//! # Staying out of the default suite
//!
//! Every test that runs `kli` carries `#[ignore]`, and lives in a `tests/live_*.rs` file;
//! `tests/guard.rs`, which is not ignored, reads those files and fails if a test in them is not
//! ignored. Ignored tests are still compiled, so `cargo clippy --all-targets` keeps them building.
//!
//! # Running them
//!
//! They need keripy's `kli`, named by `KERI_WATCHER_KLI` or found on the `PATH`, and on macOS the
//! libsodium keripy loads, through `DYLD_FALLBACK_LIBRARY_PATH`:
//!
//! ```text
//! KERI_WATCHER_KLI=/path/to/venv/bin/kli DYLD_FALLBACK_LIBRARY_PATH=/opt/homebrew/lib \
//!     cargo test -p keri-watcher-systest -- --ignored --test-threads=1
//! ```
//!
//! [`Keripy`] runs each `kli` command with `HOME` set to a directory of its own and a `--base` of
//! its own, every keystore under [`PASSCODE`], so the keystores it creates never meet another keripy's, and stops the witnesses it
//! started and removes the directory when dropped. Witnesses listen on ports the system hands
//! out, on `127.0.0.1` only. `--test-threads=1` keeps two runs from starting `kli` at once, which
//! keripy's own scripts never do either.

use std::error::Error;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

/// Why a step of a run failed.
pub type Failure = Box<dyn Error + Send + Sync>;

static RUNS: AtomicU32 = AtomicU32::new(0);

/// The passcode every keystore of a run is encrypted with: `kli witness start` refuses a keystore
/// without one.
pub const PASSCODE: &str = "0123456789abcdefghijk";

/// A keripy installation to run `kli` with, isolated in a directory of its own.
#[derive(Debug)]
pub struct Keripy {
    kli: PathBuf,
    home: PathBuf,
    base: String,
    witnesses: Vec<Child>,
}

impl Keripy {
    /// Prepares a directory for a run's keystores, with `kli` from `KERI_WATCHER_KLI`, or the
    /// `PATH`.
    ///
    /// # Errors
    ///
    /// Returns the failure when the directory cannot be created.
    pub fn new() -> Result<Self, Failure> {
        let kli = std::env::var_os("KERI_WATCHER_KLI").map_or_else(|| PathBuf::from("kli"), PathBuf::from);
        let run = RUNS.fetch_add(1, Ordering::Relaxed);
        let base = format!("keri-watcher-systest-{}-{run}", std::process::id());
        let home = std::env::temp_dir().join(&base);
        std::fs::create_dir_all(home.join("cf").join("keri").join("cf"))?;
        Ok(Self {
            kli,
            home,
            base,
            witnesses: Vec::new(),
        })
    }

    /// Returns the directory `kli` reads configuration files from, through `--config-dir`.
    #[must_use]
    pub fn config_dir(&self) -> PathBuf {
        self.home.join("cf")
    }

    /// Writes a configuration file `kli` finds as `--config-file {name}`.
    ///
    /// # Errors
    ///
    /// Returns the failure when the file cannot be written.
    pub fn write_config(&self, name: &str, json: &str) -> Result<(), Failure> {
        std::fs::write(
            self.config_dir().join("keri").join("cf").join(format!("{name}.json")),
            json,
        )?;
        Ok(())
    }

    /// Writes a file in the run's directory, returning its path.
    ///
    /// # Errors
    ///
    /// Returns the failure when the file cannot be written.
    pub fn write_file(&self, name: &str, contents: &str) -> Result<PathBuf, Failure> {
        let path = self.home.join(name);
        std::fs::write(&path, contents)?;
        Ok(path)
    }

    fn command(&self, arguments: &[&str]) -> Command {
        let mut command = Command::new(&self.kli);
        command.args(arguments).env("HOME", &self.home);
        // Commands acting on a keystore take its base and passcode; `kli` refuses them elsewhere.
        if arguments.contains(&"--name") {
            command.args(["--base", &self.base, "--passcode", PASSCODE]);
        }
        command
    }

    /// Runs `kli` with these arguments, returning what it printed.
    ///
    /// # Errors
    ///
    /// Returns the failure when `kli` cannot be started or exits unsuccessfully, with what it
    /// printed.
    pub async fn run(&self, arguments: &[&str]) -> Result<String, Failure> {
        let mut command = self.command(arguments);
        let line = arguments.join(" ");
        let output = tokio::task::spawn_blocking(move || command.output()).await??;
        let printed = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        if !output.status.success() || printed.contains("ERR:") {
            return Err(format!("kli {line} failed: {printed}").into());
        }
        Ok(printed)
    }

    /// Starts `kli witness start` with these arguments, kept running until the run is dropped.
    ///
    /// # Errors
    ///
    /// Returns the failure when `kli` cannot be started.
    pub fn start_witness(&mut self, arguments: &[&str]) -> Result<(), Failure> {
        let log = std::fs::File::create(self.home.join(format!("witness-{}.log", self.witnesses.len())))?;
        let mut all = vec!["witness", "start"];
        all.extend_from_slice(arguments);
        let child = self
            .command(&all)
            .stdout(Stdio::from(log.try_clone()?))
            .stderr(Stdio::from(log))
            .spawn()?;
        self.witnesses.push(child);
        Ok(())
    }

    /// Returns the identifier `kli status` gives for `name`'s identifier `alias`.
    ///
    /// # Errors
    ///
    /// Returns the failure when `kli status` fails or names no identifier.
    pub async fn identifier(&self, name: &str, alias: &str) -> Result<String, Failure> {
        let status = self.run(&["status", "--name", name, "--alias", alias]).await?;
        status
            .lines()
            .find_map(|line| line.trim().strip_prefix("Identifier:"))
            .map(|identifier| identifier.trim().to_owned())
            .ok_or_else(|| format!("kli status names no identifier: {status}").into())
    }

    /// Returns the run's directory.
    #[must_use]
    pub fn home(&self) -> &Path {
        &self.home
    }
}

impl Drop for Keripy {
    fn drop(&mut self) {
        for witness in &mut self.witnesses {
            let _ = witness.kill();
            let _ = witness.wait();
        }
        let _ = std::fs::remove_dir_all(&self.home);
    }
}

/// Returns a port on `127.0.0.1` the system has just handed out, free once returned.
///
/// # Errors
///
/// Returns the failure when no port can be bound.
pub fn free_port() -> Result<u16, Failure> {
    Ok(TcpListener::bind("127.0.0.1:0")?.local_addr()?.port())
}

/// Waits until something accepts connections on `port` of `127.0.0.1`, for at most `limit`.
///
/// # Errors
///
/// Returns the failure when nothing does in time.
pub async fn listening(port: u16, limit: Duration) -> Result<(), Failure> {
    let deadline = tokio::time::Instant::now() + limit;
    while tokio::net::TcpStream::connect(("127.0.0.1", port)).await.is_err() {
        if tokio::time::Instant::now() >= deadline {
            return Err(format!("nothing listens on port {port}").into());
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    Ok(())
}

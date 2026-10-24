//! The watcher's identity: a non-transferable key, derived from a salt kept in a file.
//!
//! On first start the salt is generated and written to a new file, readable only by its owner on
//! Unix; afterwards it is read back, so the watcher keeps its identifier across restarts. The
//! identifier is the key's own, as for keripy's watchers and witnesses.

use std::io::Write;
use std::path::Path;

use keri_cesr::crypto::salt::{Salt, SecurityTier};
use keri_cesr::crypto::signer::Signer;
use keri_cesr::crypto::verifier::KeyTransferability;
use keri_protocol::attachment::ReceiptCouple;
use keri_protocol::prefix::IdentifierPrefix;

use crate::error::WatcherError;

/// The path the key is derived at from the salt.
const DERIVATION_PATH: &str = "watcher";

/// The watcher's key and identifier.
#[derive(Debug)]
pub struct Identity {
    signer: Signer,
    prefix: IdentifierPrefix,
}

impl Identity {
    /// Takes a non-transferable key as the watcher's.
    ///
    /// # Errors
    ///
    /// Returns [`WatcherError::Key`] or [`WatcherError::Prefix`] when the key's identifier cannot
    /// be written.
    pub fn from_signer(signer: Signer) -> Result<Self, WatcherError> {
        let qb64 = signer
            .verifier()
            .qb64()
            .map_err(|source| WatcherError::Key { source })?;
        let prefix = IdentifierPrefix::from_qb64(&qb64).map_err(|source| WatcherError::Prefix { source })?;
        Ok(Self { signer, prefix })
    }

    /// Reads the salt from `path`, or generates one and writes it there when the file does not
    /// exist, and derives the key from it.
    ///
    /// # Errors
    ///
    /// Returns [`WatcherError::File`] when the file cannot be read or written, and
    /// [`WatcherError::Key`] when it does not hold a valid salt or the key cannot be derived.
    pub fn load_or_create(path: &Path) -> Result<Self, WatcherError> {
        let file = |source| WatcherError::File {
            path: path.to_path_buf(),
            source,
        };
        let key = |source| WatcherError::Key { source };
        let salt = match std::fs::read_to_string(path) {
            Ok(text) => Salt::from_qb64(text.trim(), SecurityTier::Low).map_err(key)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let salt = Salt::generate(SecurityTier::Low).map_err(key)?;
                let qb64 = salt.expose_qb64().map_err(key)?;
                let mut created = new_private_file(path).map_err(file)?;
                created.write_all(qb64.as_bytes()).map_err(file)?;
                created.sync_all().map_err(file)?;
                salt
            }
            Err(error) => return Err(file(error)),
        };
        Self::from_signer(
            salt.derive_signer(DERIVATION_PATH, KeyTransferability::NonTransferable)
                .map_err(key)?,
        )
    }

    /// Returns the watcher's identifier.
    #[must_use]
    pub const fn prefix(&self) -> &IdentifierPrefix {
        &self.prefix
    }

    /// Signs `serialization`, as a couple of the watcher's key and its signature.
    pub(crate) fn sign(&self, serialization: &[u8]) -> Result<ReceiptCouple, WatcherError> {
        let signature = self
            .signer
            .sign_unindexed(serialization)
            .map_err(|source| WatcherError::Key { source })?;
        Ok(ReceiptCouple::new(self.signer.verifier().clone(), signature)?)
    }
}

#[cfg(unix)]
fn new_private_file(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
fn new_private_file(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new().write(true).create_new(true).open(path)
}

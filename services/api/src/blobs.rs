//! Attachment bytes on disk. The relay stores ciphertext it holds no key for — see
//! `core/mls-core/src/attachment.rs` for what the client did to it and why the server cannot read
//! it. Authorization and retention metadata live in Postgres (`attachments`, migration V26); this
//! module only moves opaque bytes.
//!
//! **Filesystem, deliberately, for now.** `ARCHITECTURE.md` says object storage, and a multi-node
//! deployment needs it (two API instances do not share a disk). This trait is the seam: `FsBlobStore`
//! is a single-node/self-host implementation, and an S3 implementation drops in behind it without
//! touching a handler — the same shape `PushTransport` and `RangeProvider` already use. Until that
//! exists, `docs/HOSTING.md` must not claim object storage is in place.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

/// Opaque ciphertext keyed by a 16-byte id.
pub trait BlobStore: Send + Sync {
    fn put(&self, id: &[u8; 16], bytes: &[u8]) -> io::Result<()>;
    /// `Ok(None)` when the object is not there (swept, or never written).
    fn get(&self, id: &[u8; 16]) -> io::Result<Option<Vec<u8>>>;
    fn delete(&self, id: &[u8; 16]) -> io::Result<()>;
    /// Remove objects last modified before `now - ttl`, returning how many went.
    ///
    /// This sweeps the STORE, not the table, on purpose: a conversation deleted through the
    /// `attachments` cascade takes its rows with it and would otherwise leave files nobody can
    /// reach and nothing would ever collect. Sweeping by age catches those too.
    fn sweep_older_than(&self, ttl: Duration) -> io::Result<u64>;
}

/// One file per blob under `root`, named by the hex id.
pub struct FsBlobStore {
    root: PathBuf,
}

impl FsBlobStore {
    /// Creates the directory if needed. `NEDWONS_BLOB_DIR` selects it; unset disables attachments.
    pub fn new(root: impl Into<PathBuf>) -> io::Result<Self> {
        let root = root.into();
        fs::create_dir_all(&root)?;
        Ok(Self { root })
    }

    pub fn from_env() -> Option<Self> {
        let dir = std::env::var("NEDWONS_BLOB_DIR").ok()?;
        match Self::new(&dir) {
            Ok(store) => {
                tracing::info!("attachment blob store: {dir}");
                Some(store)
            }
            Err(e) => {
                // Fail loudly but do not take the server down: every other feature still works,
                // and uploads answer 503 rather than writing somewhere unintended.
                tracing::error!("attachment blob store unavailable ({dir}): {e}");
                None
            }
        }
    }

    fn path(&self, id: &[u8; 16]) -> PathBuf {
        let mut name = String::with_capacity(32);
        for b in id {
            use std::fmt::Write;
            let _ = write!(name, "{b:02x}");
        }
        self.root.join(name)
    }
}

impl BlobStore for FsBlobStore {
    /// Temp file + rename, so a crash mid-write can never leave a truncated object that would then
    /// fail to decrypt with no way to tell why.
    fn put(&self, id: &[u8; 16], bytes: &[u8]) -> io::Result<()> {
        let final_path = self.path(id);
        let tmp = final_path.with_extension("tmp");
        {
            use std::io::Write;
            let mut file = fs::File::create(&tmp)?;
            file.write_all(bytes)?;
            file.sync_all()?;
        }
        fs::rename(&tmp, &final_path)
    }

    fn get(&self, id: &[u8; 16]) -> io::Result<Option<Vec<u8>>> {
        match fs::read(self.path(id)) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn delete(&self, id: &[u8; 16]) -> io::Result<()> {
        match fs::remove_file(self.path(id)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }

    fn sweep_older_than(&self, ttl: Duration) -> io::Result<u64> {
        let cutoff = SystemTime::now()
            .checked_sub(ttl)
            .unwrap_or(SystemTime::UNIX_EPOCH);
        let mut removed = 0;
        for entry in fs::read_dir(&self.root)? {
            let entry = entry?;
            let path = entry.path();
            if !is_blob_file(&path) {
                continue;
            }
            let modified = entry.metadata().and_then(|m| m.modified());
            if matches!(modified, Ok(t) if t < cutoff) && fs::remove_file(&path).is_ok() {
                removed += 1;
            }
        }
        Ok(removed)
    }
}

/// Only files this store wrote: 32 hex characters, no extension. Anything else in the directory —
/// including a `.tmp` from an interrupted write — is left alone rather than deleted blindly.
fn is_blob_file(path: &Path) -> bool {
    path.file_name()
        .and_then(|n| n.to_str())
        .map(|n| n.len() == 32 && n.bytes().all(|b| b.is_ascii_hexdigit()))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (FsBlobStore, PathBuf) {
        let dir = std::env::temp_dir().join(format!("nedwons-blobs-{}", uuid()));
        (FsBlobStore::new(&dir).expect("store"), dir)
    }

    fn uuid() -> String {
        let n = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        format!("{n:x}")
    }

    #[test]
    fn round_trips_and_deletes() {
        let (store, dir) = store();
        let id = [1u8; 16];
        assert!(
            store.get(&id).expect("get").is_none(),
            "absent reads as None"
        );
        store.put(&id, b"ciphertext").expect("put");
        assert_eq!(
            store.get(&id).expect("get").as_deref(),
            Some(b"ciphertext".as_slice())
        );
        store.delete(&id).expect("delete");
        assert!(store.get(&id).expect("get").is_none());
        store.delete(&id).expect("deleting twice is fine");
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn sweeps_only_old_blob_files() {
        let (store, dir) = store();
        store.put(&[2u8; 16], b"fresh").expect("put");
        fs::write(dir.join("not-a-blob.txt"), b"leave me").expect("write");
        // Nothing is old enough yet.
        assert_eq!(
            store
                .sweep_older_than(Duration::from_secs(3600))
                .expect("sweep"),
            0
        );
        // With a zero TTL everything qualifies — except the file that is not ours.
        assert_eq!(store.sweep_older_than(Duration::ZERO).expect("sweep"), 1);
        assert!(
            dir.join("not-a-blob.txt").exists(),
            "foreign files are untouched"
        );
        let _ = fs::remove_dir_all(dir);
    }
}

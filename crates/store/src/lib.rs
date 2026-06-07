//! Profile store: secret-free metadata on disk, the link in a `SecureStore`.
//!
//! A profile is split across two backings so the bearer credential (the link)
//! never lands in a plaintext file:
//!
//! - the link itself — a [`profile::Profile`] (server, auth, TLS, obfs) — is
//!   serialized to JSON and handed to the native [`SecureStore`], keyed by the
//!   profile's id;
//! - the non-secret [`Entry`] metadata (`id`, `name`, `created_at`) is persisted
//!   as one schema-versioned JSON document, written atomically (temp + rename)
//!   to a container path.
//!
//! [`Store::list`] yields the secret-free metadata the app shows in its profile
//! list; the link is read back only on demand via [`Store::load`] (to connect or
//! to share). This crate depends on `profile` alone — not the `config` URI parser
//! — so the privileged tunnel extension can link it without pulling in
//! untrusted-input parsing; callers hand it an already-parsed [`profile::Profile`].

use std::fs;
use std::io;
use std::io::Write as _;
use std::path::Path;
use std::path::PathBuf;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use profile::Profile;
use rand::Rng as _;
use serde::Deserialize;
use serde::Serialize;
use tempfile::NamedTempFile;
use uuid::Builder;

/// The bytes of a stored secret: a [`profile::Profile`] serialized to JSON,
/// opaque to the [`SecureStore`] backend.
pub type SecretBytes = Vec<u8>;

/// The on-disk metadata document format version. Bump on a breaking change and
/// add a migration; an unrecognized (higher) version is refused rather than
/// silently truncated.
const SCHEMA_VERSION: u32 = 1;

/// Native secret storage (Keychain / Keystore / DPAPI), keyed by profile id.
///
/// Secrets cross as byte buffers, not C strings. Implemented natively in the app
/// on each platform and passed to [`Store::new`]; the privileged tunnel
/// extension links a read-only view and calls only [`get`](SecureStore::get).
pub trait SecureStore {
    /// The secret bytes for `id`, or `None` if there is no such entry.
    ///
    /// # Errors
    /// Backend failure (locked device, IPC error).
    fn get(&self, id: &str) -> Result<Option<SecretBytes>, SecureStoreError>;

    /// Store (or overwrite) the secret bytes for `id`.
    ///
    /// # Errors
    /// Backend failure.
    fn set(&self, id: &str, secret: &[u8]) -> Result<(), SecureStoreError>;

    /// Remove the secret for `id`; succeeds whether or not it existed.
    ///
    /// # Errors
    /// Backend failure.
    fn delete(&self, id: &str) -> Result<(), SecureStoreError>;
}

/// An opaque, secret-free failure from a [`SecureStore`] backend. It carries a
/// short message for diagnostics and never the secret itself.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("secure store error: {message}")]
pub struct SecureStoreError {
    message: String,
}

impl SecureStoreError {
    /// Wrap a backend failure description.
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

/// Failures from [`Store`] operations.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// Reading or writing the metadata document failed.
    #[error("could not read or write the profile store: {0}")]
    Io(#[from] io::Error),
    /// (De)serializing the metadata document or a profile failed.
    #[error("the profile store data could not be parsed: {0}")]
    Serde(#[from] serde_json::Error),
    /// The [`SecureStore`] backend failed.
    #[error("{0}")]
    Secure(#[from] SecureStoreError),
    /// The system clock is before the Unix epoch (`created_at` cannot be set).
    #[error("the system clock is set before 1970; fix the clock")]
    Clock,
    /// The metadata document is a newer schema than this build understands.
    #[error(
        "the profile store is version {0}, newer than this app supports ({supported}); \
         update the app to open it",
        supported = SCHEMA_VERSION
    )]
    UnsupportedSchema(u32),
}

/// Secret-free metadata for one stored profile. The link itself lives in the
/// [`SecureStore`] and is read on demand with [`Store::load`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    /// Stable identifier (a v4 UUID), the [`SecureStore`] key.
    pub id: String,
    /// Display name: the link's `#fragment` when the caller supplies one, else
    /// the server host.
    pub name: String,
    /// Creation time, Unix seconds.
    pub created_at: u64,
}

/// The on-disk document: a schema version plus the ordered metadata list. Holds
/// no secret.
#[derive(Debug, Serialize, Deserialize)]
struct Document {
    schema_version: u32,
    entries: Vec<Entry>,
}

/// The profile store over a metadata document path plus a [`SecureStore`].
pub struct Store<S: SecureStore> {
    doc_path: PathBuf,
    secure: S,
    entries: Vec<Entry>,
}

impl<S: SecureStore> Store<S> {
    /// Open the store at `doc_path`, loading existing metadata if the document
    /// exists (an absent document is an empty store).
    ///
    /// # Errors
    /// I/O or deserialization failure, or a newer-than-supported schema.
    pub fn new(doc_path: impl Into<PathBuf>, secure: S) -> Result<Self, StoreError> {
        let doc_path = doc_path.into();
        let entries = match fs::read(&doc_path) {
            Ok(bytes) => {
                let doc: Document = serde_json::from_slice(&bytes)?;
                if doc.schema_version > SCHEMA_VERSION {
                    return Err(StoreError::UnsupportedSchema(doc.schema_version));
                }
                doc.entries
            },
            Err(e) if e.kind() == io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(e.into()),
        };
        Ok(Self {
            doc_path,
            secure,
            entries,
        })
    }

    /// The stored metadata, in insertion order. Secret-free.
    #[must_use]
    pub fn list(&self) -> &[Entry] {
        &self.entries
    }

    /// Add `link`, returning its [`Entry`]. `name` is the caller-supplied label
    /// (the link's `#fragment`); when `None`/empty the host is used.
    ///
    /// Adds are idempotent by profile identity: an existing entry whose stored
    /// link equals `link` is returned unchanged rather than duplicated.
    ///
    /// # Errors
    /// Clock, [`SecureStore`], or persistence failure.
    pub fn add(&mut self, link: &Profile, name: Option<&str>) -> Result<Entry, StoreError> {
        if let Some(existing) = self.find_matching(link)? {
            return Ok(existing);
        }

        let id = new_uuid_v4();
        let name = match name.map(str::trim).filter(|s| !s.is_empty()) {
            Some(n) => n.to_string(),
            None => host_of(&link.server).to_string(),
        };
        let created_at = now_unix_secs()?;

        // Write the secret first: a half-written add then leaves an orphaned
        // secret (overwritten on retry) rather than a metadata entry whose link
        // cannot be loaded.
        let secret = serde_json::to_vec(link)?;
        self.secure.set(&id, &secret)?;

        let entry = Entry {
            id,
            name,
            created_at,
        };
        self.entries.push(entry.clone());
        if let Err(e) = self.persist() {
            // Roll back so memory and the secure store match the failed doc.
            self.entries.pop();
            let _ = self.secure.delete(&entry.id);
            return Err(e);
        }
        Ok(entry)
    }

    /// Delete the entry `id` and its secret. Returns whether an entry was
    /// present. The secret is removed even if no metadata entry exists.
    ///
    /// # Errors
    /// [`SecureStore`] or persistence failure.
    pub fn delete(&mut self, id: &str) -> Result<bool, StoreError> {
        let Some(pos) = self.entries.iter().position(|e| e.id == id) else {
            // No metadata, but clear any stray secret defensively.
            self.secure.delete(id)?;
            return Ok(false);
        };
        let removed = self.entries.remove(pos);
        if let Err(e) = self.persist() {
            self.entries.insert(pos, removed);
            return Err(e);
        }
        self.secure.delete(id)?;
        Ok(true)
    }

    /// Rename the entry `id` to `new_name`, returning whether it was present.
    ///
    /// Only the display name changes: the stored link (the secret) is untouched,
    /// since the connection credential has not changed — rename rewrites the
    /// metadata document alone. A blank `new_name` resets the name to the server
    /// host (as [`add`](Self::add) does). When the profile is later shared, its
    /// link's `#fragment` reflects the new name (`config::to_uri_with_name`).
    ///
    /// # Errors
    /// [`SecureStore`] (only on the blank-name host fallback) or persistence
    /// failure.
    pub fn rename(&mut self, id: &str, new_name: &str) -> Result<bool, StoreError> {
        let Some(pos) = self.entries.iter().position(|e| e.id == id) else {
            return Ok(false);
        };
        let name = match new_name.trim() {
            "" => match self.load(id)? {
                Some(profile) => host_of(&profile.server).to_string(),
                // No stored secret to derive a host from: leave the name as is.
                None => return Ok(true),
            },
            trimmed => trimmed.to_string(),
        };
        let previous = std::mem::replace(&mut self.entries[pos].name, name);
        if let Err(e) = self.persist() {
            self.entries[pos].name = previous;
            return Err(e);
        }
        Ok(true)
    }

    /// Read the link for `id` from the [`SecureStore`], or `None` if there is no
    /// stored secret. The single secret-reading path (connect and share).
    ///
    /// # Errors
    /// [`SecureStore`] or deserialization failure.
    pub fn load(&self, id: &str) -> Result<Option<Profile>, StoreError> {
        match self.secure.get(id)? {
            Some(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
            None => Ok(None),
        }
    }

    /// Find an existing entry whose stored link equals `link` (dedup key).
    fn find_matching(&self, link: &Profile) -> Result<Option<Entry>, StoreError> {
        for entry in &self.entries {
            if self.load(&entry.id)?.as_ref() == Some(link) {
                return Ok(Some(entry.clone()));
            }
        }
        Ok(None)
    }

    /// Write the metadata document atomically: write a sibling temp file via
    /// `tempfile`, then rename it over the target (atomic on the same
    /// filesystem). The temp file gets a unique, `O_EXCL` name in the same
    /// directory, so concurrent writers and symlink races are not a concern.
    fn persist(&self) -> Result<(), StoreError> {
        let parent = self.doc_path.parent().unwrap_or(Path::new("."));
        fs::create_dir_all(parent)?;
        let doc = Document {
            schema_version: SCHEMA_VERSION,
            entries: self.entries.clone(),
        };
        let bytes = serde_json::to_vec_pretty(&doc)?;
        let mut tmp = NamedTempFile::new_in(parent)?;
        tmp.write_all(&bytes)?;
        tmp.persist(&self.doc_path)
            .map_err(|e| StoreError::Io(e.error))?;
        Ok(())
    }
}

/// A fresh random v4 UUID, lowercase hyphenated. `uuid` sets the version/variant
/// bits and formats; the 16 random bytes come from `rand` (already in the tree),
/// so no separate `getrandom` is pulled in.
fn new_uuid_v4() -> String {
    let bytes: [u8; 16] = rand::rng().random();
    Builder::from_random_bytes(bytes).into_uuid().to_string()
}

/// Now as Unix seconds.
fn now_unix_secs() -> Result<u64, StoreError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| StoreError::Clock)
}

/// The host portion of a `hysteria2://` server spec (`host`, `host:port`, or
/// `host:port-range[,port…]`), for the fallback display name. Handles a
/// bracketed IPv6 literal; otherwise the port spec follows the last colon.
fn host_of(server: &str) -> &str {
    let s = server.trim();
    if let Some(rest) = s.strip_prefix('[')
        && let Some(end) = rest.find(']')
    {
        return &rest[..end];
    }
    match s.rsplit_once(':') {
        Some((host, _port)) if !host.is_empty() => host,
        _ => s,
    }
}

/// An in-memory, plaintext [`SecureStore`] for dev binaries and tests. Gated
/// behind the `dev-stub` feature (and available in this crate's own tests) so it
/// can never link into a shipped binary.
#[cfg(any(test, feature = "dev-stub"))]
type SecretMap = std::collections::HashMap<String, Vec<u8>>;

#[cfg(any(test, feature = "dev-stub"))]
#[derive(Default)]
pub struct DevSecureStore {
    map: std::sync::Mutex<SecretMap>,
}

#[cfg(any(test, feature = "dev-stub"))]
impl DevSecureStore {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, SecretMap>, SecureStoreError> {
        self.map
            .lock()
            .map_err(|_| SecureStoreError::new("dev secure store mutex poisoned"))
    }
}

#[cfg(any(test, feature = "dev-stub"))]
impl SecureStore for DevSecureStore {
    fn get(&self, id: &str) -> Result<Option<SecretBytes>, SecureStoreError> {
        Ok(self.lock()?.get(id).cloned())
    }

    fn set(&self, id: &str, secret: &[u8]) -> Result<(), SecureStoreError> {
        self.lock()?.insert(id.to_string(), secret.to_vec());
        Ok(())
    }

    fn delete(&self, id: &str) -> Result<(), SecureStoreError> {
        self.lock()?.remove(id);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::*;

    fn sample(server: &str, auth: &str) -> Profile {
        Profile {
            server: server.to_string(),
            auth: auth.to_string(),
            ..Profile::default()
        }
    }

    /// A fresh temp dir (auto-removed on drop) plus the doc path inside it. The
    /// caller binds the dir so it outlives the test.
    fn temp_doc() -> anyhow::Result<(tempfile::TempDir, PathBuf)> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("profiles.json");
        Ok((dir, path))
    }

    #[test]
    fn add_then_list_and_load_round_trips() -> anyhow::Result<()> {
        let (_dir, path) = temp_doc()?;
        let mut store = Store::new(&path, DevSecureStore::new())?;
        let link = sample("example.com:443", "secret-token");

        let entry = store.add(&link, Some("Home"))?;
        assert_eq!(entry.name, "Home", "explicit name is used");
        assert_eq!(store.list().len(), 1, "one entry listed");
        assert_eq!(store.list()[0], entry, "listed entry matches");

        let loaded = store.load(&entry.id)?;
        assert_eq!(loaded.as_ref(), Some(&link), "link round-trips via load");
        Ok(())
    }

    #[test]
    fn name_falls_back_to_host() -> anyhow::Result<()> {
        let (_dir, path) = temp_doc()?;
        let mut store = Store::new(&path, DevSecureStore::new())?;
        let entry = store.add(&sample("vpn.example.com:7000-8000,9000", ""), None)?;
        assert_eq!(
            entry.name, "vpn.example.com",
            "host is derived from the server spec, port spec stripped"
        );
        Ok(())
    }

    #[test]
    fn add_is_idempotent_by_profile() -> anyhow::Result<()> {
        let (_dir, path) = temp_doc()?;
        let mut store = Store::new(&path, DevSecureStore::new())?;
        let link = sample("example.com:443", "tok");

        let first = store.add(&link, Some("A"))?;
        let second = store.add(&link, Some("B"))?;
        assert_eq!(
            first, second,
            "re-adding the same link returns the same entry"
        );
        assert_eq!(store.list().len(), 1, "no duplicate is created");

        // A different auth is a distinct profile.
        store.add(&sample("example.com:443", "other"), None)?;
        assert_eq!(store.list().len(), 2, "differing auth is a separate entry");
        Ok(())
    }

    #[test]
    fn delete_removes_metadata_and_secret() -> anyhow::Result<()> {
        let (_dir, path) = temp_doc()?;
        let mut store = Store::new(&path, DevSecureStore::new())?;
        let entry = store.add(&sample("example.com:443", "tok"), None)?;

        assert!(
            store.delete(&entry.id)?,
            "delete reports the entry was present"
        );
        assert!(store.list().is_empty(), "metadata is gone");
        assert_eq!(store.load(&entry.id)?, None, "secret is gone");
        assert!(!store.delete(&entry.id)?, "deleting again reports absent");
        Ok(())
    }

    #[test]
    fn rename_changes_only_the_name_not_the_secret() -> anyhow::Result<()> {
        let (_dir, path) = temp_doc()?;
        let mut store = Store::new(&path, DevSecureStore::new())?;
        let link = sample("example.com:443", "tok");
        let entry = store.add(&link, Some("Home"))?;

        assert!(store.rename(&entry.id, "Work")?, "rename reports present");
        assert_eq!(store.list()[0].name, "Work", "name updated");
        assert_eq!(store.list()[0].id, entry.id, "id unchanged");
        assert_eq!(
            store.list()[0].created_at,
            entry.created_at,
            "created_at unchanged"
        );
        assert_eq!(
            store.load(&entry.id)?.as_ref(),
            Some(&link),
            "the stored link (secret) is untouched by rename"
        );

        // Blank name resets to the host.
        assert!(
            store.rename(&entry.id, "   ")?,
            "blank rename still present"
        );
        assert_eq!(
            store.list()[0].name,
            "example.com",
            "a blank rename falls back to the host"
        );

        assert!(
            !store.rename("no-such-id", "X")?,
            "renaming a missing id reports absent"
        );
        Ok(())
    }

    #[test]
    fn metadata_persists_across_reopen() -> anyhow::Result<()> {
        let (_dir, path) = temp_doc()?;
        let secure = DevSecureStore::new();
        let entry = {
            let mut store = Store::new(&path, &secure)?;
            store.add(&sample("example.com:443", "tok"), Some("Home"))?
        };

        // Reopen with the same secure backend: metadata is read from disk, the
        // secret from the store.
        let reopened = Store::new(&path, &secure)?;
        assert_eq!(
            reopened.list(),
            std::slice::from_ref(&entry),
            "metadata survived reopen"
        );
        assert_eq!(
            reopened.load(&entry.id)?.map(|p| p.auth),
            Some("tok".to_string()),
            "secret still loadable after reopen"
        );
        Ok(())
    }

    #[test]
    fn doc_file_holds_no_secret() -> anyhow::Result<()> {
        let (_dir, path) = temp_doc()?;
        let mut store = Store::new(&path, DevSecureStore::new())?;
        store.add(
            &sample("example.com:443", "super-secret-token"),
            Some("Home"),
        )?;

        let on_disk = fs::read_to_string(&path)?;
        assert!(
            !on_disk.contains("super-secret-token"),
            "the metadata document must never contain the auth credential: {on_disk}"
        );
        assert!(
            on_disk.contains("\"schema_version\""),
            "the document is schema-versioned: {on_disk}"
        );
        Ok(())
    }

    #[test]
    fn newer_schema_is_refused() -> anyhow::Result<()> {
        let (_dir, path) = temp_doc()?;
        fs::write(&path, br#"{"schema_version":999,"entries":[]}"#)?;

        let outcome = Store::new(&path, DevSecureStore::new()).map(|_| ());
        assert!(
            matches!(outcome, Err(StoreError::UnsupportedSchema(999))),
            "a newer schema is refused, not truncated: {outcome:?}"
        );
        Ok(())
    }

    // `&DevSecureStore` is itself a `SecureStore`, so a borrowed backend can be
    // shared across reopened stores in tests.
    impl SecureStore for &DevSecureStore {
        fn get(&self, id: &str) -> Result<Option<SecretBytes>, SecureStoreError> {
            (**self).get(id)
        }
        fn set(&self, id: &str, secret: &[u8]) -> Result<(), SecureStoreError> {
            (**self).set(id, secret)
        }
        fn delete(&self, id: &str) -> Result<(), SecureStoreError> {
            (**self).delete(id)
        }
    }
}

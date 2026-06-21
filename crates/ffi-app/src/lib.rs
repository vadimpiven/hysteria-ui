//! `ffi-app`: the app-side `UniFFI` component, the only crate the Kotlin app
//! links. It wraps [`model::Model`] and exposes it across the C ABI as the
//! [`App`] object plus a handful of callback interfaces.
//!
//! The boundary is all proc-macro (`#[uniffi::export]`, library mode); there is
//! no UDL. Four traits are implemented in the foreign language and handed in:
//! [`SecureStore`] (Keychain/Keystore/DPAPI), [`TunnelControl`] (the OS VPN —
//! `NEVPNManager` / `VpnService` / the Windows service), [`StateObserver`]
//! (state snapshots), and [`StatsObserver`] (the separate, subscribable stats
//! channel). Everything else crosses as `UniFFI` records/enums, never ad-hoc
//! JSON.
//!
//! This crate depends only on `model` (plus the leaf `store`/`conn-error` for
//! the boundary types) — never `dataplane`/`hysteria`. The tunnel is driven
//! through the OS (§4 of `PLAN.md`).

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::PoisonError;

use store::Store;

uniffi::setup_scaffolding!();

// ---- Value types crossing the boundary ----

/// The OS-derived connection state (mirrors [`model::ConnectionState`]).
#[derive(uniffi::Enum)]
pub enum ConnectionState {
    /// No tunnel is up.
    Disconnected,
    /// The OS reports the tunnel is coming up.
    Connecting,
    /// The tunnel is up.
    Connected,
    /// The OS reports the tunnel is tearing down.
    Disconnecting,
}

/// Secret-free profile metadata (mirrors `store::Entry`).
#[derive(uniffi::Record)]
pub struct ProfileEntry {
    /// The profile id (a v4 UUID), the [`SecureStore`] key.
    pub id: String,
    /// The display name.
    pub name: String,
    /// Creation time, Unix seconds.
    pub created_at: u64,
}

/// A discrete, secret-free state snapshot (mirrors [`model::Snapshot`]).
#[derive(uniffi::Record)]
pub struct Snapshot {
    /// The snapshot schema version (see [`model::SCHEMA_VERSION`]).
    pub schema_version: u32,
    /// The stored profiles.
    pub profiles: Vec<ProfileEntry>,
    /// The selected profile's id, if any.
    pub selected_id: Option<String>,
    /// The OS-derived connection state.
    pub connection: ConnectionState,
    /// One actionable, secret-free UI sentence for the last error, or `None`.
    pub last_error: Option<String>,
}

/// Throttled byte counters (mirrors [`model::Stats`]).
#[derive(uniffi::Record)]
pub struct Stats {
    /// Bytes sent since the connection came up.
    pub tx_bytes: u64,
    /// Bytes received since the connection came up.
    pub rx_bytes: u64,
}

/// An error from a synchronous [`App`] call.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum AppError {
    /// The underlying store failed.
    #[error("store error: {message}")]
    Store {
        /// A secret-free description.
        message: String,
    },
    /// The Model actor has stopped.
    #[error("the app has stopped")]
    Stopped,
}

/// A secret-free failure from a [`SecureStore`] backend.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum SecureStoreError {
    /// The backend (Keychain/Keystore/DPAPI) failed.
    #[error("secure store backend failed: {message}")]
    Backend {
        /// A secret-free description.
        message: String,
    },
}

// ---- Foreign callback interfaces (implemented in Kotlin/Swift) ----

/// The OS secret store, implemented natively (Keychain / Keystore / DPAPI).
#[uniffi::export(with_foreign)]
pub trait SecureStore: Send + Sync {
    /// The secret bytes for `id`, or `None`.
    #[expect(
        clippy::type_complexity,
        reason = "FFI contract: Option<Vec<u8>> is the secret-or-absent shape UniFFI maps"
    )]
    fn get(&self, id: String) -> Result<Option<Vec<u8>>, SecureStoreError>;
    /// Store (or overwrite) the secret bytes for `id`.
    fn set(&self, id: String, secret: Vec<u8>) -> Result<(), SecureStoreError>;
    /// Remove the secret for `id` (succeeds whether or not it existed).
    fn delete(&self, id: String) -> Result<(), SecureStoreError>;
}

/// The OS VPN control, implemented natively (`NEVPNManager` / `VpnService` /
/// the Windows service). The Model asks it to start/stop and learns the result
/// only via [`App::on_os_status`] (§4) — never optimistically.
#[uniffi::export(with_foreign)]
pub trait TunnelControl: Send + Sync {
    /// Ask the OS to bring up the tunnel for `profile_id`.
    fn start(&self, profile_id: String);
    /// Ask the OS to tear the tunnel down.
    fn stop(&self);
}

/// Receives discrete state snapshots. The binding layer marshals these onto the
/// UI thread.
#[uniffi::export(with_foreign)]
pub trait StateObserver: Send + Sync {
    /// Called once at startup and after every state change.
    fn on_state(&self, snapshot: Snapshot);
}

/// Receives throttled stats — the separate channel, subscribed only while a
/// connection view is open (see [`App::subscribe_stats`]).
#[uniffi::export(with_foreign)]
pub trait StatsObserver: Send + Sync {
    /// Called for each stats update.
    fn on_stats(&self, stats: Stats);
}

// ---- Adapters: foreign traits -> `model` traits ----

/// Adapts the foreign [`SecureStore`] to `store::SecureStore` (owned args, a
/// secret-free error).
struct SecureStoreAdapter(Arc<dyn SecureStore>);

impl store::SecureStore for SecureStoreAdapter {
    fn get(&self, id: &str) -> Result<Option<Vec<u8>>, store::SecureStoreError> {
        self.0.get(id.to_string()).map_err(adapt_secure_err)
    }
    fn set(&self, id: &str, secret: &[u8]) -> Result<(), store::SecureStoreError> {
        self.0
            .set(id.to_string(), secret.to_vec())
            .map_err(adapt_secure_err)
    }
    fn delete(&self, id: &str) -> Result<(), store::SecureStoreError> {
        self.0.delete(id.to_string()).map_err(adapt_secure_err)
    }
}

fn adapt_secure_err(error: SecureStoreError) -> store::SecureStoreError {
    let SecureStoreError::Backend { message } = error;
    store::SecureStoreError::new(message)
}

/// Adapts the foreign [`TunnelControl`] to `model::TunnelControl`.
struct TunnelControlAdapter(Arc<dyn TunnelControl>);

impl model::TunnelControl for TunnelControlAdapter {
    fn start(&self, profile_id: &str) {
        self.0.start(profile_id.to_string());
    }
    fn stop(&self) {
        self.0.stop();
    }
}

/// Adapts the foreign [`StateObserver`] to `model::StateObserver`.
struct StateObserverAdapter(Arc<dyn StateObserver>);

impl model::StateObserver for StateObserverAdapter {
    fn on_state(&self, snapshot: model::Snapshot) {
        self.0.on_state(snapshot.into());
    }
}

/// The stats sink handed to the Model: forwards to the currently-subscribed
/// foreign [`StatsObserver`], if any. The shared slot is also held by [`App`]
/// so [`App::subscribe_stats`]/[`App::unsubscribe_stats`] can swap it.
type StatsSlot = Arc<Mutex<Option<Arc<dyn StatsObserver>>>>;

struct StatsGate(StatsSlot);

impl model::StatsObserver for StatsGate {
    fn on_stats(&self, stats: model::Stats) {
        // Clone the subscriber out and release the lock *before* calling it: a
        // foreign on_stats that re-enters (e.g. unsubscribe_stats) would
        // otherwise deadlock on this same non-reentrant mutex.
        let observer = lock(&self.0).as_ref().map(Arc::clone);
        if let Some(observer) = observer {
            observer.on_stats(stats.into());
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

// ---- Conversions ----

impl From<model::ConnectionState> for ConnectionState {
    fn from(state: model::ConnectionState) -> Self {
        match state {
            model::ConnectionState::Disconnected => Self::Disconnected,
            model::ConnectionState::Connecting => Self::Connecting,
            model::ConnectionState::Connected => Self::Connected,
            model::ConnectionState::Disconnecting => Self::Disconnecting,
        }
    }
}

impl From<ConnectionState> for model::ConnectionState {
    fn from(state: ConnectionState) -> Self {
        match state {
            ConnectionState::Disconnected => Self::Disconnected,
            ConnectionState::Connecting => Self::Connecting,
            ConnectionState::Connected => Self::Connected,
            ConnectionState::Disconnecting => Self::Disconnecting,
        }
    }
}

impl From<store::Entry> for ProfileEntry {
    fn from(entry: store::Entry) -> Self {
        Self {
            id: entry.id,
            name: entry.name,
            created_at: entry.created_at,
        }
    }
}

impl From<model::Snapshot> for Snapshot {
    fn from(snapshot: model::Snapshot) -> Self {
        Self {
            schema_version: snapshot.schema_version,
            profiles: snapshot.profiles.into_iter().map(Into::into).collect(),
            selected_id: snapshot.selected_id,
            connection: snapshot.connection.into(),
            last_error: snapshot.last_error,
        }
    }
}

impl From<model::Stats> for Stats {
    fn from(stats: model::Stats) -> Self {
        Self {
            tx_bytes: stats.tx_bytes,
            rx_bytes: stats.rx_bytes,
        }
    }
}

impl From<Stats> for model::Stats {
    fn from(stats: Stats) -> Self {
        Self {
            tx_bytes: stats.tx_bytes,
            rx_bytes: stats.rx_bytes,
        }
    }
}

impl From<model::ModelError> for AppError {
    fn from(error: model::ModelError) -> Self {
        match error {
            model::ModelError::Store(e) => Self::Store {
                message: e.to_string(),
            },
            model::ModelError::Stopped => Self::Stopped,
        }
    }
}

// ---- The app facade ----

/// The app-side facade over the Model. Created with [`App::new`]; all mutating
/// calls are non-blocking and results surface through the [`StateObserver`].
#[derive(uniffi::Object)]
pub struct App {
    model: model::Model,
    stats: StatsSlot,
}

#[uniffi::export]
impl App {
    /// Open the store at `container_path` and start the Model, driving the OS
    /// via `control` and reporting state to `observer`. Emits an initial
    /// snapshot at startup.
    #[uniffi::constructor]
    pub fn new(
        container_path: String,
        secure: Arc<dyn SecureStore>,
        control: Arc<dyn TunnelControl>,
        observer: Arc<dyn StateObserver>,
    ) -> Result<Arc<Self>, AppError> {
        let store = Store::new(container_path, SecureStoreAdapter(secure)).map_err(|e| {
            AppError::Store {
                message: e.to_string(),
            }
        })?;
        let stats: StatsSlot = Arc::new(Mutex::new(None));
        let model = model::Model::new(
            store,
            Box::new(TunnelControlAdapter(control)),
            Box::new(StateObserverAdapter(observer)),
            Box::new(StatsGate(Arc::clone(&stats))),
        );
        Ok(Arc::new(Self { model, stats }))
    }

    /// Add a profile from a `hysteria2://` link (the universal add path).
    pub fn add_profile_from_uri(&self, uri: String) {
        self.model.send(model::Intent::AddProfileFromUri(uri));
    }

    /// Rename a profile (metadata only; a blank name resets it to the host).
    pub fn rename_profile(&self, id: String, name: String) {
        self.model.send(model::Intent::RenameProfile { id, name });
    }

    /// Delete a profile and its secret.
    pub fn delete_profile(&self, id: String) {
        self.model.send(model::Intent::DeleteProfile(id));
    }

    /// Select a profile (the connect target).
    pub fn select_profile(&self, id: String) {
        self.model.send(model::Intent::SelectProfile(id));
    }

    /// Ask the OS to bring up the tunnel for the selected profile.
    pub fn connect(&self) {
        self.model.send(model::Intent::Connect);
    }

    /// Ask the OS to tear the tunnel down.
    pub fn disconnect(&self) {
        self.model.send(model::Intent::Disconnect);
    }

    /// Feed an OS connection-status change. `error_code` is a `conn-error` code
    /// set only on a failure (see `conn_error::ConnError`).
    pub fn on_os_status(&self, state: ConnectionState, error_code: Option<i32>) {
        let error = error_code.map(conn_error::ConnError::from_code);
        self.model.on_os_status(state.into(), error);
    }

    /// Feed a stats update from the tunnel.
    pub fn on_stats(&self, stats: Stats) {
        self.model.on_stats(stats.into());
    }

    /// Subscribe to stats while a connection view is open.
    pub fn subscribe_stats(&self, observer: Arc<dyn StatsObserver>) {
        *lock(&self.stats) = Some(observer);
    }

    /// Stop receiving stats.
    pub fn unsubscribe_stats(&self) {
        *lock(&self.stats) = None;
    }

    /// The share-view query: read the link from the secure store, re-encode it
    /// with the display name as the `#fragment`, and return it as bytes
    /// (`None` if no such profile). Never enters a snapshot (§7).
    #[expect(
        clippy::type_complexity,
        clippy::needless_pass_by_value,
        reason = "FFI contract: owned String arg, Option<Vec<u8>> return"
    )]
    pub fn export_profile_uri(&self, id: String) -> Result<Option<Vec<u8>>, AppError> {
        self.model.export_profile_uri(&id).map_err(AppError::from)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::mpsc;
    use std::sync::mpsc::Receiver;
    use std::time::Duration;

    use anyhow::Context as _;
    use anyhow::Result;
    use pretty_assertions::assert_eq;
    use tempfile::TempDir;

    use super::*;

    /// An in-memory foreign `SecureStore` for the test.
    type Secrets = Mutex<HashMap<String, Vec<u8>>>;
    #[derive(Default)]
    struct MemStore(Secrets);
    impl SecureStore for MemStore {
        fn get(&self, id: String) -> Result<Option<Vec<u8>>, SecureStoreError> {
            Ok(lock(&self.0).get(&id).cloned())
        }
        fn set(&self, id: String, secret: Vec<u8>) -> Result<(), SecureStoreError> {
            lock(&self.0).insert(id, secret);
            Ok(())
        }
        fn delete(&self, id: String) -> Result<(), SecureStoreError> {
            lock(&self.0).remove(&id);
            Ok(())
        }
    }

    struct ChannelObserver(mpsc::Sender<Snapshot>);
    impl StateObserver for ChannelObserver {
        fn on_state(&self, snapshot: Snapshot) {
            let _ = self.0.send(snapshot);
        }
    }

    struct StatsChannel(mpsc::Sender<Stats>);
    impl StatsObserver for StatsChannel {
        fn on_stats(&self, stats: Stats) {
            let _ = self.0.send(stats);
        }
    }

    struct NoControl;
    impl TunnelControl for NoControl {
        fn start(&self, _: String) {}
        fn stop(&self) {}
    }

    struct Harness {
        app: Arc<App>,
        snapshots: Receiver<Snapshot>,
        _dir: TempDir,
    }

    fn harness() -> Result<Harness> {
        let dir = TempDir::new()?;
        let (tx, snapshots) = mpsc::channel();
        let app = App::new(
            dir.path()
                .join("profiles.json")
                .to_string_lossy()
                .into_owned(),
            Arc::new(MemStore::default()),
            Arc::new(NoControl),
            Arc::new(ChannelObserver(tx)),
        )?;
        Ok(Harness {
            app,
            snapshots,
            _dir: dir,
        })
    }

    fn next(snapshots: &Receiver<Snapshot>) -> Result<Snapshot> {
        snapshots
            .recv_timeout(Duration::from_secs(5))
            .context("timed out waiting for a snapshot")
    }

    const LINK: &str = "hysteria2://token@example.com:443/?sni=example.com#Home";

    #[test]
    fn add_then_export_round_trips_through_the_ffi_surface() -> Result<()> {
        let h = harness()?;
        let initial = next(&h.snapshots)?;
        assert!(initial.profiles.is_empty(), "starts empty");
        assert_eq!(
            initial.schema_version,
            model::SCHEMA_VERSION,
            "carries schema version"
        );

        h.app.add_profile_from_uri(LINK.to_string());
        let s = next(&h.snapshots)?;
        assert_eq!(s.profiles.len(), 1, "one profile added");
        assert_eq!(s.profiles[0].name, "Home", "name from #fragment");

        let id = s.profiles[0].id.clone();
        let bytes = h.app.export_profile_uri(id)?.context("profile exists")?;
        let uri = String::from_utf8(bytes)?;
        assert!(uri.contains("#Home"), "re-encoded with name: {uri}");
        Ok(())
    }

    #[test]
    fn os_status_drives_connection_state() -> Result<()> {
        let h = harness()?;
        next(&h.snapshots)?; // initial
        h.app.on_os_status(ConnectionState::Connected, None);
        let s = next(&h.snapshots)?;
        assert!(
            matches!(s.connection, ConnectionState::Connected),
            "OS-derived state crosses the boundary"
        );
        Ok(())
    }

    #[test]
    fn subscribed_stats_reach_the_foreign_observer() -> Result<()> {
        let h = harness()?;
        next(&h.snapshots)?;

        let (tx, stats_rx) = mpsc::channel();
        h.app.subscribe_stats(Arc::new(StatsChannel(tx)));
        h.app.on_stats(Stats {
            tx_bytes: 10,
            rx_bytes: 20,
        });
        let st = stats_rx
            .recv_timeout(Duration::from_secs(5))
            .context("subscribed stats received")?;
        assert_eq!(st.tx_bytes, 10, "tx counter crosses the boundary");
        assert_eq!(st.rx_bytes, 20, "rx counter crosses the boundary");
        Ok(())
    }
}

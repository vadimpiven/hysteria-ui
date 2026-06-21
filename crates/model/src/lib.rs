//! The Model: the serialized, app-side facade of the Model–View contract.
//!
//! `model` owns the app state (the profile list, the selected profile, the
//! OS-derived connection state, and the last error sentence) and is the only
//! crate the app-side FFI (`ffi-app`) links. It depends on `config`, `store`,
//! `conn-error`, and `profile`, and **never** on `dataplane`/`hysteria`: the
//! tunnel is driven through the OS (§4 of `PLAN.md`), so the Model asks the OS
//! to start/stop via the [`TunnelControl`] port and derives [`ConnectionState`]
//! only from OS status events fed back through [`Model::on_os_status`] — never
//! optimistically.
//!
//! Concurrency: `UniFFI` calls in from arbitrary threads, so the Model is a
//! serialized actor — one thread draining a command channel. Intents
//! ([`Model::send`]) are non-blocking and return immediately; results surface
//! only through the [`StateObserver`] callback. Stats are a second, separate
//! output channel ([`StatsObserver`]) so a high-frequency byte counter never
//! forces a full state re-render.
//!
//! ```
//! use model::{Model, Intent, StateObserver, StatsObserver, TunnelControl, Snapshot, Stats};
//! use std::sync::mpsc;
//!
//! struct Obs(mpsc::Sender<Snapshot>);
//! impl StateObserver for Obs { fn on_state(&self, s: Snapshot) { let _ = self.0.send(s); } }
//! struct NoStats; impl StatsObserver for NoStats { fn on_stats(&self, _: Stats) {} }
//! struct NoTunnel; impl TunnelControl for NoTunnel { fn start(&self, _: &str) {} fn stop(&self) {} }
//!
//! let dir = tempfile::tempdir().unwrap(); // hermetic per-run store
//! let store = store::Store::new(dir.path().join("profiles.json"), store::DevSecureStore::new()).unwrap();
//! let (tx, rx) = mpsc::channel();
//! let model = Model::new(store, Box::new(NoTunnel), Box::new(Obs(tx)), Box::new(NoStats));
//! let initial = rx.recv().unwrap();
//! assert!(initial.profiles.is_empty());
//! model.send(Intent::AddProfileFromUri("hysteria2://tok@example.com:443/#Home".into()));
//! let after = rx.recv().unwrap();
//! assert_eq!(after.profiles.len(), 1);
//! ```

use std::sync::mpsc;
use std::sync::mpsc::Sender;
use std::thread;

use conn_error::ConnError;
use store::SecureStore;
use store::Store;

/// The snapshot schema version. The Model–View contract is additive-only and
/// versioned; every [`Snapshot`] carries this so the binding layer can detect a
/// mismatch.
pub const SCHEMA_VERSION: u32 = 1;

/// The OS-owned connection state, derived from OS status events (`NEVPNStatus` /
/// `VpnService` / the Windows service), never set optimistically by the Model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ConnectionState {
    /// No tunnel is up.
    #[default]
    Disconnected,
    /// The OS reports the tunnel is coming up.
    Connecting,
    /// The tunnel is up.
    Connected,
    /// The OS reports the tunnel is tearing down.
    Disconnecting,
}

/// Throttled byte counters, the second (separate) output channel. Fed from the
/// tunnel via [`Model::on_stats`] and surfaced through [`StatsObserver`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Stats {
    /// Bytes sent since the connection came up.
    pub tx_bytes: u64,
    /// Bytes received since the connection came up.
    pub rx_bytes: u64,
}

/// A discrete, secret-free state snapshot pushed to the [`StateObserver`] after
/// every state change. Carries no link/auth — the share link is fetched only
/// on demand via [`Model::export_profile_uri`] (§7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    /// See [`SCHEMA_VERSION`].
    pub schema_version: u32,
    /// The stored profiles, secret-free metadata.
    pub profiles: Vec<store::Entry>,
    /// The selected profile's id, if any. In-memory only (the OS reads the
    /// active profile itself on autoconnect; §4).
    pub selected_id: Option<String>,
    /// The OS-derived connection state.
    pub connection: ConnectionState,
    /// One actionable, secret-free UI sentence for the last error, or `None`.
    pub last_error: Option<String>,
}

/// A user intent. Non-blocking: [`Model::send`] returns immediately and the
/// result surfaces through the [`StateObserver`].
#[derive(Debug, Clone)]
pub enum Intent {
    /// Parse a `hysteria2://` link and add it (the universal add path). The
    /// link's `#fragment` becomes the display name. Selects the new profile.
    AddProfileFromUri(String),
    /// Rename a profile (metadata only; the stored link is untouched). A blank
    /// name resets it to the server host.
    RenameProfile {
        /// The profile id.
        id: String,
        /// The new display name.
        name: String,
    },
    /// Delete a profile and its secret.
    DeleteProfile(String),
    /// Select a profile (the connect target).
    SelectProfile(String),
    /// Ask the OS to bring up the tunnel for the selected profile.
    Connect,
    /// Ask the OS to tear down the tunnel.
    Disconnect,
}

/// Receives discrete state snapshots. Callbacks may arrive on the actor thread;
/// the binding layer marshals them to the UI thread.
pub trait StateObserver: Send {
    /// Called once at startup and after every state change.
    fn on_state(&self, snapshot: Snapshot);
}

/// Receives throttled stats — the separate, never-merged output channel.
pub trait StatsObserver: Send {
    /// Called for each stats update fed via [`Model::on_stats`].
    fn on_stats(&self, stats: Stats);
}

/// The outbound port to the OS tunnel. The Model never connects directly (§4);
/// it asks the OS to start/stop and waits for status to come back through
/// [`Model::on_os_status`]. The platform layer implements this
/// (`NEVPNManager` / `VpnService` / the Windows service).
pub trait TunnelControl: Send {
    /// Ask the OS to bring up the tunnel for `profile_id`.
    fn start(&self, profile_id: &str);
    /// Ask the OS to tear the tunnel down.
    fn stop(&self);
}

/// The result of the [`Model::export_profile_uri`] query: the re-encoded link
/// bytes, `None` if no such profile, or a [`ModelError`].
pub type ExportResult = Result<Option<Vec<u8>>, ModelError>;

/// A Model error surfaced from a synchronous query.
#[derive(Debug, thiserror::Error)]
pub enum ModelError {
    /// The underlying store failed.
    #[error("store error: {0}")]
    Store(#[from] store::StoreError),
    /// The actor thread has stopped (the Model was dropped).
    #[error("model actor has stopped")]
    Stopped,
}

/// Commands drained by the actor thread: user intents plus the OS/tunnel inputs
/// and the one synchronous query.
enum Command {
    Intent(Intent),
    OsStatus {
        state: ConnectionState,
        error: Option<ConnError>,
    },
    Stats(Stats),
    ExportUri {
        id: String,
        reply: Sender<ExportResult>,
    },
}

/// The actor's owned state.
#[derive(Default)]
struct State {
    entries: Vec<store::Entry>,
    selected_id: Option<String>,
    connection: ConnectionState,
    last_error: Option<String>,
}

impl State {
    fn snapshot(&self) -> Snapshot {
        Snapshot {
            schema_version: SCHEMA_VERSION,
            profiles: self.entries.clone(),
            selected_id: self.selected_id.clone(),
            connection: self.connection,
            last_error: self.last_error.clone(),
        }
    }
}

/// A handle to the serialized Model actor. Dropping it closes the command
/// channel, which stops the actor thread.
pub struct Model {
    tx: Sender<Command>,
}

impl Model {
    /// Spawn the actor over `store`, driving the OS via `control` and reporting
    /// to `view` (state snapshots) / `stats_sink` (stats). Emits an initial
    /// snapshot at startup.
    #[must_use]
    pub fn new<S: SecureStore + Send + 'static>(
        store: Store<S>,
        control: Box<dyn TunnelControl>,
        view: Box<dyn StateObserver>,
        stats_sink: Box<dyn StatsObserver>,
    ) -> Self {
        let (tx, rx) = mpsc::channel();
        // ponytail: a dedicated std thread, not a tokio task — the Model does
        // only sync fs work (store) and zero async I/O, so blocking the app's
        // single-threaded tokio runtime would be wrong. mpsc serializes it.
        thread::spawn(move || {
            run_actor(
                &rx,
                store,
                control.as_ref(),
                view.as_ref(),
                stats_sink.as_ref(),
            );
        });
        Self { tx }
    }

    /// Submit a user intent. Non-blocking; the result surfaces via the
    /// [`StateObserver`]. A no-op if the actor has stopped.
    pub fn send(&self, intent: Intent) {
        // Best-effort: a closed channel means the app is shutting down.
        let _ = self.tx.send(Command::Intent(intent));
    }

    /// Feed an OS connection-status change. `error` is set only when the OS
    /// reports a failure (e.g. on transition to disconnected). The Model derives
    /// [`ConnectionState`] solely from this (§4).
    pub fn on_os_status(&self, state: ConnectionState, error: Option<ConnError>) {
        let _ = self.tx.send(Command::OsStatus { state, error });
    }

    /// Feed a stats update from the tunnel. Forwarded to the [`StatsObserver`]
    /// without touching state.
    pub fn on_stats(&self, stats: Stats) {
        let _ = self.tx.send(Command::Stats(stats));
    }

    /// The one on-demand query (the share view): read the link from the secure
    /// store, re-encode it with the display name as the `#fragment`, and return
    /// it as bytes. Returns `Ok(None)` if no such profile exists. The URI is
    /// never placed in any snapshot (snapshots stay secret-free; §7).
    pub fn export_profile_uri(&self, id: &str) -> ExportResult {
        let (reply_tx, reply_rx) = mpsc::channel();
        self.tx
            .send(Command::ExportUri {
                id: id.to_string(),
                reply: reply_tx,
            })
            .map_err(|_| ModelError::Stopped)?;
        reply_rx.recv().map_err(|_| ModelError::Stopped)?
    }
}

/// The serialized actor loop: drain commands, mutate state, emit snapshots.
fn run_actor<S: SecureStore>(
    rx: &mpsc::Receiver<Command>,
    mut store: Store<S>,
    control: &dyn TunnelControl,
    view: &dyn StateObserver,
    stats_sink: &dyn StatsObserver,
) {
    let mut state = State {
        entries: store.list().to_vec(),
        ..State::default()
    };
    view.on_state(state.snapshot());

    while let Ok(cmd) = rx.recv() {
        match cmd {
            Command::Stats(counters) => {
                stats_sink.on_stats(counters);
                continue; // stats never trigger a state snapshot
            },
            Command::ExportUri { id, reply } => {
                let result = export(&store, &state, &id);
                let _ = reply.send(result);
                continue; // a query never changes state
            },
            Command::OsStatus { state: os, error } => {
                state.connection = os;
                state.last_error = error.map(error_sentence);
            },
            Command::Intent(intent) => apply_intent(&mut store, &mut state, control, intent),
        }
        view.on_state(state.snapshot());
    }
}

/// Apply a state-changing intent. Snapshot emission is the caller's job.
fn apply_intent<S: SecureStore>(
    store: &mut Store<S>,
    state: &mut State,
    control: &dyn TunnelControl,
    intent: Intent,
) {
    match intent {
        Intent::AddProfileFromUri(uri) => match config::parse_uri(&uri) {
            Some(profile) => {
                let name = config::name_from_uri(&uri);
                match store.add(&profile, name.as_deref()) {
                    Ok(entry) => {
                        state.selected_id = Some(entry.id);
                        state.last_error = None;
                    },
                    Err(_) => state.last_error = Some("Couldn't save that profile.".to_string()),
                }
                state.entries = store.list().to_vec();
            },
            None => {
                state.last_error = Some("That doesn't look like a hysteria2:// link.".to_string());
            },
        },
        Intent::RenameProfile { id, name } => {
            if store.rename(&id, &name).is_err() {
                state.last_error = Some("Couldn't rename that profile.".to_string());
            }
            state.entries = store.list().to_vec();
        },
        Intent::DeleteProfile(id) => {
            match store.delete(&id) {
                // Only drop the selection if the profile is actually gone; a
                // failed delete leaves it in the list, so it stays selectable.
                Ok(_) => {
                    if state.selected_id.as_deref() == Some(id.as_str()) {
                        state.selected_id = None;
                    }
                },
                Err(_) => {
                    state.last_error = Some("Couldn't delete that profile.".to_string());
                },
            }
            state.entries = store.list().to_vec();
        },
        Intent::SelectProfile(id) => {
            if state.entries.iter().any(|e| e.id == id) {
                state.selected_id = Some(id);
            }
        },
        Intent::Connect => match &state.selected_id {
            // No optimistic state change: ConnectionState comes back via
            // on_os_status (§4). We only clear a stale error on a fresh attempt.
            Some(id) => {
                state.last_error = None;
                control.start(id);
            },
            None => state.last_error = Some("Select a profile before connecting.".to_string()),
        },
        Intent::Disconnect => control.stop(),
    }
}

/// Read and re-encode a profile's share link with its display name.
fn export<S: SecureStore>(store: &Store<S>, state: &State, id: &str) -> ExportResult {
    Ok(store.load(id)?.map(|profile| {
        let name = state
            .entries
            .iter()
            .find(|e| e.id == id)
            .map(|e| e.name.as_str());
        config::to_uri_with_name(&profile, name).into_bytes()
    }))
}

/// Map a connect error to one actionable, secret-free UI sentence (no
/// diagnostics screen; §5).
fn error_sentence(error: ConnError) -> String {
    match error {
        ConnError::AuthFailed => "Authentication failed. Check the profile's credentials.",
        ConnError::ServerUnreachable => {
            "Can't reach the server. Check your network and the server address."
        },
        ConnError::Timeout => "The connection timed out. Try again.",
        ConnError::Unknown => "Couldn't connect. Try again.",
    }
    .to_string()
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::sync::mpsc;
    use std::sync::mpsc::Receiver;
    use std::time::Duration;

    use anyhow::Context as _;
    use anyhow::Result;
    use pretty_assertions::assert_eq;
    use store::DevSecureStore;
    use tempfile::TempDir;

    use super::*;

    /// A state observer that forwards snapshots to a channel, so a test can
    /// block until the actor has processed an intent (no sleeps).
    struct ChannelObserver(Sender<Snapshot>);
    impl StateObserver for ChannelObserver {
        fn on_state(&self, snapshot: Snapshot) {
            let _ = self.0.send(snapshot);
        }
    }

    /// A stats observer forwarding to a channel.
    struct StatsChannel(Sender<Stats>);
    impl StatsObserver for StatsChannel {
        fn on_stats(&self, stats: Stats) {
            let _ = self.0.send(stats);
        }
    }

    /// Records `start`/`stop` calls so tests can assert the OS was asked.
    #[derive(Default, Clone)]
    struct SpyTunnel(std::sync::Arc<Mutex<Vec<String>>>);
    impl TunnelControl for SpyTunnel {
        fn start(&self, profile_id: &str) {
            lock(&self.0).push(format!("start:{profile_id}"));
        }
        fn stop(&self) {
            lock(&self.0).push("stop".to_string());
        }
    }

    fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
        m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    struct Harness {
        model: Model,
        snapshots: Receiver<Snapshot>,
        stats: Receiver<Stats>,
        tunnel: SpyTunnel,
        _dir: TempDir,
    }

    fn harness() -> Result<Harness> {
        let dir = TempDir::new()?;
        let store = Store::new(dir.path().join("profiles.json"), DevSecureStore::new())?;
        let (snap_tx, snapshots) = mpsc::channel();
        let (stats_tx, stats) = mpsc::channel();
        let tunnel = SpyTunnel::default();
        let model = Model::new(
            store,
            Box::new(tunnel.clone()),
            Box::new(ChannelObserver(snap_tx)),
            Box::new(StatsChannel(stats_tx)),
        );
        Ok(Harness {
            model,
            snapshots,
            stats,
            tunnel,
            _dir: dir,
        })
    }

    /// Block for the next snapshot, failing the test on timeout.
    fn next(snapshots: &Receiver<Snapshot>) -> Result<Snapshot> {
        snapshots
            .recv_timeout(Duration::from_secs(5))
            .context("timed out waiting for a snapshot")
    }

    const LINK: &str = "hysteria2://token@example.com:443/?sni=example.com#Home";

    #[test]
    fn emits_initial_empty_snapshot() -> Result<()> {
        let h = harness()?;
        let s = next(&h.snapshots)?;
        assert_eq!(s.schema_version, SCHEMA_VERSION, "carries schema version");
        assert!(s.profiles.is_empty(), "starts with no profiles");
        assert_eq!(
            s.connection,
            ConnectionState::Disconnected,
            "starts disconnected"
        );
        Ok(())
    }

    #[test]
    fn add_parses_link_names_it_and_selects_it() -> Result<()> {
        let h = harness()?;
        next(&h.snapshots)?; // initial
        h.model.send(Intent::AddProfileFromUri(LINK.to_string()));
        let s = next(&h.snapshots)?;
        assert_eq!(s.profiles.len(), 1, "one profile added");
        assert_eq!(s.profiles[0].name, "Home", "display name from #fragment");
        assert_eq!(
            s.selected_id.as_deref(),
            Some(s.profiles[0].id.as_str()),
            "new profile is selected"
        );
        assert_eq!(s.last_error, None, "no error on success");
        Ok(())
    }

    #[test]
    fn add_rejects_a_non_link_with_a_sentence() -> Result<()> {
        let h = harness()?;
        next(&h.snapshots)?;
        h.model
            .send(Intent::AddProfileFromUri("not a link".to_string()));
        let s = next(&h.snapshots)?;
        assert!(s.profiles.is_empty(), "nothing added");
        assert!(s.last_error.is_some(), "an error sentence is shown");
        Ok(())
    }

    #[test]
    fn rename_changes_only_the_name() -> Result<()> {
        let h = harness()?;
        next(&h.snapshots)?;
        h.model.send(Intent::AddProfileFromUri(LINK.to_string()));
        let added = next(&h.snapshots)?;
        let id = added.profiles[0].id.clone();
        h.model.send(Intent::RenameProfile {
            id: id.clone(),
            name: "Work".to_string(),
        });
        let s = next(&h.snapshots)?;
        assert_eq!(s.profiles[0].name, "Work", "name updated");
        assert_eq!(s.profiles[0].id, id, "same profile");
        Ok(())
    }

    #[test]
    fn delete_removes_and_clears_selection() -> Result<()> {
        let h = harness()?;
        next(&h.snapshots)?;
        h.model.send(Intent::AddProfileFromUri(LINK.to_string()));
        let added = next(&h.snapshots)?;
        let id = added.profiles[0].id.clone();
        h.model.send(Intent::DeleteProfile(id));
        let s = next(&h.snapshots)?;
        assert!(s.profiles.is_empty(), "profile gone");
        assert_eq!(s.selected_id, None, "selection cleared");
        Ok(())
    }

    #[test]
    fn connect_asks_os_but_state_stays_until_os_reports() -> Result<()> {
        let h = harness()?;
        next(&h.snapshots)?;
        h.model.send(Intent::AddProfileFromUri(LINK.to_string()));
        let added = next(&h.snapshots)?;
        let id = added.profiles[0].id.clone();

        h.model.send(Intent::Connect);
        let s = next(&h.snapshots)?;
        assert_eq!(
            s.connection,
            ConnectionState::Disconnected,
            "no optimistic state change on Connect"
        );

        // The OS reports the transition; the Model now reflects it.
        h.model.on_os_status(ConnectionState::Connected, None);
        let s = next(&h.snapshots)?;
        assert_eq!(s.connection, ConnectionState::Connected, "OS-derived state");

        assert_eq!(
            lock(&h.tunnel.0).as_slice(),
            [format!("start:{id}")],
            "OS asked to start"
        );
        Ok(())
    }

    #[test]
    fn connect_without_selection_errors() -> Result<()> {
        let h = harness()?;
        next(&h.snapshots)?;
        h.model.send(Intent::Connect);
        let s = next(&h.snapshots)?;
        assert!(s.last_error.is_some(), "asks the user to select a profile");
        assert!(lock(&h.tunnel.0).is_empty(), "OS not asked to start");
        Ok(())
    }

    #[test]
    fn os_failure_sets_an_error_sentence() -> Result<()> {
        let h = harness()?;
        next(&h.snapshots)?;
        h.model
            .on_os_status(ConnectionState::Disconnected, Some(ConnError::AuthFailed));
        let s = next(&h.snapshots)?;
        assert_eq!(
            s.last_error.as_deref(),
            Some("Authentication failed. Check the profile's credentials."),
            "maps the conn-error to a sentence"
        );
        Ok(())
    }

    #[test]
    fn stats_go_to_their_own_channel_not_a_snapshot() -> Result<()> {
        let h = harness()?;
        next(&h.snapshots)?; // initial
        h.model.on_stats(Stats {
            tx_bytes: 10,
            rx_bytes: 20,
        });
        let st = h
            .stats
            .recv_timeout(Duration::from_secs(5))
            .context("no stats received")?;
        assert_eq!(
            st,
            Stats {
                tx_bytes: 10,
                rx_bytes: 20
            },
            "stats forwarded"
        );
        assert!(
            h.snapshots
                .recv_timeout(Duration::from_millis(200))
                .is_err(),
            "stats do not emit a state snapshot"
        );
        Ok(())
    }

    #[test]
    fn export_reencodes_link_with_name_and_is_secret_free_in_snapshots() -> Result<()> {
        let h = harness()?;
        next(&h.snapshots)?;
        h.model.send(Intent::AddProfileFromUri(LINK.to_string()));
        let added = next(&h.snapshots)?;
        let id = added.profiles[0].id.clone();

        let bytes = h
            .export_profile_uri_blocking(&id)?
            .context("profile should exist")?;
        let uri = String::from_utf8(bytes)?;
        assert!(uri.starts_with("hysteria2://"), "re-encoded link: {uri}");
        assert!(
            uri.contains("#Home"),
            "carries the display name fragment: {uri}"
        );

        // The link/auth never appears in a snapshot.
        assert!(
            !format!("{added:?}").contains("token"),
            "snapshot is secret-free"
        );
        Ok(())
    }

    impl Harness {
        fn export_profile_uri_blocking(&self, id: &str) -> Result<Option<Vec<u8>>> {
            Ok(self.model.export_profile_uri(id)?)
        }
    }
}

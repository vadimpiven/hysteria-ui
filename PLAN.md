# Hysteria UI — Architecture & Plan

Native Hysteria 2 client apps over a shared Rust core (the app Model plus the Hysteria client —
all state, logic, and protocol) and a single shared Compose Multiplatform (Kotlin) View (the UI).
Only the thin OS-integration shims (TUN provider, secure store) are platform-specific. Build order:
macOS, then Android/Android TV, Windows. Targets: macOS, Windows, Android, Android TV (no iOS).

Features (v1): add a profile (enter a `hysteria2://` link — type it, or scan its QR where there
is a camera), rename a profile (its display name only), share a profile (show its link with a
Copy button plus a QR code), delete a profile, connect/disconnect a system-wide TUN.

Dependencies (pinned to exact versions at integration; enforced by `cargo-deny`):

- `quinn` — QUIC (MIT/Apache-2.0); its public `congestion::Controller` trait carries Hysteria's
  Brutal congestion control. Fallback: `s2n-quic`.
- `rustls` — TLS (Apache-2.0/ISC/MIT) with the `aws-lc-rs` provider (Apache/ISC); `ring` is the
  named fallback. `rustls-platform-verifier` (MIT/Apache-2.0) verifies the server certificate
  against the OS trust store (incl. Android via JNI).
- `netstack-smoltcp` — userspace TUN netstack over `smoltcp` (MIT/Apache; smoltcp 0BSD): accepts
  flows from the TUN's IP packets and hands back async TCP streams + a UDP socket. Fallback: `ipstack`.
- `tun-rs` — TUN device / fd wrapper (MIT/Apache-2.0). Fallback: raw fd + `wintun` crate.
- `h3` + `h3-quinn` — HTTP/3 auth handshake. `tokio` — async runtime (MIT).
- `uniffi` — generates the FFI plus the Kotlin (app) and Swift (Apple extension) bindings from the
  Rust interface (MPL-2.0). Permissive fallback: hand-rolled `jni` (MIT/Apache-2.0) for the JVM side
  plus a C ABI for Swift, dropping the codegen.
- Compose Multiplatform UI (pinned in the Gradle project, not Cargo): Compose Multiplatform +
  Kotlin stdlib (Apache-2.0), Skiko/Skia (Apache-2.0 over Skia BSD-3), `androidx.tv` for Android TV
  (Apache-2.0). The desktop runtime is a bundled OpenJDK (GPL-2.0 **with the Classpath Exception**,
  which permits redistribution without copyleft reaching our code); Android uses the OS-provided ART
  (nothing bundled).

The Rust tree is permissive (MIT / Apache-2.0 / 0BSD / ISC) plus `uniffi` (MPL-2.0, file-level
copyleft); `cargo-deny` enforces that set. The UI runtime is not purely permissive — see §3.7.

---

## 1. Principles

- Minimal, granny-friendly. The entire UI is: add a link, rename a profile, share a link, delete
  a link, connect, disconnect. Entering the link is the universal add path (typed text), so every
  platform — including Android TV and any device with no camera — shares one interface; QR scanning
  is only an optional shortcut where a camera exists. Sharing is a read-only view (the link with a
  Copy button plus its QR), the one per-profile view. Renaming changes only the display name (the
  link's `#fragment`), never the connection: no settings screen, and no editing the connection
  itself — a profile is its link (to change the server/auth/obfs, delete and re-add). Every
  setting that can have a default is
  defaulted and hidden (routing, autoconnect, launch-at-login, DNS, reconnect). A setting with no
  safe default is a design smell — re-derive it from the link or pick an opinionated default.
- Security-first. When security trades against simplicity or smaller scope, take the secure
  option. Less UI surface is also less attack surface, so the two principles reinforce each
  other. A memory-safe Rust core hardens the network- and untrusted-input-facing code by
  construction. Full posture: §7.

---

## 2. Architecture

```text
                Shared Rust core (cargo workspace, UniFFI-bound)
   crates/  (rich Rust, internal to the workspace)
     profile/     parsed hysteria2:// profile (pure serde data)
     config/      hysteria2:// parse + validate                (app-only)
     store/       JSON doc + SecureStore (secrets)
     conn-error/  connect-error enum (leaf)
     hysteria/    Hysteria 2 client on Quinn: auth + TCP + UDP + Brutal
     netstack/  socket-style API over smoltcp + tun-rs fd
     dataplane/   relays flows through hysteria/ (UDP NAT, counters)
     model/       the Model: async actor — snapshots + intents
   ffi-app/  ffi-ext/   two UniFFI components (disjoint deps; the app/ext wall)
                          │  cdylib (Android/JVM) / staticlib (Apple) per target
                          ▼  UniFFI-generated Kotlin (app) · Swift (Apple ext)
              Single Compose Multiplatform View — shared by ALL platforms
              (macOS · Android(+TV) · Windows)

   Platform-native shims (each in its own language, behind the core):
     Apple → Swift NE system extension          Android → VpnService (Kotlin)
     Windows → service + Wintun
```

Model–View with the Model in Rust and a single shared Compose Multiplatform View. The View renders
a state snapshot from the Rust `model` crate and sends back user intents; there is no business
logic in Kotlin, only a thin shell over the Rust Model. The only platform-specific code is the
OS-integration shims (TUN provider, secure store), each in its native language behind the core.
State flows one way: tunnel → OS → model observes → snapshot → UI (§4).

### 2.1 Layers

| Layer                          | Component                                                     |
| ------------------------------ | ------------------------------------------------------------- |
| UI / View                      | `ui/` — Compose Multiplatform (Kotlin), one shared View       |
| FFI binding                    | `ffi-app` / `ffi-ext` — two UniFFI components (Kotlin/Swift)  |
| Model (state machine)          | `model/` — async actor: snapshots + intents                   |
| Profile store + secrets        | `store/` JSON doc + native `SecureStore`                      |
| Config / URI parse + validate  | `config/`                                                     |
| Profile model                  | `profile/` (pure serde data)                                  |
| Client API + proxy framing     | `hysteria/`                                                   |
| HTTP/3 auth handshake          | `h3` + `h3-quinn`                                             |
| Obfuscation (Salamander/gecko) | wrapping Quinn `AsyncUdpSocket`                               |
| Congestion control (Brutal)    | Quinn `congestion::Controller` impl                           |
| QUIC transport                 | `quinn`                                                       |
| TLS + cert verification        | `rustls` + `rustls-platform-verifier` (OS trust store)        |
| Userspace netstack             | `netstack-smoltcp` (over `smoltcp`)                           |
| TUN device / fd                | `tun-rs`                                                      |
| Async runtime / concurrency    | single-thread `tokio` + serialized actor                      |
| QR generation (share)          | `qrcode` crate                                                |

---

## 3. Constraints that shape the design

Platform baselines (minimum OS versions): macOS 13, Windows 10, Android `minSdk` 28
(Android 9 — `VpnService` plus Keystore fully supported, reaching most Android TV boxes). These set
which OS APIs the design may rely on (e.g. the memory bounding for low-RAM Android TV boxes, §3.3;
the best-effort sensitive-clipboard flag, §7.4).

### 3.1 TUN is platform-mediated; one netstack serves all

Each OS hands the tunnel a file descriptor, or (Windows) the core opens the adapter:

| Platform             | Mechanism                                         | Core receives          |
| -------------------- | ------------------------------------------------- | ---------------------- |
| macOS                | NetworkExtension Packet Tunnel Provider           | utun fd                |
| Android / Android TV | `VpnService.establish()` → `ParcelFileDescriptor` | fd                     |
| Windows              | Wintun adapter (kernel driver)                    | core opens it directly |

`tun-rs` is the cross-platform fd/device wrapper: on macOS/Android we hand it the OS-provided fd;
on Windows it opens the Wintun adapter (bundled `wintun.dll`, §3.7). Either way it yields raw IP
packets that feed the netstack (§3.2). No privileged route/iptables work lives in the
core: the OS (macOS `NEPacketTunnelNetworkSettings`, Android `VpnService`) or the Windows service
sets routes.

### 3.2 Userspace netstack: netstack-smoltcp

A TUN yields raw IP packets; a netstack turns them into connections. `netstack-smoltcp` wraps the
pure-Rust `smoltcp` TCP/IP stack and hands back accepted flows directly, so the core does not
hand-roll packet parsing, socket lifecycle, or NAT.

The bridge pumps tun-rs packets into the netstack and relays each accepted flow through the
Hysteria client (§5, `hysteria/`):

- accepted TCP flow (async stream, carrying the original destination) → `HysteriaClient::tcp(raddr)`
  → a Quinn bidi stream, spliced with `copy_bidirectional`
- UDP datagrams (with original source/destination) → per-source NAT over a Hysteria UDP session on
  QUIC datagrams (RFC 9221, `Connection::send_datagram`)

No raw sockets, no route table, no iptables — just the fd plus outbound QUIC dials, all permitted
in the macOS NE sandbox. [Validate the netstack + Quinn + fd writes in the NE sandbox at the macOS
NE de-risk (§6, step 3).]

### 3.3 Memory bounding

The tunnel runs in a sandboxed extension (macOS NE) or the app process (Android `VpnService`).
Memory is provisioned, not unbounded: the weight is Quinn's send/receive buffers plus the
netstack's per-connection buffers. Bound it by capping concurrent flows (`dataplane`'s
`Limits::max_tcp_flows` / `max_udp_sessions`) and keeping a single-threaded runtime in the
extension. The binding target for the cap is the low-RAM Android TV box, where an app may be killed
past a few hundred MB. Validate the tunnel in the macOS NE sandbox at the de-risk gate (§6, step 3)
and re-check RSS on a real Android TV box at fan-out (§6, step 8).

### 3.4 Binding surface: UniFFI generates Kotlin and Swift from one Rust interface

The View is a single Compose Multiplatform app (§2), so the app side consumes the core from Kotlin;
the privileged macOS tunnel is Swift (§3.6). `uniffi` generates **both** bindings from the same
Rust interface (`#[uniffi::export]`): Kotlin for the app (Android via the bundled `.so`; desktop
JVM via the `.dylib`/`.dll` loaded through JNA) and Swift for the Apple system extension (linking
the `staticlib`). The core builds as a `cdylib` (Android/JVM) or `staticlib` (Apple). UniFFI owns
the C scaffolding we would otherwise hand-roll: the handle map, panic trapping (no Rust panic
crosses the boundary — the libs still build `panic = "abort"`), and **foreign callback interfaces**,
which is how the native `SecureStore` (implemented in Kotlin/Swift) is passed back into Rust.
Complex values cross as UniFFI records/enums rather than ad-hoc JSON. The app/ext wall is preserved
structurally: `ffi-app` and `ffi-ext` are two separate UniFFI component crates with disjoint
dependencies (§3.8), so each generates only its own surface.

### 3.5 Secrets live in platform-native secure storage

The `hysteria2://` link is a bearer credential, read/written via a native `SecureStore`
(`get`/`set`/`delete`, keyed by profile id) — never a core-written file (chosen for security):

- Apple — Keychain plus Access Group (shares app↔extension), accessibility
  `kSecAttrAccessibleAfterFirstUnlock` (extension reconnects while locked; nothing readable
  before first unlock).
- Android — Keystore-wrapped AES-GCM (hardware-backed where available).
- Windows — DPAPI (`CryptProtectData`, per-user).

The `SecureStore` trait is defined in the Rust `store` crate (consumer-side) and implemented
natively as a UniFFI foreign callback interface — in Kotlin in the app (Android Keystore; Windows
DPAPI via the JVM FFI) and in Swift in the Apple extension, which reads the secret itself via the
shared Keychain Access Group (§4). The dev plaintext stub is `cfg`/feature gated and never shipped.

### 3.6 macOS TUN: NetworkExtension as a System Extension

Use a NE Packet Tunnel `NEPacketTunnelProvider`, a thin Swift shim linking the Rust `staticlib`.
For off-store **Developer-ID** distribution (§8), it must be packaged as a **system extension**
(`.systemextension`), not an app extension — Apple does not allow a non-system Network Extension to
ship under Developer ID. The Compose Desktop host app embeds, activates (`OSSystemExtensionRequest`),
and signs the system extension; this needs the Network Extensions + System Extension entitlements,
and the signing/entitlements must be handled outside Xcode in our packaging (§3.8). A paid Apple
Developer account suffices to build, test, and Developer-ID-notarize.

### 3.7 Licensing

Our code is dual `Apache-2.0 OR MIT` (`LICENSE-*` at root). The Rust tree is permissive, with one
deliberate exception (`uniffi`):

- `quinn`, `tun-rs`, `tokio`, `h3`, `netstack-smoltcp` (MIT/Apache-2.0), `rustls` (Apache/ISC/MIT),
  `smoltcp` (0BSD), crypto provider (`aws-lc-rs` Apache/ISC; `ring` ISC-style fallback).
- `uniffi` — **MPL-2.0**, file-level weak copyleft: combining the unmodified `uniffi` runtime with
  our code is fine; only edits to `uniffi`'s own files would carry an obligation. If MPL is
  unacceptable, the permissive fallback is hand-rolled `jni` (MIT/Apache) plus a C ABI for Swift.

The UI runtime is **not** purely permissive:

- Compose Multiplatform, Kotlin stdlib, Skiko, `androidx.tv` — Apache-2.0 (Skia is BSD-3).
- Desktop (macOS/Windows) bundles an **OpenJDK runtime — GPL-2.0 with the Classpath Exception**.
  The Classpath Exception exists precisely so a bundled JRE can ship with code under any license:
  no copyleft reaches our code; we just redistribute the OpenJDK image and carry its notice. Android
  uses the OS-provided ART, so nothing JVM is bundled there.
- Windows Wintun — `tun-rs` uses the bundled `wintun.dll` (the signed build from wintun.net,
  redistributable via its §3d API-use grant). Vendor the signed DLL into the installer, pinned
  with a build-time checksum plus Authenticode verification; redistribute as-is, never sign the
  driver ourselves.

`cargo-deny` enforces the Rust license policy — permissive set **plus MPL-2.0 for `uniffi`** — plus
RustSec advisories in CI; the JVM/Kotlin tree is license-scanned on the Gradle side (§8). [Not legal
advice — confirm with counsel before release, especially the OpenJDK redistribution notice.]

### 3.8 Cross-compilation and the app/ext wall

Rust cross-compiles with cargo: macOS slices (`aarch64-apple-darwin`, `x86_64-apple-darwin`, lipo'd
into one `staticlib` for the system extension — no iOS, so no simulator/device slices or
xcframework), Android (`cargo-ndk`, a `cdylib` per ABI), Windows (MSVC, a `cdylib`). `uniffi`
emits the Kotlin and Swift bindings from the Rust interface. The crypto provider (`aws-lc-rs`)
carries C/asm and needs a C toolchain plus CMake (and NASM on the Windows target); these are pinned
in `mise.toml` (below), so cargo builds it per target.

Build orchestration is `mise` plus Gradle (the Compose/Kotlin build) plus TypeScript (the test
harness). `mise.toml` is the single source of truth for tool versions (Rust, `cargo-ndk`,
`cargo-deny`, `uniffi-bindgen`, CMake plus a C toolchain and NASM-on-Windows for `aws-lc-rs`, the
JDK, Gradle, Node, pnpm, …) and tasks, so contributors install nothing globally and run
`mise run <task>`. Multi-step logic — per-target Rust builds, the macOS lipo, `uniffi` codegen into
`bindings/`, the system-extension embed/sign, packaging — is driven from `mise`/Gradle; the
TypeScript under `scripts/` remains for the reference-server test harness. A
`mise run hysteria-server` task fetches
the pinned reference server (rev `c3a806b`) under a checksum, generates a self-signed cert (which
tests trust out of band, since the client verifies against the OS trust store), and runs it with
known auth — first-class test infrastructure from the first commit, backing both the
`transport-socks5` conformance loop (§5) and the TLS verification path (§7.3).

The dependency-wall and supply-chain gates (`cargo-deny`, the `cargo tree` wall assertion below,
`[workspace.lints]`) are scaffolded in the first commit so the wall — a structural invariant —
holds from the moment crates start growing edges (§6, step 0).

The app/extension wall is a compile-time crate-dependency guarantee: `ffi-ext` does not depend on
`config` (the parser) or `model` (the state machine) in its `Cargo.toml`, so they cannot link in;
a `cargo tree` assertion (a `mise` task, run locally and in CI) fails the build if that changes.
The extension links only `{profile, store (read), conn-error, dataplane (which pulls hysteria)}`,
never the URL parser or the Model (keeping the extension minimal, §3.3).

Workspace conventions: shared versions in `[workspace.dependencies]`, shared metadata in
`[workspace.package]` (`publish = false`, MSRV, license), and `[workspace.lints]` setting
`unsafe_code = "forbid"` for every crate except `ffi-app`/`ffi-ext` — so the `unsafe` UniFFI
generates is confined to the two binding crates.

---

## 4. Process, state and concurrency model

This is where VPN clients usually break, so the contract is explicit.

- The OS owns connection state. `NEVPNStatus` / `VpnService` / the Windows service is
  authoritative: the user can toggle the VPN from OS settings, and the OS can tear it
  down or memory-kill the extension. So `model` derives `ConnectionState` from OS status events,
  never optimistically. One-way flow: tunnel → OS status → model observes → snapshot → UI.
- A privileged tunnel process, walled from the app. On Apple (NE extension) and Windows
  (service) the tunnel runs in a separate privileged process with no shared heap; on Android it
  shares the app process (the wall is then logical). The two UniFFI components link disjoint subsets:
  `ffi-app` → `model` (the sole app-side facade); `ffi-ext` → `{dataplane, store (read), conn-error,
profile}`, never `config` or `model`. Profiles are
  validated app-side at save time, and the tunnel consumes a minimal validated blob — a
  `profile::Profile` serialized as JSON, deserialized without linking the parser (which is why `profile`
  is its own crate, apart from `config`). The JVM/ART runtime lives only in the app process; the
  privileged side is a native shim (Swift system extension / Windows service) plus the Rust
  `staticlib`, never the JVM. The crate-dependency wall (§3.8) holds on every platform, even where
  (Android) it is one process.
- The tunnel process is self-sufficient. On autoconnect/on-demand it may start with the app not
  running; it reads the active profile and secret itself (Apple: App Group plus Keychain; Windows:
  per-user store plus DPAPI). The app/GUI is never on the connect path.
- Concurrency. UniFFI calls Rust from arbitrary JVM threads; the tunnel runs on a
  single-threaded `tokio` runtime (Quinn is async). So `model` is a serialized actor (one task
  draining an `mpsc` intent channel); intents are non-blocking and return immediately; results
  surface only via the observer callback; callbacks may arrive on any thread and must be marshaled
  to the UI thread (Compose's `Dispatchers.Main` via `kotlinx.coroutines`).

---

## 5. The Rust core

```text
hysteria-ui/
  Cargo.toml               # cargo workspace (virtual manifest) at the repo root: [workspace] members + workspace.{dependencies,lints,package}; publish = false
  mise.toml                # single source of truth: pinned tool versions + tasks (setup/build/test/check/fix)
  package.json             # "type": "module"; pnpm scripts + devDeps (test harness only)
  scripts/                 # TypeScript: reference-server test harness (the Rust↔UI build is mise + Gradle)
  crates/
    profile/               # pure serde data types; #![forbid(unsafe_code)]; deps: serde
    config/                # hysteria2:// parse + validate -> profile::Profile; untrusted-input parser (app-only)
    store/                 # JSON doc + SecureStore trait DEFINED here; deps: profile
    conn-error/            # connect-error enum; leaf (only thiserror); crosses the app/ext wall
    hysteria/              # Hysteria 2 client on Quinn (mods: transport, auth, proxy, frag, obfs, brutal); builds the client from &profile::Profile
    netstack/  # socket-style API over smoltcp + tun-rs fd; no hysteria dep
    dataplane/             # relays through the hysteria client (ext-only); UDP NAT, counters
    transport-tun/            # dev TUN-harness binary over dataplane/ (the transport-socks5 counterpart); never linked into any ffi-* lib
    model/                 # the Model: async serialized actor; sole app-side facade; state + stats snapshots; intents (app-only)
    ffi-app/               # cdylib+staticlib UniFFI component (Kotlin app); deps: model
    ffi-ext/               # cdylib+staticlib UniFFI component (Swift extension); deps: dataplane, store, conn-error, profile
    transport-socks5/         # standalone SOCKS5 front-end over the hysteria client (also the protocol conformance harness); deps: hysteria, config; never linked into any ffi-* lib
  fuzz/                    # cargo-fuzz targets (config parser); EXCLUDED from the workspace (own nightly target)
  testdata/                # mise-managed: pinned reference Hysteria 2 server (rev c3a806b) + self-signed cert (trusted out of band in tests) + known auth; the conformance fixture
  bindings/                # generated (gitignored): UniFFI Kotlin + Swift bindings, produced at build time by uniffi-bindgen (Gradle / the uniffi-bindgen bin); ui/ + apple/ consume
  ui/                      # ONE Compose Multiplatform (Kotlin/Gradle) project: shared View + platform heads (Android, Android TV, desktop JVM)
  apple/                   # Swift NE system extension + packaging (desktop host app embeds + signs it)
  android/                 # VpnService glue (in the Kotlin Android head) + packaging (later)
  windows/                 # privileged service + Wintun + installer (later)
  PLAN.md
```

- `profile/` plus `config/` (split on purpose). `profile::Profile` is the parsed connection
  profile — pure `serde` data (TLS/QUIC/auth/bandwidth/obfs, including `obfsGecko`), depending on
  nothing but `serde` and holding no parser. The extension holds a validated blob without linking
  the URI parser, and `hysteria` (not `profile`) owns the `&Profile -> client config` builder, so
  `profile` stays a true leaf. `config/` parses and validates the `hysteria2://` URI (including
  port-hopping) into `profile::Profile`; it runs app-side at save time (§4), is app-only, and ships
  a golden-corpus plus fuzz test (`cargo fuzz`). The link's `#fragment` is read as the display name
  (`name_from_uri`) on import and re-emitted on share (`to_uri_with_name`) — a client naming
  convention the Go reference ignores; the name is non-secret metadata, not connection data, so it
  stays out of `profile::Profile` and lives in `store`.
- `store/` — `store::Entry { id, name, created_at }` is secret-free metadata: it is what the JSON
  doc persists and what `model` puts in (secret-free) snapshots. The link itself — a
  `profile::Profile` — lives only in `SecureStore` and is read on demand via `load(id)` (the
  connect path and the share view), never held in the metadata or a snapshot. API: `add` (consumes
  a `profile::Profile`, writing the secret to `SecureStore` and the metadata to the doc), `rename`
  (changes the display name only — a metadata-doc rewrite that leaves the secret untouched, since
  the connection has not changed; on share the new name reappears as the link's `#fragment`),
  `delete`, `list` (metadata), `load` (the secret). `id` = UUID; dedup by config-normalized
  profile equality (the caller hands `store` an already-parsed, normalized `profile::Profile`,
  since `store` does not link the URI parser); `name` is supplied by the caller (from the link's
  `#fragment`), else
  `store` derives it from the host. Non-secret metadata → one schema-versioned JSON doc written
  atomically (temp + rename) to a platform container path; secret → `SecureStore`. The `SecureStore`
  trait is defined here (native-implemented, passed in at construction; §3.5); the extension calls
  only `get`. The dev plaintext stub is feature-gated (`dev-stub`) and never shipped. No SQLite: a
  tiny ordered list needs no SQL engine.
- `hysteria/` — the Hysteria 2 client (§6, step 1); owns the `&profile::Profile -> client config`
  builder. On Quinn: the HTTP/3 auth handshake (`h3`/`h3-quinn`), TCP relay over Quinn bidi streams
  and UDP relay over QUIC datagrams with fragmentation, Brutal congestion control as a Quinn
  `congestion::Controller`, Salamander obfuscation as a wrapping `AsyncUdpSocket`, and port hopping
  at the socket layer (modules: transport, auth, proxy, frag, obfs, brutal). Exposes a library API
  (`tcp_connect`, UDP sessions, `Close`) plus a byte counter at the stream/session boundary (the
  protocol carries no live counters). Maps connect failures into the `conn-error` enum.
  Conformance-tested against the reference Hysteria 2 server (§6, §7). This library API is the
  front-end seam: `hysteria` never assumes who drives it. Front-ends are interchangeable consumers —
  the TUN netstack (`dataplane/`) for the system-wide VPN, and the SOCKS5 listener (`transport-socks5`)
  for a per-app/browser proxy. `transport-socks5` is already a usable standalone front-end; keeping
  the seam clean leaves the door open to shipping it more widely later (e.g. a pure-Rust
  native-messaging host that a browser extension points `chrome.proxy` at — bypassing UniFFI and
  the JVM entirely); out of v1 scope, an invariant to preserve.
- `netstack/` — a socket-style API over `netstack-smoltcp` (§3.2) plus a `tun-rs`
  fd: builds the smoltcp stack, pumps packets between the TUN device and the netstack, and hands
  back accepted TCP flows plus a UDP socket. Transport-agnostic — no `hysteria` dependency.
- `dataplane/` — drives the `hysteria` client over `netstack`: relay each accepted
  TCP flow to `hysteria::tcp` and NAT UDP over a `hysteria` UDP session, copying bytes both ways.
  Among shipped libs, ext-only (a separate dev TUN harness drives it too). Counts traffic at the
  netstack↔hysteria seam for the stats snapshot.
- `transport-socks5/` — a standalone SOCKS5 front-end over the `hysteria` client (TCP `CONNECT` plus
  UDP `ASSOCIATE`, covering both the TCP relay and the UDP/datagram relay), doubling as the
  protocol's local conformance loop. It takes a `hysteria2://` link (`--url`), parsed via `config`
  into a `profile::Profile` and built into the client config, plus a `--socks5` listen address.
  Usable on its own (per-app/browser proxying without a system-wide TUN); never linked into any
  `ffi-*` lib. The SOCKS5 protocol itself is delegated to `fast-socks5`. The TUN front-end (the
  `dataplane` netstack over a root-opened utun on macOS) is a separate dev binary added alongside
  `dataplane/` in step 2. Tested against the mise-managed local server (below).
- `conn-error/` — a leaf owning the connect-error enum (`thiserror`-derived; `AuthFailed |
ServerUnreachable | Timeout | Unknown`; a rejected certificate folds into `ServerUnreachable`,
  since the QUIC layer does not surface it separately). Produced in the extension (which must
  not link `model`) and relayed up; both `dataplane`/`hysteria` and `model` depend on it, neither on
  the other.
- `model/` — the serialized Model (the Model of Model–View) and the sole app-side facade. Depends
  on `config`, `store`, `conn-error`, `profile`, never `dataplane`/`hysteria` (connect is driven
  through the OS, §4).
  - State: `Vec<store::Entry>`, `selected_id`, OS-derived `ConnectionState` (owned here),
      `last_error` (a `conn-error` value).
  - Intents: `AddProfileFromURI`, `RenameProfile`, `DeleteProfile`, `SelectProfile`, `Connect`,
      `Disconnect`. `RenameProfile` is a `store::rename` (metadata-only; §5 `store/`): it updates
      the display name in a snapshot without touching the stored link.
  - One on-demand query `export_profile_uri(id) -> Vec<u8>` for the share view: reads the link
      from `SecureStore` only when the user opens share, re-encodes it with the display name as the
      `#fragment` (`config::to_uri_with_name`), returns it as bytes, and never places the URI in any
      state snapshot (snapshots stay secret-free; §7).
  - Two output channels, never merged: discrete state snapshots, and throttled stats.
  - `last_error` maps to one actionable UI sentence, no diagnostics screen.
- `ffi-app/` plus `ffi-ext/` — the binding boundary: two UniFFI component crates, the only crates
  allowed `unsafe` (the scaffolding UniFFI generates). UniFFI supplies the machinery we would
  otherwise hand-roll — handle map, panic trapping, and the foreign callback interface for
  `SecureStore` (implemented in Kotlin/Swift). Two entry points:
  `ffi-app: app_new(container_path, secure: SecureStore)` and `ffi-ext: tunnel_new(...)`. The
  observer surface (`StateObserver`, `SubscribeStats`) is a UniFFI callback interface. On Android
  both `.so`s load in one process, so UniFFI's per-component namespacing keeps them disjoint. The
  contract is additive-only and versioned; every snapshot carries a `schema_version`.

Crate dependency DAG (must stay acyclic): `profile` (serde-only) and `conn-error` are sinks.
`config → profile`; `store → profile`; `hysteria → profile, conn-error`; `dataplane → hysteria, netstack,
profile, conn-error`; `model → config, store, conn-error, profile` (never `dataplane`/`hysteria`);
`ffi-app → model`; `ffi-ext → dataplane, store, conn-error, profile`. `ffi-ext`
must never reach `config` or `model` — enforced by Cargo deps plus a `cargo tree` assertion (a
`mise` task; local and CI; §3.8).

Link entry is a Compose text field, the universal add path (including Android TV). QR scanning
is an optional shortcut only where a camera exists (camera → string → `AddProfileFromURI`). QR
generation for the share view is rendered in Rust (a `qrcode` crate) from `export_profile_uri`;
the Compose layer displays it alongside a Copy button.

---

## 6. Roadmap

Core-first: retire the hardest risk early — protocol correctness — and prove the tunnel runs in a
sandboxed NE before any OS/FFI/UI investment is built on top of it. The protocol is validated
through the `transport-socks5` front-end and a dev TUN harness (§5) against a mise-managed local server
(§3.8); FFI and UI come once the core is proven.

0. Workspace plus guardrails — the repo-root `Cargo.toml` virtual manifest with empty crate skeletons,
   `[workspace.dependencies]`/`[workspace.lints]` (`unsafe_code = "forbid"` except `ffi-*`),
   `mise.toml` pinned toolchain, and the supply-chain/wall gates (`cargo-deny` plus the `cargo tree`
   wall assertion, §3.8) wired in CI from the first commit. Enroll in the paid Apple Developer
   Program and enable the Network Extensions + System Extension capabilities (§3.6) — required for
   the macOS de-risk (step 3).
1. Hysteria 2 client plus local SOCKS5 loop — `profile/` (leaf), `conn-error/`, and `hysteria/`
   (h3 auth handshake, TCP relay, UDP/datagram relay plus fragmentation, Brutal as a Quinn
   `congestion::Controller` — validate its pacing maps onto Quinn's pacer — Salamander obfs, port
   hopping), driven off a `profile::Profile`. `transport-socks5` exposes the client as a local SOCKS5
   proxy: TCP `CONNECT` first, then UDP `ASSOCIATE` (SOCKS5 exercises the UDP/datagram relay,
   the riskiest path). Conformance against the mise-managed pinned reference server (rev `c3a806b`):
   `curl` over TCP and `dig` over UDP, with and without obfs, trusting the server's self-signed cert
   out of band (the `--ca` path; §7.3).
2. Userspace TUN, standalone — `dataplane/` (netstack plus tun-rs), exercised by its
   own dev TUN-harness binary (the counterpart to `transport-socks5`): on macOS open a utun via raw
   fd as root — no NE, no FFI — feed packets through the netstack into the proven `hysteria` client.
   Validates the netstack end-to-end against the same local server; counts bytes at the
   netstack↔hysteria seam.
3. macOS de-risk — a minimal `staticlib` → Swift `NEPacketTunnelProvider` packaged as a **system
   extension** linking the `dataplane/` crate, one hardcoded target, no UI. Confirm the netstack +
   Quinn + fd read/write run in the sandboxed extension, **and that a non-Xcode host app can embed,
   activate, sign and Developer-ID-notarize the system extension** (the riskiest macOS unknown), and
   that the macOS-slice `staticlib` + UniFFI Swift cross-compile path works (the full UniFFI Kotlin
   binding comes at step 5). Sanity-check RSS here; the concurrency cap is sized against a real
   low-RAM Android TV box at fan-out (§3.3). Must pass before the fan-out (step 8) is committed.
   Needs the capabilities from step 0; runs in parallel with step 4.
4. Config plus store (mock secrets) — `config` parser (→ `profile::Profile`, plus `#fragment`
   name read/emit) with `cargo fuzz` plus golden corpus; `store` over a container path with the
   `SecureStore` trait plus a dev-stub impl (`add`/`rename`/`delete`/`list`/`load`). Off the
   protocol critical path (shares only the `profile/` leaf) — parallelizable with steps 2–3.
5. Model plus macOS UI (mocked tunnel) — `model` plus the `ffi-app` UniFFI component (Kotlin
   bindings); the Compose Multiplatform desktop View (list / add / rename / share (link + Copy + QR)
   / delete / select / connect) (§1), against a mocked tunnel. First real exercise of the Model–View
   contract: snapshots/intents, observer callback, Compose coroutine (`Dispatchers.Main`)
   marshaling. This View fans out to every platform (step 8).
6. Real tunnel on macOS — the `ffi-ext` UniFFI component (Swift) linking `dataplane/`; the Swift system
   extension from step 3 wired for real; App Group plus Keychain; `ConnectionState` from
   `NEVPNStatus` (§4); status/stats IPC. Hidden defaults: full-tunnel route, autoconnect last
   profile.
7. Native secure store plus add-link/share UX — replace the dev stub with the native `SecureStore`
   (Keychain first, §3.5), now that `model` (app) and the extension (read) consume it; Compose text
   entry (the universal path, including Android TV) plus an optional QR scanner where there is a
   camera (CameraX on Android); per-profile share view: the link with a Copy button (clipboard
   marked sensitive / local-only / auto-expiring; §7) plus its Rust-rendered QR.
8. Fan out — only the OS shim, secure store, and packaging are new per platform: Android/Android TV
   (`VpnService` in the Kotlin Android head; Keystore store; `androidx.tv` D-pad/focus), Windows
   (privileged service plus Wintun plus DPAPI store plus installer).

---

## 7. Security posture

Asset: the stored links (server plus auth, bearer credentials). Mitigations: local malware → OS
sandbox plus native secure store; locked-device theft → Keychain accessibility plus file
data-protection; network MITM → TLS verified against the OS trust store; supply chain → pinned
crates plus signed builds; implementation bugs → memory-safe Rust plus conformance/fuzz testing.

1. At rest — links only in the secure store (§3.5); the JSON doc holds no auth and uses
   `NSFileProtectionCompleteUntilFirstUserAuthentication` on Apple.
2. In memory — secrets cross the boundary as byte buffers (not C strings), zeroized after a
   connect via `zeroize`.
3. Transport — the link carries only `sni` (auth in userinfo). The server certificate is verified
   against the OS trust store via `rustls-platform-verifier`; there is no `insecure` bypass and no
   `pinSHA256` in links, so a server must present a publicly-trusted (e.g. ACME) certificate. The
   trade-off: self-signed servers are unsupported from the GUI; the `transport-socks5` dev tool keeps
   a `--ca` flag to trust a private CA out of band (also how the conformance tests reach the
   self-signed reference server). A rejected certificate is reported as `ServerUnreachable` (the
   QUIC layer folds the TLS alert into a generic handshake failure).
4. Explicit import and share — a `hysteria2://` deep link or clipboard never auto-saves; adding
   always needs confirmation. Sharing is user-initiated only: no background clipboard writes; an
   explicit Copy in the share view tags the clipboard item with each platform's free, set-once
   privacy attributes — sensitive (Android `ClipDescription.EXTRA_IS_SENSITIVE`, API 33+, applied
   best-effort behind a `Build.VERSION` check since `minSdk` is 28, §3), local-only (Apple
   `UIPasteboard` `.localOnly`), and Apple's native one-shot expiry (`.expirationDate` ≈ 30 s). We
   do not run an active clipboard-clearing timer (no native expiry on Android/Windows; a timer would
   risk clobbering whatever the user copied next) — exposure is bounded by these OS attributes, not
   by us mutating the clipboard later. The share view reads the secret on demand
   (`export_profile_uri`, §5) and never surfaces it in a state snapshot.
5. No telemetry — zero analytics / third-party SDKs.
6. No logging in shipped builds — `ffi-app`/`ffi-ext` install no `tracing`/`log` subscriber, so
   dependency log events (`quinn`/`rustls`/`tokio`/`h3`) reach no sink and there is nothing to leak;
   the `conn-error` enum (§5), mapped to an int in the extension, is the only diagnostic channel, so
   the server address cannot cross the boundary. The `transport-socks5` binary and the dev/test
   harnesses (conformance, the macOS de-risk) keep `tracing` to stderr.
7. Supply chain and licensing — pin every crate; enforce with `cargo-deny` (license — permissive
   plus MPL-2.0 for `uniffi` — plus RustSec advisories) and a Gradle/JVM dependency license scan.
   Prefer reproducible builds.
8. Protocol implementation is security-sensitive — conformance tests against the reference server,
   `cargo fuzz` on the parser and frame decoders, pinned reference revision, and a pre-release
   audit of `hysteria/`.
9. Distribution and least privilege — sign plus notarize on Apple, requesting only NE / App-Group
   / Keychain entitlements; signed non-debuggable Android release; Authenticode-signed Windows DLL
   plus installer over the signed Wintun driver.

---

## 8. Release gates and open decisions

- Crypto provider — committed to `aws-lc-rs` (rustls default, actively maintained, FIPS-capable);
  `ring` is the named fallback. The macOS NE de-risk (step 3) verifies `aws-lc-rs` builds and runs
  in the sandboxed extension, and is the only point where we would reverse to `ring`. Build prereqs
  (C toolchain, CMake, NASM on Windows) are pinned in `mise.toml` (§3.8).
- Server-cert trust — committed to the OS trust store via `rustls-platform-verifier` (§7.3): no
  cert pinning, no `insecure` bypass. The macOS de-risk (step 3) must confirm it verifies inside
  the sandboxed extension (it calls Security.framework); the same gate covers Android's JNI path at
  fan-out (step 8).
- UI stack — committed to Compose Multiplatform (Kotlin) over the prior .NET/Avalonia plan, chosen
  for the {macOS, Windows, Android, Android TV} target mix: Android TV is first-class via
  `androidx.tv`, and `uniffi` generates both the Kotlin (app) and Swift (extension) bindings from
  one Rust interface. Accepted trade-offs: the desktop runtime is a bundled OpenJDK (GPL-2.0 +
  Classpath Exception; §3.7) rather than a leaner AOT runtime, and `uniffi` is MPL-2.0. Open: if
  MPL must be avoided, fall back to hand-rolled `jni` + a C ABI for Swift (§3.7).
- macOS extension packaging — for Developer-ID (off-store) the tunnel must be a **system
  extension**, not an app-extension Packet Tunnel Provider (§3.6); a paid Apple Developer account
  suffices. Enable the Network Extensions + System Extension capabilities before the macOS de-risk
  (step 3), which gates whether a non-Xcode host can sign/notarize it.
- Distribution — off-store only, so no organization/LLC/D-U-N-S enrollment is needed: macOS
  Developer-ID-signed and notarized (outside the Mac App Store), Android via a signed APK / F-Droid,
  Windows via a signed installer outside the Microsoft Store.
- Acknowledgements bundle — generate a third-party-notices screen at build time spanning all trees:
  the Rust crates (`cargo-about`/`cargo-deny`), the Kotlin/Gradle tree, and the bundled OpenJDK
  (GPL-2.0 + Classpath Exception) notice, plus the Wintun notice.
- Profile schema — version from day one for migration.
- Runtime defaults (deferred) — the values for the "defaulted and hidden" policies (reconnect,
  keepalive, autoconnect, on-demand match rules; §1) are deferred to step 6; the named defaults
  land with the real macOS tunnel.

---

## 9. Reference points

Protocol: Hysteria 2 spec — <https://v2.hysteria.network/docs/developers/Protocol/>

Crate APIs:

- `quinn` — `quinn::congestion::{Controller, ControllerFactory}` (Brutal);
  `Connection::send_datagram`/`read_datagram` (UDP relay); custom `AsyncUdpSocket` (Salamander
  obfs plus port-hop); `TransportConfig`.
- `netstack-smoltcp` — `StackBuilder` → accepted `TcpListener`/`UdpSocket` flows over `smoltcp`,
  fed by tun-rs, routed to the `hysteria` client.
- `tun-rs` — cross-platform TUN device / fd wrapper (utun, Wintun, OS-provided
  fd).
- `h3` plus `h3-quinn` — HTTP/3 for the auth handshake over the Quinn connection.

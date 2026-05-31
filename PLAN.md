# Hysteria UI — Architecture & Plan

Native Hysteria 2 client apps over a shared Rust core (the app Model plus the Hysteria client —
all state, logic, and protocol) and a single shared .NET/Avalonia View (the UI). Only the thin
OS-integration shims (TUN provider, secure store) are platform-specific. Build order: macOS,
then iOS/iPadOS, Android/Android TV, Windows, Linux.

Features (v1): add a profile (enter a `hysteria2://` link — type it, or scan its QR where there
is a camera), share a profile (show its link with a Copy button plus a QR code), delete a
profile, connect/disconnect a system-wide TUN.

Dependencies (pinned to exact versions at integration; enforced by `cargo-deny`):

- `quinn` — QUIC (MIT/Apache-2.0); its public `congestion::Controller` trait carries Hysteria's
  Brutal congestion control. Fallback: `s2n-quic`.
- `rustls` — TLS (Apache-2.0/ISC/MIT); provider `ring` vs `aws-lc-rs` decided at integration.
- `smoltcp` — userspace netstack (0BSD). Fallback: `ipstack`.
- `tun-rs` — TUN device / fd wrapper (MIT/Apache-2.0). Fallback: raw fd + `wintun` crate.
- `h3` + `h3-quinn` — HTTP/3 auth handshake. `tokio` — async runtime (MIT).
- `csbindgen` — generates the Rust `extern "C"` plus C# P/Invoke bindings. Alternative:
  `interoptopus`.
- .NET / Avalonia UI (pinned in the UI project, not Cargo): Avalonia (MIT), SkiaSharp (MIT, over
  Skia BSD-3).

The runtime tree is permissive (MIT / Apache-2.0 / 0BSD / ISC); `cargo-deny` keeps it so.

---

## 1. Principles

- Minimal, granny-friendly. The entire UI is: add a link, share a link, delete a link, connect,
  disconnect. Entering the link is the universal add path (typed text), so every platform —
  including Android TV and any device with no camera — shares one interface; QR scanning is only
  an optional shortcut where a camera exists. Sharing is a read-only view (the link with a Copy
  button plus its QR), the one per-profile view. No settings screen, no rename, no editing: a
  profile is its link (to change it, delete and re-add). Every setting that can have a default is
  defaulted and hidden (routing, autoconnect, launch-at-login, DNS, reconnect). A setting with no
  safe default is a design smell — re-derive it from the link or pick an opinionated default.
- Security-first. When security trades against simplicity or smaller scope, take the secure
  option. Less UI surface is also less attack surface, so the two principles reinforce each
  other. A memory-safe Rust core hardens the network- and untrusted-input-facing code by
  construction. Full posture: §7.

---

## 2. Architecture

```text
                Shared Rust core (cargo workspace, C-ABI bound)
   ┌─────────────────────────────────────────────────────────────────┐
   │   crates/  (rich Rust — internal to the workspace):              │
   │     profile/   parsed hysteria2:// profile (struct + serde)      │
   │     config/    hysteria2:// parse + validate    (app-only)       │
   │     store/     JSON doc + SecureStore (secrets)                  │
   │     hysteria/  Hysteria 2 client on Quinn: auth+TCP+UDP+Brutal   │
   │     tunnel/    smoltcp netstack + tun-rs fd + drives hysteria/   │
   │     app/       Model: async actor — snapshots + intents          │
   │     errkind/   connect-error enum (leaf)                         │
   │   bind-app/ + bind-ext/  extern "C" + csbindgen — flat (JSON+cb) │
   └─────────────────────────────────────────────────────────────────┘
                          │  staticlib / cdylib  — ONE C ABI, every target
                          ▼  P/Invoke
              Single .NET / Avalonia View — shared by ALL platforms
              (macOS · iOS/iPadOS · Android(+TV) · Windows · Linux)

   Platform-native shims (each in its own language, behind the core):
     Apple → Swift NE PacketTunnelProvider      Android → VpnService
     Windows → service + Wintun                 Linux → systemd daemon + /dev/net/tun
```

Model–View with the Model in Rust and a single shared .NET/Avalonia View. The View renders a
state snapshot from the Rust `app` Model and sends back user intents; there is no business logic
in C#, only a thin shell over the Rust Model. The only platform-specific code is the
OS-integration shims (TUN provider, secure store), each in its native language behind the core.
State flows one way: tunnel → OS → app observes → snapshot → UI (§4).

### 2.1 Layers

| Layer                          | Component                                          |
|--------------------------------|----------------------------------------------------|
| UI / View                      | `ui/` — Avalonia (.NET), one shared View           |
| FFI binding                    | `bind-app` / `bind-ext` (`extern "C"` + csbindgen) |
| App state machine              | `app/` — async actor: snapshots + intents          |
| Profile store + secrets        | `store/` JSON doc + native `SecureStore`           |
| Config / URI parse + validate  | `config/`                                          |
| Profile model                  | `profile/` (struct + serde + config mapper)        |
| Client API + proxy framing     | `hysteria/`                                        |
| HTTP/3 auth handshake          | `h3` + `h3-quinn`                                  |
| Obfuscation (Salamander/gecko) | wrapping Quinn `AsyncUdpSocket`                    |
| Congestion control (Brutal)    | Quinn `congestion::Controller` impl                |
| QUIC transport                 | `quinn`                                            |
| TLS + cert pinning             | `rustls` + custom `ServerCertVerifier`             |
| Userspace netstack             | `smoltcp`                                          |
| TUN device / fd                | `tun-rs`                                           |
| Async runtime / concurrency    | single-thread `tokio` + serialized actor           |
| QR generation (share)          | `qrcode` crate                                     |

---

## 3. Constraints that shape the design

### 3.1 TUN is platform-mediated; one netstack serves all

Each OS hands the tunnel a file descriptor, or (Windows) the core opens the adapter:

| Platform             | Mechanism                                         | Core receives            |
|----------------------|---------------------------------------------------|--------------------------|
| iOS / iPadOS / macOS | NetworkExtension Packet Tunnel Provider           | utun fd                  |
| Android / Android TV | `VpnService.establish()` → `ParcelFileDescriptor` | fd                       |
| Windows              | Wintun adapter (kernel driver)                    | core opens it directly   |
| Linux                | `/dev/net/tun` via `ioctl(TUNSETIFF)` (kernel)    | daemon opens it directly |

`tun-rs` is the cross-platform fd/device wrapper: on Apple/Android we hand it the OS-provided fd;
on Windows it opens the Wintun adapter (bundled `wintun.dll`, §3.7); on Linux the privileged
daemon opens `/dev/net/tun` (`ioctl(TUNSETIFF)`, needs `CAP_NET_ADMIN`). Either way it yields raw
IP packets that feed the `smoltcp` netstack (§3.2). No privileged route/iptables work lives in
the core: the OS (Apple `NEPacketTunnelNetworkSettings`, Android `VpnService`) or the privileged
side (Windows service; Linux daemon via netlink/rtnetlink) sets routes.

### 3.2 Userspace netstack: smoltcp

A TUN yields raw IP packets; a netstack turns them into connections. `smoltcp` is a pure-Rust,
`no_std`-capable userspace TCP/IP stack: each `Interface` is independent, and it is light enough
for the iOS cap (§3.3).

The bridge feeds tun-rs packets into a smoltcp `Interface`, and for each reconstructed flow opens
a proxied path through the Hysteria client (§5, `hysteria/`):

- accepted TCP flow → `HysteriaClient::tcp_connect(raddr)` → a Quinn bidi stream
- UDP flow → a Hysteria UDP session over QUIC datagrams (RFC 9221, `Connection::send_datagram`)

No raw sockets, no route table, no iptables — just the fd plus outbound QUIC dials, all permitted
in the iOS NE sandbox. [Validate smoltcp + Quinn + fd writes in the NE sandbox in the Phase-2
spike (§6).]

### 3.3 iOS NE memory budget

The core must fit the NE extension's hard memory cap. The cap rose to 50 MB in iOS 15, but recent
reports (iPhone 14 Pro Max, iOS 17.3.1) show kills above ~15 MB, so design to 15 MB and treat
50 MB as an unreliable ceiling. The material weight is Quinn's send/receive buffers plus smoltcp's
packet buffers, both bounded and tunable. Engineer the ceiling: bound the buffer pools, cap
concurrent flows, keep a single-threaded runtime in the extension. iOS is the constraint; macOS's
cap is generous. The Phase-2 spike measures it on-device (§6).

### 3.4 Binding surface is flat — one C ABI for every platform

The View is a single .NET/Avalonia app (§2), so every platform consumes the core through the same
C ABI via P/Invoke. The core builds as a Rust `staticlib` (statically linked on Apple, including
the NE extension) or `cdylib` `.so`/`.dll` (Linux/Windows/Android), and `csbindgen` generates the
C# P/Invoke bindings. A C ABI exports only primitives, byte buffers (`*const u8` plus len),
ints-for-errors, and C-function-pointer callbacks — no generics, maps, or rich slices. So `bind-*`
is flat:
primitives plus JSON strings for complex objects plus a callback for the observer; all richness
stays behind it (in the internal crates, §5). One adapter: `#[no_mangle] extern "C"` functions
plus a handle table over `bind-{app, ext}`, marshaled on the .NET side by P/Invoke.

### 3.5 Secrets live in platform-native secure storage

The `hysteria2://` link is a bearer credential, read/written via a native `SecureStore`
(`get`/`set`/`delete`, keyed by profile id) — never a core-written file (chosen for security):

- Apple — Keychain plus Access Group (shares app↔extension), accessibility
  `kSecAttrAccessibleAfterFirstUnlock` (extension reconnects while locked; nothing readable
  before first unlock).
- Android — Keystore-wrapped AES-GCM (hardware-backed where available).
- Windows — DPAPI (`CryptProtectData`, per-user).
- Linux — the Secret Service API over D-Bus (gnome-keyring / KWallet), collection-locked with the
  login session. Reached over D-Bus, so nothing LGPL is linked (§3.7).

The `SecureStore` trait is defined in the Rust `store` crate (consumer-side) and implemented in
C# in the app on every platform; on Apple the NE extension additionally reads the secret itself
in Swift via the shared Keychain Access Group (§4). The dev plaintext stub is `cfg`/feature gated
and never shipped.

### 3.6 macOS TUN: NetworkExtension

Use a NE Packet Tunnel (sandboxed, App-Store-eligible, same code as iOS). The extension is a thin
Swift `PacketTunnelProvider` linking the Rust `staticlib`. Needs the Network Extensions
entitlement (a paid account suffices to build/test; an org is needed only for App Store, §8).

### 3.7 Licensing

The distributed binary statically links everything, so the tree stays permissive (no
GPL/LGPL/MPL):

- Our code is dual `Apache-2.0 OR MIT` (`LICENSE-*` at root).
- `quinn`, `tun-rs`, `tokio`, `h3` (MIT/Apache-2.0), `rustls` (Apache/ISC/MIT), `smoltcp` (0BSD),
  crypto provider (`ring` ISC-style / `aws-lc-rs` Apache/ISC).
- .NET runtime plus BCL (MIT), Avalonia (MIT), SkiaSharp (MIT, over Skia BSD-3). On Linux the
  secret store is reached over the Secret Service D-Bus API, so LGPL `libsecret`/GTK are never
  linked.
- Windows Wintun — `tun-rs` uses the bundled `wintun.dll` (the signed build from wintun.net,
  redistributable via its §3d API-use grant). Vendor the signed DLL into the installer, pinned
  with a build-time checksum plus Authenticode verification; redistribute as-is, never sign the
  driver ourselves.

`cargo-deny` enforces the license policy (plus RustSec advisories) in CI. [Not legal advice —
confirm with counsel before release.]

### 3.8 Cross-compilation and the app/ext wall

Rust cross-compiles with cargo: Apple device plus simulator slices (`aarch64-apple-ios`, `*-sim`,
`*-darwin`, lipo'd into an xcframework), Android (`cargo-ndk`), Windows (MSVC or GNU), Linux.
`csbindgen` emits the Rust `extern "C"` plus C# bindings. The crypto provider
(`ring`/`aws-lc-rs`) carries some C/asm, but cargo handles it per target.

The app/extension wall is a compile-time crate-dependency guarantee: `bind-ext` does not depend
on `config` (the parser) or `app` (the state machine) in its `Cargo.toml`, so they cannot link
in; a CI `cargo tree` / `cargo-deny` check fails the build if that changes. The extension links
only `{profile, store (read), hysteria, tunnel, errkind}`, never the URL parser or the Model (the
lever for the iOS cap, §3.3).

---

## 4. Process, state and concurrency model

This is where VPN clients usually break, so the contract is explicit.

- The OS owns connection state. `NEVPNStatus` / `VpnService` / the Windows service / the Linux
  daemon is authoritative: the user can toggle the VPN from OS settings, and the OS can tear it
  down or memory-kill the extension. So `app` derives `ConnectionState` from OS status events,
  never optimistically. One-way flow: tunnel → OS status → app observes → snapshot → UI.
- A privileged tunnel process, walled from the app. On Apple (NE extension), Windows (service),
  and Linux (systemd daemon) the tunnel runs in a separate privileged process with no shared
  heap; on Android it shares the app process (the wall is then logical). The two binding crates
  link disjoint crate subsets: `bind-app` → `{profile, config, store, app}`; `bind-ext` →
  `{profile, store (read), hysteria, tunnel, errkind}` only, never `config` or `app`. Profiles are
  validated app-side at save time, and the tunnel consumes a minimal validated blob — a serialized
  `profile::Profile`, deserialized without linking the parser (which is why `profile` is its own
  crate, apart from `config`). The .NET/Avalonia runtime lives only in the app process; the
  privileged side is a native shim (Swift / service / daemon) plus the Rust `staticlib`, never
  .NET. The crate-dependency wall (§3.8) holds on every platform, even where (Android) it is one
  process.
- The tunnel process is self-sufficient. On autoconnect/on-demand it may start with the app not
  running; it reads the active profile and secret itself (Apple: App Group plus Keychain; Linux:
  config dir plus Secret Service; Windows: per-user store plus DPAPI). The app/GUI is never on the
  connect path.
- Concurrency. P/Invoke calls Rust from arbitrary .NET threads; the tunnel runs on a
  single-threaded `tokio` runtime (Quinn is async). So `app` is a serialized actor (one task
  draining an `mpsc` intent channel); intents are non-blocking and return immediately; results
  surface only via the observer callback; callbacks may arrive on any thread and must be marshaled
  to the UI thread (Avalonia's `Dispatcher.UIThread`).

---

## 5. The Rust core

```text
hysteria-ui/
  core/                   # one cargo workspace; only bind-* produce C-ABI libs
    Cargo.toml            # [workspace]
    crates/
      profile/            # parsed hysteria2:// profile: struct + serde + client-config mapper; NO parser (ext-linkable)
      config/             # hysteria2:// parse + validate -> profile::Profile; the untrusted-input parser (app-only)
      store/              # profile store: JSON doc + secrets; SecureStore trait DEFINED here
      hysteria/           # the Hysteria 2 client on Quinn: h3 auth + TCP + UDP/datagram + frag + Brutal CC + Salamander obfs + port-hop
      tunnel/             # smoltcp netstack + tun-rs fd; drives the hysteria client (ext-only)
      app/                # the Model: async serialized actor; state + stats snapshots; intents (app-only)
      errkind/            # connect-error enum; zero deps; produced in ext, relayed to app
      bind-app/           # cdylib+staticlib: extern "C" + csbindgen over {profile, config, store, app}
      bind-ext/           # cdylib+staticlib: extern "C" + csbindgen over {profile, store, hysteria, tunnel, errkind}
  ui/                     # ONE Avalonia .NET solution: shared views + platform heads (P/Invoke the C ABI)
  apple/                  # Swift NE PacketTunnelProvider + Xcode packaging (app head + extension)
  android/                # VpnService glue (in the .NET Android head) + packaging (later)
  windows/                # privileged service + Wintun + installer (later)
  linux/                  # privileged systemd daemon + packaging: Flatpak/AppImage/deb/rpm (later)
  PLAN.md
```

- `profile/` plus `config/` (split on purpose). `profile::Profile` is the parsed connection
  profile: struct plus `serde` plus a mapper to the `hysteria` client's config
  (TLS/QUIC/auth/bandwidth/obfs, including `obfsGecko`). It depends on `hysteria` types but no
  parser, so the extension can hold a validated blob and build a client without linking the URI
  parser. `config/` parses and validates the `hysteria2://` URI (including port-hopping) into
  `profile::Profile`. It runs app-side at save time (§4) and is app-only. As it parses untrusted
  input it ships a golden-corpus plus fuzz test (`cargo fuzz`).
- `store/` — `store::Entry { id, name, created_at, link: profile::Profile }` (the stored record
  holds a parsed profile, not a second `Profile`); add/delete/list only. `id` = UUID; dedup by
  normalized URI; `name` from the link's `#fragment`, else host. Non-secret metadata → one JSON
  doc written atomically to a platform container path; secret → `SecureStore`. The `SecureStore`
  trait is defined here (native-implemented, passed in at construction; §3.5); the extension uses
  a read-only view. No SQLite: a tiny ordered list needs no SQL engine.
- `hysteria/` — the Hysteria 2 client (§6, Phase 3). On Quinn: the HTTP/3 auth handshake
  (`h3`/`h3-quinn`), TCP relay over Quinn bidi streams and UDP relay over QUIC datagrams with
  fragmentation, Brutal congestion control as a Quinn `congestion::Controller`, Salamander
  obfuscation as a wrapping `AsyncUdpSocket`, and port hopping at the socket layer. Exposes a
  library API (`tcp_connect`, UDP sessions, `Close`) plus a byte counter at the stream/session
  boundary (the protocol carries no live counters). Maps connect failures into the `errkind` enum.
  Conformance-tested against the reference Hysteria 2 server (§6, §7).
- `tunnel/` — `smoltcp` netstack (§3.2) plus `tun-rs` fd, driving the `hysteria` client: feed
  tun-rs packets into smoltcp, route each accepted flow to `hysteria::tcp_connect` or a UDP
  session, copy bytes both ways. Ext-only. Counts traffic at the smoltcp↔hysteria seam for the
  stats snapshot.
- `errkind/` — a dependency-free leaf owning the connect-error enum (`AuthFailed |
ServerUnreachable | TlsPinMismatch | Timeout | Unknown`). Produced in the extension (which must
  not link `app`) and relayed up; both `tunnel`/`hysteria` and `app` depend on it, neither on the
  other.
- `app/` — the serialized `app` Model (the Model of Model–View). Depends on `config`, `store`,
  `errkind`, `profile`, never `tunnel`/`hysteria` (connect is driven through the OS, §4).
  - State: `Vec<store::Entry>`, `selected_id`, OS-derived `ConnectionState` (owned here),
      `last_error` (an `errkind` value).
  - Intents: `AddProfileFromURI`, `DeleteProfile`, `SelectProfile`, `Connect`, `Disconnect`.
  - One on-demand query `export_profile_uri(id) -> Vec<u8>` for the share view: reads the link
      from `SecureStore` only when the user opens share, returns it as bytes, and never places the
      URI in any state snapshot (snapshots stay secret-free; §7).
  - Two output channels, never merged: discrete state snapshots, and throttled stats.
  - `last_error` maps to one actionable UI sentence, no diagnostics screen.
- `bind-app/` plus `bind-ext/` — the binding boundary; the only crates that produce C-ABI libs.
  Two entry points: `bind-app: app_new(container_path, secure: SecureStore)` and
  `bind-ext: tunnel_new(...)`. The observer surface (`StateObserver`, `SubscribeStats`) is
  declared here as C-function-pointer callbacks; the internal crates stay decoupled behind Rust
  channels. The contract is additive-only and versioned; every snapshot carries a `schema_version`.

Crate dependency DAG (must stay acyclic): `profile` and `errkind` are sinks. `config → profile`;
`store → profile`; `hysteria → profile, errkind`; `tunnel → hysteria, profile, errkind`; `app →
config, store, errkind, profile` (never `tunnel`/`hysteria`); `bind-app → app, store, config`;
`bind-ext → tunnel, hysteria, store, errkind`. `bind-ext` must never reach `config` or `app` —
enforced at compile time by Cargo deps plus a `cargo tree` CI gate (§3.8).

Link entry is an Avalonia text field, the universal add path (including Android TV). QR scanning
is an optional shortcut only where a camera exists (camera → string → `AddProfileFromURI`). QR
generation for the share view is rendered in Rust (a `qrcode` crate) from `export_profile_uri`;
the Avalonia layer displays it alongside a Copy button.

---

## 6. Roadmap

1. Bootstrap the binding — `core/` cargo workspace; build a `staticlib`/`cdylib` with `csbindgen`
   and P/Invoke a single exported function from an empty Avalonia desktop app.
2. Memory spike — throwaway NE tunnel on a real iPhone: smoltcp plus a Quinn echo/dial, one
   hardcoded target, no UI. Measure RSS against the cap (§3.3); confirm smoltcp + Quinn + fd
   read/write run in the NE sandbox. Needs the entitlement in hand.
3. Implement the Hysteria 2 client (`hysteria/`) — developed standalone (no TUN yet): h3 auth
   handshake, TCP relay, UDP/datagram relay plus fragmentation, Brutal as a Quinn
   `congestion::Controller` (validate its pacing maps onto Quinn's pacer), Salamander obfs, port
   hopping. Conformance-test against the reference Hysteria 2 server (round-trip TCP plus UDP,
   with and without obfs), pinned to reference revision `c3a806b`.
4. Config plus store — `config` parser (→ `profile::Profile`) with `cargo fuzz` plus corpus;
   `store` over a container path plus `SecureStore`, with dev stubs; wire the
   `cargo tree`/`cargo-deny` CI gates (§3.8).
5. Model plus macOS UI (mocked tunnel) — `app` plus `bind-app`; the Avalonia desktop View (list /
   add / share (link + Copy + QR) / delete / select / connect) over P/Invoke (§1). This View fans
   out to every platform (step 8).
6. Real tunnel on macOS — `tunnel` (smoltcp plus tun-rs, driving the `hysteria` client) in
   `bind-ext`; Swift NE extension linking the `staticlib`; App Group plus Keychain;
   `ConnectionState` from `NEVPNStatus` (§4); status/stats IPC. Hidden defaults: full-tunnel
   route, autoconnect last profile.
7. Add-link UX plus share — Avalonia text entry (the universal path, including Android TV) plus an
   optional QR scanner where there is a camera; per-profile share view: the link with a Copy
   button (clipboard marked sensitive / local-only / auto-expiring; §7) plus its QR.
8. Fan out — only the OS shim, secure store, and packaging are new per platform: iOS/iPadOS (reuse
   the Swift NE extension; Avalonia iOS head), Android/Android TV (`VpnService` in the .NET Android
   head; D-pad focus pass), Windows (privileged service plus Wintun plus installer), Linux
   (privileged systemd daemon over `/dev/net/tun` plus Secret Service; Flatpak/AppImage/deb/rpm).

---

## 7. Security posture

Asset: the stored links (server plus auth, bearer credentials). Mitigations: local malware → OS
sandbox plus native secure store; locked-device theft → Keychain accessibility plus file
data-protection; network MITM → TLS pinning; supply chain → pinned crates plus signed builds;
implementation bugs → memory-safe Rust plus conformance/fuzz testing.

1. At rest — links only in the secure store (§3.5); the JSON doc holds no auth and uses
   `NSFileProtectionCompleteUntilFirstUserAuthentication` on Apple, `0600` perms under
   `$XDG_CONFIG_HOME` on Linux.
2. In memory — secrets cross the boundary as byte buffers (not C strings), zeroized after a
   connect via `zeroize`.
3. Transport — the link carries only `sni`, `insecure`, `pinSHA256` (auth in userinfo); a custom
   CA is config-file-only, so `pinSHA256` is the only secure path for self-signed servers via a
   link. Pin the end-entity cert (a rustls custom `ServerCertVerifier`) even when `insecure=1`:
    - accept `insecure=1` only with a `pinSHA256` (cert pinning, stronger than CA trust);
    - reject `insecure=1` without a pin;
    - accept plain CA-verified links.
4. Explicit import and share — a `hysteria2://` deep link or clipboard never auto-saves; adding
   always needs confirmation. Sharing is user-initiated only: no background clipboard writes; an
   explicit Copy in the share view marks the clipboard item sensitive (Android
   `ClipDescription.EXTRA_IS_SENSITIVE`), local-only (Apple `UIPasteboard` `.localOnly`), and
   auto-expiring (`.expirationDate` ≈ 30 s). The share view reads the secret on demand
   (`export_profile_uri`, §5) and never surfaces it in a state snapshot.
5. No telemetry — zero analytics / third-party SDKs.
6. Logging — release builds redact link, auth, and server address at the logger; the connect
   error is mapped to an `errkind` int in the extension, so the server address cannot leak across
   the boundary.
7. Supply chain and licensing — pin every crate; enforce with `cargo-deny` (license plus RustSec
   advisories) and a NuGet license scan. Prefer reproducible builds.
8. Protocol implementation is security-sensitive — conformance tests against the reference server,
   `cargo fuzz` on the parser and frame decoders, pinned reference revision, and a pre-release
   audit of `hysteria/`.
9. Distribution and least privilege — sign plus notarize on Apple, requesting only NE / App-Group
   / Keychain entitlements; signed non-debuggable Android release; Authenticode-signed Windows DLL
   plus installer over the signed Wintun driver; Linux via Flatpak (sandboxed) / AppImage / distro
   packages, with the systemd daemon granted only `CAP_NET_ADMIN` (not full root) and the GUI
   unprivileged.

---

## 8. Release gates and open decisions

- Crypto provider — pick the `rustls` provider (`ring` vs `aws-lc-rs`) by binary size and
  build-friendliness on iOS/Android. [Decide in the Phase-2 spike.]
- Store publishing org entity — Apple (Guideline 5.4) and Google Play both require organization
  enrollment plus D-U-N-S to publish a VPN; an individual account cannot. One legal entity (LLC or
  non-profit) covers both. Off-store routes need no entity: macOS Developer-ID-notarized, Android
  via APK/F-Droid, Windows outside the Microsoft Store, Linux via Flathub / distro repos. Gates
  release only. [Decision deferred until the core works.]
- App Store Guideline 5.4 — use NEVPNManager; the privacy policy commits to no third-party data
  sale; declare data collection before use.
- Acknowledgements bundle — generate a third-party-notices screen at build time spanning both
  trees: the Rust crates (`cargo-about`/`cargo-deny`) and the .NET/NuGet tree, plus the Wintun
  notice.
- Profile schema — version from day one for migration.

---

## 9. Reference points

Protocol: Hysteria 2 spec — <https://v2.hysteria.network/docs/developers/Protocol/>

Crate APIs:

- `quinn` — `quinn::congestion::{Controller, ControllerFactory}` (Brutal);
  `Connection::send_datagram`/`read_datagram` (UDP relay); custom `AsyncUdpSocket` (Salamander
  obfs plus port-hop); `TransportConfig`.
- `smoltcp` — `Interface` plus sockets (the userspace TCP/IP stack); fed by tun-rs, flows routed
  to the `hysteria` client.
- `tun-rs` — cross-platform TUN device / fd wrapper (utun, `/dev/net/tun`, Wintun, OS-provided
  fd).
- `h3` plus `h3-quinn` — HTTP/3 for the auth handshake over the Quinn connection.

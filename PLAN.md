# Hysteria UI — Architecture & Plan

Native Hysteria 2 **client** apps over a **shared Go core** (the app **Model** — all state + logic); only the UI is
platform-specific. Build macOS first, then iOS/iPadOS, Android/Android TV, and Windows.
_(Goal, scope, platforms: from user.)_

**Features (v1):** add a profile (**enter** a `hysteria2://` link — type it, or scan its QR where
there's a camera), share a profile (show its link with a Copy button + a QR code), delete a profile,
connect/disconnect a system-wide TUN.

**Upstream:** sibling repo `../hysteria`; we consume `apernet/hysteria/core/v2/client` and the same
`apernet/sing-tun` hysteria pins (its **system** stack — no gVisor; §3.2). Pinned versions:

- hysteria `c3a806b`
- `apernet/sing-tun v0.2.6-0.20250920121535-299f04629986` (`app/go.mod:11`)
- `apernet/quic-go v0.59.1-0.20260425001925-6c6cc9bcb716` (`core/go.mod:8`)

---

## 1. Principles

- **Minimal, granny-friendly.** The entire UI is: add a link, share a link, delete a link, connect,
  disconnect. **Entering** the link is the universal add path — typed text — so every platform,
  including **Android TV** (and any device with no camera), shares one interface; QR scanning is only
  an optional shortcut where a camera exists. Sharing is a **read-only** view (the link with a Copy
  button + its QR) — the one per-profile view there is. No settings screen, no rename, no editing: a
  profile _is_ its link (to change it, delete and re-add). Every setting that can have a default is
  defaulted and hidden (routing, autoconnect, launch-at-login, DNS, reconnect). A setting with no safe
  default is a design smell — re-derive it from the link or pick an opinionated default.
- **Security-first.** When security trades against simplicity or smaller scope, take the secure
  option. Less UI surface is also less attack surface, so the two principles reinforce each other.
  Full posture: §7.

---

## 2. Architecture

```text
                Shared Go core (one module, bound per platform)
   ┌─────────────────────────────────────────────────────────────────┐
   │   internal/  (rich Go — hidden from native & external imports): │
   │     profile/  parsed hysteria2:// profile (struct + JSON)       │
   │     config/   hysteria2:// parse + validate   (app-only)        │
   │     store/    JSON doc + SecureStore (secrets)                  │
   │     tunnel/   system netstack + core/client   (ext-only)        │
   │     app/      Model: serialized actor — snapshots + intents     │
   │     errkind/  connect-error enum (leaf)                         │
   │   bind/  app + ext facades — flat, binding-safe (JSON + cb)     │
   └─────────────────────────────────────────────────────────────────┘
        │ gomobile xcframework        │ gomobile .aar       │ c-shared DLL
        ▼ (Apple)                     ▼ (Android)           ▼ (Windows)
   SwiftUI Views                 Compose Views          WinUI/.NET Views
   (macOS/iOS/iPadOS)            (AndroidTV too)        (Windows)
```

**Model–View** with the **Model in Go**. The native View is the only platform-specific layer: it renders
a state snapshot from the Go `app.Model` and sends back user intents — no business logic in
Swift/Kotlin/C#. State flows one way: tunnel → OS → app observes → snapshot → UI (§4).

---

## 3. Constraints that shape the design

### 3.1 TUN is platform-mediated; one netstack serves all

Each OS hands the tunnel a file descriptor, or (Windows) the core opens the adapter:

| Platform             | Mechanism                                         | Core receives          |
| -------------------- | ------------------------------------------------- | ---------------------- |
| iOS / iPadOS / macOS | NetworkExtension Packet Tunnel Provider           | utun **fd**            |
| Android / Android TV | `VpnService.establish()` → `ParcelFileDescriptor` | **fd**                 |
| Windows              | **Wintun** adapter (kernel driver)                | core opens it directly |

`sing-tun` exposes `Options.FileDescriptor` (`tun.go:65`, used in `tun_darwin.go:52`), so the core
runs the whole netstack + client from a handed-in fd.

### 3.2 System netstack (apernet/sing-tun), on every platform

A TUN yields raw IP packets; a netstack turns them into connections. `sing-tun` offers two
(`stack.go:36`):

- **gVisor** — a userspace TCP/IP stack. The apernet fork hysteria pins **omits it**
  (`stack_gvisor_stub.go`: `WithGVisor = false`, no real `stack_gvisor.go`).
- **system** — what hysteria's CLI uses (`tun.NewSystem`, `server.go:79`).

**The system stack is also fully userspace — not kernel reinjection** (verified in
`stack_system.go`). It parses headers with `internal/clashtcpip`, opens a **local listener** on the
TUN gateway address, redirects TCP via a NAT table (`tcpNat`) and UDP via `udpnat`, then dials out
through the `Handler`. It uses **no raw sockets, no route table, no iptables** — only the utun **fd**,
a localhost listener, and outbound dials, all permitted in the iOS NE sandbox. (On desktop,
route/`autoRoute` setup is the privileged part — but that's the _app's_ job, separate from the stack;
on Apple `NEPacketTunnelNetworkSettings` does it instead.) It's exactly sing-box's non-gVisor option,
which ships on iOS.

**Decision: the system stack everywhere.** Keep the `apernet/sing-tun` hysteria already pins (no fork
swap to `sagernet/sing-tun`, no `sagernet/gvisor` dependency); it's also far lighter than gVisor on
the iOS NE memory cap (§3.3). Bridge to `core/client` by **reusing hysteria's `tunHandler` almost
verbatim** (`NewConnection → HyClient.TCP`, `NewPacketConnection → HyClient.UDP`; `server.go:105`/`:143`).
`[The one thing source can't prove is live NE-sandbox behavior of the listener + fd writes — the Phase-2 spike (§6) validates it, now on a much lighter stack.]`

### 3.3 iOS NE memory is the gate

The Go runtime + Hysteria + the netstack must fit the NE extension's hard memory cap. The cap rose to
**50 MB in iOS 15**, but recent reports (iPhone 14 Pro Max, iOS 17.3.1) show kills above **~15 MB**
(Apple Dev Forums; Xray-core #4422) — so **design to 15 MB** and treat 50 MB as an unreliable
ceiling. Choosing the **system stack over gVisor (§3.2) removes the single biggest memory consumer**;
the remaining weight is the Go runtime + quic-go buffers, not a userspace TCP/IP stack. Still tight,
so mitigate with GC tuning (`debug.SetMemoryLimit` ≈ 12 MB, set **only in the extension's entry
point** — a separate process on Apple; on Android/Windows the single shared process must not be
throttled that low) and by linking only the minimal subset into the extension (§4). iOS is the constraint; macOS's cap is generous — so measure this first (§6,
Phase 2). `[Confirm the live ceiling on target devices in the spike.]`

### 3.4 Binding surface is flat

gomobile / c-shared export only primitives, `[]byte`, `error`, exported structs (by reference), and
native-implemented callback interfaces — no generics, maps, or rich slices. So `bind/` is flat:
primitives + JSON strings for complex objects + an observer interface; all richness stays behind it
(under `internal/`, §5). The surface needs **two ABI adapters, not one**: `gomobile bind` wants Go
interfaces/structs, while the Windows **c-shared** build is a C ABI (`//export` funcs, a handle
table, C-function-pointer callbacks) — see `bind/cshared` (§5).

### 3.5 Secrets live in platform-native secure storage

The `hysteria2://` link is a bearer credential, read/written via a native `SecureStore`
(`get/set/delete`, keyed by profile id) — never a Go-written file (chosen for security):

- **Apple** — Keychain + **Access Group** (shares app↔extension), accessibility
  `kSecAttrAccessibleAfterFirstUnlock` (extension reconnects while locked; nothing readable before
  first unlock).
- **Android** — Keystore-wrapped AES-GCM (hardware-backed where available).
- **Windows** — DPAPI (`CryptProtectData`, per-user).

The dev plaintext stub is build-tag gated and never shipped.

### 3.6 macOS TUN: NetworkExtension, not a privileged helper

Use a NE Packet Tunnel (sandboxed, App-Store-eligible, **same code as iOS**) rather than a privileged
launchd helper (no App Store, you own privilege escalation). Needs the Network Extensions entitlement
(a paid account suffices to build/test; org only for App Store — §8).

---

## 4. Process, state & concurrency model

This is where VPN clients usually break, so the contract is explicit.

- **The OS owns connection state.** `NEVPNStatus` / `VpnService` / the Windows service is
  authoritative — the user can toggle the VPN from OS settings, and the OS can tear it down or
  memory-kill the extension. So `app/` **derives** `ConnectionState` from OS status events, never
  optimistically. One-way flow: extension → OS status → app observes → snapshot → UI.
- **Two binaries on Apple — a structural wall, not a convention.** App and NE extension are separate
  processes with no shared heap. All rich Go lives under `core/internal/` (hidden from native and
  external importers), and the two binding packages link **disjoint** subsets: `bind/app` →
  `internal/{profile, config, store, app}`; `bind/ext` → `internal/{profile, store (read), tunnel,
errkind}` **only** — never `config` (the parser) or `app` (the state machine). Keeping
  parsing/validation/app out of the extension is the lever for the iOS cap (§3.3): profiles are
  validated **app-side at save time**, and the extension consumes a minimal validated blob — a
  serialized `profile.Profile`, deserialized **without** linking the parser (that's why the struct
  lives in its own `profile` leaf, apart from `config`). A CI gate (`go list -deps ./bind/ext`)
  **fails the build** if an app-only package leaks in — the linker's dead-code elimination is not a
  guarantee to bet a hard memory cap on. On Android/Windows both subsets compile into one process —
  there the boundary is logical, but the import graph stays identical so the wall still holds.
- **The extension is self-sufficient.** On autoconnect/on-demand the OS may start it with the app not
  running; it reads the active profile (App Group) and secret (Keychain) itself. The app is never on
  the connect path.
- **Concurrency.** gomobile calls Go from arbitrary native threads; Go callbacks fire on a goroutine.
  So `app.Model` is a **serialized actor** (one goroutine draining an intent channel); intents are
  non-blocking and return immediately; results surface only via the observer; native callbacks may
  arrive on any thread and must be marshaled to the UI thread.

---

## 5. The Go core

```text
hysteria-ui/
  core/                   # one Go module; only bind/* are gomobile/c-shared bound
    go.mod                # require apernet/hysteria/core; replace -> ../../hysteria/core (dev)
    internal/             # all rich Go — unreachable from native and external importers
      profile/            # parsed hysteria2:// profile: struct + JSON + ClientConfig(); imports core/client, NO parser (ext-linkable)
      config/             # ParseURI(hysteria2://) + Validate -> profile.Profile; the untrusted-input parser (app-only)
      store/              # profile store: JSON doc + secrets; SecureStore interface DEFINED here
      tunnel/             # system netstack (apernet/sing-tun) + core/client from profile.Profile (ext-only)
      app/                # app.Model: serialized actor; state + stats snapshots; intents (app-only)
      errkind/            # connect-error enum; zero deps; produced in ext, relayed to app
    bind/                 # the gomobile/c-shared binding boundary; flat, binding-safe (§3.4)
      app/                # full surface: imports internal/{profile, config, store, app}
      ext/                # tunnel + read-only profile/secret ONLY: internal/{profile, store, tunnel, errkind}
      cshared/            # (Windows) cgo //export shim + handle table over bind/{app, ext}
  apple/                  # Xcode workspace
  android/                # Gradle (later)
  windows/                # .NET/WinUI (later)
  PLAN.md
```

- **`profile/` + `config/`** (split on purpose). `profile.Profile` is the parsed connection profile
  — **struct + JSON + a `ClientConfig() *client.Config`** mapper (the TLS/QUIC/auth/bandwidth/obfs
  fillers, incl. `obfsGecko`); it imports `core/client` but **no parser**, so the extension can hold
  a validated blob and build a client **without** linking the URI parser. `config/` ports hysteria's
  `hysteria2://` logic (`parseURI` `client.go:518`, `URI()` `:474`, plus `app/internal/url/url.go`
  for port-hopping) into `config.Parse`/`config.Validate` → `profile.Profile`; don't import the
  `app` module (drags cobra/viper) — copy and trim. It runs **app-side at save time** (§4) and is
  **app-only**. As it parses untrusted input it ships a **golden-corpus + fuzz test** and an
  upstream-sync procedure; upstreaming a stable package is the long-term fix.
- **`store/`** — `store.Entry{ID, Name, CreatedAt, Link profile.Profile}` (the stored record holds a
  parsed profile; named `Entry`, **not** a second `Profile`), add/delete/list only. `ID` = UUID;
  **dedup by normalized URI**; `Name` from the link's `#fragment`, else host. Non-secret metadata →
  one JSON doc written atomically by Go to a platform container path; secret → `SecureStore`. The
  **`SecureStore` interface is defined here** (consumer-side, Go idiom — `get/set/delete`,
  native-implemented, passed in at construction; §3.5); the extension uses the read-only slice, so
  `store` stays its sole consumer (no separate `secure/` package). **No SQLite:** a tiny ordered list
  needs no SQL engine, which would bloat the iOS extension and risk cross-process file-lock
  corruption. (`modernc.org/sqlite` is the escape hatch if real queries ever appear.)
- **`tunnel/`** — `apernet/sing-tun` **system** netstack (§3.2) bridged to
  `core/client.NewReconnectableClient` via a near-verbatim copy of hysteria's `tunHandler`; builds
  the client from `profile.Profile.ClientConfig()`; **ext-only**. `core/client` has **no byte
  counters** (`Client` is `TCP`/`UDP`/`Close`, `client.go:26`; `HandshakeInfo.Tx` is handshake
  bandwidth, not live traffic), so `tunnel/` counts traffic at a wrapping `client.ConnFactory`. It
  maps connect failures (`core/errors`) into the `errkind` enum **here in the extension** and
  surfaces the int via its callback — the rich error never crosses the boundary, so the server
  address can't leak (§7.6).
- **`errkind/`** — a dependency-free leaf owning the connect-error enum (`authFailed |
serverUnreachable | tlsPinMismatch | timeout | unknown`). Lives apart from `app` because it's
  produced in the **extension** (which must not link `app`) and relayed up; both `tunnel` and `app`
  import it, neither imports the other.
- **`app/`** — serialized `app.Model` (the "Model" of Model–View; the package is named for its
  capability, the live app state machine). Imports `config`, `store`, `errkind`, `profile` — **never
  `tunnel`** (connect is driven through the OS, §4).
    - State: `[]store.Entry`, `selectedID`, OS-derived `ConnectionState` (owned here), `lastError` (an
      `errkind` value).
    - Intents: `AddProfileFromURI`, `DeleteProfile`, `SelectProfile`, `Connect`, `Disconnect`.
    - One on-demand **query** `ExportProfileURI(id) → []byte` for the share view: it reads the link from
      `SecureStore` only when the user opens share, returns it as `[]byte` (not a snapshot field), and
      **never** places the URI in any state snapshot — snapshots stay secret-free (§7).
    - **Two output channels, never merged:** discrete state snapshots, and throttled stats.
    - `lastError` maps to one actionable UI sentence, no diagnostics screen (reconciles the minimal UI
      of §1 with the no-telemetry rule of §7).
- **`bind/`** — the binding boundary; the **only** non-`internal` packages, the only ones
  `gomobile bind` / c-shared export. Two entry points: `bind/app NewApp(containerPath, secure
SecureStore)` and `bind/ext NewTunnel(...)`. The native-implemented observer interfaces
  (`StateObserver`, `SubscribeStats`) are **declared in `bind/*`** (not in `app`) — gomobile
  generates the native stubs from the bound package's signatures, and `app` stays decoupled behind
  Go-native channels. `bind/cshared` adds the Windows C-ABI wrappers (handle table, C-function-pointer
  callbacks). A multi-consumer contract (three UIs) → **additive-only, versioned**; every snapshot
  carries a `schemaVersion`.

**Import DAG (must stay acyclic):** `profile` and `errkind` are sinks (imported widely; `profile`
imports only `core/client`, `errkind` imports nothing). `config → profile`; `store → profile`;
`tunnel → profile, errkind`; `app → config, store, errkind, profile` (never `tunnel`); `bind/app →
app, store, config`; `bind/ext → tunnel, store, errkind`. `bind/ext` must never reach `config` or
`app` — the `go list -deps` CI gate (§4) enforces it.

Link entry is native text input — the universal add path (incl. Android TV). QR **scanning** is an
optional native shortcut only where a camera exists (camera → string → `AddProfileFromURI`). QR
**generation** for the share view reuses `app/internal/utils/qr.go` (Go renders the QR from
`ExportProfileURI`); the native layer displays it alongside a Copy button.

---

## 6. Roadmap

1. **Bootstrap the binding** — `core/` with `replace → ../../hysteria/core`; build a trivial
   xcframework (`-target ios,iossimulator,macos`) and call Go from an empty SwiftUI app.
2. **Memory spike (de-risk first)** — throwaway NE tunnel on a **real iPhone**: system stack + client
    - one hardcoded profile, no UI. Measure RSS against the cap, and confirm the system stack actually
      runs in the NE sandbox (local listener + fd writes; §3.2). If it doesn't fit, the architecture
      changes (§3.3) — so learn it now. Needs the entitlement in hand. **Also the one-module-vs-two
      decision point:** if `internal/` + dead-code elimination don't keep the ext footprint down, split
      the bindings into separate modules — until then, one module (§5).
3. **Config + store** — port the parser into `internal/config` (→ `profile.Profile`) with fuzz +
   corpus tests; `internal/store` over a container path + `SecureStore`, with dev stubs; add the
   `go list -deps ./bind/ext` CI gate (§4).
4. **Model + macOS UI (mocked tunnel)** — `internal/app` + `bind/app`; SwiftUI list / add (text
   entry) / share (link + Copy + QR) / delete / select / connect — nothing else (§1).
5. **Real tunnel on macOS** — `internal/tunnel` in `bind/ext`; NE extension; App Group + Keychain;
   `ConnectionState` from `NEVPNStatus` (§4); status/stats IPC. Hidden defaults: full-tunnel route,
   autoconnect last profile.
6. **Add-link UX + share** — native text entry (the universal path, incl. Android TV) + optional QR
   scanner where there's a camera; per-profile **share view**: show the link with a Copy button
   (clipboard marked sensitive / local-only / auto-expiring; §7.4) + its QR (`qr.go`).
7. **Fan out** — iOS/iPadOS (reuse extension + core), then Android (`.aar` + `VpnService` + Compose),
   then Windows (DLL + Wintun service + WinUI).

---

## 7. Security posture (security-first)

**Asset:** the stored links (server + auth — bearer credentials). **Adversaries → mitigations:**
local malware → OS sandbox + native secure store; locked-device theft → Keychain accessibility +
file data-protection; network MITM → TLS pinning; supply chain → pinned deps + signed builds.

1. **At rest** — links only in the secure store (§3.5); the JSON doc holds no auth and uses
   `NSFileProtectionCompleteUntilFirstUserAuthentication` on Apple.
2. **In memory** — secrets cross the boundary as `[]byte` (not `string`), best-effort zeroed after a
   connect. `[Go GC may copy — zeroization is best-effort.]`
3. **Transport** (decided vs. schema) — the link carries only `sni`, `insecure`, `pinSHA256` (auth in
   userinfo); a custom CA is config-file-only, so `pinSHA256` is the only secure path for self-signed
   servers via a link. `pinSHA256` pins the end-entity cert even when `insecure=1` (`fillTLSConfig`,
   `client.go:359`). So:
    - **accept `insecure=1` only with a `pinSHA256`** (that is cert pinning, stronger than CA trust);
    - **reject `insecure=1` without a pin** (a MITM downgrade);
    - accept plain CA-verified links.
4. **Explicit import & share** — a `hysteria2://` deep link or clipboard never auto-saves; adding
   always needs confirmation. Sharing is **user-initiated only**: no background or automatic clipboard
   writes, but an explicit **Copy** in the share view is allowed, with mitigations — the clipboard
   item is marked **sensitive** (Android `ClipDescription.EXTRA_IS_SENSITIVE`, redacts the OS paste
   preview), **local-only** (Apple `UIPasteboard` `.localOnly` — no Universal/cross-device clipboard),
   and **auto-expiring** (`.expirationDate` ≈ 30 s). The shown link and QR are the bearer credential,
   so the share view requires the user to explicitly open it, reads the secret on demand
   (`ExportProfileURI`, §5), and never surfaces it in a state snapshot. QR export is likewise
   sensitive — show it only on an explicit, user-driven screen.
5. **No telemetry** — zero analytics / third-party SDKs.
6. **Logging** — release builds redact link, auth, and server address at the logger.
7. **Supply chain** — pin every dependency (see header); we add **no new netstack** — `sing-tun` is
   the same `apernet` fork hysteria already vets. Prefer reproducible builds.
8. **Distribution & least privilege** — sign + notarize on Apple, requesting only NE / App-Group /
   Keychain entitlements; signed non-debuggable Android release; Authenticode-signed Windows DLL +
   installer over the Microsoft-signed Wintun driver.

---

## 8. Open questions & release gates

- **iOS NE memory** — design to **~15 MB**; the Go runtime + quic-go are now the weight (the system
  stack dropped gVisor, §3.2), but it stays the top risk, measured in the Phase-2 device spike (§3.3).
- **Store publishing needs an org entity — for _both_ Apple and Google.** The Apple App Store
  (Guideline 5.4) and Google Play both require **organization** enrollment + D-U-N-S to publish a VPN;
  an individual account cannot (user has only an individual Apple account, no org). One legal entity
  covers both stores — an **LLC** (simple, pays the fees) or a **non-profit** (also valid; Apple
  waives the fee for a free app, but more governance). **Off-store routes need no entity:** macOS
  Developer-ID-notarized, Android via APK/F-Droid/third-party stores, Windows outside the Microsoft
  Store — **only the iOS App Store has no individual path**. Gates release only, not development or
  the Phase-2 spike. Verify in-jurisdiction (tax residency may create obligations regardless).
  `[Decision deferred until the core works.]`
- **App Store Guideline 5.4** — use NEVPNManager; the privacy policy must commit to no third-party
  data sale/disclosure; declare data collection before use; some territories need a VPN license in
  review notes. Our no-telemetry stance (§7) covers the data clause.
- **Profile schema** — version from day one for migration (design choice).

---

## 9. Reference points (`../hysteria`)

- `core/client/client.go:26` — `Client` interface (`TCP`/`UDP`/`Close`).
- `core/client/config.go`, `core/client/reconnect.go` — `Config` + `NewReconnectableClient`.
- `app/cmd/client.go:72` — full client config schema (mirror in `profile.Profile` + its fillers).
- `app/cmd/client.go:474` / `:518` — `URI()` / `parseURI` (the `hysteria2://` logic to port into `config`).
- `app/internal/url/url.go` — custom URL parser (port-hopping); copy into `internal/config`.
- `app/internal/tun/server.go:79` — `tun.NewSystem` (the system stack we keep); `:105`/`:143` —
  `tunHandler.NewConnection`/`NewPacketConnection` (→ `HyClient.TCP`/`UDP`), reuse near-verbatim.
- `apernet/sing-tun/stack_system.go` — system stack: `clashtcpip` headers + local listener + NAT,
  fully userspace (no raw sockets / routes / iptables).
- `app/internal/utils/qr.go` — QR generation for share/export.

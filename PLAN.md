# Hysteria UI — Architecture & Plan

Native Hysteria 2 **client** apps over a **shared Go core** (model + view-model); only the UI is
platform-specific. Build macOS first, then iOS/iPadOS, Android/Android TV, and Windows; tvOS is a
stretch goal (§8). _(Goal, scope, platforms: from user.)_

**Features (v1):** add a profile (paste a `hysteria2://` link or scan its QR), delete a profile,
connect/disconnect a system-wide TUN.

**Upstream:** sibling repo `../hysteria`; we consume `apernet/hysteria/core/v2/client` and a
gVisor-capable `sing-tun`. Pin hysteria `c3a806b` +
`apernet/quic-go v0.59.1-0.20260425001925-6c6cc9bcb716` (`core/go.mod:8`).

---

## 1. Principles

- **Minimal, granny-friendly.** The entire UI is: add a link, delete a link, connect, disconnect.
  No settings screen, no rename, no profile detail — a profile _is_ its link (to change it, delete
  and re-add). Every setting that can have a default is defaulted and hidden (routing, autoconnect,
  launch-at-login, DNS, reconnect). A setting with no safe default is a design smell: re-derive it
  from the link or pick an opinionated default.
- **Security-first.** When security trades against simplicity or smaller scope, take the secure
  option. Less UI surface is also less attack surface, so the two principles reinforce each other.
  Full posture: §7.

---

## 2. Architecture

```text
                Shared Go core (one codebase, bound per platform)
   ┌────────────────────────────────────────────────────────────────┐
   │  config/   profile model, hysteria2:// parse + validate        │
   │  store/    profile store: JSON doc + SecureStore for secrets   │
   │  tunnel/   gVisor netstack + Profile -> core/client            │
   │  vm/       AppModel: state + stats snapshots + intents         │
   │  bind/     app + ext facades; flat, binding-safe (JSON + cb)   │
   └────────────────────────────────────────────────────────────────┘
        │ gomobile xcframework        │ gomobile .aar       │ c-shared DLL
        ▼ (Apple)                     ▼ (Android)           ▼ (Windows)
   SwiftUI Views                 Compose Views          WinUI/.NET Views
   (macOS/iOS/iPadOS/tvOS)       (AndroidTV too)        (Windows)
```

MVVM with the **Model and ViewModel in Go**. The View is the only platform-specific layer: it
renders a state snapshot from the Go `AppModel` and sends back user intents — no business logic in
Swift/Kotlin/C#. State flows one way: tunnel → OS → app observes → snapshot → UI (§4).

---

## 3. Constraints that shape the design

### 3.1 TUN is platform-mediated; one netstack serves all

Each OS hands the tunnel a file descriptor, or (Windows) the core opens the adapter:

| Platform                    | Mechanism                                         | Core receives          |
| --------------------------- | ------------------------------------------------- | ---------------------- |
| iOS / iPadOS / tvOS / macOS | NetworkExtension Packet Tunnel Provider           | utun **fd**            |
| Android / Android TV        | `VpnService.establish()` → `ParcelFileDescriptor` | **fd**                 |
| Windows                     | **Wintun** adapter (kernel driver)                | core opens it directly |

`sing-tun` exposes `Options.FileDescriptor` (`tun.go:65`, used in `tun_darwin.go:52`), so the core
runs the whole netstack + client from a handed-in fd.

### 3.2 gVisor netstack, on every platform

A TUN yields raw IP packets; a netstack turns them into connections. Two strategies
(`sing-tun/stack.go:36`): the **system** stack reinjects via host sockets (hysteria's CLI uses it —
`tun.NewSystem`, `server.go:79`) but needs socket/route access the **iOS NE sandbox forbids**, so
Apple requires the userspace **gVisor** stack. The apernet `sing-tun` fork hysteria depends on
**ships no gVisor** (`stack_gvisor_stub.go`: `WithGVisor = false`), so we bring `sagernet/sing-tun`
built `-tags with_gvisor`.

**Decision: gVisor everywhere**, not just Apple — one behavior profile, one test surface. The
system stack is at most a later, measured, desktop-only optimization. Bridge to `core/client` with
hysteria's handler pattern (`NewConnection → TCP`, `NewPacketConnection → UDP`;
`server.go:117`/`:154`).

### 3.3 iOS NE memory is the gate

gVisor + Go runtime + Hysteria must fit the NE extension's hard memory cap. The cap rose to
**50 MB in iOS 15**, but recent reports (iPhone 14 Pro Max, iOS 17.3.1) show kills above **~15 MB**
(Apple Dev Forums; Xray-core #4422) — so **design to 15 MB** and treat 50 MB as an unreliable
ceiling. That is tight for Go + gVisor, hence the top risk. Mitigate with GC tuning
(`debug.SetMemoryLimit` ≈ 12 MB) and by linking only the minimal subset into the extension (§4).
iOS is the constraint; macOS's cap is generous — so this is measured first (§6, Phase 2).
`[Confirm the live ceiling on target devices in the spike.]`

### 3.4 Binding surface is flat

gomobile / c-shared export only primitives, `[]byte`, `error`, exported structs (by reference), and
native-implemented callback interfaces — no generics, maps, or rich slices. So `bind/` is flat:
primitives + JSON strings for complex objects + an observer interface. All richness stays behind it.

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

Use a NE Packet Tunnel (sandboxed, App-Store-eligible, **same code as iOS**) rather than a
privileged launchd helper (no App Store, you own privilege escalation). Needs the Network
Extensions entitlement (a paid account suffices to build/test; org only for App Store — §8).

---

## 4. Process, state & concurrency model

This is where VPN clients usually break, so the contract is explicit.

- **The OS owns connection state.** `NEVPNStatus` / `VpnService` / the Windows service is
  authoritative — the user can toggle the VPN from OS settings, and the OS can tear it down or
  memory-kill the extension. So `vm/` **derives** `ConnectionState` from OS status events, never
  optimistically. One-way flow: extension → OS status → app observes → snapshot → UI.
- **Two binaries on Apple.** App and NE extension are separate processes with no shared heap:
    - `bind/app` → `config/` + `store/` + `vm/`;
    - `bind/ext` → `tunnel/` + secret/profile read **only**.

        Keeping parsing/validation/vm out of the extension is the lever for the iOS cap (§3.3): profiles
        are validated **app-side at save time**; the extension consumes a minimal validated blob. On
        Android/Windows both sets compile into one process — the boundary is logical.

- **The extension is self-sufficient.** On autoconnect/on-demand the OS may start it with the app
  not running; it reads the active profile (App Group) and secret (Keychain) itself. The app is
  never on the connect path.
- **Concurrency.** gomobile calls Go from arbitrary native threads; Go callbacks fire on a
  goroutine. So `AppModel` is a **serialized actor** (one goroutine draining an intent channel);
  intents are non-blocking and return immediately; results surface only via the observer; native
  callbacks may arrive on any thread and must be marshaled to the UI thread.

---

## 5. The Go core

```text
hysteria-ui/
  core/                 # shared Go module; gomobile/c-shared bindable
    go.mod              # require apernet/hysteria/core; replace -> ../../hysteria/core (dev)
    config/             # Profile{} ; ParseURI(hysteria2://) ; Validate ; ToClientConfig()
    store/              # profile store; JSON doc at a container path + SecureStore for secrets
    tunnel/             # gVisor netstack + core/client; status/stats callbacks
    vm/                 # AppModel: serialized actor; state + stats snapshots; intents
    bind/
      app/              # facade for the app process: config + store + vm (full surface)
      ext/              # facade for the extension: tunnel + secret/profile read ONLY
  apple/                # Xcode workspace
  android/              # Gradle (later)
  windows/              # .NET/WinUI (later)
  PLAN.md
```

- **config/** — port hysteria's `hysteria2://` logic (`parseURI` `client.go:518`, `URI()` `:474`,
  plus `app/internal/url/url.go` for port-hopping); don't import the `app` module (drags
  cobra/viper) — copy and trim. Emits `*client.Config` via the CLI's fillers
  (TLS/QUIC/auth/bandwidth/obfs incl. `obfsGecko`). Runs app-side at save time (§4). As it parses
  untrusted input, it ships a **golden-corpus + fuzz test** and an upstream-sync procedure;
  upstreaming a stable package is the long-term fix.
- **store/** — `Profile{id, name, parsedFields, createdAt}`, add/delete/list only. `id` = UUID;
  **dedup by normalized URI**; `name` from the link's `#fragment`, else host. Non-secret metadata →
  one JSON doc written atomically by Go to a platform container path; secret → `SecureStore`
  (§3.5). **No SQLite**: a tiny ordered list needs no SQL engine, which would bloat the iOS
  extension and risk cross-process file-lock corruption. (`modernc.org/sqlite` is the escape hatch
  if real queries ever appear.)
- **tunnel/** — gVisor netstack (§3.2) bridged to `core/client.NewReconnectableClient`; linked only
  into the extension. `core/client` has **no byte counters** (`Client` is `TCP`/`UDP`/`Close`,
  `client.go:26`; `HandshakeInfo.Tx` is handshake bandwidth, not live traffic), so `tunnel/` counts
  traffic at a wrapping `client.ConnFactory`.
- **vm/** — serialized `AppModel`. State: `[]Profile`, `selectedID`, OS-derived `ConnectionState`,
  `lastError`. Intents: `AddProfileFromURI`, `DeleteProfile`, `SelectProfile`, `Connect`,
  `Disconnect`. **Two output channels, never merged**: discrete state snapshots, and throttled
  stats. `lastError` is a mapped enum (`authFailed | serverUnreachable | tlsPinMismatch | timeout |
unknown`) from `core/errors` → one actionable UI sentence, no diagnostics screen (reconciles the
  minimal UI of §1 with the no-telemetry rule of §7).
- **bind/** — two entry points: `bind/app NewApp(containerPath, secure SecureStore)` and
  `bind/ext NewTunnel(...)`; `Subscribe(StateObserver)` + `SubscribeStats(...)`, implemented
  natively. A multi-consumer contract (three UIs) → **additive-only, versioned**; every snapshot
  carries a `schemaVersion`.

QR scanning is native (camera → string → `AddProfileFromURI`); generation reuses
`app/internal/utils/qr.go`.

---

## 6. Roadmap

1. **Bootstrap the binding** — `core/` with `replace → ../../hysteria/core`; build a trivial
   xcframework (`-target ios,iossimulator,macos`) and call Go from an empty SwiftUI app. (No tvOS
   here — gomobile can't target it; §8.)
2. **Memory spike (de-risk first)** — throwaway NE tunnel on a **real iPhone**: gVisor + client +
   one hardcoded profile, no UI. Measure RSS against the cap. If it doesn't fit, the architecture
   changes (§3.3) — so learn it now. Needs the entitlement in hand.
3. **Config + store** — port parsing into `config/` with fuzz + corpus tests; `store/` over a
   container path + `SecureStore`, with dev stubs.
4. **ViewModel + macOS UI (mocked tunnel)** — `vm/` + `bind/app`; SwiftUI list / add / delete /
   select / connect — nothing else (§1).
5. **Real tunnel on macOS** — `tunnel/` in `bind/ext`; NE extension; App Group + Keychain;
   `ConnectionState` from `NEVPNStatus` (§4); status/stats IPC. Hidden defaults: full-tunnel route,
   autoconnect last profile.
6. **QR** — native scanner + share/export.
7. **Fan out** — iOS/iPadOS (reuse extension + core), then Android (`.aar` + `VpnService` +
   Compose), then Windows (DLL + Wintun service + WinUI). tvOS is a **stretch goal** (manual
   `c-archive` build, no camera → manual entry; §8), not part of v1.

---

## 7. Security posture (security-first)

**Asset:** the stored links (server + auth — bearer credentials). **Adversaries → mitigations:**
local malware → OS sandbox + native secure store; locked-device theft → Keychain accessibility +
file data-protection; network MITM → TLS pinning; supply chain → pinned deps + signed builds.

1. **At rest** — links only in the secure store (§3.5); the JSON doc holds no auth and uses
   `NSFileProtectionCompleteUntilFirstUserAuthentication` on Apple.
2. **In memory** — secrets cross the boundary as `[]byte` (not `string`), best-effort zeroed after
   a connect. `[Go GC may copy — zeroization is best-effort.]`
3. **Transport** (decided vs. schema) — the link carries only `sni`, `insecure`, `pinSHA256` (auth
   in userinfo); a custom CA is config-file-only, so `pinSHA256` is the only secure path for
   self-signed servers via a link. `pinSHA256` pins the end-entity cert even when `insecure=1`
   (`fillTLSConfig`, `client.go:359`). So: **accept `insecure=1` only with a `pinSHA256`** (that is
   cert pinning, stronger than CA trust); **reject `insecure=1` without a pin** (a MITM downgrade);
   accept plain CA-verified links.
4. **Explicit import** — a `hysteria2://` deep link or clipboard never auto-saves; adding always
   needs confirmation. We never write secrets to the clipboard; QR export is sensitive.
5. **No telemetry** — zero analytics / third-party SDKs.
6. **Logging** — release builds redact link, auth, and server address at the logger.
7. **Supply chain** — pin every dependency (see header); review the added `sing-tun`; prefer
   reproducible builds.
8. **Distribution & least privilege** — sign + notarize on Apple, requesting only NE / App-Group /
   Keychain entitlements; signed non-debuggable Android release; Authenticode-signed Windows DLL +
   installer over the Microsoft-signed Wintun driver.

---

- **iOS NE memory** — design to **~15 MB**; Go + gVisor make this the top risk, measured in the
  Phase-2 device spike (§3.3).
- **tvOS — feasible, off the happy path** (not blocked). gomobile can't emit tvOS, but Go builds
  for it with `GOOS=ios` + the AppleTV SDK (`-target arm64-apple-tvos…`) — the pattern Tailscale
  ships (`runtime.GOOS` reports `ios` on tvOS, distinguished at runtime; their Go fork helps but
  isn't required). So tvOS = a manual `c-archive`→xcframework build, not research. Real blockers:
  the extra build rig and no camera (QR → manual entry). Deferred for sequencing, not capability.
- **Apple account** — individual, no org available (from user). App Store VPN publishing requires
  **organization** enrollment (Guideline 5.4), which needs a real **legal entity** + D-U-N-S (no
  DBAs/sole-proprietors). Options: an **LLC/company** (simple, pays the $99/yr) or a **non-profit**
  (also valid; a _free_ app gets the fee waived and a privacy tool is a legitimate mission, but
  more governance). Gates only iOS/tvOS **store release** — not development or the Phase-2 spike
  (the individual account + NE entitlement cover those), and macOS can ship Developer-ID-notarized
  with no entity. Verify feasibility in-jurisdiction. `[Decision: LLC vs non-profit vs
macOS-only-for-now — deferred until the core works.]`
- **App Store Guideline 5.4** — use NEVPNManager; the privacy policy must commit to no third-party
  data sale/disclosure; declare data collection before use; some territories need a VPN license in
  review notes. Our no-telemetry stance (§7) covers the data clause.
- **Profile schema** — version from day one for migration (design choice).

---

## 9. Reference points (`../hysteria`)

- `core/client/client.go:26` — `Client` interface (`TCP`/`UDP`/`Close`).
- `core/client/config.go`, `core/client/reconnect.go` — `Config` + `NewReconnectableClient`.
- `app/cmd/client.go:72` — full client config schema (mirror in `config/Profile`).
- `app/cmd/client.go:474` / `:518` — `URI()` / `parseURI` (the `hysteria2://` logic to port).
- `app/internal/url/url.go` — custom URL parser (port-hopping); copy into `config/`.
- `app/internal/tun/server.go` — sing-tun handler pattern to mirror in `tunnel/`.
- `app/internal/utils/qr.go` — QR generation for share/export.

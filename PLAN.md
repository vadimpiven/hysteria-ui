# Hysteria UI — Architecture & Plan

Native Hysteria 2 **client** apps over a **shared Go core** (the app **Model** — all state + logic) and a
**single shared .NET/Avalonia View** (the UI); only the thin OS-integration shims (TUN provider, secure
store) are platform-specific. Build macOS first, then iOS/iPadOS, Android/Android TV, Windows, and Linux.
_(Goal, scope, platforms: from user.)_

**Features (v1):** add a profile (**enter** a `hysteria2://` link — type it, or scan its QR where
there's a camera), share a profile (show its link with a Copy button + a QR code), delete a profile,
connect/disconnect a system-wide TUN.

**Upstream:** sibling repo `../hysteria` — we consume **only** `apernet/hysteria/core/v2/client`
(MIT). The TUN netstack is **Outline SDK** (`golang.getoutline.org/sdk`, Apache-2.0) — *not*
`apernet/sing-tun`, which is GPL-3.0 and would foreclose the iOS App Store (§3.7). Pinned versions:

- hysteria `c3a806b` (core module only)
- `golang.getoutline.org/sdk` (Apache-2.0) — its `network` + `network/lwip2transport` (§3.2); pin at integration
- `eycorsican/go-tun2socks v1.16.11` (transitive via Outline — Go wrapper MIT, lwIP C core BSD-3)
- `apernet/quic-go v0.59.1-0.20260425001925-6c6cc9bcb716` (`core/go.mod:8`)
- **.NET / Avalonia UI** (pinned in the UI project, not `go.mod`): Avalonia (MIT), SkiaSharp (MIT over Skia BSD-3) — §3.7

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
                Shared Go core (one Go module, C-ABI bound)
   ┌─────────────────────────────────────────────────────────────────┐
   │   internal/  (rich Go — hidden from native & external imports): │
   │     profile/  parsed hysteria2:// profile (struct + JSON)       │
   │     config/   hysteria2:// parse + validate   (app-only)        │
   │     store/    JSON doc + SecureStore (secrets)                  │
   │     tunnel/   Outline lwIP netstack + core/client (ext-only)    │
   │     app/      Model: serialized actor — snapshots + intents     │
   │     errkind/  connect-error enum (leaf)                         │
   │   bind/  app + ext facades + C-ABI shim — flat (JSON + cb)      │
   └─────────────────────────────────────────────────────────────────┘
                          │  c-archive / c-shared — ONE C ABI, every target
                          ▼  P/Invoke
              Single .NET / Avalonia View — shared by ALL platforms
              (macOS · iOS/iPadOS · Android(+TV) · Windows · Linux)

   Platform-native shims (each in its own language, behind the core):
     Apple → Swift NE PacketTunnelProvider      Android → VpnService
     Windows → service + Wintun                 Linux → systemd daemon + /dev/net/tun
```

**Model–View** with the **Model in Go** and a **single shared .NET/Avalonia View**. The View renders a
state snapshot from the Go `app.Model` and sends back user intents — no business logic in C# either; it
is a thin shell over the Go Model. The only platform-specific code is the OS-integration shims (TUN
provider, secure store), each in its native language behind the core. State flows one way: tunnel → OS →
app observes → snapshot → UI (§4).

---

## 3. Constraints that shape the design

### 3.1 TUN is platform-mediated; one netstack serves all

Each OS hands the tunnel a file descriptor, or (Windows) the core opens the adapter:

| Platform             | Mechanism                                         | Core receives          |
| -------------------- | ------------------------------------------------- | ---------------------- |
| iOS / iPadOS / macOS | NetworkExtension Packet Tunnel Provider           | utun **fd**            |
| Android / Android TV | `VpnService.establish()` → `ParcelFileDescriptor` | **fd**                 |
| Windows              | **Wintun** adapter (kernel driver)                | core opens it directly |
| Linux                | `/dev/net/tun` via `ioctl(TUNSETIFF)` (kernel)    | daemon opens it directly |

Outline's netstack consumes a `network.IPDevice` — a plain `Read`/`Write`/`Close` over raw IP
packets (`network/device.go:33`). On Apple/Android we wrap the handed-in **fd** as an `IPDevice`
and `io.Copy` it against the lwIP device (§3.2); on Windows we open the **Wintun** adapter via
WireGuard's `wintun` Go bindings (MIT) — which `LoadLibrary` the bundled `wintun.dll` (§3.7) — and
on Linux the privileged daemon opens **`/dev/net/tun`** (`ioctl(TUNSETIFF)`, needs `CAP_NET_ADMIN`),
wrapping *that* fd as an `IPDevice`. No
privileged route/iptables work lives in the core — the OS (Apple `NEPacketTunnelNetworkSettings`,
Android `VpnService`) or the privileged side (Windows service; Linux daemon via netlink/rtnetlink)
sets routes.

### 3.2 Userspace netstack: Outline SDK lwIP, on every platform

A TUN yields raw IP packets; a netstack turns them into connections. We use **Outline SDK**'s
netstack (`golang.getoutline.org/sdk`, Apache-2.0) — Google Jigsaw's, shipping in production VPN
clients — instead of `apernet/sing-tun`. The driver is **licensing** (§3.7): `sing-tun` is GPL-3.0;
Outline's stack and its dependencies are permissive (Apache-2.0 / MIT / BSD-3), so the binary stays
App-Store-eligible.

Under the hood it is **lwIP** — a fully-userspace embedded C TCP/IP stack via
`eycorsican/go-tun2socks` (no raw sockets, no route table, no iptables; just the fd + outbound
dials, all permitted in the iOS NE sandbox). The bridge is one call:

```go
lwip2transport.ConfigureDevice(sd transport.StreamDialer, pp network.PacketProxy) (network.IPDevice, error)
```

— it returns an `IPDevice` we `io.Copy` against the platform TUN fd (§3.1). We supply `sd`/`pp` by
**adapting `core/client` onto Outline's open transport interfaces** (our own code, §5) — the same
glue hysteria's `tunHandler` does, but re-derived onto a permissive interface instead of copied from
GPL code:

- `transport.StreamDialer.DialStream(ctx, raddr)` → `client.Client.TCP(raddr)` (`client.go:27`)
- `network.PacketProxy` session → `client.Client.UDP()` (`HyUDPConn.Send`/`Receive`, `client.go:28,32`)

Two caveats: lwIP is **C, so the core now links cgo** (standard for NE / gomobile / c-shared, but it
shapes the build), and lwIP is a **process-wide singleton** — one tunnel at a time, which a
single-VPN client never exceeds.
`[The one thing source can't prove is live NE-sandbox behavior of lwIP + fd writes — the Phase-2 spike (§6) validates it.]`

### 3.3 iOS NE memory is the gate

The Go runtime + Hysteria + the netstack must fit the NE extension's hard memory cap. The cap rose to
**50 MB in iOS 15**, but recent reports (iPhone 14 Pro Max, iOS 17.3.1) show kills above **~15 MB**
(Apple Dev Forums; Xray-core #4422) — so **design to 15 MB** and treat 50 MB as an unreliable
ceiling. **lwIP (§3.2) is an embedded C stack designed for KB-scale RAM**, so the netstack is the
*lightest* of the options (far below gVisor; lighter than sing-tun's system stack); the dominant
weight is the Go runtime + quic-go buffers, not the TCP/IP stack. Still tight, so mitigate with GC
tuning (`debug.SetMemoryLimit` ≈ 12 MB, set **only in the extension's entry point** — a separate
process on Apple; on Android/Windows the single shared process must not be throttled that low) and
by linking only the minimal subset into the extension (§4). **The .NET/Avalonia runtime never enters
the extension** — it lives only in the app process; the NE extension is a Swift shim + Go (c-archive),
so the shared-UI choice can't threaten the cap. iOS is the constraint; macOS's cap is
generous — so measure this first (§6, Phase 2). `[Confirm the live ceiling on target devices in the spike.]`

### 3.4 Binding surface is flat — one C ABI for every platform

Because the View is a single .NET/Avalonia app (§2), every platform consumes the core through the
**same C ABI** via P/Invoke — `gomobile` is dropped. The core ships as a `c-archive` (statically
linked on Apple, incl. the NE extension) or `c-shared` `.so`/`.dll` (Linux/Windows/Android), built
once with `CGO_ENABLED=1`. A C ABI exports only primitives, `[]byte` (pointer+len), ints-for-errors,
and C-function-pointer callbacks — no generics, maps, or rich slices — so `bind/` is flat: primitives
+ JSON strings for complex objects + a callback for the observer; all richness stays behind it (under
`internal/`, §5). **One adapter, not two**: a handle table over `bind/{app, ext}` with `//export`
funcs and function-pointer callbacks, marshaled on the .NET side by P/Invoke — see `bind/cshared` (§5).

### 3.5 Secrets live in platform-native secure storage

The `hysteria2://` link is a bearer credential, read/written via a native `SecureStore`
(`get/set/delete`, keyed by profile id) — never a Go-written file (chosen for security):

- **Apple** — Keychain + **Access Group** (shares app↔extension), accessibility
  `kSecAttrAccessibleAfterFirstUnlock` (extension reconnects while locked; nothing readable before
  first unlock).
- **Android** — Keystore-wrapped AES-GCM (hardware-backed where available).
- **Windows** — DPAPI (`CryptProtectData`, per-user).
- **Linux** — the **Secret Service** API over D-Bus (gnome-keyring / KWallet), collection-locked with
  the login session. Reached over D-Bus, so nothing LGPL is linked (§3.7).

`SecureStore` is implemented in C# in the app on every platform; on Apple the NE extension additionally
reads the secret itself in Swift via the shared Keychain Access Group (§4). The dev plaintext stub is
build-tag gated and never shipped.

### 3.6 macOS TUN: NetworkExtension, not a privileged helper

Use a NE Packet Tunnel (sandboxed, App-Store-eligible, **same code as iOS**) rather than a privileged
launchd helper (no App Store, you own privilege escalation). Needs the Network Extensions entitlement
(a paid account suffices to build/test; org only for App Store — §8).

### 3.7 Licensing constrains the netstack (the reason for §3.2)

The distributed binary's license is set by its heaviest-copyleft link, and a Go binary statically
links everything. The pieces:

- `apernet/hysteria/core` — **MIT**; the client is a clean, maintainer-blessed library import.
- `golang.getoutline.org/sdk` — **Apache-2.0**; `go-tun2socks` wrapper **MIT**, lwIP C core **BSD-3**.
- `golang.zx2c4.com/wintun` (Windows) — the Go bindings are **MIT**, but they `LoadLibrary`
  a separate **`wintun.dll`** — a bundled *binary* dependency, not a Go module. Its source is GPLv2,
  but the prebuilt signed DLL from wintun.net ships under a *more permissive* license whose §3d
  grants redistribution **alongside software that uses it only via the public `wintun.h` API** — no
  written consent needed. So we vendor the signed DLL into the installer (we don't rebrand it as
  "Wintun" — trademark), pinned to a fixed version with **build-time checksum + Authenticode
  verification** (the Mullvad model). It's WireGuard-LLC-kernel-signed; we redistribute as-is and
  never sign the driver ourselves. End users download nothing separately. `[Supply-chain note: we
  depend on WireGuard LLC's MS signing standing — pin a known-good DLL rather than fetch latest.]`
- `.NET` runtime + BCL (**MIT**), `Avalonia` (**MIT**), `SkiaSharp` (**MIT** wrapper over Skia, **BSD-3**) —
  the shared-UI stack is wholly permissive; on Linux the secret store is reached over the Secret
  Service **D-Bus** API, so LGPL `libsecret`/GTK are never linked.
- **Linux TUN** — `/dev/net/tun` is a kernel interface (no bundled driver, unlike Wintun), so Linux
  adds no binary-redistribution or licensing burden.
- `apernet/sing-tun` — **GPL-3.0**. Linking it makes the whole binary a combined GPL-3.0 work on
  distribution, widely held **incompatible with the Apple App Store** (the VLC precedent; FSF's
  standing position). sing-box ships on the App Store only because its author *is* sing-tun's
  copyright holder and self-grants — a third party is bound.

So the netstack choice **is** the App-Store-eligibility choice: Outline's permissive lwIP keeps the
iOS path open (§8); sing-tun would close it. This also matches hysteria's maintainers' on-record
stance — depend on `core` (MIT) as a library, and the `app` module is MIT to copy *except the TUN
feature*, the carve-out being precisely sing-tun's GPL (PR `apernet/hysteria#996`). The full runtime
tree is otherwise permissive (MIT / Apache-2.0 / BSD-3) — **no GPL/LGPL/MPL once sing-tun is out** —
so our own code is free to take any license (it does: dual `Apache-2.0 OR MIT`, `LICENSE-*` at root).
`[Not legal advice — confirm with counsel before release.]`

### 3.8 cgo on every build path

The C ABI (§3.4) is `c-archive`/`c-shared`, which requires `CGO_ENABLED=1` even when our Go adds no C —
so every target needs a C toolchain and a configured cross-compile in CI: Apple (clang, device +
simulator slices), Android (NDK clang), Windows (mingw-w64 or MSVC), Linux (gcc/clang). `CGO_ENABLED=0`
is ruled out on every path; it shapes the CI runners. The asymmetry that matters is now about
*third-party* C, not cgo-on/off: `core/client` and the whole `bind/app` subset pull in **no C library**
(pure-Go quic-go), while only `bind/ext` links **lwIP**. So the extension carries the C netstack and
the app does not — the weight that maps to the iOS memory wall (§3.3) — reinforcing the two-binary
split (§4).

---

## 4. Process, state & concurrency model

This is where VPN clients usually break, so the contract is explicit.

- **The OS owns connection state.** `NEVPNStatus` / `VpnService` / the Windows service is
  authoritative — the user can toggle the VPN from OS settings, and the OS can tear it down or
  memory-kill the extension. So `app/` **derives** `ConnectionState` from OS status events, never
  optimistically. One-way flow: extension → OS status → app observes → snapshot → UI.
- **A privileged tunnel process, walled from the app — structural, not a convention.** On Apple (NE
  extension), Windows (service), and Linux (systemd daemon) the tunnel runs in a **separate privileged
  process** with no shared heap; on Android it shares the app process (the wall is then logical). All
  rich Go lives under `core/internal/` (hidden from native and external importers), and the two binding
  facades link **disjoint** subsets: `bind/app` → `internal/{profile, config, store, app}`; `bind/ext`
  → `internal/{profile, store (read), tunnel, errkind}` **only** — never `config` (the parser) or
  `app` (the state machine). Keeping parsing/validation/app out of the tunnel process is the lever for
  the iOS cap (§3.3): profiles are validated **app-side at save time**, and the tunnel consumes a
  minimal validated blob — a serialized `profile.Profile`, deserialized **without** linking the parser
  (that's why the struct lives in its own `profile` leaf, apart from `config`). The **.NET/Avalonia
  runtime lives only in the app process**; the privileged side is a native shim (Swift / service /
  daemon) + Go (c-archive), never .NET — so the UI toolkit never weighs on the tunnel. A CI gate
  (`go list -deps ./bind/ext`) **fails the build** if an app-only package leaks in — the linker's
  dead-code elimination is not a guarantee to bet a hard memory cap on. The import graph is identical
  on every platform, so the wall holds even where (Android) it's one process.
- **The tunnel process is self-sufficient.** On autoconnect/on-demand it may start with the app not
  running; it reads the active profile and secret itself (Apple: App Group + Keychain; Linux: config
  dir + Secret Service; Windows: per-user store + DPAPI). The app/GUI is never on the connect path.
- **Concurrency.** P/Invoke calls Go from arbitrary .NET threads; Go callbacks fire on a goroutine and
  cross back as C function pointers. So `app.Model` is a **serialized actor** (one goroutine draining
  an intent channel); intents are non-blocking and return immediately; results surface only via the
  observer; callbacks may arrive on any thread and must be marshaled to the UI thread (Avalonia's
  `Dispatcher.UIThread`).

---

## 5. The Go core

```text
hysteria-ui/
  core/                   # one Go module; only bind/* are C-ABI exported (c-archive/c-shared)
    go.mod                # require apernet/hysteria/core; replace -> ../../hysteria/core (dev)
    internal/             # all rich Go — unreachable from native and external importers
      profile/            # parsed hysteria2:// profile: struct + JSON + ClientConfig(); imports core/client, NO parser (ext-linkable)
      config/             # ParseURI(hysteria2://) + Validate -> profile.Profile; the untrusted-input parser (app-only)
      store/              # profile store: JSON doc + secrets; SecureStore interface DEFINED here
      tunnel/             # Outline lwIP netstack (cgo) + core/client adapter from profile.Profile (ext-only)
      app/                # app.Model: serialized actor; state + stats snapshots; intents (app-only)
      errkind/            # connect-error enum; zero deps; produced in ext, relayed to app
    bind/                 # the C-ABI binding boundary; flat, binding-safe (§3.4)
      app/                # full surface: imports internal/{profile, config, store, app}
      ext/                # tunnel + read-only profile/secret ONLY: internal/{profile, store, tunnel, errkind}
      cshared/            # the single C ABI for ALL platforms: cgo //export shim + handle table over bind/{app, ext}
  ui/                     # ONE Avalonia .NET solution: shared views + platform heads (P/Invoke the C ABI)
  apple/                  # Swift NE PacketTunnelProvider + Xcode packaging (app head + extension)
  android/                # VpnService glue (in the .NET Android head) + packaging (later)
  windows/                # privileged service + Wintun + installer (later)
  linux/                  # privileged systemd daemon + packaging: Flatpak/AppImage/deb/rpm (later)
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
- **`tunnel/`** — Outline SDK's **lwIP** netstack (§3.2) bridged to
  `core/client.NewReconnectableClient` via **our own adapter** (not copied from hysteria): a
  `transport.StreamDialer` wrapping `client.TCP` and a `network.PacketProxy` wrapping `client.UDP`,
  handed to `lwip2transport.ConfigureDevice`, with an `io.Copy` loop against the platform fd (§3.1).
  Builds the client from `profile.Profile.ClientConfig()`; links **cgo** (lwIP is C); **ext-only**.
  `core/client` has **no byte counters** (`Client` is `TCP`/`UDP`/`Close`, `client.go:26`;
  `HandshakeInfo.Tx` is handshake bandwidth, not live traffic), so `tunnel/` counts traffic **in the
  adapter** (wrapping the `StreamConn` + packet sessions). It maps connect failures (`core/errors`)
  into the `errkind` enum **here in the extension** and surfaces the int via its callback — the rich
  error never crosses the boundary, so the server address can't leak (§7.6).
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
- **`bind/`** — the binding boundary; the **only** non-`internal` packages, the only ones the C ABI
  exports. Two entry points: `bind/app NewApp(containerPath, secure SecureStore)` and `bind/ext
  NewTunnel(...)`. The observer surface (`StateObserver`, `SubscribeStats`) is **declared in `bind/*`**
  (not in `app`), and `app` stays decoupled behind Go-native channels. `bind/cshared` is the **single
  C-ABI shim for every platform** (handle table, `//export` funcs, C-function-pointer callbacks),
  consumed from C# by P/Invoke — there is no second (gomobile) adapter. A single multi-platform
  consumer (one .NET View) still gets an **additive-only, versioned** contract; every snapshot carries
  a `schemaVersion`.

**Import DAG (must stay acyclic):** `profile` and `errkind` are sinks (imported widely; `profile`
imports only `core/client`, `errkind` imports nothing). `config → profile`; `store → profile`;
`tunnel → profile, errkind`; `app → config, store, errkind, profile` (never `tunnel`); `bind/app →
app, store, config`; `bind/ext → tunnel, store, errkind`. `bind/ext` must never reach `config` or
`app` — the `go list -deps` CI gate (§4) enforces it.

Link entry is an Avalonia text field — the universal add path (incl. Android TV). QR **scanning** is an
optional shortcut only where a camera exists (camera → string → `AddProfileFromURI`). QR
**generation** for the share view reuses `app/internal/utils/qr.go` (Go renders the QR from
`ExportProfileURI`); the Avalonia layer displays it alongside a Copy button.

---

## 6. Roadmap

1. **Bootstrap the binding** — `core/` with `replace → ../../hysteria/core`; build the C-ABI lib
   (`c-archive`/`c-shared`) and P/Invoke a single exported function from an empty Avalonia desktop app.
2. **Memory spike (de-risk first)** — throwaway NE tunnel on a **real iPhone**: lwIP stack + client
    - one hardcoded profile, no UI — the extension is Swift + Go (`c-archive`), no .NET runtime, so it
      measures the real shipping footprint. Measure RSS against the cap, and confirm lwIP + cgo actually
      run in the NE sandbox (fd read/write loop; §3.2). If it doesn't fit, the architecture
      changes (§3.3) — so learn it now. Needs the entitlement in hand. **Also the one-module-vs-two
      decision point:** if `internal/` + dead-code elimination don't keep the ext footprint down, split
      the bindings into separate modules — until then, one module (§5).
3. **Config + store** — port the parser into `internal/config` (→ `profile.Profile`) with fuzz +
   corpus tests; `internal/store` over a container path + `SecureStore`, with dev stubs; add the
   `go list -deps ./bind/ext` CI gate (§4).
4. **Model + macOS UI (mocked tunnel)** — `internal/app` + `bind/app` + `bind/cshared`; the Avalonia
   desktop View (list / add (text entry) / share (link + Copy + QR) / delete / select / connect) over
   P/Invoke — nothing else (§1). This View is the one that fans out to every platform (step 7).
5. **Real tunnel on macOS** — `internal/tunnel` (hysteria→Outline adapter, §5) in `bind/ext`; NE
   extension; App Group + Keychain; `ConnectionState` from `NEVPNStatus` (§4); status/stats IPC.
   Hidden defaults: full-tunnel route, autoconnect last profile.
6. **Add-link UX + share** — Avalonia text entry (the universal path, incl. Android TV) + optional QR
   scanner where there's a camera; per-profile **share view**: show the link with a Copy button
   (clipboard marked sensitive / local-only / auto-expiring; §7.4) + its QR (`qr.go`).
7. **Fan out (reuse the one View)** — each platform reuses the Avalonia View + the C-ABI core; only the
   OS shim, secure store, and packaging are new per platform: iOS/iPadOS (reuse the Swift NE extension;
   Avalonia iOS head), Android/Android TV (`VpnService` in the .NET Android head; D-pad focus pass),
   Windows (privileged service + Wintun + installer), **Linux** (privileged systemd daemon over
   `/dev/net/tun` + Secret Service; Flatpak/AppImage/deb/rpm).

---

## 7. Security posture (security-first)

**Asset:** the stored links (server + auth — bearer credentials). **Adversaries → mitigations:**
local malware → OS sandbox + native secure store; locked-device theft → Keychain accessibility +
file data-protection; network MITM → TLS pinning; supply chain → pinned deps + signed builds.

1. **At rest** — links only in the secure store (§3.5); the JSON doc holds no auth and uses
   `NSFileProtectionCompleteUntilFirstUserAuthentication` on Apple, `0600` perms under
   `$XDG_CONFIG_HOME` on Linux.
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
7. **Supply chain & licensing** — pin every dependency (see header). The netstack is **Outline SDK**
   (Apache-2.0, Google Jigsaw, production-shipped), deliberately **not** `apernet/sing-tun` (GPL-3.0,
   App-Store-incompatible; §3.7). All links are permissive (MIT / Apache / BSD) — Go side and the
   .NET/Avalonia/Skia UI side alike; Linux avoids LGPL by reaching the secret store over D-Bus (§3.7).
   Prefer reproducible builds.
8. **Distribution & least privilege** — sign + notarize on Apple, requesting only NE / App-Group /
   Keychain entitlements; signed non-debuggable Android release; Authenticode-signed Windows DLL +
   installer over the Microsoft-signed Wintun driver; Linux via Flatpak (sandboxed) / AppImage / distro
   packages, with the systemd daemon granted only **`CAP_NET_ADMIN`** (not full root) and the GUI
   unprivileged.

---

## 8. Open questions & release gates

- **iOS NE memory** — design to **~15 MB**; the Go runtime + quic-go are the weight (lwIP is a tiny
  embedded stack, §3.2), but it stays the top risk, measured in the Phase-2 device spike (§3.3). The
  .NET/Avalonia runtime never enters the extension (§3.3, §4), so the shared-UI choice doesn't move it.
- **Netstack license (resolved, keep verified)** — the App-Store path depends on the netstack staying
  permissive: Outline lwIP (Apache / MIT / BSD), never `sing-tun` (GPL-3.0). A CI license-scan on
  `bind/ext`'s dep tree should fail on any GPL ingress (§3.7). `[Confirm with counsel before release.]`
- **Store publishing needs an org entity — for _both_ Apple and Google.** The Apple App Store
  (Guideline 5.4) and Google Play both require **organization** enrollment + D-U-N-S to publish a VPN;
  an individual account cannot (user has only an individual Apple account, no org). One legal entity
  covers both stores — an **LLC** (simple, pays the fees) or a **non-profit** (also valid; Apple
  waives the fee for a free app, but more governance). **Off-store routes need no entity:** macOS
  Developer-ID-notarized, Android via APK/F-Droid/third-party stores, Windows outside the Microsoft
  Store, Linux via Flathub / distro repos — **only the iOS App Store has no individual path**. Gates
  release only, not development or
  the Phase-2 spike. Verify in-jurisdiction (tax residency may create obligations regardless).
  `[Decision deferred until the core works.]`
- **App Store Guideline 5.4** — use NEVPNManager; the privacy policy must commit to no third-party
  data sale/disclosure; declare data collection before use; some territories need a VPN license in
  review notes. Our no-telemetry stance (§7) covers the data clause.
- **Acknowledgements bundle** — generate a third-party-notices screen at build time (union of every
  dependency's notice: Apache `NOTICE`, MIT/BSD copyright lines), spanning **both** dependency trees —
  the Go modules (e.g. via `go-licenses`) **and** the .NET/NuGet tree (Avalonia, SkiaSharp, runtime).
  A distribution duty independent of our own `LICENSE-*` (§3.7); app-store reviewers expect it.
- **Profile schema** — version from day one for migration (design choice).

---

## 9. Reference points

**`../hysteria` (MIT):**

- `core/client/client.go:26` — `Client` interface (`TCP`/`UDP`/`Close`); `:32` — `HyUDPConn`
  (`Receive`/`Send`/`Close`). The two surfaces our Outline adapter wraps (§3.2, §5).
- `core/client/config.go`, `core/client/reconnect.go` — `Config` + `NewReconnectableClient`.
- `app/cmd/client.go:72` — full client config schema (mirror in `profile.Profile` + its fillers).
- `app/cmd/client.go:474` / `:518` — `URI()` / `parseURI` (the `hysteria2://` logic to port into `config`).
- `app/internal/url/url.go` — custom URL parser (port-hopping); copy into `internal/config` (MIT).
- `app/internal/tun/server.go:105`/`:143` — `tunHandler.NewConnection`/`NewPacketConnection`
  (→ `HyClient.TCP`/`UDP`); **reference only** — we re-derive this glue onto Outline's interfaces,
  not copy it (the file links GPL sing-tun; §3.7).
- `app/internal/utils/qr.go` — QR generation for share/export.

**Outline SDK `golang.getoutline.org/sdk` (Apache-2.0):**

- `network/device.go:33` — `IPDevice` (raw-IP `Read`/`Write`/`Close`); we wrap the platform fd as one.
- `network/lwip2transport/device.go:72` — `ConfigureDevice(StreamDialer, PacketProxy) (IPDevice, error)`.
- `transport/stream.go:128` — `StreamDialer.DialStream(ctx, raddr)`; `:24` — `StreamConn` (half-close).
- `network/packet_proxy.go:31` — `PacketProxy` (UDP session interface).
- `x/examples/outline-cli/` — reference wiring: fd→`IPDevice`, `ConfigureDevice`, dual `io.Copy`.

# Modern IP Scanner (`mipscan`)

A cross-platform **LAN inventory and troubleshooting tool** for Windows and
Linux — a modern successor to Angry IP Scanner / Advanced IP Scanner, built
around one idea: **inventory and diff, not scan-and-forget**.

Every scan tells you what's **new**, what **changed**, and what's **gone** on
the networks you actually use. Devices are identified by a composite
fingerprint (name signals + OUI + first-seen network) instead of MAC alone,
because MAC randomisation broke MAC-as-identity. Devices get **persistent
user-assigned names** — the feature everything else hangs off.

## Non-negotiables

- **Unprivileged by default.** Neighbor-cache reads, mDNS/SSDP/NetBIOS probes
  and targeted pings need no elevation. Windows uses the IP Helper API only —
  no pcap, no Npcap, no drivers. Ever.
- **The integrity rule.** A scan only reports a device *gone* if it could
  actually have seen it: every enabled strategy finished cleanly **and** the
  scan demonstrably covered the network (an exhaustive sweep ran, and the
  gateway answered). Anything less is *partial* — still reporting *new* and
  *changed*, never *gone*. Plus a grace period, default two scans. Devices
  with randomised MACs and no name are never reported gone at all, because a
  rotation is indistinguishable from a departure. Enforced in the core
  (`diff`), so CLI, GUI and export can't disagree.
- **Not a security scanner.** No port scanning, no vuln checks, no WoL.

## Layout

```
crates/core     discovery strategies, identity, SQLite store, diff engine
crates/cli      `mipscan` headless CLI (same core as the GUI)
crates/helper   `modern-ip-scanner-helper` optional privileged helper (full ARP)
crates/gui      Tauri 2 app shell
ui/             React + TypeScript frontend
```

## Build & run

Requires Rust (MSVC toolchain on Windows) and Node.js for the UI.

```bash
cargo build --workspace          # binaries land in target/debug
npm --prefix ui install          # frontend deps (once)
cargo run -p modern-ip-scanner -- scan      # CLI scan
cargo test --workspace           # unit tests (incl. integrity invariants)
```

**Running the GUI takes one more step than you would expect.** A debug build
loads `devUrl` (the Vite dev server), so `cargo run -p modern-ip-scanner-gui` on its own
opens a window showing *"can't reach this page"*. Either run the dev server
alongside it:

```bash
npm --prefix ui run dev          # leave running, then in another shell:
cargo run -p modern-ip-scanner-gui
```

`cargo tauri dev` does that for you if you have the Tauri CLI.

### Building a runnable app

`--release` on its own is **not** enough. Tauri decides dev-versus-production
from the `custom-protocol` feature, not from the cargo profile — its build
script does `let dev = !custom_protocol` — so a release build without it still
tries to load `devUrl` and opens on *"localhost refused to connect"*.

```bash
npm --prefix ui run build                                  # produce ui/dist
cargo build --release -p modern-ip-scanner-gui -p modern-ip-scanner -p modern-ip-scanner-helper \
  --features modern-ip-scanner-gui/custom-protocol
```

That leaves `modern-ip-scanner-gui.exe`, `mipscan.exe` and `modern-ip-scanner-helper.exe` together in
`target/release/`. Keep the helper beside the GUI: it is looked for next to
the executable, and it is what makes the elevated full-ARP sweep available.

## CLI cheat sheet

```
mipscan scan [--helper] [--strategy ID ...]   scan + record diff
mipscan devices [--network KEY] [--json]      inventory (rows = devices)
mipscan diff [--network KEY]                  what the last scan changed
mipscan name <id|key> "My Printer"            assign a persistent name
mipscan name <id|key> --clear                 remove an assigned name
mipscan networks                              remembered networks
mipscan label <key> "Home"                    label a remembered network
mipscan config [KEY [VALUE]]                  read or change a setting
mipscan history <id|key>                      per-device timeline
mipscan export [--format csv|json] [--network KEY]
```

`LANINV_DB=/path/db.sqlite3` overrides the database location (default:
`%APPDATA%/modern-ip-scanner/modern-ip-scanner.sqlite3` on Windows,
`~/.local/share/modern-ip-scanner/modern-ip-scanner.sqlite3` on Linux).

## The privileged helper (optional)

Full ARP coverage (every address in the prefix, definitive up/down) needs
elevation on Linux (`pkexec` + raw socket) and helps on locked-down Windows
(`SendARP` via a UAC-elevated helper serving a named pipe).

The pipe is restricted to the launching user's SID and both ends
authenticate: the helper checks the connecting client's token, and the client
checks that the pipe is served by the process it launched.

- CLI: `mipscan scan --helper`
- GUI: tick **helper** before scanning (shown when the helper binary is
  found; Settings lists every path that is checked).

Without it, everything still works — scans that needed it are marked
**partial** and "gone" is suppressed for them. On Windows, native `SendARP`
usually works unprivileged and no helper is needed at all.

## Discovery strategies (v1)

| id          | packets | privilege | what it adds                     |
| ----------- | ------- | --------- | -------------------------------- |
| arp-cache   | none    | none      | MACs for everything the OS knows |
| ping-sweep  | few     | ICMP echo | liveness for candidate addresses (no range loops) |
| mdns        | 1 group | none      | hostnames (Apple, cast, printers)|
| ssdp        | 2 group + 1 HTTP | none | friendly names + vendor (UPnP, IoT, TVs) |
| netbios     | per-host| none      | hostnames (Windows, Samba)       |
| arp-ping    | full    | ARP resolve | exhaustive coverage (the only range loop, privileged by design) |

IPv6 will arrive as new strategies behind the same `Strategy` trait — not a
rewrite.

## Status / notes

- The CLI prints timestamps in UTC and labels them so; the GUI formats in the
  viewer's local time. There is no timezone database in the core.
- Packaging is not configured: `bundle.active` is false, so there is no
  installer and nothing ships the optional helper. Build it with
  `cargo build -p modern-ip-scanner-helper` and put it beside the app, or point
  `LANINV_HELPER` at it — the Settings panel lists every path that is checked.
- The Linux code paths have now been built, tested and **run** natively
  (Ubuntu 24.04 on WSL2): the full suite passes there, and the helper's
  raw-socket ARP resolves real addresses as root. What remains unproven is
  the `pkexec` launch path, since polkit is absent from that image, and any
  network larger than WSL's own NAT'd subnet.

## Working on this

CI builds and tests on Linux and Windows (`.github/workflows/ci.yml`). That
matters more than usual here: every Linux-only line sits behind a `#[cfg]`
that a Windows build never type-checks, so the platform rots silently without
it. Two Linux-only defects were introduced or caught in a single session
before CI existed.

Locally on Windows you can still check the helper for Linux, because it has no
C dependencies:

```bash
rustup target add x86_64-unknown-linux-gnu
cargo check -p modern-ip-scanner-helper --target x86_64-unknown-linux-gnu
```

`modern-ip-scanner-core` cannot be cross-*compiled* this way: bundled SQLite needs a C
cross-compiler. Build it inside Linux instead, which takes about twenty
seconds and needs no CI:

```bash
wsl -d Ubuntu-24.04 -e bash -c \
  'cd /mnt/c/path/to/repo && CARGO_TARGET_DIR=~/t cargo test -p modern-ip-scanner-core -p modern-ip-scanner -p modern-ip-scanner-helper'
```

Exclude `modern-ip-scanner-gui` there unless the Tauri system libraries are installed,
and build as your normal user rather than root, or rustup will not find a
toolchain and root-owned files end up in your cargo directories.

Keep as little as possible behind `#[cfg]`. Wire formats, parsing and address
arithmetic are platform-independent even when only one platform calls them;
put them in a plain module so both builds check them and both test runs
exercise them (see `crates/helper/src/main.rs::arp`).

# LAN Inventory (`laninv`)

A cross-platform **LAN inventory and troubleshooting tool** for Windows and
Linux — a modern successor to Angry IP Scanner / Advanced IP Scanner, built
around one idea: **inventory and diff, not scan-and-forget**.

Every scan tells you what's **new**, what **changed**, and what's **gone** on
the networks you actually use. Devices are identified by a composite
fingerprint (name signals + OUI + first-seen network) instead of MAC alone,
because MAC randomisation broke MAC-as-identity. Devices get **persistent
user-assigned names** — the feature everything else hangs off.

## Non-negotiables (see `docs/design.md`)

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
crates/cli      `laninv` headless CLI (same core as the GUI)
crates/helper   `laninv-helper` optional privileged helper (full ARP)
crates/gui      Tauri 2 app shell
ui/             React + TypeScript frontend
```

## Build & run

Requires Rust (MSVC toolchain on Windows) and Node.js for the UI.

```bash
cargo build --workspace          # binaries land in target/debug
npm --prefix ui install          # frontend deps (once)
cargo run -p laninv -- scan      # CLI scan
cargo test --workspace           # unit tests (incl. integrity invariants)
```

**Running the GUI takes one more step than you would expect.** A debug build
loads `devUrl` (the Vite dev server), so `cargo run -p laninv-gui` on its own
opens a window showing *"can't reach this page"*. Either run the dev server
alongside it:

```bash
npm --prefix ui run dev          # leave running, then in another shell:
cargo run -p laninv-gui
```

`cargo tauri dev` does that for you if you have the Tauri CLI.

### Building a runnable app

`--release` on its own is **not** enough. Tauri decides dev-versus-production
from the `custom-protocol` feature, not from the cargo profile — its build
script does `let dev = !custom_protocol` — so a release build without it still
tries to load `devUrl` and opens on *"localhost refused to connect"*.

```bash
npm --prefix ui run build                                  # produce ui/dist
cargo build --release -p laninv-gui -p laninv -p laninv-helper \
  --features laninv-gui/custom-protocol
```

That leaves `laninv-gui.exe`, `laninv.exe` and `laninv-helper.exe` together in
`target/release/`. Keep the helper beside the GUI: it is looked for next to
the executable, and it is what makes the elevated full-ARP sweep available.

## CLI cheat sheet

```
laninv scan [--helper] [--strategy ID ...]   scan + record diff
laninv devices [--network KEY] [--json]      inventory (rows = devices)
laninv diff [--network KEY]                  what the last scan changed
laninv name <id|key> "My Printer"            assign a persistent name
laninv name <id|key> --clear                 remove an assigned name
laninv networks                              remembered networks
laninv label <key> "Home"                    label a remembered network
laninv config [KEY [VALUE]]                  read or change a setting
laninv history <id|key>                      per-device timeline
laninv export [--format csv|json] [--network KEY]
```

`LANINV_DB=/path/db.sqlite3` overrides the database location (default:
`%APPDATA%/laninv/laninv.sqlite3` on Windows,
`~/.local/share/laninv/laninv.sqlite3` on Linux).

## The privileged helper (optional)

Full ARP coverage (every address in the prefix, definitive up/down) needs
elevation on Linux (`pkexec` + raw socket) and helps on locked-down Windows
(`SendARP` via a UAC-elevated helper serving a named pipe).

The pipe is restricted to the launching user's SID and both ends
authenticate: the helper checks the connecting client's token, and the client
checks that the pipe is served by the process it launched.

- CLI: `laninv scan --helper`
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
  `cargo build -p laninv-helper` and put it beside the app, or point
  `LANINV_HELPER` at it — the Settings panel lists every path that is checked.
- The Linux code paths have now been built, tested and **run** natively
  (Ubuntu 24.04 on WSL2): the full suite passes there, and the helper's
  raw-socket ARP resolves real addresses as root. What remains unproven is
  the `pkexec` launch path, since polkit is absent from that image, and any
  network larger than WSL's own NAT'd subnet.
- `docs/design.md` holds the invariants — check changes against it.

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
cargo check -p laninv-helper --target x86_64-unknown-linux-gnu
```

`laninv-core` cannot be cross-*compiled* this way: bundled SQLite needs a C
cross-compiler. Build it inside Linux instead, which takes about twenty
seconds and needs no CI:

```bash
wsl -d Ubuntu-24.04 -e bash -c \
  'cd /mnt/c/path/to/repo && CARGO_TARGET_DIR=~/t cargo test -p laninv-core -p laninv -p laninv-helper'
```

Exclude `laninv-gui` there unless the Tauri system libraries are installed,
and build as your normal user rather than root, or rustup will not find a
toolchain and root-owned files end up in your cargo directories.

Keep as little as possible behind `#[cfg]`. Wire formats, parsing and address
arithmetic are platform-independent even when only one platform calls them;
put them in a plain module so both builds check them and both test runs
exercise them (see `crates/helper/src/main.rs::arp`).

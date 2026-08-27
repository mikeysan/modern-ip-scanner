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
- **The integrity rule.** A scan whose privilege state isn't confirmed is
  marked *partial* and **never reports a device as gone**. `gone` also
  requires a grace period (default: missed in 2 consecutive complete scans).
  Enforced in the core (`diff`), so CLI, GUI and export can't disagree.
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
npm --prefix ui run build        # produce ui/dist for the GUI

cargo run -p laninv-gui          # GUI
cargo run -p laninv -- scan      # CLI scan
cargo test -p laninv-core        # unit tests (incl. integrity invariants)
```

For development of the UI with hot reload: `cargo run -p laninv-gui` uses the
`devUrl`; run `npm --prefix ui run dev` alongside.

## CLI cheat sheet

```
laninv scan [--helper] [--strategy ID ...]   scan + record diff
laninv devices [--network KEY] [--json]      inventory (rows = devices)
laninv diff [--network KEY]                  what the last scan changed
laninv name <id|key> "My Printer"            assign a persistent name
laninv networks                              remembered networks
laninv history <id|key>                      per-device timeline
laninv export [--format csv|json] [--network KEY]
```

`LANINV_DB=/path/db.sqlite3` overrides the database location (default:
`%APPDATA%/laninv/laninv.sqlite3` on Windows,
`~/.local/share/laninv/laninv.sqlite3` on Linux).

## The privileged helper (optional)

Full ARP coverage (every address in the prefix, definitive up/down) needs
elevation on Linux (`pkexec`/`sudo` + raw socket) and helps on locked-down
Windows (`SendARP` via UAC-elevated helper serving a named pipe).

- CLI: `laninv scan --helper`
- GUI: tick **helper** before scanning (shown when the helper binary is
  installed next to the app).

Without it, everything still works — scans that needed it are marked
**partial** and "gone" is suppressed for them. On Windows, native `SendARP`
usually works unprivileged and no helper is needed at all.

## Discovery strategies (v1)

| id          | packets | privilege | what it adds                     |
| ----------- | ------- | --------- | -------------------------------- |
| arp-cache   | none    | none      | MACs for everything the OS knows |
| ping-sweep  | few     | ICMP echo | liveness for candidate addresses (no range loops) |
| mdns        | 1 group | none      | hostnames (Apple, cast, printers)|
| ssdp        | 2 group | none      | USN/vendor (UPnP, IoT, TVs)      |
| netbios     | per-host| none      | hostnames (Windows, Samba)       |
| arp-ping    | full    | ARP resolve | exhaustive coverage (the only range loop, privileged by design) |

IPv6 will arrive as new strategies behind the same `Strategy` trait — not a
rewrite.

## Status / notes

- Timestamps are displayed in UTC (`YYYY-MM-DD HH:MM`) by the CLI, and in
  local time by the GUI. They should agree; they do not yet.
- The Linux code paths (getifaddrs, `/proc/net/arp`, dgram ICMP, raw-ARP
  helper) **compile and are covered by CI**, and the helper's ARP wire format
  and routing logic are unit-tested on every platform. They have still never
  been *run* against a real Linux network — treat the helper's raw-socket path
  as unproven until someone does.
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

`laninv-core` cannot be cross-checked this way — bundled SQLite needs a C
cross-compiler — so CI is the gate for it.

Keep as little as possible behind `#[cfg]`. Wire formats, parsing and address
arithmetic are platform-independent even when only one platform calls them;
put them in a plain module so both builds check them and both test runs
exercise them (see `crates/helper/src/main.rs::arp`).

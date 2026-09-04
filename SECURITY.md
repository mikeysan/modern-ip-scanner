# Security Policy

## Reporting a vulnerability

Please report security issues **privately** through GitHub's private
vulnerability reporting: open the repository's **Security** tab and choose
**Report a vulnerability**. That opens a channel visible only to the
maintainers.

Please do not open a public issue for a suspected vulnerability, and please do
not disclose it elsewhere until a fix is available.

Include what you need to make the problem reproducible — the platform, whether
the privileged helper was in use, and the packets or database state involved.
A proof of concept is welcome but not required.

Expect an acknowledgement within a week. This is a small project with no
dedicated security team, so please be patient with the fix timeline.

## Supported versions

The project is pre-1.0. Only the latest commit on `main` receives fixes; there
are no maintained release branches yet.

## Where the risk actually is

If you are looking for somewhere to point a fuzzer, these are the places that
matter, roughly in order:

**Parsers fed by untrusted network data.** Every discovery strategy consumes
bytes written by whatever else is on the LAN, none of which is trustworthy:
ARP replies, mDNS records, SSDP/UPnP responses (including the follow-up HTTP
fetch of the device description), and NetBIOS name replies. A malicious or
merely broken device on the same network controls this input.

**The privileged helper and its IPC.** The helper runs elevated — `pkexec`
plus a raw socket on Linux, a UAC-elevated process serving a named pipe on
Windows. The pipe's DACL is restricted to the launching user's SID, and both
ends authenticate: the helper checks the connecting client's token, and the
client checks that the pipe is served by the process it launched. Anything
that defeats that mutual check, escapes the SID restriction, or gets the
helper to act on a request it should have refused is in scope. So is the
wire-format parsing on the helper's side of the pipe.

**The GUI webview.** The Tauri webview runs under a Content Security Policy
and a restricted capability set. Device-supplied strings — hostnames, UPnP
friendly names, vendor strings — are rendered in that webview, so anything
that turns one into script execution or escapes the capability allowlist is in
scope.

**The local store.** The SQLite database holds an inventory of the networks
the user scans. Anything that lets another local user read or corrupt it
beyond the platform's normal file permissions is in scope.

## Not vulnerabilities

- **Using this tool to scan a network you do not have permission to scan.**
  That is on the operator, not the software.
- **The tool being detectable**, or setting off an IDS. It is an inventory
  tool and makes no attempt to hide.
- **Requiring elevation for full ARP coverage.** That is the design. Scans
  that needed the helper and did not get it are reported as *partial* rather
  than being silently downgraded.
- **`RUSTSEC-2024-0429` (`glib`, unsound `VariantStrIter` iterators).** Known
  and already tracked. It reaches the Linux build through `tauri` → `gtk 0.18`
  and cannot be resolved here until that dependency moves upstream.

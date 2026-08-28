//! Client side of the optional privileged helper (`laninv-helper`).
//!
//! Protocol: newline-delimited JSON, one request and one response per line.
//! `arp-batch` resolves many addresses per request, which matters because
//! there is exactly one connection: anything not batched is paid for in
//! series.
//! - Linux: helper is spawned via `pkexec` and speaks over stdio.
//! - Windows: helper is spawned elevated via `ShellExecuteEx(runas)` and
//!   serves a named pipe restricted to the launching user's SID. Both ends
//!   authenticate: the helper checks the connecting client's token, and the
//!   client checks that the pipe is served by the process it launched.
//!
//! The helper is optional everywhere: when `launch` fails, callers degrade
//! gracefully and scans lose only the full-ARP coverage.

use std::io::Write;
use std::time::Duration;

/// How long to wait for the elevated helper's pipe to appear (Windows only:
/// the Linux launcher gets its pipes from the child process directly).
#[cfg(windows)]
const CONNECT_TIMEOUT: Duration = Duration::from_secs(45);
/// Most addresses to put in one `arp-batch`. Must not exceed the helper's own
/// cap, which rejects anything larger; see `MAX_BATCH` in `laninv-helper`.
const MAX_BATCH: usize = 128;

/// A quiet address costs the helper one ARP wait: about a second on Linux,
/// and up to ~3.2s on Windows, where SendARP retries internally. Measured at
/// 3.17s against a silent address, so this budget is deliberately well clear
/// of a slow answer -- anything beyond it means the helper has wedged.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// "Is a byte available to read right now?", for one specific transport.
type ReadyProbe = Box<dyn FnMut(Duration) -> Result<bool, String> + Send>;

pub struct HelperClient {
    /// The child process, when the transport is one. Kept so `shutdown` can
    /// reap it.
    child: Option<std::process::Child>,
    writer: Box<dyn Write + Send>,
    /// Deliberately unbuffered -- see `ready`.
    reader: Box<dyn std::io::Read + Send>,
    /// Answers "is a byte waiting?" for the *same* buffer `reader` draws
    /// from, and is stored beside it so the two cannot drift apart.
    ///
    /// This pairing is the whole point: the probe asks the operating system
    /// what is in the pipe, so a reader that buffers ahead of it would move
    /// bytes somewhere the probe cannot see them. Every reply would then
    /// strand after its first byte and time out. Do not wrap `reader`.
    ready: ReadyProbe,
    #[cfg(windows)]
    _pipe: Option<PipeHandle>,
    /// Set once the helper stops answering; every later request fails fast.
    dead: bool,
}

#[derive(serde::Serialize)]
struct Req<'a> {
    op: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    ip: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ips: Option<&'a [String]>,
}

#[derive(serde::Deserialize)]
struct Resp {
    ok: bool,
    #[serde(default)]
    mac: Option<String>,
    /// One slot per address of an `arp-batch`, in the order asked.
    #[serde(default)]
    macs: Option<Vec<Option<String>>>,
    #[serde(default)]
    error: Option<String>,
}

impl HelperClient {
    /// Locate and launch the helper, elevating if the OS asks.
    pub fn launch() -> Result<HelperClient, String> {
        let path = super::helper_path().ok_or("helper binary not found next to executable")?;
        #[cfg(target_os = "linux")]
        {
            Self::launch_stdio(path)
        }
        #[cfg(windows)]
        {
            Self::launch_pipe(path)
        }
        #[cfg(not(any(windows, target_os = "linux")))]
        {
            let _ = path;
            Err("helper not supported on this platform".into())
        }
    }

    #[cfg(target_os = "linux")]
    fn launch_stdio(path: std::path::PathBuf) -> Result<HelperClient, String> {
        // Already privileged: pkexec would only add a prompt, and is absent on
        // plenty of headless systems. Run the helper directly.
        let mut command = if unsafe { libc::geteuid() } == 0 {
            std::process::Command::new(&path)
        } else {
            // pkexec only. `sudo` reads its password prompt from stdin, which
            // is the JSON request channel — it would swallow the first
            // request as a password attempt and then fail.
            let launcher = which("pkexec").ok_or(
                "pkexec not found; install polkit, or run laninv as root for full ARP coverage",
            )?;
            let mut command = std::process::Command::new(launcher);
            command.arg(&path);
            command
        };
        command.arg("--stdio");
        Self::from_command(command)
    }

    /// Build a client around a child process that speaks the protocol on its
    /// stdio (`laninv-helper --stdio`).
    ///
    /// Separate from `launch_stdio` so the protocol can be exercised against
    /// the real helper binary without a privilege prompt: the elevation is
    /// the launcher's business, not the protocol's.
    #[cfg(any(target_os = "linux", all(windows, test)))]
    fn from_command(mut command: std::process::Command) -> Result<HelperClient, String> {
        use std::process::Stdio;
        command.stdin(Stdio::piped()).stdout(Stdio::piped());
        let mut child = command
            .spawn()
            .map_err(|e| format!("failed to spawn helper: {e}"))?;
        let stdin = child.stdin.take().ok_or("no stdin")?;
        let stdout = child.stdout.take().ok_or("no stdout")?;
        #[cfg(target_os = "linux")]
        let ready = poll_probe(std::os::fd::AsRawFd::as_raw_fd(&stdout));
        #[cfg(windows)]
        let ready = peek_probe(PipeHandle(windows::Win32::Foundation::HANDLE(
            std::os::windows::io::AsRawHandle::as_raw_handle(&stdout),
        )));
        Ok(HelperClient {
            child: Some(child),
            writer: Box::new(stdin),
            reader: Box::new(stdout),
            ready,
            #[cfg(windows)]
            _pipe: None,
            dead: false,
        })
    }

    /// This process's user SID, as an `S-1-...` string.
    ///
    /// Handed to the elevated helper so it can restrict its pipe to exactly
    /// this user instead of everyone on the machine.
    #[cfg(windows)]
    fn current_user_sid() -> Result<String, String> {
        use windows::Win32::Foundation::{CloseHandle, LocalFree, HANDLE, HLOCAL};
        use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
        use windows::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER};
        use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

        unsafe {
            let mut token = HANDLE::default();
            OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)
                .map_err(|e| format!("cannot read this process's token: {e}"))?;
            let mut needed = 0u32;
            let _ = GetTokenInformation(token, TokenUser, None, 0, &mut needed);
            let mut buf = vec![0u8; needed as usize];
            let got = GetTokenInformation(
                token,
                TokenUser,
                Some(buf.as_mut_ptr() as *mut core::ffi::c_void),
                needed,
                &mut needed,
            );
            let _ = CloseHandle(token);
            got.map_err(|e| format!("cannot read this process's user: {e}"))?;

            let user = &*(buf.as_ptr() as *const TOKEN_USER);
            let mut raw = windows::core::PWSTR::null();
            ConvertSidToStringSidW(user.User.Sid, &mut raw)
                .map_err(|e| format!("cannot format this process's SID: {e}"))?;
            let sid = raw.to_string().map_err(|_| "SID was not valid UTF-16")?;
            let _ = LocalFree(Some(HLOCAL(raw.0 as *mut core::ffi::c_void)));
            Ok(sid)
        }
    }

    #[cfg(windows)]
    fn launch_pipe(path: std::path::PathBuf) -> Result<HelperClient, String> {
        use windows::core::PCWSTR;
        use windows::Win32::Foundation::GENERIC_READ;
        use windows::Win32::Foundation::GENERIC_WRITE;
        use windows::Win32::Storage::FileSystem::CreateFileW;
        use windows::Win32::Storage::FileSystem::FILE_ATTRIBUTE_NORMAL;
        use windows::Win32::Storage::FileSystem::OPEN_EXISTING;
        use windows::Win32::Storage::FileSystem::SECURITY_IDENTIFICATION;
        use windows::Win32::Storage::FileSystem::SECURITY_SQOS_PRESENT;
        use windows::Win32::System::Pipes::GetNamedPipeServerProcessId;
        use windows::Win32::System::Threading::GetProcessId;
        use windows::Win32::UI::Shell::{
            ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW,
        };
        use windows::Win32::UI::WindowsAndMessaging::SW_HIDE;

        let sid = Self::current_user_sid()?;
        let name = format!(
            "laninv-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        );
        let pipe_name = format!(r"\\.\pipe\{name}");

        let verb: Vec<u16> = "runas".encode_utf16().chain([0]).collect();
        let file: Vec<u16> = path
            .as_os_str()
            .to_string_lossy()
            .encode_utf16()
            .chain([0])
            .collect();
        // The SID is not a secret; the pipe's DACL, not the argument, is what
        // keeps other users out.
        let args = format!("--pipe {name} --owner {sid}");
        let args_utf: Vec<u16> = args.encode_utf16().chain([0]).collect();

        // ShellExecuteEx rather than ShellExecute: we need the process handle
        // to prove later that the pipe we connected to is the helper we
        // launched, and not something that squatted the name first.
        let mut info = SHELLEXECUTEINFOW {
            cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
            fMask: SEE_MASK_NOCLOSEPROCESS,
            lpVerb: PCWSTR(verb.as_ptr()),
            lpFile: PCWSTR(file.as_ptr()),
            lpParameters: PCWSTR(args_utf.as_ptr()),
            nShow: SW_HIDE.0,
            ..Default::default()
        };
        unsafe { ShellExecuteExW(&mut info) }
            .map_err(|_| "elevation declined (UAC prompt refused)".to_string())?;
        let helper_pid = unsafe { GetProcessId(info.hProcess) };
        if helper_pid == 0 {
            return Err("could not identify the helper process".into());
        }

        let wide: Vec<u16> = pipe_name.encode_utf16().chain([0]).collect();
        let deadline = std::time::Instant::now() + CONNECT_TIMEOUT;
        loop {
            let handle = unsafe {
                CreateFileW(
                    PCWSTR(wide.as_ptr()),
                    (GENERIC_READ | GENERIC_WRITE).0,
                    Default::default(),
                    None,
                    OPEN_EXISTING,
                    // Let the helper read who we are so it can check us
                    // against the SID it was launched for. Identification,
                    // not Impersonation: it needs to *know* the caller, not
                    // to act as them. Without an explicit level Windows
                    // treats the client as anonymous and the check fails.
                    FILE_ATTRIBUTE_NORMAL | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                    None,
                )
            };
            if let Ok(h) = handle {
                // Mutual authentication: the helper checked us via the pipe's
                // DACL and an impersonation check; this is us checking it.
                let mut server_pid = 0u32;
                let identified = unsafe { GetNamedPipeServerProcessId(h, &mut server_pid) }.is_ok();
                if !identified || server_pid != helper_pid {
                    let _ = unsafe { windows::Win32::Foundation::CloseHandle(h) };
                    return Err(
                        "the helper pipe is served by a different process; refusing to use it"
                            .into(),
                    );
                }
                let pipe = PipeHandle(h);
                return Ok(HelperClient {
                    child: None,
                    writer: Box::new(PipeWriter(pipe.clone())),
                    reader: Box::new(PipeReader(pipe.clone())),
                    ready: peek_probe(pipe.clone()),
                    _pipe: Some(pipe),
                    dead: false,
                });
            }
            if std::time::Instant::now() >= deadline {
                return Err("helper pipe did not appear (UAC declined or helper failed)".into());
            }
            std::thread::sleep(Duration::from_millis(250));
        }
    }

    /// Resolve one IPv4 address to a MAC via the helper.
    pub fn arp(&mut self, ip: &str) -> Result<Option<String>, String> {
        let req = Req {
            op: "arp",
            ip: Some(ip),
            ips: None,
        };
        let line = serde_json::to_string(&req).map_err(|e| e.to_string())?;
        self.roundtrip(&line)
    }

    /// Resolve many addresses per round trip, one result slot per input.
    ///
    /// Chunks internally, so callers may hand over a whole subnet.
    pub fn arp_batch(&mut self, ips: &[String]) -> Result<Vec<Option<String>>, String> {
        let mut out = Vec::with_capacity(ips.len());
        for chunk in ips.chunks(MAX_BATCH) {
            out.extend(self.arp_batch_chunk(chunk)?);
        }
        Ok(out)
    }

    fn arp_batch_chunk(&mut self, ips: &[String]) -> Result<Vec<Option<String>>, String> {
        if ips.is_empty() {
            return Ok(Vec::new());
        }
        let req = Req {
            op: "arp-batch",
            ip: None,
            ips: Some(ips),
        };
        let line = serde_json::to_string(&req).map_err(|e| e.to_string())?;
        let resp = self.exchange(&line, batch_timeout(ips.len()))?;
        if !resp.ok {
            return Err(resp.error.unwrap_or_else(|| "helper error".into()));
        }
        // Positional results are only usable if there is one per address, so
        // a short reply is an error rather than something to pad out: padding
        // would attribute one address's MAC to another.
        let macs = resp
            .macs
            .ok_or_else(|| "helper answered a batch without results".to_string())?;
        if macs.len() != ips.len() {
            return Err(format!(
                "helper answered {} of {} addresses",
                macs.len(),
                ips.len()
            ));
        }
        Ok(macs)
    }

    /// Ask the helper to exit cleanly.
    pub fn shutdown(&mut self) {
        let req = Req {
            op: "shutdown",
            ip: None,
            ips: None,
        };
        if let Ok(line) = serde_json::to_string(&req) {
            let _ = self.roundtrip(&line);
        }
        if let Some(child) = self.child.as_mut() {
            let _ = child.wait();
        }
    }

    fn roundtrip(&mut self, line: &str) -> Result<Option<String>, String> {
        let resp = self.exchange(line, REQUEST_TIMEOUT)?;
        if !resp.ok {
            return Err(resp.error.unwrap_or_else(|| "helper error".into()));
        }
        Ok(resp.mac)
    }

    /// One request, one reply, with the caller's own budget.
    ///
    /// A batch needs a longer one than a single address: the helper answers
    /// it with bounded concurrency, so its cost scales with the batch.
    fn exchange(&mut self, line: &str, budget: Duration) -> Result<Resp, String> {
        if self.dead {
            return Err("helper is no longer usable".into());
        }
        writeln!(self.writer, "{line}").map_err(|e| format!("helper write failed: {e}"))?;
        self.writer
            .flush()
            .map_err(|e| format!("helper flush failed: {e}"))?;
        let response = match self.read_line_before(std::time::Instant::now() + budget) {
            Ok(r) => r,
            Err(e) => {
                // A helper that stopped answering will not start again, and a
                // caller looping over 4096 addresses must not wait on each.
                self.dead = true;
                return Err(e);
            }
        };
        if response.trim().is_empty() {
            self.dead = true;
            return Err("helper closed the connection".into());
        }
        serde_json::from_str(response.trim()).map_err(|e| format!("bad helper reply: {e}"))
    }
}

impl HelperClient {
    /// Read one newline-terminated reply, giving up at `deadline`.
    ///
    /// Deliberately built from a platform-independent loop plus one tiny
    /// per-platform "is a byte ready?" primitive, so the timeout logic itself
    /// is checked by every build.
    fn read_line_before(&mut self, deadline: std::time::Instant) -> Result<String, String> {
        let mut line = Vec::new();
        loop {
            if std::time::Instant::now() >= deadline {
                return Err("helper did not answer in time".into());
            }
            if !(self.ready)(Duration::from_millis(50))? {
                continue;
            }
            let mut byte = [0u8; 1];
            match self.reader.read(&mut byte) {
                Ok(0) => return Err("helper closed the connection".into()),
                Ok(_) => {
                    if byte[0] == b'\n' {
                        return String::from_utf8(line)
                            .map_err(|_| "helper sent invalid UTF-8".to_string());
                    }
                    line.push(byte[0]);
                }
                Err(e) => return Err(format!("helper read failed: {e}")),
            }
        }
    }
}

/// How long to allow a batch of `n` addresses.
///
/// The helper resolves a batch with bounded concurrency, so the cost is a
/// fraction of `n` ARP waits rather than all of them. The allowance is
/// deliberately loose: a quiet address costs up to ~3.2s on Windows, and a
/// batch that is merely slow must not be mistaken for a wedged helper.
fn batch_timeout(n: usize) -> Duration {
    REQUEST_TIMEOUT + Duration::from_millis(150) * (n.min(MAX_BATCH) as u32)
}

/// Wait for readability on a file descriptor the child writes to.
#[cfg(target_os = "linux")]
fn poll_probe(fd: std::os::fd::RawFd) -> ReadyProbe {
    Box::new(move |wait: Duration| {
        let mut pollfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let rc = unsafe { libc::poll(&mut pollfd, 1, wait.as_millis() as libc::c_int) };
        if rc < 0 {
            return Err("poll on helper stdout failed".into());
        }
        Ok(rc > 0)
    })
}

/// Ask a pipe whether a byte is waiting, rather than blocking on it.
///
/// Works for both transports: the named pipe the elevated helper serves, and
/// the anonymous pipe behind a child's stdout.
#[cfg(windows)]
fn peek_probe(handle: PipeHandle) -> ReadyProbe {
    Box::new(move |wait: Duration| {
        use windows::Win32::System::Pipes::PeekNamedPipe;
        let mut available: u32 = 0;
        // `handle.raw()` and not `handle.0`: a field access would capture the
        // bare HANDLE, which is not Send, instead of the wrapper that is.
        let ok = unsafe { PeekNamedPipe(handle.raw(), None, 0, None, Some(&mut available), None) };
        if ok.is_err() {
            return Err("helper pipe closed".into());
        }
        if available > 0 {
            return Ok(true);
        }
        std::thread::sleep(wait);
        Ok(false)
    })
}

#[cfg(target_os = "linux")]
fn which(program: &str) -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(program))
        .find(|p| p.exists())
}

#[cfg(windows)]
#[derive(Clone)]
struct PipeHandle(windows::Win32::Foundation::HANDLE);

// A HANDLE is an opaque integer; sharing the value across threads is fine
// (we never close it while the reader/writer borrow it).
#[cfg(windows)]
unsafe impl Send for PipeHandle {}
#[cfg(windows)]
unsafe impl Sync for PipeHandle {}

#[cfg(windows)]
impl PipeHandle {
    fn raw(&self) -> windows::Win32::Foundation::HANDLE {
        self.0
    }
}

#[cfg(windows)]
struct PipeReader(PipeHandle);

#[cfg(windows)]
impl std::io::Read for PipeReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        use windows::Win32::Storage::FileSystem::ReadFile;
        let mut read = 0u32;
        let ok = unsafe { ReadFile(self.0.raw(), Some(buf), Some(&mut read), None) };
        ok.map_err(|_| std::io::Error::last_os_error())?;
        Ok(read as usize)
    }
}

#[cfg(windows)]
struct PipeWriter(PipeHandle);

#[cfg(windows)]
impl Write for PipeWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        use windows::Win32::Storage::FileSystem::WriteFile;
        let mut written = 0u32;
        let ok = unsafe { WriteFile(self.0.raw(), Some(buf), Some(&mut written), None) };
        ok.map_err(|_| std::io::Error::last_os_error())?;
        Ok(written as usize)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `target/<profile>/laninv-helper[.exe]`, when the workspace has been
    /// built. The test binary lives one level deeper, in `deps/`.
    fn helper_binary() -> Option<std::path::PathBuf> {
        let exe = std::env::current_exe().ok()?;
        let candidate = exe
            .parent()?
            .parent()?
            .join(crate::privilege::helper_file_name());
        candidate.exists().then_some(candidate)
    }

    /// Every request gets its own reply, whole.
    ///
    /// Regression test for a client that asked the operating system whether
    /// the pipe held bytes but read through a `BufReader`: the first read
    /// moved the entire reply into the reader's private buffer, the probe
    /// then saw an empty pipe forever, and the request timed out having
    /// assembled a single byte. Nothing resynchronised afterwards, so the
    /// following request was answered with the tail of the previous reply.
    ///
    /// Driven against the real helper binary over `--stdio`, which needs no
    /// privileges: elevation is the launcher's business, not the protocol's.
    #[test]
    fn each_request_gets_its_own_whole_reply() {
        let Some(bin) = helper_binary() else {
            eprintln!(
                "SKIPPED each_request_gets_its_own_whole_reply: no laninv-helper \
                 beside the test binary (build the workspace first)"
            );
            return;
        };
        let mut command = std::process::Command::new(bin);
        command.arg("--stdio");
        let mut client = HelperClient::from_command(command).expect("spawn helper --stdio");

        // Rejected by the helper without touching the network, so this tests
        // the round trip and nothing else.
        let first = client.arp("not-an-ip");
        assert_eq!(
            first,
            Err("invalid or missing ip".to_string()),
            "first round trip did not come back"
        );

        // And the stream is still in step: this reply is its own, not the
        // tail of the one before.
        let second = client.arp("still-not-an-ip");
        assert_eq!(
            second,
            Err("invalid or missing ip".to_string()),
            "replies drifted out of step after the first"
        );

        client.shutdown();
    }

    /// A batch costs one round trip and answers every address in order.
    ///
    /// Regression test for the helper being a serialization point: the
    /// resolver held one connection behind a mutex, so an exhaustive sweep
    /// queued 254 round trips through it, one ARP wait at a time.
    #[test]
    fn a_batch_answers_every_address_and_leaves_the_stream_in_step() {
        let Some(bin) = helper_binary() else {
            eprintln!(
                "SKIPPED a_batch_answers_every_address_and_leaves_the_stream_in_step:                  no laninv-helper beside the test binary (build the workspace first)"
            );
            return;
        };
        let mut command = std::process::Command::new(bin);
        command.arg("--stdio");
        let mut client = HelperClient::from_command(command).expect("spawn helper --stdio");

        // Rejected by the helper without touching the network, so this tests
        // the round trip and nothing else.
        let ips: Vec<String> = vec!["not-an-ip".into(), "nor-this".into(), "or-this".into()];
        let got = client.arp_batch(&ips).expect("batch round trip");
        assert_eq!(got, vec![None, None, None]);

        // One reply was consumed, not one per address: a single request after
        // it must still get its own answer.
        assert_eq!(
            client.arp("not-an-ip"),
            Err("invalid or missing ip".to_string()),
            "the batch reply left the stream out of step"
        );

        client.shutdown();
    }
}

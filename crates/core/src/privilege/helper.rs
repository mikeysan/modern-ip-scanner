//! Client side of the optional privileged helper (`laninv-helper`).
//!
//! Protocol: newline-delimited JSON, one request and one response per line.
//! - Linux: helper is spawned via `pkexec` and speaks over stdio.
//! - Windows: helper is spawned elevated via `ShellExecuteW(runas)` and
//!   serves a named pipe the client connects to.
//!
//! The helper is optional everywhere: when `launch` fails, callers degrade
//! gracefully and scans lose only the full-ARP coverage.

use std::io::{BufRead, BufReader, Write};
use std::time::Duration;

/// How long to wait for the elevated helper's pipe to appear (Windows only:
/// the Linux launcher gets its pipes from the child process directly).
#[cfg(windows)]
const CONNECT_TIMEOUT: Duration = Duration::from_secs(45);
/// The helper's own ARP wait is one second, so anything beyond this means it
/// has wedged rather than that the address is quiet.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

pub struct HelperClient {
    #[cfg(target_os = "linux")]
    child: std::process::Child,
    /// Raw fd of the child's stdout, for readiness polling.
    #[cfg(target_os = "linux")]
    stdout_fd: std::os::fd::RawFd,
    writer: Box<dyn Write + Send>,
    reader: Box<dyn BufRead + Send>,
    #[cfg(windows)]
    _pipe: PipeHandle,
    /// Set once the helper stops answering; every later request fails fast.
    dead: bool,
}

#[derive(serde::Serialize)]
struct Req<'a> {
    op: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    ip: Option<&'a str>,
}

#[derive(serde::Deserialize)]
struct Resp {
    ok: bool,
    #[serde(default)]
    mac: Option<String>,
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
        use std::process::{Command, Stdio};
        // pkexec only. `sudo` reads its password prompt from stdin, which is
        // the JSON request channel — it would swallow the first request as a
        // password attempt and then fail.
        let launcher = which("pkexec").ok_or(
            "pkexec not found; install polkit, or run laninv as root for full ARP coverage",
        )?;
        let mut command = Command::new(launcher);
        command.arg(&path).arg("--stdio");
        command.stdin(Stdio::piped()).stdout(Stdio::piped());
        let mut child = command
            .spawn()
            .map_err(|e| format!("failed to spawn pkexec: {e}"))?;
        let stdin = child.stdin.take().ok_or("no stdin")?;
        let stdout = child.stdout.take().ok_or("no stdout")?;
        let stdout_fd = std::os::fd::AsRawFd::as_raw_fd(&stdout);
        Ok(HelperClient {
            child,
            stdout_fd,
            writer: Box::new(stdin),
            reader: Box::new(BufReader::new(stdout)),
            dead: false,
        })
    }

    #[cfg(windows)]
    fn launch_pipe(path: std::path::PathBuf) -> Result<HelperClient, String> {
        use windows::core::PCWSTR;
        use windows::Win32::Foundation::GENERIC_READ;
        use windows::Win32::Foundation::GENERIC_WRITE;
        use windows::Win32::Storage::FileSystem::CreateFileW;
        use windows::Win32::Storage::FileSystem::FILE_ATTRIBUTE_NORMAL;
        use windows::Win32::Storage::FileSystem::OPEN_EXISTING;
        use windows::Win32::UI::Shell::ShellExecuteW;
        use windows::Win32::UI::WindowsAndMessaging::SW_HIDE;

        let name = format!(
            "laninv-{}",
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
        let args = format!("--pipe {name}");
        let args_utf: Vec<u16> = args.encode_utf16().chain([0]).collect();
        let rc = unsafe {
            ShellExecuteW(
                None,
                PCWSTR(verb.as_ptr()),
                PCWSTR(file.as_ptr()),
                PCWSTR(args_utf.as_ptr()),
                None,
                SW_HIDE,
            )
        };
        if rc.0 as isize <= 32 {
            return Err("elevation declined (ShellExecuteW runas failed)".into());
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
                    FILE_ATTRIBUTE_NORMAL,
                    None,
                )
            };
            if let Ok(h) = handle {
                let pipe = PipeHandle(h);
                return Ok(HelperClient {
                    writer: Box::new(PipeWriter(pipe.clone())),
                    reader: Box::new(BufReader::new(PipeReader(pipe.clone()))),
                    _pipe: pipe,
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
        };
        let line = serde_json::to_string(&req).map_err(|e| e.to_string())?;
        self.roundtrip(&line)
    }

    /// Ask the helper to exit cleanly.
    pub fn shutdown(&mut self) {
        let req = Req {
            op: "shutdown",
            ip: None,
        };
        if let Ok(line) = serde_json::to_string(&req) {
            let _ = self.roundtrip(&line);
        }
        #[cfg(target_os = "linux")]
        {
            let _ = self.child.wait();
        }
    }

    fn roundtrip(&mut self, line: &str) -> Result<Option<String>, String> {
        if self.dead {
            return Err("helper is no longer usable".into());
        }
        writeln!(self.writer, "{line}").map_err(|e| format!("helper write failed: {e}"))?;
        self.writer
            .flush()
            .map_err(|e| format!("helper flush failed: {e}"))?;
        let response = match self.read_line_before(std::time::Instant::now() + REQUEST_TIMEOUT) {
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
        let resp: Resp =
            serde_json::from_str(response.trim()).map_err(|e| format!("bad helper reply: {e}"))?;
        if !resp.ok {
            return Err(resp.error.unwrap_or_else(|| "helper error".into()));
        }
        Ok(resp.mac)
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
            if !self.readable(Duration::from_millis(50))? {
                continue;
            }
            let mut byte = [0u8; 1];
            match std::io::Read::read(&mut self.reader, &mut byte) {
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

#[cfg(target_os = "linux")]
impl HelperClient {
    /// Wait for readability on the child's stdout.
    fn readable(&mut self, wait: Duration) -> Result<bool, String> {
        let mut pollfd = libc::pollfd {
            fd: self.stdout_fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let rc = unsafe { libc::poll(&mut pollfd, 1, wait.as_millis() as libc::c_int) };
        if rc < 0 {
            return Err("poll on helper stdout failed".into());
        }
        Ok(rc > 0)
    }
}

#[cfg(windows)]
impl HelperClient {
    /// Ask the pipe whether a byte is waiting, rather than blocking on it.
    fn readable(&mut self, wait: Duration) -> Result<bool, String> {
        use windows::Win32::System::Pipes::PeekNamedPipe;
        let mut available: u32 = 0;
        let ok =
            unsafe { PeekNamedPipe(self._pipe.raw(), None, 0, None, Some(&mut available), None) };
        if ok.is_err() {
            return Err("helper pipe closed".into());
        }
        if available > 0 {
            return Ok(true);
        }
        std::thread::sleep(wait);
        Ok(false)
    }
}

#[cfg(not(any(windows, target_os = "linux")))]
impl HelperClient {
    fn readable(&mut self, _wait: Duration) -> Result<bool, String> {
        Ok(true)
    }
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

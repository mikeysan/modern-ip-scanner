//! Client side of the optional privileged helper (`laninv-helper`).
//!
//! Protocol: newline-delimited JSON, one request and one response per line.
//! - Linux: helper is spawned via `pkexec`/`sudo` and speaks over stdio.
//! - Windows: helper is spawned elevated via `ShellExecuteW(runas)` and
//!   serves a named pipe the client connects to.
//!
//! The helper is optional everywhere: when `launch` fails, callers degrade
//! gracefully and scans lose only the full-ARP coverage.

use std::io::{BufRead, BufReader, Write};
use std::time::Duration;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(45);

pub struct HelperClient {
    #[cfg(target_os = "linux")]
    child: std::process::Child,
    writer: Box<dyn Write + Send>,
    reader: Box<dyn BufRead + Send>,
    #[cfg(windows)]
    _pipe: PipeHandle,
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
        let launcher = ["pkexec", "sudo"]
            .iter()
            .find(|l| which(l).is_some())
            .ok_or("neither pkexec nor sudo found")?;
        let mut command = Command::new(launcher);
        command.arg(&path).arg("--stdio");
        command.stdin(Stdio::piped()).stdout(Stdio::piped());
        let mut child = command
            .spawn()
            .map_err(|e| format!("failed to spawn {launcher}: {e}"))?;
        let stdin = child.stdin.take().ok_or("no stdin")?;
        let stdout = child.stdout.take().ok_or("no stdout")?;
        Ok(HelperClient {
            child,
            writer: Box::new(stdin),
            reader: Box::new(BufReader::new(stdout)),
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
        writeln!(self.writer, "{line}").map_err(|e| format!("helper write failed: {e}"))?;
        self.writer
            .flush()
            .map_err(|e| format!("helper flush failed: {e}"))?;
        let mut response = String::new();
        // The helper always answers or exits; process/pipe exit unblocks the
        // read with EOF rather than hanging forever.
        self.reader
            .read_line(&mut response)
            .map_err(|e| format!("helper read failed: {e}"))?;
        if response.trim().is_empty() {
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

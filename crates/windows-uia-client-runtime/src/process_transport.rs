use std::fs;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{JsonLineTransport, WindowsUiaClientError};

const DEFAULT_MAX_RESPONSE_BYTES: usize = 1024 * 1024;

pub struct ChildJsonLineTransport {
    child: Child,
    stdin: BufWriter<ChildStdin>,
    stdout: BufReader<ChildStdout>,
    max_response_bytes: usize,
}

impl ChildJsonLineTransport {
    pub fn spawn(
        host_path: impl AsRef<Path>,
        trusted_host_sha256: &str,
    ) -> Result<Self, WindowsUiaClientError> {
        Self::spawn_with_limit(host_path, trusted_host_sha256, DEFAULT_MAX_RESPONSE_BYTES)
    }

    pub fn spawn_with_limit(
        host_path: impl AsRef<Path>,
        trusted_host_sha256: &str,
        max_response_bytes: usize,
    ) -> Result<Self, WindowsUiaClientError> {
        validate_sha256(trusted_host_sha256)?;
        if max_response_bytes == 0 {
            return Err(WindowsUiaClientError::HostProcess(
                "maximum response size must be positive".to_owned(),
            ));
        }

        let host_bytes = fs::read(host_path.as_ref())
            .map_err(|error| WindowsUiaClientError::HostProcess(error.to_string()))?;
        let actual_digest = format!("{:x}", Sha256::digest(host_bytes));
        if actual_digest != trusted_host_sha256 {
            return Err(WindowsUiaClientError::HostDigestMismatch);
        }

        let mut child = Command::new(host_path.as_ref())
            .arg("--stdio")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|error| WindowsUiaClientError::HostProcess(error.to_string()))?;
        let stdin = child.stdin.take().ok_or_else(|| {
            WindowsUiaClientError::HostProcess("host stdin is unavailable".to_owned())
        })?;
        let stdout = child.stdout.take().ok_or_else(|| {
            WindowsUiaClientError::HostProcess("host stdout is unavailable".to_owned())
        })?;

        Ok(Self {
            child,
            stdin: BufWriter::new(stdin),
            stdout: BufReader::new(stdout),
            max_response_bytes,
        })
    }
}

impl JsonLineTransport for ChildJsonLineTransport {
    fn exchange(&mut self, command: &Value) -> Result<Value, String> {
        let command_text = serde_json::to_string(command).map_err(|error| error.to_string())?;
        self.stdin
            .write_all(command_text.as_bytes())
            .and_then(|()| self.stdin.write_all(b"\n"))
            .and_then(|()| self.stdin.flush())
            .map_err(|error| error.to_string())?;

        let mut response = String::new();
        let read = self
            .stdout
            .read_line(&mut response)
            .map_err(|error| error.to_string())?;
        if read == 0 {
            return Err("Windows UIA host closed stdout before responding".to_owned());
        }
        if response.len() > self.max_response_bytes {
            return Err("Windows UIA host response exceeds the configured limit".to_owned());
        }
        if !response.ends_with('\n') {
            return Err("Windows UIA host response is not newline terminated".to_owned());
        }

        serde_json::from_str(response.trim_end_matches(['\r', '\n']))
            .map_err(|error| error.to_string())
    }
}

impl Drop for ChildJsonLineTransport {
    fn drop(&mut self) {
        let _ = self.stdin.flush();
        match self.child.try_wait() {
            Ok(Some(_)) => {}
            Ok(None) | Err(_) => {
                let _ = self.child.kill();
                let _ = self.child.wait();
            }
        }
    }
}

fn validate_sha256(digest: &str) -> Result<(), WindowsUiaClientError> {
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|value| value.is_ascii_digit() || (b'a'..=b'f').contains(&value))
    {
        return Err(WindowsUiaClientError::InvalidHostDigest);
    }
    Ok(())
}

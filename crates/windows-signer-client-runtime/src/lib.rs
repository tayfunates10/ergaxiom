#![forbid(unsafe_code)]

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use ergaxiom_windows_signer_protocol_runtime::{
    SignerProtocolError, SignerRequest, SignerResponse,
};
use thiserror::Error;

const MAX_STDOUT_BYTES: usize = 128 * 1024;
const MAX_STDERR_BYTES: usize = 8 * 1024;

#[derive(Debug, Clone)]
pub struct SignerProcessClient {
    executable: PathBuf,
    test_store: Option<PathBuf>,
}

impl SignerProcessClient {
    pub fn production(executable: impl Into<PathBuf>) -> Result<Self, SignerClientError> {
        let executable = executable.into();
        validate_executable(&executable)?;
        Ok(Self {
            executable,
            test_store: None,
        })
    }

    pub fn isolated_test(
        executable: impl Into<PathBuf>,
        store: impl Into<PathBuf>,
    ) -> Result<Self, SignerClientError> {
        let executable = executable.into();
        let store = store.into();
        validate_executable(&executable)?;
        if !store.is_absolute() {
            return Err(SignerClientError::StorePathMustBeAbsolute);
        }
        Ok(Self {
            executable,
            test_store: Some(store),
        })
    }

    pub fn invoke(&self, request: &SignerRequest) -> Result<SignerResponse, SignerClientError> {
        request.validate()?;
        let request_json = serde_json::to_vec(request)?;
        if request_json.len() > MAX_STDOUT_BYTES {
            return Err(SignerClientError::RequestTooLarge);
        }

        let mut command = Command::new(&self.executable);
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(store) = &self.test_store {
            command
                .arg("--store")
                .arg(store)
                .env("ERGAXIOM_SIGNER_TEST_MODE", "1");
        }

        let mut child = command.spawn().map_err(SignerClientError::Spawn)?;
        let mut stdin = child
            .stdin
            .take()
            .ok_or(SignerClientError::MissingChildStdin)?;
        stdin
            .write_all(&request_json)
            .map_err(SignerClientError::WriteRequest)?;
        stdin
            .write_all(b"\n")
            .map_err(SignerClientError::WriteRequest)?;
        drop(stdin);

        let output = child.wait_with_output().map_err(SignerClientError::Wait)?;
        if output.stdout.len() > MAX_STDOUT_BYTES {
            return Err(SignerClientError::ResponseTooLarge);
        }
        if output.stderr.len() > MAX_STDERR_BYTES {
            return Err(SignerClientError::StderrTooLarge);
        }
        if !output.stderr.is_empty() {
            return Err(SignerClientError::UnexpectedStderr);
        }

        let response: SignerResponse = serde_json::from_slice(&output.stdout)?;
        if response.contains_private_material_field() {
            return Err(SignerClientError::ForbiddenResponseMaterial);
        }
        if !output.status.success() {
            let SignerResponse::Error { code, .. } = response else {
                return Err(SignerClientError::NonZeroWithoutErrorResponse);
            };
            return Err(SignerClientError::SignerRejected(code));
        }
        Ok(response)
    }

    #[must_use]
    pub fn executable(&self) -> &Path {
        &self.executable
    }
}

fn validate_executable(path: &Path) -> Result<(), SignerClientError> {
    if !path.is_absolute() {
        return Err(SignerClientError::ExecutablePathMustBeAbsolute);
    }
    let metadata = fs::metadata(path).map_err(SignerClientError::ExecutableMetadata)?;
    if !metadata.is_file() {
        return Err(SignerClientError::ExecutableIsNotFile);
    }
    Ok(())
}

#[derive(Debug, Error)]
pub enum SignerClientError {
    #[error("signer executable path must be absolute")]
    ExecutablePathMustBeAbsolute,
    #[error("signer executable metadata could not be read: {0}")]
    ExecutableMetadata(#[source] std::io::Error),
    #[error("signer executable path is not a file")]
    ExecutableIsNotFile,
    #[error("test signer store path must be absolute")]
    StorePathMustBeAbsolute,
    #[error("signer request exceeds the protocol size limit")]
    RequestTooLarge,
    #[error("signer process response exceeds the protocol size limit")]
    ResponseTooLarge,
    #[error("signer process stderr exceeds the protocol size limit")]
    StderrTooLarge,
    #[error("signer process emitted unexpected stderr")]
    UnexpectedStderr,
    #[error("signer process response contains forbidden secret-shaped fields")]
    ForbiddenResponseMaterial,
    #[error("signer process could not be started: {0}")]
    Spawn(#[source] std::io::Error),
    #[error("signer process stdin was unavailable")]
    MissingChildStdin,
    #[error("signer request could not be written: {0}")]
    WriteRequest(#[source] std::io::Error),
    #[error("signer process could not be awaited: {0}")]
    Wait(#[source] std::io::Error),
    #[error("signer process exited unsuccessfully without an error response")]
    NonZeroWithoutErrorResponse,
    #[error("signer rejected the request: {0}")]
    SignerRejected(String),
    #[error(transparent)]
    Protocol(#[from] SignerProtocolError),
    #[error("signer JSON serialization failed: {0}")]
    Json(#[from] serde_json::Error),
}

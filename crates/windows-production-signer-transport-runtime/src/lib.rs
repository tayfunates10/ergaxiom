#![cfg_attr(not(windows), forbid(unsafe_code))]

#[cfg(windows)]
mod windows;

use ergaxiom_windows_production_signer_protocol_runtime::ProductionSignerRequest;
use ergaxiom_windows_production_signer_runtime::AuthenticatedCallerIdentity;
use ergaxiom_windows_production_signer_service_runtime::AuthorizedProductionSignerPackage;
use ergaxiom_windows_signer_service_identity_runtime::{
    NamedPipeSecurityContract, SignerIdentityError,
};
use serde::{Serialize, de::DeserializeOwned};
use thiserror::Error;

pub const CLIENT_PIPE_RIGHTS: u32 = 0x0012_0183;
pub const PIPE_CONNECT_TIMEOUT_MS: u32 = 5_000;

pub fn production_pipe_sddl(
    contract: &NamedPipeSecurityContract,
) -> Result<String, ProductionSignerTransportError> {
    contract.validate()?;
    Ok(format!(
        "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x{CLIENT_PIPE_RIGHTS:08x};;;{})",
        contract.allowed_principal_sid
    ))
}

#[derive(Debug)]
pub struct AuthenticatedPipeConnection {
    #[cfg(windows)]
    inner: windows::PipeConnection,
    caller: Option<AuthenticatedCallerIdentity>,
    max_request_bytes: u32,
    max_response_bytes: u32,
}

impl AuthenticatedPipeConnection {
    pub fn caller(&self) -> Result<&AuthenticatedCallerIdentity, ProductionSignerTransportError> {
        self.caller
            .as_ref()
            .ok_or(ProductionSignerTransportError::CallerIdentityUnavailable)
    }

    pub fn read_request(
        &mut self,
    ) -> Result<ProductionSignerRequest, ProductionSignerTransportError> {
        self.read_json(self.max_request_bytes)
    }

    pub fn write_package(
        &mut self,
        package: &AuthorizedProductionSignerPackage,
    ) -> Result<(), ProductionSignerTransportError> {
        self.write_json(package, self.max_response_bytes)
    }

    pub fn read_json<T: DeserializeOwned>(
        &mut self,
        max_bytes: u32,
    ) -> Result<T, ProductionSignerTransportError> {
        #[cfg(windows)]
        {
            let bytes = self.inner.read_message(max_bytes)?;
            if self.caller.is_none() {
                self.caller = Some(self.inner.derive_authenticated_caller()?);
            }
            serde_json::from_slice(&bytes).map_err(ProductionSignerTransportError::Json)
        }
        #[cfg(not(windows))]
        {
            let _ = max_bytes;
            Err(ProductionSignerTransportError::UnsupportedPlatform)
        }
    }

    pub fn write_json<T: Serialize>(
        &mut self,
        value: &T,
        max_bytes: u32,
    ) -> Result<(), ProductionSignerTransportError> {
        let bytes = serde_json::to_vec(value)?;
        if bytes.is_empty() || bytes.len() > max_bytes as usize {
            return Err(ProductionSignerTransportError::MessageSizeInvalid);
        }
        #[cfg(windows)]
        {
            self.inner.write_message(&bytes)
        }
        #[cfg(not(windows))]
        {
            Err(ProductionSignerTransportError::UnsupportedPlatform)
        }
    }
}

#[derive(Debug)]
pub struct ProductionSignerPipeServer {
    #[cfg(windows)]
    inner: windows::PipeServer,
    contract: NamedPipeSecurityContract,
}

impl ProductionSignerPipeServer {
    pub fn bind(
        contract: NamedPipeSecurityContract,
    ) -> Result<Self, ProductionSignerTransportError> {
        contract.validate()?;
        let sddl = production_pipe_sddl(&contract)?;
        #[cfg(windows)]
        {
            let inner = windows::PipeServer::bind(&contract, &sddl)?;
            Ok(Self { inner, contract })
        }
        #[cfg(not(windows))]
        {
            let _ = sddl;
            Err(ProductionSignerTransportError::UnsupportedPlatform)
        }
    }

    pub fn accept(
        &mut self,
    ) -> Result<AuthenticatedPipeConnection, ProductionSignerTransportError> {
        #[cfg(windows)]
        {
            let inner = self.inner.accept()?;
            Ok(AuthenticatedPipeConnection {
                inner,
                caller: None,
                max_request_bytes: self.contract.max_request_bytes,
                max_response_bytes: self.contract.max_response_bytes,
            })
        }
        #[cfg(not(windows))]
        {
            Err(ProductionSignerTransportError::UnsupportedPlatform)
        }
    }

    #[must_use]
    pub const fn contract(&self) -> &NamedPipeSecurityContract {
        &self.contract
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ProductionSignerPipeClient;

impl ProductionSignerPipeClient {
    pub fn invoke(
        &self,
        request: &ProductionSignerRequest,
    ) -> Result<AuthorizedProductionSignerPackage, ProductionSignerTransportError> {
        self.exchange(request, 64 * 1024, 128 * 1024)
    }

    pub fn exchange<Request, Response>(
        &self,
        request: &Request,
        max_request_bytes: u32,
        max_response_bytes: u32,
    ) -> Result<Response, ProductionSignerTransportError>
    where
        Request: Serialize,
        Response: DeserializeOwned,
    {
        let bytes = serde_json::to_vec(request)?;
        if bytes.is_empty() || bytes.len() > max_request_bytes as usize {
            return Err(ProductionSignerTransportError::MessageSizeInvalid);
        }
        #[cfg(windows)]
        {
            let response = windows::client_exchange(&bytes, max_response_bytes)?;
            serde_json::from_slice(&response).map_err(ProductionSignerTransportError::Json)
        }
        #[cfg(not(windows))]
        {
            let _ = max_response_bytes;
            Err(ProductionSignerTransportError::UnsupportedPlatform)
        }
    }
}

#[derive(Debug, Error)]
pub enum ProductionSignerTransportError {
    #[error("production signer named-pipe transport is unavailable on this platform")]
    UnsupportedPlatform,
    #[error("production signer caller identity is unavailable before the bounded request is read")]
    CallerIdentityUnavailable,
    #[error("production signer named-pipe message size is invalid")]
    MessageSizeInvalid,
    #[error("production signer named-pipe SDDL conversion failed: {0}")]
    SecurityDescriptorConversionFailed(#[source] std::io::Error),
    #[error("production signer named-pipe server creation failed: {0}")]
    PipeCreationFailed(#[source] std::io::Error),
    #[error("production signer named-pipe connection failed: {0}")]
    PipeConnectionFailed(#[source] std::io::Error),
    #[error("production signer named-pipe client open failed: {0}")]
    PipeClientOpenFailed(#[source] std::io::Error),
    #[error("production signer named-pipe mode configuration failed: {0}")]
    PipeModeFailed(#[source] std::io::Error),
    #[error("production signer named-pipe read failed: {0}")]
    PipeReadFailed(#[source] std::io::Error),
    #[error("production signer named-pipe write failed: {0}")]
    PipeWriteFailed(#[source] std::io::Error),
    #[error("production signer named-pipe message is incomplete")]
    IncompleteMessage,
    #[error("production signer named-pipe JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Identity(#[from] SignerIdentityError),
}

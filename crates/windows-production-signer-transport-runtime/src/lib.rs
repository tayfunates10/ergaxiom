#![cfg_attr(not(windows), forbid(unsafe_code))]

#[cfg(windows)]
mod windows;

use ergaxiom_proof_kernel::{HashingError, canonical_json_sha256};
use ergaxiom_windows_production_signer_protocol_runtime::{
    ProductionSignerRequest, ProductionSignerResponse,
};
use ergaxiom_windows_production_signer_runtime::AuthenticatedCallerIdentity;
use ergaxiom_windows_production_signer_service_runtime::AuthorizedProductionSignerPackage;
use ergaxiom_windows_production_trust_state_runtime::{
    DeployedAuthorizedProductionSignerPackage, DeployedProductionSignerError,
    DeployedProductionSignerIdentityProof, ProductionSignerIdentityChallenge,
    ProductionSignerIdentityProofError,
};
use ergaxiom_windows_signer_service_identity_runtime::{
    NamedPipeSecurityContract, SignerIdentityError,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;
use thiserror::Error;

pub const CLIENT_PIPE_RIGHTS: u32 = 0x0012_0183;
pub const PIPE_CONNECT_TIMEOUT_MS: u32 = 5_000;
pub const PIPE_IO_TIMEOUT_MS: u32 = 5_000;
pub const PRODUCTION_SIGNER_HOST_RESPONSE_SCHEMA: &str = "0.1.0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProductionSignerHostRequest {
    Sign {
        request: ProductionSignerRequest,
    },
    ProveIdentity {
        challenge: ProductionSignerIdentityChallenge,
    },
}

impl ProductionSignerHostRequest {
    #[must_use]
    pub fn sign(request: ProductionSignerRequest) -> Self {
        Self::Sign { request }
    }

    #[must_use]
    pub fn prove_identity(challenge: ProductionSignerIdentityChallenge) -> Self {
        Self::ProveIdentity { challenge }
    }

    #[must_use]
    pub fn request_id(&self) -> &str {
        match self {
            Self::Sign { request } => &request.request_id,
            Self::ProveIdentity { challenge } => &challenge.request_id,
        }
    }
}

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
        self.read_json_with_timeout(max_bytes, PIPE_IO_TIMEOUT_MS)
    }

    pub fn read_json_with_timeout<T: DeserializeOwned>(
        &mut self,
        max_bytes: u32,
        timeout_ms: u32,
    ) -> Result<T, ProductionSignerTransportError> {
        #[cfg(windows)]
        {
            let bytes = self.inner.read_message(max_bytes, timeout_ms)?;
            if self.caller.is_none() {
                self.caller = Some(self.inner.derive_authenticated_caller()?);
            }
            serde_json::from_slice(&bytes).map_err(ProductionSignerTransportError::Json)
        }
        #[cfg(not(windows))]
        {
            let _ = (max_bytes, timeout_ms);
            Err(ProductionSignerTransportError::UnsupportedPlatform)
        }
    }

    pub fn write_json<T: Serialize>(
        &mut self,
        value: &T,
        max_bytes: u32,
    ) -> Result<(), ProductionSignerTransportError> {
        self.write_json_with_timeout(value, max_bytes, PIPE_IO_TIMEOUT_MS)
    }

    pub fn write_json_with_timeout<T: Serialize>(
        &mut self,
        value: &T,
        max_bytes: u32,
        timeout_ms: u32,
    ) -> Result<(), ProductionSignerTransportError> {
        let bytes = serde_json::to_vec(value)?;
        if bytes.is_empty() || bytes.len() > max_bytes as usize {
            return Err(ProductionSignerTransportError::MessageSizeInvalid);
        }
        #[cfg(windows)]
        {
            self.inner.write_message(&bytes, timeout_ms)
        }
        #[cfg(not(windows))]
        {
            let _ = timeout_ms;
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProductionSignerHostResponse {
    Success {
        schema_version: String,
        package: Box<DeployedAuthorizedProductionSignerPackage>,
        response_digest: String,
    },
    IdentityProof {
        schema_version: String,
        request_id: String,
        proof: Box<DeployedProductionSignerIdentityProof>,
        response_digest: String,
    },
    Rejected {
        schema_version: String,
        request_id: Option<String>,
        code: String,
        response_digest: String,
    },
}

impl ProductionSignerHostResponse {
    pub fn success(
        package: DeployedAuthorizedProductionSignerPackage,
    ) -> Result<Self, ProductionSignerTransportError> {
        package.validate_seal()?;
        let mut response = Self::Success {
            schema_version: PRODUCTION_SIGNER_HOST_RESPONSE_SCHEMA.to_owned(),
            package: Box::new(package),
            response_digest: String::new(),
        };
        response.set_digest()?;
        Ok(response)
    }

    pub fn identity_proof(
        request_id: impl Into<String>,
        proof: DeployedProductionSignerIdentityProof,
    ) -> Result<Self, ProductionSignerTransportError> {
        proof.validate_seal()?;
        let mut response = Self::IdentityProof {
            schema_version: PRODUCTION_SIGNER_HOST_RESPONSE_SCHEMA.to_owned(),
            request_id: request_id.into(),
            proof: Box::new(proof),
            response_digest: String::new(),
        };
        response.set_digest()?;
        Ok(response)
    }

    pub fn rejected(
        request_id: Option<String>,
        code: impl Into<String>,
    ) -> Result<Self, ProductionSignerTransportError> {
        let mut response = Self::Rejected {
            schema_version: PRODUCTION_SIGNER_HOST_RESPONSE_SCHEMA.to_owned(),
            request_id,
            code: code.into(),
            response_digest: String::new(),
        };
        response.set_digest()?;
        Ok(response)
    }

    pub fn validate_seal(&self) -> Result<(), ProductionSignerTransportError> {
        let (schema_version, response_digest) = match self {
            Self::Success {
                schema_version,
                response_digest,
                ..
            }
            | Self::IdentityProof {
                schema_version,
                response_digest,
                ..
            }
            | Self::Rejected {
                schema_version,
                response_digest,
                ..
            } => (schema_version, response_digest),
        };
        if schema_version != PRODUCTION_SIGNER_HOST_RESPONSE_SCHEMA {
            return Err(ProductionSignerTransportError::UnsupportedHostResponseSchema);
        }
        if response_digest != &self.expected_digest()? {
            return Err(ProductionSignerTransportError::HostResponseDigestMismatch);
        }
        Ok(())
    }

    pub fn into_deployed_package(
        self,
        expected_request_id: &str,
    ) -> Result<DeployedAuthorizedProductionSignerPackage, ProductionSignerTransportError> {
        self.validate_seal()?;
        match self {
            Self::Success { package, .. } => {
                package.validate_seal()?;
                let actual_request_id = match &package.signer_package.signer_response {
                    ProductionSignerResponse::Success { request_id, .. } => {
                        Some(request_id.as_str())
                    }
                    ProductionSignerResponse::Error { request_id, .. } => request_id.as_deref(),
                };
                if actual_request_id != Some(expected_request_id) {
                    return Err(ProductionSignerTransportError::HostResponseRequestIdMismatch);
                }
                Ok(*package)
            }
            Self::IdentityProof { .. } => {
                Err(ProductionSignerTransportError::UnexpectedHostResponse)
            }
            Self::Rejected {
                request_id, code, ..
            } => {
                if request_id
                    .as_deref()
                    .is_some_and(|request_id| request_id != expected_request_id)
                {
                    return Err(ProductionSignerTransportError::HostResponseRequestIdMismatch);
                }
                Err(ProductionSignerTransportError::HostRejected { request_id, code })
            }
        }
    }

    pub fn into_identity_proof(
        self,
        expected_request_id: &str,
    ) -> Result<DeployedProductionSignerIdentityProof, ProductionSignerTransportError> {
        self.validate_seal()?;
        match self {
            Self::IdentityProof {
                request_id, proof, ..
            } => {
                if request_id != expected_request_id
                    || proof.payload.request_id != expected_request_id
                {
                    return Err(ProductionSignerTransportError::HostResponseRequestIdMismatch);
                }
                proof.validate_seal()?;
                Ok(*proof)
            }
            Self::Rejected {
                request_id, code, ..
            } => {
                if request_id
                    .as_deref()
                    .is_some_and(|request_id| request_id != expected_request_id)
                {
                    return Err(ProductionSignerTransportError::HostResponseRequestIdMismatch);
                }
                Err(ProductionSignerTransportError::HostRejected { request_id, code })
            }
            Self::Success { .. } => Err(ProductionSignerTransportError::UnexpectedHostResponse),
        }
    }

    fn set_digest(&mut self) -> Result<(), ProductionSignerTransportError> {
        let digest = self.expected_digest()?;
        match self {
            Self::Success {
                response_digest, ..
            }
            | Self::IdentityProof {
                response_digest, ..
            }
            | Self::Rejected {
                response_digest, ..
            } => *response_digest = digest,
        }
        self.validate_seal()
    }

    fn expected_digest(&self) -> Result<String, ProductionSignerTransportError> {
        let mut value = serde_json::to_value(self)?;
        let object = value
            .as_object_mut()
            .ok_or(ProductionSignerTransportError::InvalidHostResponseObject)?;
        object.insert("response_digest".to_owned(), Value::String(String::new()));
        Ok(canonical_json_sha256(&value)?)
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ProductionSignerPipeClient;

impl ProductionSignerPipeClient {
    pub fn invoke(
        &self,
        request: &ProductionSignerRequest,
    ) -> Result<AuthorizedProductionSignerPackage, ProductionSignerTransportError> {
        let deployed = self.invoke_deployed(request)?;
        deployed.validate_seal()?;
        Ok(deployed.signer_package)
    }

    pub fn invoke_deployed(
        &self,
        request: &ProductionSignerRequest,
    ) -> Result<DeployedAuthorizedProductionSignerPackage, ProductionSignerTransportError> {
        let host_request = ProductionSignerHostRequest::sign(request.clone());
        let response: ProductionSignerHostResponse =
            self.exchange(&host_request, 64 * 1024, 128 * 1024)?;
        response.into_deployed_package(&request.request_id)
    }

    pub fn prove_identity(
        &self,
        challenge: &ProductionSignerIdentityChallenge,
    ) -> Result<DeployedProductionSignerIdentityProof, ProductionSignerTransportError> {
        let request = ProductionSignerHostRequest::prove_identity(challenge.clone());
        let response: ProductionSignerHostResponse =
            self.exchange(&request, 64 * 1024, 128 * 1024)?;
        response.into_identity_proof(&challenge.request_id)
    }

    pub fn decode_host_response(
        &self,
        bytes: &[u8],
        expected_request_id: &str,
    ) -> Result<DeployedAuthorizedProductionSignerPackage, ProductionSignerTransportError> {
        let response: ProductionSignerHostResponse = serde_json::from_slice(bytes)?;
        response.into_deployed_package(expected_request_id)
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
        self.exchange_with_timeout(
            request,
            max_request_bytes,
            max_response_bytes,
            PIPE_IO_TIMEOUT_MS,
        )
    }

    pub fn exchange_with_timeout<Request, Response>(
        &self,
        request: &Request,
        max_request_bytes: u32,
        max_response_bytes: u32,
        timeout_ms: u32,
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
            let response = windows::client_exchange(&bytes, max_response_bytes, timeout_ms)?;
            serde_json::from_slice(&response).map_err(ProductionSignerTransportError::Json)
        }
        #[cfg(not(windows))]
        {
            let _ = (max_response_bytes, timeout_ms);
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
    #[error("production signer named-pipe I/O timeout is invalid")]
    IoTimeoutInvalid,
    #[error("production signer named-pipe I/O timed out")]
    IoTimedOut,
    #[error("production signer named-pipe I/O deadline setup failed: {0}")]
    IoDeadlineSetupFailed(#[source] std::io::Error),
    #[error("production signer named-pipe I/O deadline worker failed")]
    IoDeadlineWorkerFailed,
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
    #[error("production signer host response schema is unsupported")]
    UnsupportedHostResponseSchema,
    #[error("production signer host response digest does not match")]
    HostResponseDigestMismatch,
    #[error("production signer host response request identity does not match")]
    HostResponseRequestIdMismatch,
    #[error("production signer host response canonical object is invalid")]
    InvalidHostResponseObject,
    #[error("production signer host returned a response for a different operation")]
    UnexpectedHostResponse,
    #[error("production signer host rejected request {request_id:?} with code {code}")]
    HostRejected {
        request_id: Option<String>,
        code: String,
    },
    #[error("production signer named-pipe JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Hashing(#[from] HashingError),
    #[error(transparent)]
    Deployed(#[from] DeployedProductionSignerError),
    #[error(transparent)]
    IdentityProof(#[from] ProductionSignerIdentityProofError),
    #[error(transparent)]
    Identity(#[from] SignerIdentityError),
}

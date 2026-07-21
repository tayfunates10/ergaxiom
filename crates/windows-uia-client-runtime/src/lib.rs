#![forbid(unsafe_code)]

use ergaxiom_windows_bridge_runtime::{
    ObservedWindowsState, WindowsAdapterTransition, WindowsBridgeAdapter, WindowsBridgeRequest,
    WindowsControlMethod,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;
use thiserror::Error;

#[cfg(windows)]
mod process_transport;

#[cfg(windows)]
pub use process_transport::ChildJsonLineTransport;

const OBSERVE_COMMAND: &str = "observe";
const EXECUTE_COMMAND: &str = "execute";

pub trait JsonLineTransport {
    fn exchange(&mut self, command: &Value) -> Result<Value, String>;
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum WindowsUiaClientError {
    #[error("Windows UIA request must use the UI_AUTOMATION control method")]
    UnsupportedControlMethod,
    #[error("Windows UIA client is not idle")]
    ClientNotIdle,
    #[error("Windows UIA client has not been primed")]
    ClientNotPrimed,
    #[error("Windows UIA client request identity changed during the transaction")]
    RequestIdentityMismatch,
    #[error("Windows UIA request expected pre-state does not match the primed observation")]
    ExpectedPreStateMismatch,
    #[error("Windows UIA transport failed: {0}")]
    Transport(String),
    #[error("Windows UIA host response is malformed: {0}")]
    MalformedResponse(String),
    #[error("Windows UIA host response kind {actual} does not match expected kind {expected}")]
    ResponseKindMismatch { expected: String, actual: String },
    #[error("Windows UIA host rejected {kind} with {code}: {message}")]
    HostRejected {
        kind: String,
        code: String,
        message: String,
    },
    #[error("Windows UIA host omitted {0} from a successful response")]
    MissingSuccessPayload(&'static str),
    #[error("Windows UIA host returned an unexpected success payload")]
    UnexpectedSuccessPayload,
    #[error("Windows UIA host consumed a different pre-state digest")]
    ConsumedPreStateMismatch,
    #[error("Windows UIA host executable digest is invalid")]
    InvalidHostDigest,
    #[error("Windows UIA host executable digest does not match the trusted digest")]
    HostDigestMismatch,
    #[error("Windows UIA host process could not be started: {0}")]
    HostProcess(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ClientPhase {
    Idle,
    Primed {
        request_id: String,
        state: ObservedWindowsState,
    },
    PreStateDelivered {
        request_id: String,
        state_digest: String,
    },
    AwaitingPostState {
        request_id: String,
    },
}

pub struct WindowsUiaClient<T> {
    transport: T,
    phase: ClientPhase,
}

impl<T> WindowsUiaClient<T>
where
    T: JsonLineTransport,
{
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            phase: ClientPhase::Idle,
        }
    }

    pub fn prime(
        &mut self,
        request: &WindowsBridgeRequest,
    ) -> Result<ObservedWindowsState, WindowsUiaClientError> {
        if request.control_method != WindowsControlMethod::UiAutomation {
            return Err(WindowsUiaClientError::UnsupportedControlMethod);
        }
        if self.phase != ClientPhase::Idle {
            return Err(WindowsUiaClientError::ClientNotIdle);
        }

        let state = self.send_observe(request)?;
        self.phase = ClientPhase::Primed {
            request_id: request.request_id.clone(),
            state: state.clone(),
        };
        Ok(state)
    }

    pub fn into_transport(self) -> T {
        self.transport
    }

    fn send_observe(
        &mut self,
        request: &WindowsBridgeRequest,
    ) -> Result<ObservedWindowsState, WindowsUiaClientError> {
        let response = self.exchange(HostCommand {
            kind: OBSERVE_COMMAND,
            request,
            expected_pre_state_digest: None,
        })?;
        success_payload(response, OBSERVE_COMMAND, |response| response.state, "state")
    }

    fn send_execute(
        &mut self,
        request: &WindowsBridgeRequest,
        expected_pre_state_digest: &str,
    ) -> Result<WindowsAdapterTransition, WindowsUiaClientError> {
        let response = self.exchange(HostCommand {
            kind: EXECUTE_COMMAND,
            request,
            expected_pre_state_digest: Some(expected_pre_state_digest),
        })?;
        success_payload(
            response,
            EXECUTE_COMMAND,
            |response| response.transition,
            "transition",
        )
    }

    fn exchange(
        &mut self,
        command: HostCommand<'_>,
    ) -> Result<HostResponse, WindowsUiaClientError> {
        let command_value = serde_json::to_value(command)
            .map_err(|error| WindowsUiaClientError::MalformedResponse(error.to_string()))?;
        let response_value = self
            .transport
            .exchange(&command_value)
            .map_err(WindowsUiaClientError::Transport)?;
        decode(response_value)
    }
}

impl<T> WindowsBridgeAdapter for WindowsUiaClient<T>
where
    T: JsonLineTransport,
{
    fn observe(&mut self, request: &WindowsBridgeRequest) -> Result<ObservedWindowsState, String> {
        let phase = std::mem::replace(&mut self.phase, ClientPhase::Idle);
        let result = match phase {
            ClientPhase::Primed { request_id, state } => {
                if request_id != request.request_id {
                    Err(WindowsUiaClientError::RequestIdentityMismatch)
                } else if request.expected_pre_state_digest != state.state_digest {
                    Err(WindowsUiaClientError::ExpectedPreStateMismatch)
                } else {
                    self.phase = ClientPhase::PreStateDelivered {
                        request_id,
                        state_digest: state.state_digest.clone(),
                    };
                    Ok(state)
                }
            }
            ClientPhase::AwaitingPostState { request_id } => {
                if request_id != request.request_id {
                    Err(WindowsUiaClientError::RequestIdentityMismatch)
                } else {
                    let state = self.send_observe(request)?;
                    self.phase = ClientPhase::Idle;
                    Ok(state)
                }
            }
            ClientPhase::Idle => Err(WindowsUiaClientError::ClientNotPrimed),
            ClientPhase::PreStateDelivered { .. } => Err(WindowsUiaClientError::ClientNotIdle),
        };
        if result.is_err() {
            self.phase = ClientPhase::Idle;
        }
        result.map_err(|error| error.to_string())
    }

    fn execute(
        &mut self,
        request: &WindowsBridgeRequest,
        expected_pre_state_digest: &str,
    ) -> Result<WindowsAdapterTransition, String> {
        let phase = std::mem::replace(&mut self.phase, ClientPhase::Idle);
        let result = match phase {
            ClientPhase::PreStateDelivered {
                request_id,
                state_digest,
            } => {
                if request_id != request.request_id {
                    Err(WindowsUiaClientError::RequestIdentityMismatch)
                } else if expected_pre_state_digest != state_digest {
                    Err(WindowsUiaClientError::ExpectedPreStateMismatch)
                } else {
                    let transition = self.send_execute(request, expected_pre_state_digest)?;
                    if transition.consumed_pre_state_digest != expected_pre_state_digest {
                        Err(WindowsUiaClientError::ConsumedPreStateMismatch)
                    } else {
                        self.phase = ClientPhase::AwaitingPostState { request_id };
                        Ok(transition)
                    }
                }
            }
            ClientPhase::Idle | ClientPhase::Primed { .. } => {
                Err(WindowsUiaClientError::ClientNotPrimed)
            }
            ClientPhase::AwaitingPostState { .. } => Err(WindowsUiaClientError::ClientNotIdle),
        };
        if result.is_err() {
            self.phase = ClientPhase::Idle;
        }
        result.map_err(|error| error.to_string())
    }
}

#[derive(Debug, Serialize)]
struct HostCommand<'a> {
    kind: &'static str,
    request: &'a WindowsBridgeRequest,
    expected_pre_state_digest: Option<&'a str>,
}

#[derive(Debug, Deserialize)]
struct HostResponse {
    ok: bool,
    kind: String,
    state: Option<ObservedWindowsState>,
    transition: Option<WindowsAdapterTransition>,
    error: Option<HostError>,
}

#[derive(Debug, Deserialize)]
struct HostError {
    code: String,
    message: String,
}

fn decode<T: DeserializeOwned>(value: Value) -> Result<T, WindowsUiaClientError> {
    serde_json::from_value(value)
        .map_err(|error| WindowsUiaClientError::MalformedResponse(error.to_string()))
}

fn success_payload<T, F>(
    response: HostResponse,
    expected_kind: &str,
    take_payload: F,
    payload_name: &'static str,
) -> Result<T, WindowsUiaClientError>
where
    F: FnOnce(HostResponse) -> Option<T>,
{
    if response.kind != expected_kind {
        return Err(WindowsUiaClientError::ResponseKindMismatch {
            expected: expected_kind.to_owned(),
            actual: response.kind,
        });
    }
    if !response.ok {
        let error = response.error.ok_or_else(|| {
            WindowsUiaClientError::MalformedResponse(
                "failed response does not contain an error object".to_owned(),
            )
        })?;
        return Err(WindowsUiaClientError::HostRejected {
            kind: expected_kind.to_owned(),
            code: error.code,
            message: error.message,
        });
    }
    if response.error.is_some() {
        return Err(WindowsUiaClientError::UnexpectedSuccessPayload);
    }
    take_payload(response).ok_or(WindowsUiaClientError::MissingSuccessPayload(payload_name))
}

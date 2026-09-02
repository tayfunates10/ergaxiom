use std::env;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::thread;
use std::time::Duration;

use ergaxiom_intent_contract_compiler_runtime::{
    IntentCompileOutcome, StaticSocialPostIntent, compile_static_social_post_intent,
};
use ergaxiom_proof_kernel::canonical_json_sha256;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use thiserror::Error;

const DEFAULT_GATEWAY_URL: &str = "http://127.0.0.1:3000";
const CHAT_COMPLETIONS_PATH: &str = "/v1/chat/completions";
const MAX_INPUT_BYTES: usize = 8 * 1024;
const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_ATTEMPTS: usize = 3;

const SYSTEM_PROMPT: &str = r#"You are an UNTRUSTED drafting assistant inside Ergaxiom.
Return exactly one compact JSON object and no markdown:
{"language": string|null, "visual_tone": string|null}
Only suggest language and visual_tone from the user's text. Never invent or return file paths, artifact URIs, hashes, contract IDs, timestamps, requester IDs, dimensions, color profiles, contrast values, application versions, approvals, execution claims, validation claims, evidence, or certification claims. If language or visual tone is uncertain, use null."#;

#[derive(Debug, Clone, Deserialize)]
pub struct NvidiaAssistRequest {
    pub original_text: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct NvidiaDraftProvenance {
    pub provider: &'static str,
    pub trust_class: &'static str,
    pub model: Option<String>,
    pub gateway_request_digest: String,
    pub gateway_response_digest: String,
    pub model_content_digest: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct NvidiaAssistResponse {
    pub source: &'static str,
    pub draft_provenance: NvidiaDraftProvenance,
    pub guarded_intent: StaticSocialPostIntent,
    pub compile_outcome: IntentCompileOutcome,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ModelSuggestion {
    language: Option<String>,
    visual_tone: Option<String>,
}

struct GatewayConfig {
    host: String,
    port: u16,
    host_header: String,
    token: Option<String>,
}

#[derive(Debug, Error)]
enum NvidiaAssistError {
    #[error("NVIDIA assistance input must not be empty")]
    EmptyInput,
    #[error("NVIDIA assistance input exceeds the {MAX_INPUT_BYTES}-byte limit")]
    InputTooLarge,
    #[error("NVIDIA assistance input contains a NUL byte")]
    InvalidInput,
    #[error("ERGAXIOM_NVIDIA_GATEWAY_URL must be a loopback HTTP URL using localhost or 127.0.0.1")]
    UnsafeGatewayUrl,
    #[error("ERGAXIOM_NVIDIA_GATEWAY_URL contains an invalid port")]
    InvalidGatewayPort,
    #[error("ERGAXIOM_NVIDIA_GATEWAY_TOKEN contains invalid header characters")]
    InvalidGatewayToken,
    #[error("failed to connect to the local NVIDIA gateway: {0}")]
    GatewayIo(#[from] std::io::Error),
    #[error("local NVIDIA gateway returned malformed HTTP")]
    MalformedHttp,
    #[error("local NVIDIA gateway returned HTTP {0}")]
    GatewayStatus(u16),
    #[error("local NVIDIA gateway response exceeded the size limit")]
    ResponseTooLarge,
    #[error("local NVIDIA gateway returned invalid JSON: {0}")]
    InvalidGatewayJson(serde_json::Error),
    #[error("NVIDIA model response did not contain a usable assistant message")]
    MissingModelContent,
    #[error("NVIDIA model returned an invalid guarded draft: {0}")]
    InvalidModelDraft(serde_json::Error),
    #[error("NVIDIA model suggestion field {0} is invalid")]
    InvalidSuggestion(&'static str),
    #[error("failed to hash NVIDIA assistance material")]
    Hashing,
    #[error("failed to load the Graphic Designer profession capsule: {0}")]
    Capsule(serde_json::Error),
    #[error("guarded NVIDIA draft did not pass the deterministic intent compiler: {0}")]
    Compiler(String),
}

impl GatewayConfig {
    fn from_env() -> Result<Self, NvidiaAssistError> {
        let base_url = env::var("ERGAXIOM_NVIDIA_GATEWAY_URL")
            .unwrap_or_else(|_| DEFAULT_GATEWAY_URL.to_owned());
        let token = env::var("ERGAXIOM_NVIDIA_GATEWAY_TOKEN")
            .ok()
            .filter(|value| !value.is_empty());
        Self::from_values(&base_url, token)
    }

    fn from_values(base_url: &str, token: Option<String>) -> Result<Self, NvidiaAssistError> {
        let trimmed = base_url.trim().trim_end_matches('/');
        let authority = trimmed
            .strip_prefix("http://")
            .ok_or(NvidiaAssistError::UnsafeGatewayUrl)?;

        if authority.is_empty()
            || authority.contains('/')
            || authority.contains('?')
            || authority.contains('#')
            || authority.contains('@')
        {
            return Err(NvidiaAssistError::UnsafeGatewayUrl);
        }

        let (host, port) = match authority.rsplit_once(':') {
            Some((host, port)) if !host.is_empty() && !port.is_empty() => {
                let port = port
                    .parse::<u16>()
                    .map_err(|_| NvidiaAssistError::InvalidGatewayPort)?;
                (host, port)
            }
            _ => (authority, 80),
        };

        if host != "127.0.0.1" && host != "localhost" {
            return Err(NvidiaAssistError::UnsafeGatewayUrl);
        }

        if let Some(token) = token.as_deref()
            && (token.contains('\r') || token.contains('\n'))
        {
            return Err(NvidiaAssistError::InvalidGatewayToken);
        }

        let host_header = if port == 80 {
            host.to_owned()
        } else {
            format!("{host}:{port}")
        };

        Ok(Self {
            host: host.to_owned(),
            port,
            host_header,
            token,
        })
    }
}

#[tauri::command]
pub fn draft_static_social_post_with_nvidia(
    request: NvidiaAssistRequest,
) -> Result<NvidiaAssistResponse, String> {
    let config = GatewayConfig::from_env().map_err(|error| error.to_string())?;
    draft_with_config(&config, &request.original_text).map_err(|error| error.to_string())
}

fn draft_with_config(
    config: &GatewayConfig,
    original_text: &str,
) -> Result<NvidiaAssistResponse, NvidiaAssistError> {
    validate_input(original_text)?;

    let request_body = json!({
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": original_text}
        ],
        "temperature": 0.1,
        "max_tokens": 512,
        "stream": false
    });
    let request_digest = canonical_json_sha256(&request_body).map_err(|_| NvidiaAssistError::Hashing)?;
    let gateway_response = post_chat_completion(config, &request_body)?;
    let response_digest =
        canonical_json_sha256(&gateway_response).map_err(|_| NvidiaAssistError::Hashing)?;

    let model = gateway_response
        .get("model")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let content = gateway_response
        .get("choices")
        .and_then(Value::as_array)
        .and_then(|choices| choices.first())
        .and_then(|choice| choice.get("message"))
        .and_then(|message| message.get("content"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|content| !content.is_empty())
        .ok_or(NvidiaAssistError::MissingModelContent)?;

    let suggestion: ModelSuggestion =
        serde_json::from_str(content).map_err(NvidiaAssistError::InvalidModelDraft)?;
    validate_suggestion(&suggestion)?;

    let guarded_intent = StaticSocialPostIntent {
        original_text: Some(original_text.to_owned()),
        language: suggestion.language,
        visual_tone: suggestion.visual_tone,
        require_pre_execution_approval: true,
        ..StaticSocialPostIntent::default()
    };

    let capsule: Value = serde_json::from_str(include_str!(
        "../../../../professions/graphic-designer/profession.json"
    ))
    .map_err(NvidiaAssistError::Capsule)?;
    let compile_outcome = compile_static_social_post_intent(&guarded_intent, &capsule)
        .map_err(|error| NvidiaAssistError::Compiler(error.to_string()))?;
    let model_content_digest = canonical_json_sha256(&Value::String(content.to_owned()))
        .map_err(|_| NvidiaAssistError::Hashing)?;

    Ok(NvidiaAssistResponse {
        source: "nvidia_gateway_untrusted_draft",
        draft_provenance: NvidiaDraftProvenance {
            provider: "nvidia-api-gateway",
            trust_class: "untrusted_advisory",
            model,
            gateway_request_digest: request_digest,
            gateway_response_digest: response_digest,
            model_content_digest,
        },
        guarded_intent,
        compile_outcome,
    })
}

fn validate_input(original_text: &str) -> Result<(), NvidiaAssistError> {
    if original_text.trim().is_empty() {
        return Err(NvidiaAssistError::EmptyInput);
    }
    if original_text.len() > MAX_INPUT_BYTES {
        return Err(NvidiaAssistError::InputTooLarge);
    }
    if original_text.contains('\0') {
        return Err(NvidiaAssistError::InvalidInput);
    }
    Ok(())
}

fn validate_suggestion(suggestion: &ModelSuggestion) -> Result<(), NvidiaAssistError> {
    validate_advisory_text("language", suggestion.language.as_deref(), 32)?;
    validate_advisory_text("visual_tone", suggestion.visual_tone.as_deref(), 256)?;
    Ok(())
}

fn validate_advisory_text(
    field: &'static str,
    value: Option<&str>,
    max_bytes: usize,
) -> Result<(), NvidiaAssistError> {
    if let Some(value) = value
        && (value.trim().is_empty() || value.len() > max_bytes || value.contains('\0'))
    {
        return Err(NvidiaAssistError::InvalidSuggestion(field));
    }
    Ok(())
}

fn post_chat_completion(
    config: &GatewayConfig,
    body: &Value,
) -> Result<Value, NvidiaAssistError> {
    let encoded = serde_json::to_vec(body).map_err(NvidiaAssistError::InvalidGatewayJson)?;
    let mut last_status = None;

    for attempt in 0..MAX_ATTEMPTS {
        match post_once(config, &encoded) {
            Ok(response) if response.status == 200 => {
                return serde_json::from_slice(&response.body)
                    .map_err(NvidiaAssistError::InvalidGatewayJson);
            }
            Ok(response) if is_transient_status(response.status) && attempt + 1 < MAX_ATTEMPTS => {
                last_status = Some(response.status);
                thread::sleep(Duration::from_millis(250 * (1_u64 << attempt)));
            }
            Ok(response) => return Err(NvidiaAssistError::GatewayStatus(response.status)),
            Err(error) => return Err(error),
        }
    }

    Err(NvidiaAssistError::GatewayStatus(last_status.unwrap_or(503)))
}

struct HttpResponse {
    status: u16,
    body: Vec<u8>,
}

fn post_once(config: &GatewayConfig, body: &[u8]) -> Result<HttpResponse, NvidiaAssistError> {
    let mut stream = TcpStream::connect((config.host.as_str(), config.port))?;
    stream.set_read_timeout(Some(REQUEST_TIMEOUT))?;
    stream.set_write_timeout(Some(REQUEST_TIMEOUT))?;

    let authorization = config
        .token
        .as_ref()
        .map(|token| format!("Authorization: Bearer {token}\r\n"))
        .unwrap_or_default();
    let headers = format!(
        "POST {CHAT_COMPLETIONS_PATH} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nAccept: application/json\r\n{}Content-Length: {}\r\nConnection: close\r\n\r\n",
        config.host_header,
        authorization,
        body.len()
    );
    stream.write_all(headers.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()?;

    let mut raw = Vec::new();
    let mut limited = stream.take((MAX_RESPONSE_BYTES + 1) as u64);
    limited.read_to_end(&mut raw)?;
    if raw.len() > MAX_RESPONSE_BYTES {
        return Err(NvidiaAssistError::ResponseTooLarge);
    }
    parse_http_response(&raw)
}

fn parse_http_response(raw: &[u8]) -> Result<HttpResponse, NvidiaAssistError> {
    let header_end = find_bytes(raw, b"\r\n\r\n").ok_or(NvidiaAssistError::MalformedHttp)?;
    let header_bytes = &raw[..header_end];
    let body = &raw[header_end + 4..];
    let headers = std::str::from_utf8(header_bytes).map_err(|_| NvidiaAssistError::MalformedHttp)?;
    let mut lines = headers.split("\r\n");
    let status_line = lines.next().ok_or(NvidiaAssistError::MalformedHttp)?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .ok_or(NvidiaAssistError::MalformedHttp)?
        .parse::<u16>()
        .map_err(|_| NvidiaAssistError::MalformedHttp)?;
    let chunked = lines.any(|line| {
        line.split_once(':')
            .map(|(name, value)| {
                name.eq_ignore_ascii_case("transfer-encoding")
                    && value.to_ascii_lowercase().contains("chunked")
            })
            .unwrap_or(false)
    });

    let body = if chunked {
        decode_chunked(body)?
    } else {
        body.to_vec()
    };
    if body.len() > MAX_RESPONSE_BYTES {
        return Err(NvidiaAssistError::ResponseTooLarge);
    }
    Ok(HttpResponse { status, body })
}

fn decode_chunked(mut input: &[u8]) -> Result<Vec<u8>, NvidiaAssistError> {
    let mut output = Vec::new();
    loop {
        let line_end = find_bytes(input, b"\r\n").ok_or(NvidiaAssistError::MalformedHttp)?;
        let size_text = std::str::from_utf8(&input[..line_end])
            .map_err(|_| NvidiaAssistError::MalformedHttp)?;
        let size_text = size_text.split(';').next().ok_or(NvidiaAssistError::MalformedHttp)?;
        let size = usize::from_str_radix(size_text.trim(), 16)
            .map_err(|_| NvidiaAssistError::MalformedHttp)?;
        input = &input[line_end + 2..];
        if size == 0 {
            break;
        }
        if input.len() < size + 2 || &input[size..size + 2] != b"\r\n" {
            return Err(NvidiaAssistError::MalformedHttp);
        }
        output.extend_from_slice(&input[..size]);
        if output.len() > MAX_RESPONSE_BYTES {
            return Err(NvidiaAssistError::ResponseTooLarge);
        }
        input = &input[size + 2..];
    }
    Ok(output)
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|window| window == needle)
}

fn is_transient_status(status: u16) -> bool {
    matches!(status, 429 | 502 | 503 | 504)
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::mpsc;

    use serde_json::json;

    use super::*;

    #[test]
    fn gateway_configuration_rejects_non_loopback_urls() {
        assert!(GatewayConfig::from_values("https://example.com", None).is_err());
        assert!(GatewayConfig::from_values("http://192.168.1.10:3000", None).is_err());
        assert!(GatewayConfig::from_values("http://localhost:3000/path", None).is_err());
        assert!(GatewayConfig::from_values("http://127.0.0.1:3000", None).is_ok());
    }

    #[test]
    fn model_cannot_smuggle_proof_critical_fields_into_guarded_schema() {
        let model_output = r#"{"language":"tr","visual_tone":"premium","canvas_width_px":1080}"#;
        assert!(serde_json::from_str::<ModelSuggestion>(model_output).is_err());
    }

    #[test]
    fn chunked_http_body_is_decoded() {
        let response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ntest\r\n0\r\n\r\n";
        let parsed = parse_http_response(response).expect("chunked response should parse");
        assert_eq!(parsed.status, 200);
        assert_eq!(parsed.body, b"test");
    }

    #[test]
    fn local_gateway_draft_stays_advisory_and_requires_resolution() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let port = listener.local_addr().expect("listener address").port();
        let (request_tx, request_rx) = mpsc::channel();

        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("client should connect");
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("timeout should configure");
            let request = read_complete_request(&mut stream);
            request_tx.send(request).expect("request should be captured");

            let model_content = r#"{"language":"tr","visual_tone":"technical premium"}"#;
            let body = json!({
                "model": "nvidia/test-model",
                "choices": [{"message": {"role": "assistant", "content": model_content}}]
            })
            .to_string();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream
                .write_all(response.as_bytes())
                .expect("response should write");
        });

        let config = GatewayConfig::from_values(
            &format!("http://127.0.0.1:{port}"),
            Some("gateway-test-secret".to_owned()),
        )
        .expect("local config should be accepted");
        let response = draft_with_config(
            &config,
            "Teknik ve premium görünümlü bir sosyal medya gönderisi hazırla.",
        )
        .expect("draft should succeed");

        let captured = request_rx.recv().expect("request should arrive");
        server.join().expect("server should stop cleanly");
        assert!(captured.contains("Authorization: Bearer gateway-test-secret"));
        let request_body = captured
            .split("\r\n\r\n")
            .nth(1)
            .expect("request body should exist");
        assert!(!request_body.contains("gateway-test-secret"));

        assert_eq!(response.source, "nvidia_gateway_untrusted_draft");
        assert_eq!(response.guarded_intent.language.as_deref(), Some("tr"));
        assert_eq!(
            response.guarded_intent.visual_tone.as_deref(),
            Some("technical premium")
        );
        assert!(response.guarded_intent.contract_id.is_none());
        assert!(response.guarded_intent.created_at.is_none());
        assert!(response.guarded_intent.requester_id.is_none());
        assert!(response.guarded_intent.canvas_width_px.is_none());
        assert!(response.guarded_intent.canvas_height_px.is_none());
        assert!(response.guarded_intent.color_profile.is_none());
        assert!(response.guarded_intent.approved_logo.sha256.is_none());
        assert!(response.guarded_intent.brand_profile.sha256.is_none());
        assert!(response.guarded_intent.approved_copy.sha256.is_none());
        assert!(response.guarded_intent.require_pre_execution_approval);
        assert!(matches!(
            response.compile_outcome,
            IntentCompileOutcome::NeedsResolution { .. }
        ));
    }

    fn read_complete_request(stream: &mut TcpStream) -> String {
        let mut data = Vec::new();
        let mut buffer = [0_u8; 4096];
        let mut expected_total = None;
        loop {
            let count = stream.read(&mut buffer).expect("request should read");
            if count == 0 {
                break;
            }
            data.extend_from_slice(&buffer[..count]);
            if expected_total.is_none()
                && let Some(header_end) = find_bytes(&data, b"\r\n\r\n")
            {
                let headers = std::str::from_utf8(&data[..header_end]).expect("headers are UTF-8");
                let content_length = headers
                    .split("\r\n")
                    .find_map(|line| {
                        line.split_once(':').and_then(|(name, value)| {
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse::<usize>().expect("valid length"))
                        })
                    })
                    .expect("content length should exist");
                expected_total = Some(header_end + 4 + content_length);
            }
            if expected_total.is_some_and(|total| data.len() >= total) {
                break;
            }
        }
        String::from_utf8(data).expect("request should be UTF-8")
    }
}

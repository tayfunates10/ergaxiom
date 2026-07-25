use std::io::{Read, Write};
use std::path::PathBuf;

use ergaxiom_windows_signer::{DpapiProtector, OsSeedSource, SignerService, default_store_root};
use ergaxiom_windows_signer_protocol_runtime::{SignerRequest, SignerResponse};

const MAX_REQUEST_BYTES: u64 = 64 * 1024;

fn main() {
    let exit_code = match execute() {
        Ok(()) => 0,
        Err(failure) => {
            let response = SignerResponse::rejected(failure.request_id, failure.code);
            if write_response(&response).is_err() {
                3
            } else {
                2
            }
        }
    };
    std::process::exit(exit_code);
}

fn execute() -> Result<(), PublicFailure> {
    let root = parse_store_path()?;
    let bytes = read_request()?;
    let request: SignerRequest = serde_json::from_slice(&bytes).map_err(|_| PublicFailure {
        request_id: None,
        code: "MALFORMED_JSON",
    })?;
    let request_id = Some(request.request_id.clone());
    let mut service =
        SignerService::new(root, DpapiProtector, OsSeedSource).map_err(|error| PublicFailure {
            request_id: request_id.clone(),
            code: error.code(),
        })?;
    let response = service.handle(&request).map_err(|error| PublicFailure {
        request_id,
        code: error.code(),
    })?;
    write_response(&response).map_err(|_| PublicFailure {
        request_id: Some(request.request_id),
        code: "RESPONSE_WRITE_FAILED",
    })?;
    Ok(())
}

fn parse_store_path() -> Result<PathBuf, PublicFailure> {
    let mut arguments = std::env::args_os();
    let _program = arguments.next();
    let Some(argument) = arguments.next() else {
        return default_store_root().map_err(|error| PublicFailure {
            request_id: None,
            code: error.code(),
        });
    };
    if argument != "--store"
        || std::env::var("ERGAXIOM_SIGNER_TEST_MODE").as_deref() != Ok("1")
    {
        return Err(PublicFailure {
            request_id: None,
            code: "COMMAND_LINE_REJECTED",
        });
    }
    let store = arguments.next().ok_or(PublicFailure {
        request_id: None,
        code: "COMMAND_LINE_REJECTED",
    })?;
    if arguments.next().is_some() {
        return Err(PublicFailure {
            request_id: None,
            code: "COMMAND_LINE_REJECTED",
        });
    }
    let path = PathBuf::from(store);
    if !path.is_absolute() {
        return Err(PublicFailure {
            request_id: None,
            code: "STORE_PATH_INVALID",
        });
    }
    Ok(path)
}

fn read_request() -> Result<Vec<u8>, PublicFailure> {
    let mut bytes = Vec::new();
    std::io::stdin()
        .lock()
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| PublicFailure {
            request_id: None,
            code: "REQUEST_READ_FAILED",
        })?;
    if bytes.is_empty() || bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err(PublicFailure {
            request_id: None,
            code: "REQUEST_SIZE_INVALID",
        });
    }
    Ok(bytes)
}

fn write_response(response: &SignerResponse) -> Result<(), serde_json::Error> {
    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    serde_json::to_writer(&mut lock, response)?;
    lock.write_all(b"\n").map_err(serde_json::Error::io)?;
    lock.flush().map_err(serde_json::Error::io)
}

#[derive(Debug)]
struct PublicFailure {
    request_id: Option<String>,
    code: &'static str,
}

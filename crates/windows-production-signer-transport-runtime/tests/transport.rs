use ergaxiom_windows_production_signer_transport_runtime::{
    CLIENT_PIPE_RIGHTS, ProductionSignerPipeClient, ProductionSignerPipeServer,
    ProductionSignerTransportError, production_pipe_sddl,
};
use ergaxiom_windows_signer_service_identity_runtime::NamedPipeSecurityContract;
use serde::{Deserialize, Serialize};

#[test]
fn production_sddl_uses_individual_client_rights_not_generic_write()
-> Result<(), Box<dyn std::error::Error>> {
    let contract = NamedPipeSecurityContract::production("S-1-5-21-1000")?;
    let sddl = production_pipe_sddl(&contract)?;
    assert!(sddl.starts_with("D:P"));
    assert!(sddl.contains("(A;;GA;;;SY)"));
    assert!(sddl.contains("(A;;GA;;;BA)"));
    assert!(sddl.contains(&format!("0x{CLIENT_PIPE_RIGHTS:08x}")));
    assert!(sddl.contains("S-1-5-21-1000"));
    assert!(!sddl.contains("O:SY"));
    assert!(!sddl.contains("(A;;GW;;;S-1-5-21-1000)"));
    assert!(!sddl.contains("(A;;GA;;;S-1-5-21-1000)"));
    Ok(())
}

#[cfg(not(windows))]
#[test]
fn non_windows_transport_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
    let contract = NamedPipeSecurityContract::production("S-1-5-21-1000")?;
    assert!(matches!(
        ProductionSignerPipeServer::bind(contract),
        Err(ProductionSignerTransportError::UnsupportedPlatform)
    ));
    assert!(matches!(
        ProductionSignerPipeClient.exchange::<_, TestResponse>(
            &TestRequest {
                value: "request".to_owned(),
            },
            1024,
            1024,
        ),
        Err(ProductionSignerTransportError::UnsupportedPlatform)
    ));
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct TestRequest {
    value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct TestResponse {
    value: String,
}

#[cfg(windows)]
#[test]
fn real_local_message_pipe_reads_before_deriving_connected_process_identity()
-> Result<(), Box<dyn std::error::Error>> {
    let contract = NamedPipeSecurityContract::production("S-1-1-0")?;
    let mut server = ProductionSignerPipeServer::bind(contract)?;
    let client = std::thread::spawn(|| -> Result<TestResponse, ProductionSignerTransportError> {
        ProductionSignerPipeClient.exchange(
            &TestRequest {
                value: "request".to_owned(),
            },
            1024,
            1024,
        )
    });

    let mut connection = server.accept()?;
    assert!(matches!(
        connection.caller(),
        Err(ProductionSignerTransportError::CallerIdentityUnavailable)
    ));
    let request: TestRequest = connection.read_json(1024)?;
    assert_eq!(request.value, "request");
    let caller = connection.caller()?;
    assert_eq!(caller.process_id, std::process::id());
    assert!(!caller.principal_sid.is_empty());
    assert!(!caller.executable_sha256.is_empty());
    connection.write_json(
        &TestResponse {
            value: "response".to_owned(),
        },
        1024,
    )?;

    let response = client.join().map_err(|_| "client thread panicked")??;
    assert_eq!(response.value, "response");
    Ok(())
}

#[cfg(windows)]
#[test]
fn idle_connected_client_is_disconnected_after_bounded_read_deadline()
-> Result<(), Box<dyn std::error::Error>> {
    assert_stalled_connection_times_out(false)
}

#[cfg(windows)]
#[test]
fn partial_message_client_is_disconnected_after_bounded_read_deadline()
-> Result<(), Box<dyn std::error::Error>> {
    assert_stalled_connection_times_out(true)
}

#[cfg(windows)]
fn assert_stalled_connection_times_out(
    write_partial_message: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::ptr::{null, null_mut};
    use std::time::{Duration, Instant};

    use ergaxiom_windows_signer_service_identity_runtime::PRODUCTION_PIPE_NAME;
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{CreateFileW, WriteFile};
    use windows_sys::Win32::System::Pipes::WaitNamedPipeW;

    const GENERIC_READ: u32 = 0x8000_0000;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const OPEN_EXISTING: u32 = 3;
    const FILE_ATTRIBUTE_NORMAL: u32 = 0x0000_0080;

    let contract = NamedPipeSecurityContract::production("S-1-1-0")?;
    let mut server = ProductionSignerPipeServer::bind(contract.clone())?;
    let client = std::thread::spawn(move || -> Result<(), String> {
        let pipe_name: Vec<u16> = PRODUCTION_PIPE_NAME
            .encode_utf16()
            .chain(Some(0))
            .collect();
        // SAFETY: pipe_name is a live NUL-terminated fixed local pipe name and the
        // wait is bounded for this real Windows regression.
        if unsafe { WaitNamedPipeW(pipe_name.as_ptr(), 5_000) } == 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        // SAFETY: all pointers and flags follow the documented local named-pipe open
        // contract and no handle inheritance is requested.
        let handle = unsafe {
            CreateFileW(
                pipe_name.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                null(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(std::io::Error::last_os_error().to_string());
        }
        if write_partial_message {
            let partial = b"{";
            let mut written = 0_u32;
            // SAFETY: handle is live and partial is readable for exactly one byte.
            if unsafe {
                WriteFile(
                    handle,
                    partial.as_ptr().cast(),
                    partial.len() as u32,
                    &mut written,
                    null_mut(),
                )
            } == 0
                || written != partial.len() as u32
            {
                unsafe {
                    let _ = CloseHandle(handle);
                }
                return Err(std::io::Error::last_os_error().to_string());
            }
        }
        std::thread::sleep(Duration::from_millis(500));
        // SAFETY: handle is the one owned live client handle created above.
        unsafe {
            let _ = CloseHandle(handle);
        }
        Ok(())
    });

    let mut connection = server.accept()?;
    let started = Instant::now();
    let result: Result<TestRequest, ProductionSignerTransportError> =
        connection.read_json_with_timeout(1024, 100);
    assert!(matches!(
        result,
        Err(ProductionSignerTransportError::IoTimedOut)
    ));
    assert!(started.elapsed() < Duration::from_secs(2));
    drop(connection);

    let client_result = client
        .join()
        .map_err(|_| std::io::Error::other("stalled client thread panicked"))?;
    client_result.map_err(std::io::Error::other)?;

    let replacement = ProductionSignerPipeServer::bind(contract)?;
    drop(replacement);
    Ok(())
}

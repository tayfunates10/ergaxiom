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
fn real_local_message_pipe_derives_the_connected_process_identity()
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
    let request: TestRequest = connection.read_json(1024)?;
    assert_eq!(request.value, "request");
    assert_eq!(connection.caller().process_id, std::process::id());
    assert!(!connection.caller().principal_sid.is_empty());
    assert!(!connection.caller().executable_sha256.is_empty());
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

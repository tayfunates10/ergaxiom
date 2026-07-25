use ergaxiom_key_governance_runtime::IssuerRole;
use ergaxiom_windows_signer_client_runtime::{SignerClientError, SignerProcessClient};
use ergaxiom_windows_signer_protocol_runtime::SignerRequest;

#[test]
fn production_client_rejects_relative_executable_paths() {
    let result = SignerProcessClient::production("ergaxiom-windows-signer.exe");
    assert!(matches!(
        result,
        Err(SignerClientError::ExecutablePathMustBeAbsolute)
    ));
}

#[test]
fn isolated_client_rejects_relative_store_paths() -> Result<(), Box<dyn std::error::Error>> {
    let executable = std::env::current_exe()?;
    let result = SignerProcessClient::isolated_test(executable, "relative-store");
    assert!(matches!(
        result,
        Err(SignerClientError::StorePathMustBeAbsolute)
    ));
    Ok(())
}

#[test]
fn malformed_requests_fail_before_process_launch() -> Result<(), Box<dyn std::error::Error>> {
    let executable = std::env::current_exe()?;
    let client = SignerProcessClient::production(executable)?;
    let request = SignerRequest::sign_digest(
        "request.release.0001",
        IssuerRole::Release,
        "ergaxiom.release-authority",
        "release-key-01",
        "not-a-digest",
    );
    assert!(matches!(client.invoke(&request), Err(SignerClientError::Protocol(_))));
    Ok(())
}

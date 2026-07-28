use ergaxiom_windows_production_signer_runtime::{
    AUTHENTICATED_CALLER_SCHEMA, AuthenticatedCallerIdentity, SIGNER_SERVICE_IDENTITY_SCHEMA,
    SignerServiceIdentity,
};
use ergaxiom_windows_signer_service_identity_runtime::{
    AllowedSignerCaller, NamedPipeSecurityContract, SignerCallerAllowlist,
    SignerIdentityAuthorizer, SignerIdentityError,
};

const HASH_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const HASH_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const REQUEST_A: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const REQUEST_B: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

fn allowed() -> AllowedSignerCaller {
    AllowedSignerCaller {
        caller_id: "ergaxiom.backend".to_owned(),
        principal_sid: "S-1-5-21-1000".to_owned(),
        session_id: Some(2),
        executable_path: r"C:\Program Files\Ergaxiom\ergaxiom-backend.exe".to_owned(),
        executable_sha256: HASH_A.to_owned(),
    }
}

fn caller() -> AuthenticatedCallerIdentity {
    AuthenticatedCallerIdentity {
        schema_version: AUTHENTICATED_CALLER_SCHEMA.to_owned(),
        process_id: 5000,
        process_creation_time_100ns: 123_456_789,
        principal_sid: "S-1-5-21-1000".to_owned(),
        session_id: 2,
        executable_path: r"c:\program files\ergaxiom\ERGAXIOM-BACKEND.EXE".to_owned(),
        executable_sha256: HASH_A.to_owned(),
    }
}

fn service() -> SignerServiceIdentity {
    SignerServiceIdentity {
        schema_version: SIGNER_SERVICE_IDENTITY_SCHEMA.to_owned(),
        service_id: "ergaxiom.production-signer".to_owned(),
        instance_nonce: "0123456789abcdef0123456789abcdef".to_owned(),
        process_id: 6000,
        process_creation_time_100ns: 223_456_789,
        executable_sha256: HASH_B.to_owned(),
        started_at_epoch_s: 1_800_000_000,
    }
}

#[test]
fn exact_allowlisted_caller_receives_digest_bound_receipt() -> Result<(), Box<dyn std::error::Error>>
{
    let allowlist = SignerCallerAllowlist::build(1, vec![allowed()])?;
    let caller = caller();
    let service = service();
    let mut authorizer = SignerIdentityAuthorizer::default();
    let receipt = authorizer.authorize(&caller, &service, &allowlist, REQUEST_A, 1_800_000_100)?;
    receipt.validate(&caller, &service, &allowlist)?;
    assert_eq!(receipt.caller_id, "ergaxiom.backend");
    assert_eq!(receipt.allowlist_revision, 1);
    Ok(())
}

#[test]
fn principal_session_path_and_image_substitution_fail_closed()
-> Result<(), Box<dyn std::error::Error>> {
    let allowlist = SignerCallerAllowlist::build(1, vec![allowed()])?;
    for mutation in 0..4 {
        let mut caller = caller();
        match mutation {
            0 => caller.principal_sid = "S-1-5-21-2000".to_owned(),
            1 => caller.session_id = 3,
            2 => caller.executable_path = r"C:\Temp\ergaxiom-backend.exe".to_owned(),
            3 => caller.executable_sha256 = HASH_B.to_owned(),
            _ => return Err("unexpected mutation".into()),
        }
        let mut authorizer = SignerIdentityAuthorizer::default();
        assert!(matches!(
            authorizer.authorize(&caller, &service(), &allowlist, REQUEST_A, 1_800_000_100,),
            Err(SignerIdentityError::CallerNotAllowlisted)
        ));
    }
    Ok(())
}

#[test]
fn reused_pid_and_changed_process_identity_are_rejected() -> Result<(), Box<dyn std::error::Error>>
{
    let allowlist = SignerCallerAllowlist::build(1, vec![allowed()])?;
    let service = service();
    let caller = caller();
    let mut authorizer = SignerIdentityAuthorizer::default();
    authorizer.authorize(&caller, &service, &allowlist, REQUEST_A, 1_800_000_100)?;

    let mut reused = caller.clone();
    reused.process_creation_time_100ns += 1;
    assert!(matches!(
        authorizer.authorize(&reused, &service, &allowlist, REQUEST_B, 1_800_000_101,),
        Err(SignerIdentityError::ProcessIdReused)
    ));

    let mut changed = caller;
    changed.executable_path = r"C:\PROGRAM FILES\ERGAXIOM\ergaxiom-backend.exe".to_owned();
    changed.executable_sha256 = HASH_B.to_owned();
    let expanded = SignerCallerAllowlist::build(
        2,
        vec![
            allowed(),
            AllowedSignerCaller {
                caller_id: "ergaxiom.backend.changed".to_owned(),
                executable_sha256: HASH_B.to_owned(),
                ..allowed()
            },
        ],
    )?;
    assert!(matches!(
        authorizer.authorize(&changed, &service, &expanded, REQUEST_B, 1_800_000_102,),
        Err(SignerIdentityError::ProcessIdentityChanged)
    ));
    Ok(())
}

#[test]
fn request_replay_is_rejected_before_second_authorization() -> Result<(), Box<dyn std::error::Error>>
{
    let allowlist = SignerCallerAllowlist::build(1, vec![allowed()])?;
    let mut authorizer = SignerIdentityAuthorizer::default();
    authorizer.authorize(&caller(), &service(), &allowlist, REQUEST_A, 1_800_000_100)?;
    assert!(matches!(
        authorizer.authorize(&caller(), &service(), &allowlist, REQUEST_A, 1_800_000_101,),
        Err(SignerIdentityError::RequestReplayDetected)
    ));
    Ok(())
}

#[test]
fn weakened_pipe_contract_never_validates() -> Result<(), Box<dyn std::error::Error>> {
    let contract = NamedPipeSecurityContract::production("S-1-5-21-1000")?;
    contract.validate()?;
    for mutation in 0..4 {
        let mut weakened = contract.clone();
        match mutation {
            0 => weakened.reject_remote_clients = false,
            1 => weakened.message_type = false,
            2 => weakened.message_read_mode = false,
            3 => weakened.first_instance_only = false,
            _ => return Err("unexpected mutation".into()),
        }
        assert!(matches!(
            weakened.validate(),
            Err(SignerIdentityError::PipeSecurityWeakened)
        ));
    }
    Ok(())
}

#[test]
fn duplicate_allowlist_identity_is_rejected() {
    let duplicate = AllowedSignerCaller {
        caller_id: "ergaxiom.backend.duplicate".to_owned(),
        ..allowed()
    };
    assert!(matches!(
        SignerCallerAllowlist::build(1, vec![allowed(), duplicate]),
        Err(SignerIdentityError::DuplicateCallerIdentity)
    ));
}

#[cfg(not(windows))]
#[test]
fn non_windows_pipe_identity_derivation_fails_closed() {
    assert!(matches!(
        ergaxiom_windows_signer_service_identity_runtime::derive_authenticated_caller_from_named_pipe(
            1,
        ),
        Err(SignerIdentityError::UnsupportedPlatform)
    ));
}

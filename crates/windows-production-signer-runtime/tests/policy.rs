use ergaxiom_key_governance_runtime::IssuerRole;
use ergaxiom_windows_production_signer_runtime::{
    AUTHENTICATED_CALLER_SCHEMA, AuthenticatedCallerIdentity, HardwareAssurance,
    HardwareKeyDescriptor, ProductionKeyIdentity, ProductionKeyPolicy, ProductionSignerError,
    ProvisioningReceipt, SIGNER_SERVICE_IDENTITY_SCHEMA, SignerRequestBinding,
    SignerServiceIdentity,
};

const HASH_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const HASH_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn caller() -> AuthenticatedCallerIdentity {
    AuthenticatedCallerIdentity {
        schema_version: AUTHENTICATED_CALLER_SCHEMA.to_owned(),
        process_id: 4100,
        process_creation_time_100ns: 123_456_789,
        principal_sid: "S-1-5-21-1000".to_owned(),
        session_id: 2,
        executable_path: r"C:\Program Files\Ergaxiom\ergaxiom-backend.exe".to_owned(),
        executable_sha256: HASH_A.to_owned(),
    }
}

fn service() -> SignerServiceIdentity {
    SignerServiceIdentity {
        schema_version: SIGNER_SERVICE_IDENTITY_SCHEMA.to_owned(),
        service_id: "ergaxiom.production-signer".to_owned(),
        instance_nonce: "0123456789abcdef0123456789abcdef".to_owned(),
        process_id: 4200,
        process_creation_time_100ns: 223_456_789,
        executable_sha256: HASH_B.to_owned(),
        started_at_epoch_s: 1_800_000_000,
    }
}

fn descriptor(
    policy: &ProductionKeyPolicy,
) -> Result<HardwareKeyDescriptor, ProductionSignerError> {
    Ok(HardwareKeyDescriptor {
        identity: policy.identity.clone(),
        provider: policy.provider.clone(),
        algorithm: policy.algorithm.clone(),
        public_key_encoding: policy.public_key_encoding.clone(),
        public_key_base64url: "BATESTPUBLICKEY".to_owned(),
        public_key_digest: HASH_A.to_owned(),
        signature_encoding: policy.signature_encoding.clone(),
        export_policy: policy.export_policy.clone(),
        provider_implementation_flags: 1,
        assurance: HardwareAssurance::ProvenHardwareBacked,
        policy_digest: policy.digest()?,
    })
}

#[test]
fn fixed_capability_and_attestation_profiles_are_valid() -> Result<(), Box<dyn std::error::Error>> {
    let capability = ProductionKeyPolicy::capability();
    let attestation = ProductionKeyPolicy::attestation();
    capability.validate()?;
    attestation.validate()?;
    assert_eq!(capability.identity.role, IssuerRole::Capability);
    assert_eq!(attestation.identity.role, IssuerRole::Attestation);
    assert_ne!(capability.digest()?, attestation.digest()?);
    Ok(())
}

#[test]
fn software_provider_exportable_policy_and_role_substitution_fail_closed() {
    let mut policy = ProductionKeyPolicy::capability();
    policy.provider = "Microsoft Software Key Storage Provider".to_owned();
    assert!(matches!(
        policy.validate(),
        Err(ProductionSignerError::ProviderSubstitution)
    ));

    let mut policy = ProductionKeyPolicy::capability();
    policy.export_policy = "exportable".to_owned();
    assert!(matches!(
        policy.validate(),
        Err(ProductionSignerError::ExportPolicySubstitution)
    ));

    let policy = ProductionKeyPolicy::for_identity(ProductionKeyIdentity {
        role: IssuerRole::Release,
        issuer_id: "ergaxiom.release-authority".to_owned(),
        key_id: "release-key-v1".to_owned(),
    });
    assert!(matches!(
        policy.validate(),
        Err(ProductionSignerError::UnsupportedProductionRole)
    ));
}

#[test]
fn hardware_descriptor_cannot_claim_eligibility_while_assurance_is_unproven()
-> Result<(), Box<dyn std::error::Error>> {
    let policy = ProductionKeyPolicy::capability();
    let mut descriptor = descriptor(&policy)?;
    descriptor.assurance = HardwareAssurance::Unproven;
    assert!(matches!(
        descriptor.validate_for(&policy),
        Err(ProductionSignerError::HardwareAssuranceUnproven)
    ));
    descriptor.assurance = HardwareAssurance::ProvenHardwareBacked;
    descriptor.validate_for(&policy)?;
    Ok(())
}

#[test]
fn caller_process_creation_time_and_image_digest_are_request_bound()
-> Result<(), Box<dyn std::error::Error>> {
    let policy = ProductionKeyPolicy::attestation();
    let caller = caller();
    let service = service();
    let binding = SignerRequestBinding::build(HASH_A, &caller, &service, &policy)?;

    let mut stale_pid_reuse = caller.clone();
    stale_pid_reuse.process_creation_time_100ns += 1;
    let stale_binding = SignerRequestBinding::build(HASH_A, &stale_pid_reuse, &service, &policy)?;
    assert_ne!(binding.digest()?, stale_binding.digest()?);

    let mut altered_image = caller;
    altered_image.executable_sha256 = HASH_B.to_owned();
    let altered_binding = SignerRequestBinding::build(HASH_A, &altered_image, &service, &policy)?;
    assert_ne!(binding.digest()?, altered_binding.digest()?);
    Ok(())
}

#[test]
fn signer_service_instance_substitution_changes_request_binding()
-> Result<(), Box<dyn std::error::Error>> {
    let policy = ProductionKeyPolicy::capability();
    let caller = caller();
    let service = service();
    let binding = SignerRequestBinding::build(HASH_A, &caller, &service, &policy)?;

    let mut restarted_service = service;
    restarted_service.instance_nonce = "fedcba9876543210fedcba9876543210".to_owned();
    let restarted = SignerRequestBinding::build(HASH_A, &caller, &restarted_service, &policy)?;
    assert_ne!(binding.digest()?, restarted.digest()?);
    Ok(())
}

#[test]
fn provisioning_receipt_is_public_only_and_digest_sealed() -> Result<(), Box<dyn std::error::Error>>
{
    let policy = ProductionKeyPolicy::attestation();
    let receipt = ProvisioningReceipt::from_descriptor(descriptor(&policy)?, 1_800_000_100)?;
    receipt.validate_for(&policy)?;
    let serialized = serde_json::to_string(&receipt)?;
    for forbidden in [
        "private_key",
        "private_seed",
        "protected_seed",
        "key_material",
    ] {
        assert!(!serialized.contains(forbidden));
    }

    let mut tampered = receipt;
    tampered.public_key_digest = HASH_B.to_owned();
    assert!(matches!(
        tampered.validate_for(&policy),
        Err(ProductionSignerError::ProvisioningReceiptDigestMismatch)
            | Err(ProductionSignerError::PublicKeyDigestMismatch)
    ));
    Ok(())
}

use std::fmt::Display;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey as Ed25519SigningKey};
use ergaxiom_proof_kernel::canonical_json_sha256;
use ergaxiom_windows_production_key_governance_runtime::{
    ProductionKeyRecord, ProductionKeyRegistry,
};
use ergaxiom_windows_production_service_host_runtime::{
    PRODUCTION_SIGNER_ERROR_CONTROL, PRODUCTION_SIGNER_MAX_CONFIG_BYTES,
    PRODUCTION_SIGNER_PRESHUTDOWN_TIMEOUT_MS, PRODUCTION_SIGNER_REQUIRED_PRIVILEGE,
    PRODUCTION_SIGNER_RESTART_DELAYS_MS, PRODUCTION_SIGNER_SERVICE_ACCOUNT,
    PRODUCTION_SIGNER_SERVICE_DISPLAY_NAME, PRODUCTION_SIGNER_SERVICE_MANIFEST_SCHEMA,
    PRODUCTION_SIGNER_SERVICE_NAME, PRODUCTION_SIGNER_SERVICE_SID_TYPE,
    PRODUCTION_SIGNER_SERVICE_TYPE, PRODUCTION_SIGNER_START_MODE, ProductionSignerServiceManifest,
};
use ergaxiom_windows_production_signer_host_runtime::{
    EXPECTED_FAILURE_RESET_PERIOD_SECONDS, EXPECTED_SERVICE_DACL_SDDL,
    INSTALLATION_VALIDATION_RECEIPT_SCHEMA, INSTALLED_CNG_KEY_OBSERVATION_SCHEMA,
    INSTALLED_SERVICE_SNAPSHOT_SCHEMA, InstalledCngKeyObservation,
    InstalledProductionSignerServiceSnapshot, ProductionSignerInstallationValidationReceipt,
    ProductionSignerRecoveryExerciseReceipt, RECOVERY_EXERCISE_RECEIPT_SCHEMA,
    ServiceFailureActionObservation,
};
use ergaxiom_windows_production_signer_runtime::{
    ECDSA_P256_SHA256, HardwareAssurance, HardwareKeyDescriptor,
    MICROSOFT_PLATFORM_CRYPTO_PROVIDER, NON_EXPORTABLE_POLICY, P1363_FIXED_64,
    ProductionKeyIdentity, ProductionKeyPolicy, SEC1_UNCOMPRESSED_P256,
};
use ergaxiom_windows_production_trust_state_runtime::{
    ProductionTrustStateBody, ProductionTrustStateEnvelope, TrustGovernanceKeyRecord,
    TrustGovernancePolicy, TrustGovernanceSignature, VerifiedProductionTrustState,
    trust_state_signature_message,
};
use p256::ecdsa::SigningKey;
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

use ergaxiom_windows_production_deployment_evidence_runtime::{
    DeploymentEvidenceError, DeploymentEvidenceKeyRecord, DeploymentEvidencePolicy,
    DeploymentEvidenceSignature, SignedProductionSignerInstallationEvidence,
    SignedProductionSignerRecoveryEvidence, installation_evidence_signature_message,
    recovery_evidence_signature_message,
};

const NOW: u64 = 1_900_300_000;
const DIGEST_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const DIGEST_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const DIGEST_C: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const DIGEST_D: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
const DIGEST_E: &str = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
const EXECUTABLE_PATH: &str = r"C:\Program Files\Ergaxiom\signer.exe";
const MANIFEST_PATH: &str = r"C:\ProgramData\Ergaxiom\Signer\manifest.json";

#[test]
fn threshold_signed_installation_and_recovery_evidence_verify() {
    let fixture = fixture();
    let installation = signed_installation(&fixture, false, false);
    assert!(
        installation
            .verify(
                &fixture.evidence_policy,
                &fixture.trust_policy,
                &fixture.accepted,
                NOW + 20,
            )
            .is_ok()
    );

    let recovery = signed_recovery(&fixture, false);
    assert!(
        recovery
            .verify(
                &fixture.evidence_policy,
                &fixture.trust_policy,
                &fixture.accepted,
                NOW + 30,
            )
            .is_ok()
    );
}

#[test]
fn below_threshold_and_cross_domain_signatures_fail_closed() {
    let fixture = fixture();
    let below_threshold = signed_installation(&fixture, true, false);
    assert!(matches!(
        below_threshold.verify(
            &fixture.evidence_policy,
            &fixture.trust_policy,
            &fixture.accepted,
            NOW + 20,
        ),
        Err(DeploymentEvidenceError::ThresholdNotMet)
    ));

    let wrong_domain = signed_installation(&fixture, false, true);
    assert!(matches!(
        wrong_domain.verify(
            &fixture.evidence_policy,
            &fixture.trust_policy,
            &fixture.accepted,
            NOW + 20,
        ),
        Err(DeploymentEvidenceError::SignatureVerificationFailed)
    ));

    let wrong_recovery_domain = signed_recovery(&fixture, true);
    assert!(matches!(
        wrong_recovery_domain.verify(
            &fixture.evidence_policy,
            &fixture.trust_policy,
            &fixture.accepted,
            NOW + 30,
        ),
        Err(DeploymentEvidenceError::SignatureVerificationFailed)
    ));
}

#[test]
fn reviewer_authority_cannot_reuse_trust_governance_keys() {
    let fixture = fixture();
    let reused_policy = must(DeploymentEvidencePolicy::new(
        1,
        1,
        vec![must(DeploymentEvidenceKeyRecord::new_active(
            "reused-governance-key",
            fixture.trust_key.verifying_key().to_bytes(),
            NOW - 100,
            NOW + 1_000,
        ))],
    ));
    let receipt = installation_receipt(&fixture);
    let message = must(installation_evidence_signature_message(
        &receipt.receipt_digest,
    ));
    let signature = must(DeploymentEvidenceSignature::from_signature_bytes(
        "reused-governance-key",
        receipt.receipt_digest.clone(),
        fixture.trust_key.sign(&message).to_bytes(),
    ));
    let evidence = must(SignedProductionSignerInstallationEvidence::new(
        receipt,
        &reused_policy,
        NOW + 10,
        vec![signature],
    ));
    assert!(matches!(
        evidence.verify(
            &reused_policy,
            &fixture.trust_policy,
            &fixture.accepted,
            NOW + 20,
        ),
        Err(DeploymentEvidenceError::AuthorityKeyReuse)
    ));
}

#[test]
fn receipt_substitution_invalidates_reviewer_signatures() {
    let fixture = fixture();
    let mut evidence = signed_installation(&fixture, false, false);
    evidence.receipt.machine_identity_digest = DIGEST_A.to_owned();
    seal_installation_receipt(&mut evidence.receipt);
    assert!(matches!(
        evidence.verify(
            &fixture.evidence_policy,
            &fixture.trust_policy,
            &fixture.accepted,
            NOW + 20,
        ),
        Err(DeploymentEvidenceError::SignatureDigestMismatch)
    ));
}

#[test]
fn policy_rejects_duplicate_public_keys_and_invalid_thresholds() {
    let key = Ed25519SigningKey::from_bytes(&[91_u8; 32]);
    let first = must(DeploymentEvidenceKeyRecord::new_active(
        "reviewer-a",
        key.verifying_key().to_bytes(),
        NOW - 100,
        NOW + 1_000,
    ));
    let second = must(DeploymentEvidenceKeyRecord::new_active(
        "reviewer-b",
        key.verifying_key().to_bytes(),
        NOW - 100,
        NOW + 1_000,
    ));
    assert!(matches!(
        DeploymentEvidencePolicy::new(1, 1, vec![first, second]),
        Err(DeploymentEvidenceError::PublicKeyReuse)
    ));
    assert!(matches!(
        DeploymentEvidencePolicy::new(
            1,
            2,
            vec![must(DeploymentEvidenceKeyRecord::new_active(
                "reviewer-c",
                Ed25519SigningKey::from_bytes(&[92_u8; 32])
                    .verifying_key()
                    .to_bytes(),
                NOW - 100,
                NOW + 1_000,
            ))]
        ),
        Err(DeploymentEvidenceError::InvalidPolicy)
    ));
}

struct Fixture {
    accepted: VerifiedProductionTrustState,
    trust_policy: TrustGovernancePolicy,
    trust_key: Ed25519SigningKey,
    evidence_policy: DeploymentEvidencePolicy,
    evidence_keys: [Ed25519SigningKey; 2],
    record: ProductionKeyRecord,
    descriptor: HardwareKeyDescriptor,
}

fn fixture() -> Fixture {
    let issuer_key = must(SigningKey::from_bytes((&[17_u8; 32]).into()));
    let descriptor = descriptor_from_key(&ProductionKeyPolicy::capability(), &issuer_key);
    let mut registry = ProductionKeyRegistry::default();
    let empty_digest = must(registry.registry_digest());
    must(registry.insert_initial_guarded(
        0,
        &empty_digest,
        descriptor.clone(),
        NOW - 100,
        NOW + 1_000,
        NOW - 90,
    ));
    let record = must(
        registry
            .active_record(&ProductionKeyIdentity::capability(), NOW)
            .cloned(),
    );

    let trust_key = Ed25519SigningKey::from_bytes(&[71_u8; 32]);
    let trust_policy = must(TrustGovernancePolicy::new(
        "production-trust-governance",
        1,
        1,
        vec![must(TrustGovernanceKeyRecord::new_active(
            "governance-root-a",
            trust_key.verifying_key().to_bytes(),
            NOW - 100,
            NOW + 10_000,
        ))],
    ));
    let body = must(ProductionTrustStateBody::new(
        "ergaxiom-production-a",
        1,
        None,
        registry.snapshot(),
        2,
        DIGEST_C,
        DIGEST_A,
        3,
        DIGEST_D,
        NOW,
        NOW - 10,
        NOW + 1_000,
        1,
        "offline-recovery-v1",
    ));
    let trust_message = must(trust_state_signature_message(&body.body_digest));
    let envelope = must(ProductionTrustStateEnvelope::new(
        body.clone(),
        &trust_policy,
        vec![must(TrustGovernanceSignature::from_signature_bytes(
            "governance-root-a",
            body.body_digest,
            trust_key.sign(&trust_message).to_bytes(),
        ))],
    ));
    let accepted = must(envelope.verify(&trust_policy, NOW));

    let evidence_keys = [
        Ed25519SigningKey::from_bytes(&[81_u8; 32]),
        Ed25519SigningKey::from_bytes(&[82_u8; 32]),
    ];
    let evidence_policy = must(DeploymentEvidencePolicy::new(
        1,
        2,
        vec![
            must(DeploymentEvidenceKeyRecord::new_active(
                "deployment-reviewer-a",
                evidence_keys[0].verifying_key().to_bytes(),
                NOW - 100,
                NOW + 1_000,
            )),
            must(DeploymentEvidenceKeyRecord::new_active(
                "deployment-reviewer-b",
                evidence_keys[1].verifying_key().to_bytes(),
                NOW - 100,
                NOW + 1_000,
            )),
        ],
    ));

    Fixture {
        accepted,
        trust_policy,
        trust_key,
        evidence_policy,
        evidence_keys,
        record,
        descriptor,
    }
}

fn signed_installation(
    fixture: &Fixture,
    below_threshold: bool,
    recovery_domain: bool,
) -> SignedProductionSignerInstallationEvidence {
    let receipt = installation_receipt(fixture);
    let message = if recovery_domain {
        must(recovery_evidence_signature_message(&receipt.receipt_digest))
    } else {
        must(installation_evidence_signature_message(
            &receipt.receipt_digest,
        ))
    };
    let count = if below_threshold { 1 } else { 2 };
    let signatures = fixture
        .evidence_keys
        .iter()
        .take(count)
        .enumerate()
        .map(|(index, key)| {
            must(DeploymentEvidenceSignature::from_signature_bytes(
                format!("deployment-reviewer-{}", if index == 0 { "a" } else { "b" }),
                receipt.receipt_digest.clone(),
                key.sign(&message).to_bytes(),
            ))
        })
        .collect();
    must(SignedProductionSignerInstallationEvidence::new(
        receipt,
        &fixture.evidence_policy,
        NOW + 10,
        signatures,
    ))
}

fn signed_recovery(
    fixture: &Fixture,
    installation_domain: bool,
) -> SignedProductionSignerRecoveryEvidence {
    let receipt = recovery_receipt(fixture);
    let message = if installation_domain {
        must(installation_evidence_signature_message(
            &receipt.receipt_digest,
        ))
    } else {
        must(recovery_evidence_signature_message(&receipt.receipt_digest))
    };
    let signatures = fixture
        .evidence_keys
        .iter()
        .enumerate()
        .map(|(index, key)| {
            must(DeploymentEvidenceSignature::from_signature_bytes(
                format!("deployment-reviewer-{}", if index == 0 { "a" } else { "b" }),
                receipt.receipt_digest.clone(),
                key.sign(&message).to_bytes(),
            ))
        })
        .collect();
    must(SignedProductionSignerRecoveryEvidence::new(
        receipt,
        &fixture.evidence_policy,
        NOW + 20,
        signatures,
    ))
}

fn installation_receipt(fixture: &Fixture) -> ProductionSignerInstallationValidationReceipt {
    let binding = fixture.accepted.binding().clone();
    let mut manifest = ProductionSignerServiceManifest {
        schema_version: PRODUCTION_SIGNER_SERVICE_MANIFEST_SCHEMA.to_owned(),
        deployment_id: binding.deployment_id.clone(),
        service_name: PRODUCTION_SIGNER_SERVICE_NAME.to_owned(),
        display_name: PRODUCTION_SIGNER_SERVICE_DISPLAY_NAME.to_owned(),
        service_account: PRODUCTION_SIGNER_SERVICE_ACCOUNT.to_owned(),
        service_type: PRODUCTION_SIGNER_SERVICE_TYPE.to_owned(),
        start_mode: PRODUCTION_SIGNER_START_MODE.to_owned(),
        error_control: PRODUCTION_SIGNER_ERROR_CONTROL.to_owned(),
        service_sid_type: PRODUCTION_SIGNER_SERVICE_SID_TYPE.to_owned(),
        required_privileges: vec![PRODUCTION_SIGNER_REQUIRED_PRIVILEGE.to_owned()],
        failure_restart_delays_ms: PRODUCTION_SIGNER_RESTART_DELAYS_MS.to_vec(),
        preshutdown_timeout_ms: PRODUCTION_SIGNER_PRESHUTDOWN_TIMEOUT_MS,
        executable_path: EXECUTABLE_PATH.to_owned(),
        executable_sha256: binding.signer_service_executable_digest.clone(),
        trust_store_root: r"C:\ProgramData\Ergaxiom\Signer\trust".to_owned(),
        governance_policy_path: r"C:\ProgramData\Ergaxiom\Signer\governance.json".to_owned(),
        governance_policy_digest: fixture.trust_policy.policy_digest.clone(),
        caller_allowlist_path: r"C:\ProgramData\Ergaxiom\Signer\allowlist.json".to_owned(),
        caller_allowlist_revision: binding.caller_allowlist_revision,
        caller_allowlist_digest: binding.caller_allowlist_digest.clone(),
        deployment_policy_path: r"C:\ProgramData\Ergaxiom\Signer\deployment.json".to_owned(),
        deployment_policy_revision: binding.service_policy_revision,
        deployment_policy_digest: binding.service_policy_digest.clone(),
        pipe_allowed_principal_sid: "S-1-5-21-1000".to_owned(),
        max_config_file_bytes: PRODUCTION_SIGNER_MAX_CONFIG_BYTES,
        manifest_digest: String::new(),
    };
    manifest.manifest_digest = digest_with_blank(&manifest, "manifest_digest");

    let mut snapshot = InstalledProductionSignerServiceSnapshot {
        schema_version: INSTALLED_SERVICE_SNAPSHOT_SCHEMA.to_owned(),
        service_name: PRODUCTION_SIGNER_SERVICE_NAME.to_owned(),
        service_type: PRODUCTION_SIGNER_SERVICE_TYPE.to_owned(),
        start_mode: PRODUCTION_SIGNER_START_MODE.to_owned(),
        error_control: PRODUCTION_SIGNER_ERROR_CONTROL.to_owned(),
        binary_path: format!("\"{EXECUTABLE_PATH}\" --service --manifest \"{MANIFEST_PATH}\""),
        service_account: PRODUCTION_SIGNER_SERVICE_ACCOUNT.to_owned(),
        delayed_auto_start: true,
        service_sid_type: PRODUCTION_SIGNER_SERVICE_SID_TYPE.to_owned(),
        required_privileges: vec![PRODUCTION_SIGNER_REQUIRED_PRIVILEGE.to_owned()],
        failure_actions: vec![
            ServiceFailureActionObservation {
                action: "RESTART".to_owned(),
                delay_ms: PRODUCTION_SIGNER_RESTART_DELAYS_MS[0],
            },
            ServiceFailureActionObservation {
                action: "RESTART".to_owned(),
                delay_ms: PRODUCTION_SIGNER_RESTART_DELAYS_MS[1],
            },
            ServiceFailureActionObservation {
                action: "NONE".to_owned(),
                delay_ms: 0,
            },
        ],
        failure_actions_on_non_crash_failures: true,
        failure_reset_period_seconds: EXPECTED_FAILURE_RESET_PERIOD_SECONDS,
        preshutdown_timeout_ms: PRODUCTION_SIGNER_PRESHUTDOWN_TIMEOUT_MS,
        service_dacl_sddl: EXPECTED_SERVICE_DACL_SDDL.to_owned(),
        runtime_state: "RUNNING".to_owned(),
        process_id: 5001,
        process_creation_time_100ns: 6001,
        process_executable_path: EXECUTABLE_PATH.to_owned(),
        process_executable_sha256: binding.signer_service_executable_digest.clone(),
        snapshot_digest: String::new(),
    };
    snapshot.snapshot_digest = digest_with_blank(&snapshot, "snapshot_digest");

    let mut observation = InstalledCngKeyObservation {
        schema_version: INSTALLED_CNG_KEY_OBSERVATION_SCHEMA.to_owned(),
        identity: fixture.record.identity.clone(),
        generation: fixture.record.generation,
        key_name: "Ergaxiom.Capability.g00000000000000000001".to_owned(),
        public_key_digest: fixture.record.public_key_digest.clone(),
        key_record_digest: fixture.record.record_digest.clone(),
        policy_digest: fixture.record.policy_digest.clone(),
        descriptor_digest: must(fixture.descriptor.digest()),
        provider_implementation_flags: fixture.record.provider_implementation_flags,
        provider_hardware_flag_present: true,
        provider_software_flag_present: false,
        observation_digest: String::new(),
    };
    observation.observation_digest = digest_with_blank(&observation, "observation_digest");

    let mut receipt = ProductionSignerInstallationValidationReceipt {
        schema_version: INSTALLATION_VALIDATION_RECEIPT_SCHEMA.to_owned(),
        ceremony_id: "controlled-install-1".to_owned(),
        deployment_id: binding.deployment_id.clone(),
        machine_identity_scheme: "windows-machine-guid-domain-sha256-v1".to_owned(),
        machine_identity_digest: DIGEST_E.to_owned(),
        observed_at_epoch_s: NOW + 2,
        manifest_path: MANIFEST_PATH.to_owned(),
        manifest_digest: manifest.manifest_digest.clone(),
        governance_policy_digest: fixture.trust_policy.policy_digest.clone(),
        manifest,
        trust_state_binding: binding,
        enabled_identities: vec![ProductionKeyIdentity::capability()],
        service_snapshot: snapshot,
        active_keys: vec![observation],
        pipe_probe_response_digest: DIGEST_B.to_owned(),
        receipt_digest: String::new(),
    };
    seal_installation_receipt(&mut receipt);
    assert!(receipt.verify_against_accepted(&fixture.accepted).is_ok());
    receipt
}

fn recovery_receipt(fixture: &Fixture) -> ProductionSignerRecoveryExerciseReceipt {
    let before = installation_receipt(fixture);
    let mut after = before.clone();
    after.ceremony_id = "controlled-install.after".to_owned();
    after.observed_at_epoch_s += 10;
    after.service_snapshot.process_id += 1;
    after.service_snapshot.process_creation_time_100ns += 1;
    after.service_snapshot.snapshot_digest =
        digest_with_blank(&after.service_snapshot, "snapshot_digest");
    seal_installation_receipt(&mut after);
    let mut receipt = ProductionSignerRecoveryExerciseReceipt {
        schema_version: RECOVERY_EXERCISE_RECEIPT_SCHEMA.to_owned(),
        exercise_id: "controlled-recovery-1".to_owned(),
        deployment_id: before.deployment_id.clone(),
        started_at_epoch_s: NOW + 3,
        service_stopped_at_epoch_s: NOW + 4,
        service_restarted_at_epoch_s: NOW + 7,
        completed_at_epoch_s: after.observed_at_epoch_s,
        before,
        after,
        receipt_digest: String::new(),
    };
    receipt.receipt_digest = digest_with_blank(&receipt, "receipt_digest");
    assert!(receipt.verify_against_accepted(&fixture.accepted).is_ok());
    receipt
}

fn descriptor_from_key(
    policy: &ProductionKeyPolicy,
    signing_key: &SigningKey,
) -> HardwareKeyDescriptor {
    let point = signing_key.verifying_key().to_encoded_point(false);
    let public = point.as_bytes();
    HardwareKeyDescriptor {
        identity: policy.identity.clone(),
        provider: MICROSOFT_PLATFORM_CRYPTO_PROVIDER.to_owned(),
        algorithm: ECDSA_P256_SHA256.to_owned(),
        public_key_encoding: SEC1_UNCOMPRESSED_P256.to_owned(),
        public_key_base64url: URL_SAFE_NO_PAD.encode(public),
        public_key_digest: encode_hex(&Sha256::digest(public)),
        signature_encoding: P1363_FIXED_64.to_owned(),
        export_policy: NON_EXPORTABLE_POLICY.to_owned(),
        provider_implementation_flags: 1,
        assurance: HardwareAssurance::ProvenHardwareBacked,
        policy_digest: must(policy.digest()),
    }
}
fn seal_installation_receipt(value: &mut ProductionSignerInstallationValidationReceipt) {
    value.receipt_digest = digest_with_blank(value, "receipt_digest");
}

fn digest_with_blank<T: Serialize>(value: &T, field: &str) -> String {
    let mut json = serde_json::to_value(value)
        .unwrap_or_else(|error| panic!("serialize canonical test value failed: {error}"));
    let Some(object) = json.as_object_mut() else {
        panic!("canonical test value is not an object");
    };
    object.insert(field.to_owned(), Value::String(String::new()));
    canonical_json_sha256(&json)
        .unwrap_or_else(|error| panic!("hash canonical test value failed: {error}"))
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn must<T, E: Display>(result: Result<T, E>) -> T {
    result.unwrap_or_else(|error| panic!("test fixture failed: {error}"))
}

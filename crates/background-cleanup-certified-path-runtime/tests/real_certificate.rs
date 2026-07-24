#![cfg(feature = "real-inkscape-tests")]

use std::env;
use std::error::Error;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use ergaxiom_background_cleanup_certified_path_runtime::{
    BackgroundCleanupCertificationRequest, BackgroundCleanupCompileOutcome,
    BackgroundCleanupExecutionRequest, BackgroundCleanupIntent, BackgroundCleanupPlanIdentity,
    BackgroundCleanupPlanOutcome, CleanupArtifactIntent, certify_background_cleanup,
    compile_background_cleanup_intent, encode_restricted_srgb_rgba_png, execute_background_cleanup,
    execute_inkscape_cleanup_probe, synthesize_background_cleanup_plan,
    validate_background_cleanup,
};
use ergaxiom_capability_runtime::{
    CapabilityAuthorizer, CapabilityBindings, CapabilityGrant, CapabilitySubject,
    CapabilityTokenPayload, SignatureAlgorithm, SignatureEncoding, SignedCapabilityToken,
    TokenSignature, TrustedKeyRegistry,
};
use ergaxiom_contract_runtime::{PermissionAccess, compile_contract};
use ergaxiom_execution_runtime::{
    AuthorizationReceiptRecord, AuthorizedExecutionTrace, ReceiptBoundTraceEvent,
};
use ergaxiom_inkscape_adapter_runtime::VerifiedInkscape;
use ergaxiom_operator_plan_runtime::{CompiledPlan, TraceEvent, TraceStatus, compile_plan};
use ergaxiom_proof_kernel::{
    AssuranceLevel, DecisionStatus, canonical_json_bytes, canonical_json_sha256,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const CAPABILITY_ISSUER: &str = "ergaxiom.policy-authority";
const CAPABILITY_KEY_ID: &str = "cleanup-capability-ed25519-01";
const EXECUTOR_ID: &str = "executor.background-cleanup-01";
const DEVICE_ID: &str = "device.real-inkscape-ci-01";
const NOW: u64 = 1_000;

struct TestDirectory {
    path: PathBuf,
}

impl TestDirectory {
    fn create() -> Result<Self, Box<dyn Error>> {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let path = env::temp_dir().join(format!(
            "ergaxiom-background-cleanup-certificate-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&path)?;
        Ok(Self { path })
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[test]
fn real_inkscape_background_cleanup_reaches_a_verified_acceptance_certificate()
-> Result<(), Box<dyn Error>> {
    let executable = match env::var("ERGAXIOM_INKSCAPE") {
        Ok(value) => value,
        Err(env::VarError::NotPresent) => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    let executable_digest = env::var("ERGAXIOM_INKSCAPE_SHA256")?;
    let inkscape = VerifiedInkscape::open(executable, &executable_digest)?;
    let directory = TestDirectory::create()?;

    let (source_pixels, mask_pixels) = accepted_pixels();
    let source_png = encode_restricted_srgb_rgba_png(4, 3, &source_pixels)?;
    let mask_png = encode_restricted_srgb_rgba_png(4, 3, &mask_pixels)?;
    let source_digest = sha256(&source_png);
    let mask_digest = sha256(&mask_png);
    let capsule = capsule()?;

    let compile_outcome = compile_background_cleanup_intent(
        &BackgroundCleanupIntent {
            contract_id: Some("contract.background-cleanup.real.0001".to_owned()),
            created_at: Some("2026-07-24T08:00:00Z".to_owned()),
            original_text: Some(
                "Remove the background using the approved binary cleanup mask.".to_owned(),
            ),
            language: Some("en".to_owned()),
            requester_id: Some("ci.real-inkscape".to_owned()),
            source_raster: artifact("source.png", &source_png),
            approved_cleanup_mask: artifact("approved-mask.png", &mask_png),
            source_width_px: Some(4),
            source_height_px: Some(3),
            required_application_version: Some(inkscape.identity().version_text.clone()),
            visual_preference: Some(
                "Prefer natural-looking edges, reviewed separately from hard acceptance."
                    .to_owned(),
            ),
            require_pre_execution_approval: true,
        },
        &capsule,
    )?;
    let BackgroundCleanupCompileOutcome::Compiled { contract, .. } = compile_outcome else {
        panic!("resolved cleanup intent must compile");
    };
    let compiled_contract = compile_contract(&contract, &capsule)?;

    let plan_outcome = synthesize_background_cleanup_plan(
        &BackgroundCleanupPlanIdentity {
            plan_id: Some("plan.background-cleanup.real.0001".to_owned()),
            created_at: Some("2026-07-24T08:01:00Z".to_owned()),
        },
        &contract,
        &capsule,
    )?;
    let BackgroundCleanupPlanOutcome::Planned { plan, .. } = plan_outcome else {
        panic!("resolved cleanup identity must plan");
    };
    let compiled_plan = compile_plan(&plan, &capsule, &compiled_contract)?;

    let execution = execute_background_cleanup(BackgroundCleanupExecutionRequest {
        request_id: "cleanup.real.0001",
        source_png: &source_png,
        approved_mask_png: &mask_png,
        expected_source_digest: &source_digest,
        expected_mask_digest: &mask_digest,
        expected_width: 4,
        expected_height: 3,
    })?;
    let validation = validate_background_cleanup(
        &source_png,
        &mask_png,
        &execution.cleaned_png,
        &execution.record,
    )?;
    assert!(validation.accepted);

    let integration = execute_inkscape_cleanup_probe(
        &inkscape,
        "cleanup.real.0001",
        &execution.cleaned_png,
        4,
        3,
        &directory.path,
    )?;
    assert!(integration.verified);

    let capability_key = SigningKey::from_bytes(&[17_u8; 32]);
    let trace = authorized_trace(&compiled_contract, &compiled_plan, &capability_key)?;
    let attestation_key = SigningKey::from_bytes(&[23_u8; 32]);
    let certified = certify_background_cleanup(BackgroundCleanupCertificationRequest {
        bundle_id: "bundle.background-cleanup.real.0001",
        run_id: "run.background-cleanup.real.0001",
        created_at: "2026-07-24T08:02:00Z",
        kernel_version: "github-actions-ubuntu-24.04",
        clock_source: "github-actions-trusted-fixture",
        sandbox_id: Some("sandbox.background-cleanup.real.0001"),
        source_uri: "contract://inputs/source.png",
        mask_uri: "contract://inputs/approved-mask.png",
        cleaned_uri: "contract://outputs/background-cleaned.png",
        probe_uri: "contract://outputs/background-cleanup-probe.png",
        source_png: &source_png,
        approved_mask_png: &mask_png,
        cleaned_png: &execution.cleaned_png,
        execution_record: &execution.record,
        validation_report: &validation,
        integration_report: &integration,
        authorized_trace: trace,
        compiled_contract: &compiled_contract,
        compiled_plan: &compiled_plan,
        assurance_level: AssuranceLevel::E3,
        manifest_id: "manifest.background-cleanup.real.0001",
        certificate_id: "certificate.background-cleanup.real.0001",
        issuer_id: "ergaxiom.acceptance-authority",
        key_id: "acceptance-ed25519-01",
        issued_at_epoch_s: 1_100,
        signing_key: &attestation_key,
    })?;

    assert_eq!(
        certified.verified_attestation.decision,
        DecisionStatus::Accepted
    );
    assert_eq!(certified.evidence_bundle.proof_results.len(), 12);
    assert_eq!(
        certified.attestation.certificate.payload.mandatory_passed,
        12
    );
    assert_eq!(
        certified.attestation.certificate.payload.mandatory_failed,
        0
    );
    assert_eq!(
        certified.attestation.certificate.payload.mandatory_unknown,
        0
    );
    assert_eq!(certified.evidence_bundle_digest.len(), 64);
    Ok(())
}

fn authorized_trace(
    contract: &ergaxiom_contract_runtime::CompiledContract,
    plan: &CompiledPlan,
    signing_key: &SigningKey,
) -> Result<AuthorizedExecutionTrace, Box<dyn Error>> {
    let mut trusted_keys = TrustedKeyRegistry::default();
    trusted_keys.insert_ed25519(
        CAPABILITY_ISSUER,
        CAPABILITY_KEY_ID,
        signing_key.verifying_key().to_bytes(),
    )?;
    let mut authorizer = CapabilityAuthorizer::new(trusted_keys);
    let mut receipt_records = Vec::new();

    for (index, step) in plan.steps.iter().enumerate() {
        let grant = match step.step_id.as_str() {
            "step.cleanup" | "step.certify" => CapabilityGrant {
                capability: "cleanup-runtime".to_owned(),
                resource: "isolated-workspace".to_owned(),
                access: PermissionAccess::Control,
                constraints: json!({"network": false}),
            },
            "step.probe" => CapabilityGrant {
                capability: "design-editor".to_owned(),
                resource: "integration-probe".to_owned(),
                access: PermissionAccess::Control,
                constraints: json!({"network": false}),
            },
            other => return Err(format!("unexpected cleanup step {other}").into()),
        };
        let token_id = step
            .capability_token_ids
            .first()
            .ok_or("cleanup step has no capability token")?;
        let payload = CapabilityTokenPayload {
            schema_version: "0.1.0".to_owned(),
            token_id: token_id.clone(),
            issuer_id: CAPABILITY_ISSUER.to_owned(),
            key_id: CAPABILITY_KEY_ID.to_owned(),
            subject: CapabilitySubject {
                executor_id: EXECUTOR_ID.to_owned(),
                device_id: Some(DEVICE_ID.to_owned()),
            },
            issued_at_epoch_s: 900,
            not_before_epoch_s: 950,
            expires_at_epoch_s: 1_200,
            max_uses: 1,
            nonce: format!("cleanup-capability-nonce-{index:04}"),
            bindings: CapabilityBindings {
                contract_digest: contract.seal.contract_digest.clone(),
                capsule_digest: contract.seal.capsule_digest.clone(),
                plan_id: plan.plan_id.clone(),
                plan_digest: plan.plan_digest.clone(),
                step_id: step.step_id.clone(),
                operator_id: step.operator_id.clone(),
            },
            grant,
        };
        let payload_value = serde_json::to_value(&payload)?;
        let signature = signing_key.sign(&canonical_json_bytes(&payload_value)?);
        let token_value = serde_json::to_value(SignedCapabilityToken {
            payload,
            signature: TokenSignature {
                algorithm: SignatureAlgorithm::Ed25519,
                encoding: SignatureEncoding::Base64url,
                value: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
            },
        })?;
        let receipt = authorizer.authorize(
            &token_value,
            contract,
            plan,
            NOW,
            EXECUTOR_ID,
            Some(DEVICE_ID),
        )?;
        let receipt_value = serde_json::to_value(&receipt)?;
        receipt_records.push(AuthorizationReceiptRecord {
            receipt_digest: canonical_json_sha256(&receipt_value)?,
            receipt,
        });
    }

    let mut events = Vec::new();
    for (step_index, (step, receipt)) in plan.steps.iter().zip(receipt_records.iter()).enumerate() {
        let token_id = receipt.receipt.token_id.clone();
        for (status_index, status) in [TraceStatus::Started, TraceStatus::Succeeded]
            .into_iter()
            .enumerate()
        {
            let sequence = step_index * 2 + status_index;
            events.push(ReceiptBoundTraceEvent {
                event: TraceEvent {
                    event_id: format!("event.{}.{}", step.step_id, status_index),
                    step_id: step.step_id.clone(),
                    sequence,
                    timestamp: format!("2026-07-24T08:01:{sequence:02}Z"),
                    operator_id: step.operator_id.clone(),
                    status,
                    input_digests: Vec::new(),
                    output_digests: Vec::new(),
                    capability_token_id: Some(token_id.clone()),
                },
                authorization_receipt_digest: Some(receipt.receipt_digest.clone()),
            });
        }
    }

    Ok(AuthorizedExecutionTrace {
        schema_version: "0.1.0".to_owned(),
        trace_id: "trace.background-cleanup.real.0001".to_owned(),
        plan_id: plan.plan_id.clone(),
        plan_digest: plan.plan_digest.clone(),
        claimed_conforms_to_authorized_plan: true,
        authorization_receipts: receipt_records,
        events,
    })
}

fn artifact(name: &str, bytes: &[u8]) -> CleanupArtifactIntent {
    CleanupArtifactIntent {
        uri: Some(format!("contract://inputs/{name}")),
        media_type: Some("image/png".to_owned()),
        sha256: Some(sha256(bytes)),
    }
}

fn accepted_pixels() -> (Vec<u8>, Vec<u8>) {
    let mut source = Vec::new();
    let mut mask = Vec::new();
    for index in 0_u8..12 {
        source.extend_from_slice(&[
            index.saturating_mul(13),
            255_u8.saturating_sub(index.saturating_mul(7)),
            index.saturating_mul(5),
            255,
        ]);
        mask.extend_from_slice(&[255, 255, 255, if index % 2 == 0 { 255 } else { 0 }]);
    }
    (source, mask)
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn capsule() -> Result<Value, Box<dyn Error>> {
    Ok(serde_json::from_str(include_str!(
        "../../../professions/graphic-designer/profession.json"
    ))?)
}

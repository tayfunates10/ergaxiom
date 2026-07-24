#![cfg(feature = "real-inkscape-tests")]

use std::env;
use std::error::Error;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
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
use ergaxiom_print_ready_poster_preflight_certified_path_runtime::{
    PrintArtifactIntent, PrintEvidenceKeyRegistry, PrintPreflightCertificationRequest,
    PrintPreflightCompileOutcome, PrintPreflightExecutionRequest, PrintPreflightIntent,
    PrintPreflightPlanIdentity, PrintPreflightPlanOutcome, PrintSpecification,
    certify_print_preflight, compile_print_preflight_intent, execute_print_preflight,
    render_restricted_print_svg, sign_print_preflight_execution_record,
    synthesize_print_preflight_plan, validate_print_preflight,
};
use ergaxiom_proof_kernel::{
    AssuranceLevel, DecisionStatus, canonical_json_bytes, canonical_json_sha256,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const CAPABILITY_ISSUER: &str = "ergaxiom.policy-authority";
const CAPABILITY_KEY_ID: &str = "print-capability-ed25519-01";
const EXECUTOR_ID: &str = "executor.print-preflight-01";
const DEVICE_ID: &str = "device.real-inkscape-print-ci-01";
const NOW: u64 = 1_000;

struct TestDirectory {
    path: PathBuf,
}

impl TestDirectory {
    fn create() -> Result<Self, Box<dyn Error>> {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let path = env::temp_dir().join(format!(
            "ergaxiom-print-preflight-certificate-{}-{nonce}",
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
fn real_inkscape_print_preflight_reaches_verified_acceptance_certificate()
-> Result<(), Box<dyn Error>> {
    let executable = match env::var("ERGAXIOM_INKSCAPE") {
        Ok(value) => value,
        Err(env::VarError::NotPresent) => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    let executable_digest = env::var("ERGAXIOM_INKSCAPE_SHA256")?;
    let inkscape = VerifiedInkscape::open(executable, &executable_digest)?;
    let directory = TestDirectory::create()?;
    let specification = specification();
    let source_svg = render_restricted_print_svg(&specification)?;
    let source_digest = sha256(&source_svg);
    let specification_value = serde_json::to_value(&specification)?;
    let specification_digest = canonical_json_sha256(&specification_value)?;
    let capsule = capsule()?;

    let compile_outcome = compile_print_preflight_intent(
        &PrintPreflightIntent {
            contract_id: Some("contract.print-preflight.real.0001".to_owned()),
            created_at: Some("2026-07-24T13:00:00Z".to_owned()),
            original_text: Some(
                "Preflight the outlined vector poster against the exact supplied print specification."
                    .to_owned(),
            ),
            language: Some("en".to_owned()),
            requester_id: Some("ci.real-inkscape-print".to_owned()),
            source_svg: artifact(
                "poster.svg",
                "image/svg+xml",
                source_digest.clone(),
            ),
            print_specification: artifact(
                "print-specification.json",
                "application/json",
                specification_digest.clone(),
            ),
            resolved_specification: Some(specification.clone()),
            required_application_version: Some(inkscape.identity().version_text.clone()),
            visual_preference: Some(
                "Human review may assess visual balance outside technical acceptance."
                    .to_owned(),
            ),
            require_pre_execution_approval: true,
        },
        &capsule,
    )?;
    let PrintPreflightCompileOutcome::Compiled { contract, .. } = compile_outcome else {
        panic!("resolved print preflight intent must compile");
    };
    let compiled_contract = compile_contract(&contract, &capsule)?;

    let plan_outcome = synthesize_print_preflight_plan(
        &PrintPreflightPlanIdentity {
            plan_id: Some("plan.print-preflight.real.0001".to_owned()),
            created_at: Some("2026-07-24T13:01:00Z".to_owned()),
        },
        &contract,
        &capsule,
    )?;
    let PrintPreflightPlanOutcome::Planned { plan, .. } = plan_outcome else {
        panic!("resolved print preflight plan must compile");
    };
    let compiled_plan = compile_plan(&plan, &capsule, &compiled_contract)?;

    let execution = execute_print_preflight(
        &inkscape,
        PrintPreflightExecutionRequest {
            request_id: "print-preflight.real.0001",
            source_svg: &source_svg,
            specification: &specification,
            expected_source_digest: &source_digest,
            expected_specification_digest: &specification_digest,
        },
        &directory.path,
    )?;
    let validation = validate_print_preflight(
        &source_svg,
        &specification,
        &execution.editable_svg,
        &execution.raw_pdf,
        &execution.delivery_pdf,
        &execution.record,
    )?;
    assert!(validation.accepted, "print preflight validation rejected: {validation:#?}");

    let execution_key = SigningKey::from_bytes(&[67_u8; 32]);
    let signed_execution = sign_print_preflight_execution_record(
        &execution.record,
        "ergaxiom.print-preflight-executor",
        "print-preflight-ed25519-01",
        &execution_key,
    )?;
    let mut evidence_keys = PrintEvidenceKeyRegistry::default();
    evidence_keys.insert_ed25519(
        "ergaxiom.print-preflight-executor",
        "print-preflight-ed25519-01",
        execution_key.verifying_key().to_bytes(),
    )?;

    let capability_key = SigningKey::from_bytes(&[71_u8; 32]);
    let trace = authorized_trace(&compiled_contract, &compiled_plan, &capability_key)?;
    let acceptance_key = SigningKey::from_bytes(&[73_u8; 32]);
    let certified = certify_print_preflight(PrintPreflightCertificationRequest {
        bundle_id: "bundle.print-preflight.real.0001",
        run_id: "run.print-preflight.real.0001",
        created_at: "2026-07-24T13:02:00Z",
        operating_system: "linux",
        kernel_version: "github-actions-ubuntu-24.04",
        clock_source: "github-actions-trusted-fixture",
        sandbox_id: Some("sandbox.print-preflight.real.0001"),
        source_uri: "contract://inputs/poster.svg",
        specification_uri: "contract://inputs/print-specification.json",
        editable_uri: "contract://outputs/print-ready-poster.svg",
        delivery_uri: "contract://outputs/print-ready-poster.pdf",
        source_svg: &source_svg,
        print_specification: &specification,
        editable_svg: &execution.editable_svg,
        raw_pdf: &execution.raw_pdf,
        delivery_pdf: &execution.delivery_pdf,
        signed_execution: &signed_execution,
        validation_report: &validation,
        evidence_keys: &evidence_keys,
        authorized_trace: trace,
        compiled_contract: &compiled_contract,
        compiled_plan: &compiled_plan,
        assurance_level: AssuranceLevel::E3,
        manifest_id: "manifest.print-preflight.real.0001",
        certificate_id: "certificate.print-preflight.real.0001",
        issuer_id: "ergaxiom.acceptance-authority",
        key_id: "acceptance-ed25519-01",
        issued_at_epoch_s: 1_100,
        signing_key: &acceptance_key,
    })?;

    assert_eq!(
        certified.verified_attestation.decision,
        DecisionStatus::Accepted
    );
    assert_eq!(certified.evidence_bundle.proof_results.len(), 18);
    assert_eq!(
        certified.attestation.certificate.payload.mandatory_passed,
        18
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
            "step.validate" | "step.certify" => CapabilityGrant {
                capability: "print-validator".to_owned(),
                resource: "isolated-workspace".to_owned(),
                access: PermissionAccess::Control,
                constraints: json!({"network": false}),
            },
            "step.export" => CapabilityGrant {
                capability: "design-editor".to_owned(),
                resource: "print-export".to_owned(),
                access: PermissionAccess::Control,
                constraints: json!({"network": false}),
            },
            other => return Err(format!("unexpected print preflight step {other}").into()),
        };
        let token_id = step
            .capability_token_ids
            .first()
            .ok_or("print preflight step has no capability token")?;
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
            nonce: format!("print-capability-nonce-{index:04}"),
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
                    timestamp: format!("2026-07-24T13:01:{sequence:02}Z"),
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
        trace_id: "trace.print-preflight.real.0001".to_owned(),
        plan_id: plan.plan_id.clone(),
        plan_digest: plan.plan_digest.clone(),
        claimed_conforms_to_authorized_plan: true,
        authorization_receipts: receipt_records,
        events,
    })
}

fn specification() -> PrintSpecification {
    PrintSpecification {
        schema_version: "0.1.0".to_owned(),
        manifest_id: "print-spec.a4.real.0001".to_owned(),
        trim_width_milli_mm: 210_000,
        trim_height_milli_mm: 297_000,
        bleed_milli_mm: 3_000,
        safe_margin_milli_mm: 5_000,
        background_element_id: "bleed-background".to_owned(),
        allowed_palette: vec!["#101820".to_owned(), "#ffffff".to_owned()],
        allowed_pdf_color_spaces: vec!["DeviceRGB".to_owned(), "DeviceGray".to_owned()],
        required_pdf_version: "1.5".to_owned(),
    }
}

fn artifact(name: &str, media_type: &str, digest: String) -> PrintArtifactIntent {
    PrintArtifactIntent {
        uri: Some(format!("contract://inputs/{name}")),
        media_type: Some(media_type.to_owned()),
        sha256: Some(digest),
    }
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn capsule() -> Result<Value, Box<dyn Error>> {
    Ok(serde_json::from_str(include_str!(
        "../../../professions/graphic-designer/profession.json"
    ))?)
}

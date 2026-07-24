#![cfg(feature = "real-inkscape-tests")]

use std::env;
use std::error::Error;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use ergaxiom_background_cleanup_certified_path_runtime::encode_restricted_srgb_rgba_png;
use ergaxiom_brand_compliant_export_certified_path_runtime::{
    BrandArtifactIntent, BrandBackgroundRule, BrandEvidenceKeyRegistry,
    BrandExportCertificationRequest, BrandExportCompileOutcome, BrandExportExecutionRequest,
    BrandExportIntent, BrandExportPlanIdentity, BrandExportPlanOutcome, BrandLogoRule,
    BrandRuleManifest, BrandTypographyRule, certify_brand_export, compile_brand_export_intent,
    execute_brand_export, render_restricted_brand_svg, sign_brand_export_execution_record,
    synthesize_brand_export_plan, validate_brand_export,
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
const CAPABILITY_KEY_ID: &str = "brand-capability-ed25519-01";
const EXECUTOR_ID: &str = "executor.brand-export-01";
const DEVICE_ID: &str = "device.real-inkscape-ci-01";
const NOW: u64 = 1_000;

struct TestDirectory {
    path: PathBuf,
}

impl TestDirectory {
    fn create() -> Result<Self, Box<dyn Error>> {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let path = env::temp_dir().join(format!(
            "ergaxiom-brand-export-certificate-{}-{nonce}",
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
fn real_inkscape_brand_export_reaches_a_verified_acceptance_certificate()
-> Result<(), Box<dyn Error>> {
    let executable = match env::var("ERGAXIOM_INKSCAPE") {
        Ok(value) => value,
        Err(env::VarError::NotPresent) => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    let executable_digest = env::var("ERGAXIOM_INKSCAPE_SHA256")?;
    let inkscape = VerifiedInkscape::open(executable, &executable_digest)?;
    let directory = TestDirectory::create()?;

    let logo_png = logo_png()?;
    let manifest = manifest(&logo_png);
    let source_svg = render_restricted_brand_svg(&manifest, &logo_png)?;
    let source_digest = sha256(&source_svg);
    let logo_digest = sha256(&logo_png);
    let manifest_digest = canonical_json_sha256(&serde_json::to_value(&manifest)?)?;
    let capsule = capsule()?;

    let compile_outcome = compile_brand_export_intent(
        &BrandExportIntent {
            contract_id: Some("contract.brand-export.real.0001".to_owned()),
            created_at: Some("2026-07-24T11:00:00Z".to_owned()),
            original_text: Some(
                "Export the approved SVG only after every technical brand rule is proven."
                    .to_owned(),
            ),
            language: Some("en".to_owned()),
            requester_id: Some("ci.real-inkscape".to_owned()),
            source_svg: artifact("source.svg", "image/svg+xml", &source_svg),
            brand_manifest: BrandArtifactIntent {
                uri: Some("contract://inputs/brand-manifest.json".to_owned()),
                media_type: Some("application/json".to_owned()),
                sha256: Some(manifest_digest.clone()),
            },
            approved_logo: artifact("approved-logo.png", "image/png", &logo_png),
            resolved_manifest: Some(manifest.clone()),
            required_application_version: Some(inkscape.identity().version_text.clone()),
            visual_preference: Some(
                "Prefer balanced composition, reviewed outside technical acceptance.".to_owned(),
            ),
            require_pre_execution_approval: true,
        },
        &capsule,
    )?;
    let BrandExportCompileOutcome::Compiled { contract, .. } = compile_outcome else {
        panic!("resolved brand intent must compile");
    };
    let compiled_contract = compile_contract(&contract, &capsule)?;

    let plan_outcome = synthesize_brand_export_plan(
        &BrandExportPlanIdentity {
            plan_id: Some("plan.brand-export.real.0001".to_owned()),
            created_at: Some("2026-07-24T11:01:00Z".to_owned()),
        },
        &contract,
        &capsule,
    )?;
    let BrandExportPlanOutcome::Planned { plan, .. } = plan_outcome else {
        panic!("resolved brand plan identity must plan");
    };
    let compiled_plan = compile_plan(&plan, &capsule, &compiled_contract)?;

    let execution = execute_brand_export(
        &inkscape,
        BrandExportExecutionRequest {
            request_id: "brand-export.real.0001",
            source_svg: &source_svg,
            approved_logo_png: &logo_png,
            manifest: &manifest,
            expected_source_digest: &source_digest,
            expected_manifest_digest: &manifest_digest,
            expected_logo_digest: &logo_digest,
        },
        &directory.path,
    )?;
    let validation = validate_brand_export(
        &source_svg,
        &logo_png,
        &manifest,
        &execution.editable_svg,
        &execution.raw_export_png,
        &execution.delivery_png,
        &execution.record,
    )?;
    assert!(validation.accepted);

    let execution_key = SigningKey::from_bytes(&[43_u8; 32]);
    let signed_execution = sign_brand_export_execution_record(
        &execution.record,
        "ergaxiom.brand-export-executor",
        "brand-export-ed25519-01",
        &execution_key,
    )?;
    let mut evidence_keys = BrandEvidenceKeyRegistry::default();
    evidence_keys.insert_ed25519(
        "ergaxiom.brand-export-executor",
        "brand-export-ed25519-01",
        execution_key.verifying_key().to_bytes(),
    )?;

    let capability_key = SigningKey::from_bytes(&[47_u8; 32]);
    let trace = authorized_trace(&compiled_contract, &compiled_plan, &capability_key)?;
    let acceptance_key = SigningKey::from_bytes(&[53_u8; 32]);
    let certified = certify_brand_export(BrandExportCertificationRequest {
        bundle_id: "bundle.brand-export.real.0001",
        run_id: "run.brand-export.real.0001",
        created_at: "2026-07-24T11:02:00Z",
        operating_system: "linux",
        kernel_version: "github-actions-ubuntu-24.04",
        clock_source: "github-actions-trusted-fixture",
        sandbox_id: Some("sandbox.brand-export.real.0001"),
        source_uri: "contract://inputs/source.svg",
        manifest_uri: "contract://inputs/brand-manifest.json",
        logo_uri: "contract://inputs/approved-logo.png",
        editable_uri: "contract://outputs/brand-editable.svg",
        delivery_uri: "contract://outputs/brand-delivery.png",
        source_svg: &source_svg,
        approved_logo_png: &logo_png,
        brand_manifest: &manifest,
        editable_svg: &execution.editable_svg,
        raw_export_png: &execution.raw_export_png,
        delivery_png: &execution.delivery_png,
        signed_execution: &signed_execution,
        validation_report: &validation,
        evidence_keys: &evidence_keys,
        authorized_trace: trace,
        compiled_contract: &compiled_contract,
        compiled_plan: &compiled_plan,
        assurance_level: AssuranceLevel::E3,
        manifest_id: "manifest.brand-export.real.0001",
        certificate_id: "certificate.brand-export.real.0001",
        issuer_id: "ergaxiom.acceptance-authority",
        key_id: "acceptance-ed25519-01",
        issued_at_epoch_s: 1_100,
        signing_key: &acceptance_key,
    })?;

    assert_eq!(
        certified.verified_attestation.decision,
        DecisionStatus::Accepted
    );
    assert_eq!(certified.evidence_bundle.proof_results.len(), 13);
    assert_eq!(
        certified.attestation.certificate.payload.mandatory_passed,
        13
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
                capability: "brand-validator".to_owned(),
                resource: "isolated-workspace".to_owned(),
                access: PermissionAccess::Control,
                constraints: json!({"network": false}),
            },
            "step.export" => CapabilityGrant {
                capability: "design-editor".to_owned(),
                resource: "brand-export".to_owned(),
                access: PermissionAccess::Control,
                constraints: json!({"network": false}),
            },
            other => return Err(format!("unexpected brand-export step {other}").into()),
        };
        let token_id = step
            .capability_token_ids
            .first()
            .ok_or("brand-export step has no capability token")?;
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
            nonce: format!("brand-capability-nonce-{index:04}"),
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
                    timestamp: format!("2026-07-24T11:01:{sequence:02}Z"),
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
        trace_id: "trace.brand-export.real.0001".to_owned(),
        plan_id: plan.plan_id.clone(),
        plan_digest: plan.plan_digest.clone(),
        claimed_conforms_to_authorized_plan: true,
        authorization_receipts: receipt_records,
        events,
    })
}

fn manifest(logo: &[u8]) -> BrandRuleManifest {
    BrandRuleManifest {
        schema_version: "0.1.0".to_owned(),
        manifest_id: "brand.real.0001".to_owned(),
        canvas_width_px: 320,
        canvas_height_px: 180,
        allowed_palette: vec!["#112233".to_owned(), "#ffffff".to_owned()],
        background: BrandBackgroundRule {
            element_id: "brand-background".to_owned(),
            color: "#112233".to_owned(),
        },
        logo: BrandLogoRule {
            element_id: "brand-logo".to_owned(),
            approved_sha256: sha256(logo),
            x_px: 24,
            y_px: 24,
            width_px: 48,
            height_px: 48,
            minimum_clear_space_px: 24,
        },
        typography: BrandTypographyRule {
            element_id: "brand-headline".to_owned(),
            approved_copy: "Approved Brand Export".to_owned(),
            x_px: 160,
            y_px: 120,
            font_family: "DejaVu Sans".to_owned(),
            font_size_px: 24,
            font_weight: 700,
            color: "#ffffff".to_owned(),
            text_anchor: "middle".to_owned(),
        },
    }
}

fn logo_png() -> Result<Vec<u8>, Box<dyn Error>> {
    let mut pixels = Vec::new();
    for index in 0_u8..64 {
        pixels.extend_from_slice(&[
            index.saturating_mul(3),
            255_u8.saturating_sub(index.saturating_mul(2)),
            120,
            255,
        ]);
    }
    Ok(encode_restricted_srgb_rgba_png(8, 8, &pixels)?)
}

fn artifact(name: &str, media_type: &str, bytes: &[u8]) -> BrandArtifactIntent {
    BrandArtifactIntent {
        uri: Some(format!("contract://inputs/{name}")),
        media_type: Some(media_type.to_owned()),
        sha256: Some(sha256(bytes)),
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

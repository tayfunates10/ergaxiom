use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use ergaxiom_attestation_runtime::AttestationKeyRegistry;
use ergaxiom_capability_runtime::{
    CapabilityAuthorizer, CapabilityBindings, CapabilityGrant, CapabilitySubject,
    CapabilityTokenPayload, SignatureAlgorithm, SignatureEncoding, SignedCapabilityToken,
    TokenSignature, TrustedKeyRegistry,
};
use ergaxiom_contract_runtime::{CompiledContract, PermissionAccess, compile_contract};
use ergaxiom_graphic_certified_delivery_runtime::GraphicCertificationRequest;
use ergaxiom_graphic_designer_twin_runtime::{
    ApprovedCopy, ApprovedLogo, BrandProfile, CanvasSpecification, GraphicDesignJob, PixelRect,
    Rgba8,
};
use ergaxiom_graphic_inkscape_certified_delivery_runtime::{
    CertifiedInkscapeGraphicDelivery, InkscapeGraphicCertificationRequest,
    certify_inkscape_graphic_delivery,
};
use ergaxiom_inkscape_adapter_runtime::{
    InkscapeBinaryIdentity, InkscapeExecutionRecord, SetTextAndExportRequest, observe_svg,
    read_png_info, sha256_file,
};
use ergaxiom_inkscape_execution_evidence_runtime::{
    InkscapeExecutionKeyRegistry, InkscapeExecutionMaterial, SignedInkscapeExecutionRecord,
    sign_execution_record,
};
use ergaxiom_occupational_twin_runtime::{ApplicationIdentity, EnvironmentIdentity, TwinWorkspace};
use ergaxiom_operator_plan_runtime::{CompiledPlan, compile_plan};
use ergaxiom_png_srgb_normalizer_runtime::{
    NormalizationKeyRegistry, PngSrgbNormalizationMaterial, PngSrgbNormalizationRequest,
    SignedPngSrgbNormalizationRecord, SrgbRenderingIntent, normalize_png_srgb,
    sign_normalization_record,
};
use ergaxiom_proof_kernel::{AssuranceLevel, canonical_json_bytes, canonical_json_sha256};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const CONTRACT_SOURCE: &str =
    include_str!("../../../examples/work-contracts/social-media-static-post.json");
const CAPSULE_SOURCE: &str = include_str!("../../../professions/graphic-designer/profession.json");
const POLICY_ISSUER: &str = "ergaxiom.policy-authority";
const POLICY_KEY_ID: &str = "graphic-inkscape-srgb-policy-key";
pub(crate) const EXECUTOR_ID: &str = "executor.graphic-inkscape-srgb-test";
pub(crate) const DEVICE_ID: &str = "device.graphic-inkscape-srgb-test";
pub(crate) const EXECUTION_ISSUER: &str = "ergaxiom.inkscape-execution-authority";
pub(crate) const EXECUTION_KEY_ID: &str = "inkscape-execution-key-01";
pub(crate) const NORMALIZATION_ISSUER: &str = "ergaxiom.png-normalization-authority";
pub(crate) const NORMALIZATION_KEY_ID: &str = "png-normalization-key-01";
pub(crate) const ATTESTATION_ISSUER: &str = "ergaxiom.attestation-authority";
pub(crate) const ATTESTATION_KEY_ID: &str = "attestation-key-01";
pub(crate) const NOW: u64 = 30_000;

pub(crate) struct Context {
    pub(crate) contract_value: Value,
    pub(crate) compiled_contract: CompiledContract,
    pub(crate) compiled_plan: CompiledPlan,
    pub(crate) job: GraphicDesignJob,
    pub(crate) policy_key: SigningKey,
    pub(crate) attestation_key: SigningKey,
}

pub(crate) struct TestDirectory {
    path: PathBuf,
}

impl TestDirectory {
    pub(crate) fn create(name: &str) -> Result<Self, Box<dyn Error>> {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let path = std::env::temp_dir().join(format!(
            "ergaxiom-inkscape-srgb-certified-{name}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&path)?;
        Ok(Self { path })
    }

    pub(crate) fn join(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

pub(crate) struct ExecutionFixture {
    pub(crate) _directory: TestDirectory,
    pub(crate) source: PathBuf,
    pub(crate) editable: PathBuf,
    pub(crate) raster: PathBuf,
    pub(crate) request: SetTextAndExportRequest,
    pub(crate) package: SignedInkscapeExecutionRecord,
    pub(crate) keys: InkscapeExecutionKeyRegistry,
}

pub(crate) struct NormalizationFixture {
    pub(crate) output: PathBuf,
    pub(crate) request: PngSrgbNormalizationRequest,
    pub(crate) package: SignedPngSrgbNormalizationRecord,
    pub(crate) keys: NormalizationKeyRegistry,
}

pub(crate) fn context() -> Result<Context, Box<dyn Error>> {
    let job = job();
    let mut contract_value: Value = serde_json::from_str(CONTRACT_SOURCE)?;
    set_constraint_expected(&mut contract_value, "canvas_width", json!(240))?;
    set_constraint_expected(&mut contract_value, "canvas_height", json!(300))?;
    set_constraint_expected(
        &mut contract_value,
        "color_profile",
        json!("sRGB IEC61966-2.1"),
    )?;
    set_constraint_expected(&mut contract_value, "logo_clear_space", json!(16))?;
    set_input_digest(
        &mut contract_value,
        &job.approved_logo.artifact_id,
        &sha256_hex(&job.approved_logo.content),
    )?;
    set_input_digest(
        &mut contract_value,
        &job.approved_copy.artifact_id,
        &sha256_hex(job.approved_copy.text.as_bytes()),
    )?;
    let brand_profile_bytes = serde_json::to_vec(&job.brand_profile)?;
    set_input_digest(
        &mut contract_value,
        &job.brand_profile.artifact_id,
        &sha256_hex(&brand_profile_bytes),
    )?;

    let capsule_value: Value = serde_json::from_str(CAPSULE_SOURCE)?;
    let compiled_contract = compile_contract(&contract_value, &capsule_value)?;
    let compiled_plan = compile_plan(
        &plan_value(&compiled_contract),
        &capsule_value,
        &compiled_contract,
    )?;
    Ok(Context {
        contract_value,
        compiled_contract,
        compiled_plan,
        job,
        policy_key: SigningKey::from_bytes(&[31_u8; 32]),
        attestation_key: SigningKey::from_bytes(&[47_u8; 32]),
    })
}

fn job() -> GraphicDesignJob {
    GraphicDesignJob {
        schema_version: "0.1.0".to_owned(),
        job_id: "graphic-inkscape-srgb-certified-test.0001".to_owned(),
        evaluated_at: "2026-07-23T00:00:00Z".to_owned(),
        canvas: CanvasSpecification {
            width: 240,
            height: 300,
            color_profile: "sRGB IEC61966-2.1".to_owned(),
            background: Rgba8::opaque(255, 255, 255),
        },
        safe_area: PixelRect {
            x: 12,
            y: 12,
            width: 216,
            height: 276,
        },
        logo_bounds: PixelRect {
            x: 24,
            y: 24,
            width: 80,
            height: 40,
        },
        text_origin_x: 24,
        text_origin_y: 100,
        text_scale: 3,
        text_color: Rgba8::opaque(0, 0, 0),
        approved_logo: ApprovedLogo {
            artifact_id: "approved_logo".to_owned(),
            media_type: "image/svg+xml".to_owned(),
            content: b"<svg viewBox='0 0 200 100'>approved</svg>".to_vec(),
            source_width: 200,
            source_height: 100,
            primary_color: Rgba8::opaque(20, 40, 80),
            secondary_color: Rgba8::opaque(40, 120, 220),
        },
        approved_copy: ApprovedCopy {
            artifact_id: "approved_copy".to_owned(),
            media_type: "text/plain".to_owned(),
            text: "APPROVED".to_owned(),
        },
        brand_profile: BrandProfile {
            artifact_id: "brand_profile".to_owned(),
            media_type: "application/json".to_owned(),
            minimum_logo_clear_space_px: 16,
            minimum_text_contrast_milli: 4500,
        },
        editable_master_id: "editable_master".to_owned(),
        delivery_raster_id: "delivery_raster".to_owned(),
    }
}

fn plan_value(contract: &CompiledContract) -> Value {
    json!({
        "schema_version": "0.1.0",
        "plan_id": "plan.graphic-inkscape-srgb-test.0001",
        "created_at": "2026-07-23T00:00:00Z",
        "bindings": {
            "contract": {
                "id": contract.contract_id,
                "algorithm": "sha256",
                "digest": contract.seal.contract_digest,
            },
            "profession_capsule": {
                "id": "ergaxiom.profession.graphic-designer",
                "algorithm": "sha256",
                "digest": contract.seal.capsule_digest,
            }
        },
        "steps": [
            step("step.canvas", 0, "design.create_canvas", &[], &["brand_profile"], &["editable_master"], "token.canvas"),
            step("step.logo", 1, "design.place_asset", &["step.canvas"], &["editable_master", "approved_logo"], &["editable_master"], "token.logo"),
            step("step.text", 2, "design.compose_text", &["step.logo"], &["editable_master", "approved_copy"], &["editable_master"], "token.text"),
            step("step.export", 3, "design.export_raster", &["step.text"], &["editable_master"], &["delivery_raster"], "token.export"),
        ]
    })
}

fn step(
    step_id: &str,
    sequence: usize,
    operator_id: &str,
    depends_on: &[&str],
    inputs: &[&str],
    outputs: &[&str],
    token_id: &str,
) -> Value {
    json!({
        "step_id": step_id,
        "sequence": sequence,
        "operator_id": operator_id,
        "operator_version": "0.1.0",
        "depends_on": depends_on,
        "input_artifact_ids": inputs,
        "output_artifact_ids": outputs,
        "capability_token_ids": [token_id],
        "mandatory": true,
        "rollback_step_id": null,
    })
}

pub(crate) fn workspace() -> Result<TwinWorkspace, Box<dyn Error>> {
    Ok(TwinWorkspace::new(
        "workspace.graphic-inkscape-srgb-test",
        EnvironmentIdentity {
            os: "linux".to_owned(),
            architecture: "x86_64".to_owned(),
            runtime_id: "ergaxiom.graphic-inkscape-srgb-certified-delivery".to_owned(),
            runtime_version: "0.1.0".to_owned(),
            clock_source: "test-clock".to_owned(),
            sandbox_id: "sandbox.graphic-inkscape-srgb-test".to_owned(),
            applications: vec![ApplicationIdentity {
                application_id: "ergaxiom.design-document-model".to_owned(),
                version: "0.1.0".to_owned(),
                digest: "design-document-model-digest".to_owned(),
            }],
        },
    )?)
}

pub(crate) fn authorizer(context: &Context) -> Result<CapabilityAuthorizer, Box<dyn Error>> {
    let mut keys = TrustedKeyRegistry::default();
    keys.insert_ed25519(
        POLICY_ISSUER,
        POLICY_KEY_ID,
        context.policy_key.verifying_key().to_bytes(),
    )?;
    Ok(CapabilityAuthorizer::new(keys))
}

pub(crate) fn signed_tokens(context: &Context) -> Result<Vec<Value>, Box<dyn Error>> {
    context
        .compiled_plan
        .steps
        .iter()
        .enumerate()
        .map(|(index, step)| {
            let permission = permission_for_step(context, step.operator_id.as_str())?;
            let payload = CapabilityTokenPayload {
                schema_version: "0.1.0".to_owned(),
                token_id: step.capability_token_ids[0].clone(),
                issuer_id: POLICY_ISSUER.to_owned(),
                key_id: POLICY_KEY_ID.to_owned(),
                subject: CapabilitySubject {
                    executor_id: EXECUTOR_ID.to_owned(),
                    device_id: Some(DEVICE_ID.to_owned()),
                },
                issued_at_epoch_s: NOW - 100,
                not_before_epoch_s: NOW - 50,
                expires_at_epoch_s: NOW + 100,
                max_uses: 1,
                nonce: format!("graphic-inkscape-srgb-nonce-{index:02}"),
                bindings: CapabilityBindings {
                    contract_digest: context.compiled_contract.seal.contract_digest.clone(),
                    capsule_digest: context.compiled_contract.seal.capsule_digest.clone(),
                    plan_id: context.compiled_plan.plan_id.clone(),
                    plan_digest: context.compiled_plan.plan_digest.clone(),
                    step_id: step.step_id.clone(),
                    operator_id: step.operator_id.clone(),
                },
                grant: CapabilityGrant {
                    capability: permission.capability.clone(),
                    resource: permission.resource.clone(),
                    access: permission.access,
                    constraints: permission.constraints.clone(),
                },
            };
            let payload_value = serde_json::to_value(&payload)?;
            let signature = context
                .policy_key
                .sign(&canonical_json_bytes(&payload_value)?);
            Ok(serde_json::to_value(SignedCapabilityToken {
                payload,
                signature: TokenSignature {
                    algorithm: SignatureAlgorithm::Ed25519,
                    encoding: SignatureEncoding::Base64url,
                    value: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
                },
            })?)
        })
        .collect()
}

fn permission_for_step<'a>(
    context: &'a Context,
    operator_id: &str,
) -> Result<&'a ergaxiom_contract_runtime::ContractPermission, Box<dyn Error>> {
    context
        .compiled_contract
        .permissions
        .iter()
        .find(|permission| match operator_id {
            "design.create_canvas" | "design.compose_text" => {
                permission.capability == "design-editor"
                    && permission.resource == "isolated-workspace"
                    && permission.access == PermissionAccess::Control
            }
            "design.place_asset" => {
                permission.capability == "filesystem"
                    && permission.resource == "contract://inputs/*"
                    && permission.access == PermissionAccess::Read
            }
            "design.export_raster" => {
                permission.capability == "filesystem"
                    && permission.resource == "contract://outputs/*"
                    && permission.access == PermissionAccess::Write
            }
            _ => false,
        })
        .ok_or_else(|| "required contract permission missing".into())
}

pub(crate) fn base_request<'a>(
    workspace: &'a mut TwinWorkspace,
    authorizer: &'a mut CapabilityAuthorizer,
    context: &'a Context,
    tokens: &'a [Value],
) -> GraphicCertificationRequest<'a> {
    GraphicCertificationRequest {
        workspace,
        authorizer,
        compiled_contract: &context.compiled_contract,
        contract_value: &context.contract_value,
        compiled_plan: &context.compiled_plan,
        job: &context.job,
        signed_capability_tokens: tokens,
        trusted_now_epoch_s: NOW,
        executor_id: EXECUTOR_ID,
        device_id: Some(DEVICE_ID),
        assurance_level: AssuranceLevel::E3,
        bundle_id: "bundle.graphic-inkscape-srgb-base.0001",
        run_id: "run.graphic-inkscape-srgb.0001",
        trace_id: "trace.graphic-inkscape-srgb.0001",
        manifest_id: "manifest.graphic-inkscape-srgb-base.0001",
        certificate_id: "certificate.graphic-inkscape-srgb-base.0001",
        attestation_issuer_id: ATTESTATION_ISSUER,
        attestation_key_id: ATTESTATION_KEY_ID,
        certificate_issued_at_epoch_s: NOW,
        attestation_signing_key: &context.attestation_key,
    }
}

pub(crate) fn synthetic_execution_fixture() -> Result<ExecutionFixture, Box<dyn Error>> {
    let directory = TestDirectory::create("execution")?;
    let source = directory.join("source.svg");
    let editable = directory.join("editable.svg");
    let raster = directory.join("raw.png");
    fs::write(&source, svg("BEFORE"))?;
    fs::write(&editable, svg("APPROVED"))?;
    write_png(&raster, 240, 300, b"raw-inkscape-payload")?;
    execution_fixture_from_files(directory, source, editable, raster)
}

pub(crate) fn execution_fixture_from_files(
    directory: TestDirectory,
    source: PathBuf,
    editable: PathBuf,
    raster: PathBuf,
) -> Result<ExecutionFixture, Box<dyn Error>> {
    let request = SetTextAndExportRequest {
        schema_version: "0.1.0".to_owned(),
        request_id: "request.graphic-inkscape-srgb.0001".to_owned(),
        source_svg: source.clone(),
        expected_source_digest: sha256_file(&source)?,
        target_element_id: "headline".to_owned(),
        replacement_text: "APPROVED".to_owned(),
        editable_output_svg: editable.clone(),
        raster_output_png: raster.clone(),
        export_width: 240,
        export_height: 300,
    };
    let pre = observe_svg(&source)?;
    let post = observe_svg(&editable)?;
    let png = read_png_info(&raster)?;
    let mut record = InkscapeExecutionRecord {
        schema_version: "0.1.0".to_owned(),
        request_id: request.request_id.clone(),
        request_digest: canonical_json_sha256(&serde_json::to_value(&request)?)?,
        binary: InkscapeBinaryIdentity {
            application_id: "org.inkscape.Inkscape".to_owned(),
            executable_digest: "c".repeat(64),
            version_text: "Inkscape 1.4".to_owned(),
            version_major: 1,
            version_minor: 4,
            version_patch: 0,
        },
        pre_snapshot_digest: pre.snapshot_digest,
        post_snapshot_digest: post.snapshot_digest,
        editable_output_digest: sha256_file(&editable)?,
        raster_output_digest: png.artifact_digest,
        export_command_digest: "d".repeat(64),
        target_element_id: request.target_element_id.clone(),
        replacement_text: request.replacement_text.clone(),
        export_width: request.export_width,
        export_height: request.export_height,
        verified: true,
        record_digest: String::new(),
    };
    record.record_digest = execution_record_digest(&record)?;
    let execution_key = SigningKey::from_bytes(&[73_u8; 32]);
    let package =
        sign_execution_record(&record, EXECUTION_ISSUER, EXECUTION_KEY_ID, &execution_key)?;
    let mut keys = InkscapeExecutionKeyRegistry::default();
    keys.insert_ed25519(
        EXECUTION_ISSUER,
        EXECUTION_KEY_ID,
        execution_key.verifying_key().to_bytes(),
    )?;
    Ok(ExecutionFixture {
        _directory: directory,
        source,
        editable,
        raster,
        request,
        package,
        keys,
    })
}

pub(crate) fn execution_material<'a>(
    fixture: &'a ExecutionFixture,
) -> InkscapeExecutionMaterial<'a> {
    InkscapeExecutionMaterial {
        request: &fixture.request,
        package: &fixture.package,
        source_svg: &fixture.source,
        editable_svg: &fixture.editable,
        raster_png: &fixture.raster,
    }
}

pub(crate) fn certify_base_delivery(
    context: &Context,
    workspace: &mut TwinWorkspace,
    authorizer: &mut CapabilityAuthorizer,
    tokens: &[Value],
    execution: &ExecutionFixture,
) -> Result<CertifiedInkscapeGraphicDelivery, Box<dyn Error>> {
    Ok(certify_inkscape_graphic_delivery(
        InkscapeGraphicCertificationRequest {
            base: base_request(workspace, authorizer, context, tokens),
            execution_material: execution_material(execution),
            execution_keys: &execution.keys,
            final_manifest_id: "manifest.graphic-inkscape-srgb-inkscape.0001",
            final_certificate_id: "certificate.graphic-inkscape-srgb-inkscape.0001",
        },
    )?)
}

pub(crate) fn normalization_fixture(
    execution: &ExecutionFixture,
) -> Result<NormalizationFixture, Box<dyn Error>> {
    let output = execution._directory.join("normalized.png");
    let request = PngSrgbNormalizationRequest {
        schema_version: "0.1.0".to_owned(),
        request_id: "request.graphic-inkscape-srgb-normalization.0001".to_owned(),
        source_svg: execution.editable.clone(),
        expected_source_svg_digest: sha256_file(&execution.editable)?,
        input_png: execution.raster.clone(),
        expected_input_png_digest: sha256_file(&execution.raster)?,
        output_png: output.clone(),
        rendering_intent: SrgbRenderingIntent::RelativeColorimetric,
    };
    let record = normalize_png_srgb(&request)?;
    let normalization_key = SigningKey::from_bytes(&[83_u8; 32]);
    let package = sign_normalization_record(
        &record,
        NORMALIZATION_ISSUER,
        NORMALIZATION_KEY_ID,
        &normalization_key,
    )?;
    let mut keys = NormalizationKeyRegistry::default();
    keys.insert_ed25519(
        NORMALIZATION_ISSUER,
        NORMALIZATION_KEY_ID,
        normalization_key.verifying_key().to_bytes(),
    )?;
    Ok(NormalizationFixture {
        output,
        request,
        package,
        keys,
    })
}

pub(crate) fn normalization_material<'a>(
    execution: &'a ExecutionFixture,
    normalization: &'a NormalizationFixture,
) -> PngSrgbNormalizationMaterial<'a> {
    PngSrgbNormalizationMaterial {
        request: &normalization.request,
        package: &normalization.package,
        source_svg: &execution.editable,
        input_png: &execution.raster,
        output_png: &normalization.output,
    }
}

pub(crate) fn attestation_keys(
    context: &Context,
) -> Result<AttestationKeyRegistry, Box<dyn Error>> {
    let mut keys = AttestationKeyRegistry::default();
    keys.insert_ed25519(
        ATTESTATION_ISSUER,
        ATTESTATION_KEY_ID,
        context.attestation_key.verifying_key().to_bytes(),
    )?;
    Ok(keys)
}

pub(crate) fn svg(text: &str) -> String {
    format!(
        r##"<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="240" height="300" viewBox="0 0 240 300" id="root">
  <rect id="background" x="0" y="0" width="240" height="300" fill="#ffffff" />
  <text id="headline" x="24" y="100" fill="#000000">{text}</text>
</svg>
"##
    )
}

pub(crate) fn write_png(
    path: &Path,
    width: u32,
    height: u32,
    idat: &[u8],
) -> Result<(), Box<dyn Error>> {
    let mut bytes = Vec::from(*b"\x89PNG\r\n\x1a\n");
    let mut ihdr = Vec::new();
    ihdr.extend_from_slice(&width.to_be_bytes());
    ihdr.extend_from_slice(&height.to_be_bytes());
    ihdr.extend_from_slice(&[8, 6, 0, 0, 0]);
    append_chunk(&mut bytes, b"IHDR", &ihdr);
    append_chunk(&mut bytes, b"IDAT", idat);
    append_chunk(&mut bytes, b"IEND", &[]);
    fs::write(path, bytes)?;
    Ok(())
}

fn append_chunk(output: &mut Vec<u8>, chunk_type: &[u8; 4], data: &[u8]) {
    output.extend_from_slice(&(data.len() as u32).to_be_bytes());
    output.extend_from_slice(chunk_type);
    output.extend_from_slice(data);
    output.extend_from_slice(&crc32_pair(chunk_type, data).to_be_bytes());
}

fn crc32_pair(left: &[u8], right: &[u8]) -> u32 {
    let mut crc = 0xffff_ffff_u32;
    for byte in left.iter().chain(right) {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

fn execution_record_digest(record: &InkscapeExecutionRecord) -> Result<String, Box<dyn Error>> {
    let mut value = serde_json::to_value(record)?;
    let object = value.as_object_mut().ok_or("record must be an object")?;
    object.insert("record_digest".to_owned(), Value::String(String::new()));
    Ok(canonical_json_sha256(&value)?)
}

fn set_constraint_expected(
    contract: &mut Value,
    constraint_id: &str,
    expected: Value,
) -> Result<(), Box<dyn Error>> {
    let constraints = contract
        .get_mut("requirements")
        .and_then(|value| value.get_mut("hard"))
        .and_then(Value::as_array_mut)
        .ok_or("hard requirements missing")?;
    let constraint = constraints
        .iter_mut()
        .find(|constraint| constraint.get("id").and_then(Value::as_str) == Some(constraint_id))
        .ok_or("constraint missing")?;
    constraint["expected"] = expected;
    Ok(())
}

fn set_input_digest(
    contract: &mut Value,
    artifact_id: &str,
    digest: &str,
) -> Result<(), Box<dyn Error>> {
    let inputs = contract
        .get_mut("inputs")
        .and_then(Value::as_array_mut)
        .ok_or("contract inputs missing")?;
    let input = inputs
        .iter_mut()
        .find(|input| input.get("id").and_then(Value::as_str) == Some(artifact_id))
        .ok_or("contract input missing")?;
    input["integrity"]["digest"] = json!(digest);
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

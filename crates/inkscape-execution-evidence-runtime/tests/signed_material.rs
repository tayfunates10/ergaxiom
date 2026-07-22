use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;
use ergaxiom_inkscape_adapter_runtime::{
    InkscapeBinaryIdentity, InkscapeExecutionRecord, SetTextAndExportRequest, observe_svg,
    read_png_info, sha256_file,
};
use ergaxiom_inkscape_execution_evidence_runtime::{
    InkscapeEvidenceError, InkscapeExecutionKeyRegistry, InkscapeExecutionMaterial,
    sign_execution_record, verify_execution_material,
};
use ergaxiom_proof_kernel::canonical_json_sha256;
use serde_json::Value;

const ISSUER: &str = "ergaxiom.inkscape-execution-authority";
const KEY_ID: &str = "inkscape-execution-key-01";

struct TestDirectory {
    path: PathBuf,
}

impl TestDirectory {
    fn create(name: &str) -> Result<Self, Box<dyn Error>> {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let path = std::env::temp_dir().join(format!(
            "ergaxiom-inkscape-evidence-{name}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&path)?;
        Ok(Self { path })
    }

    fn join(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

struct Fixture {
    _directory: TestDirectory,
    source: PathBuf,
    editable: PathBuf,
    raster: PathBuf,
    request: SetTextAndExportRequest,
    record: InkscapeExecutionRecord,
    signing_key: SigningKey,
}

fn fixture(undeclared_change: bool) -> Result<Fixture, Box<dyn Error>> {
    let directory = TestDirectory::create("material")?;
    let source = directory.join("source.svg");
    let editable = directory.join("editable.svg");
    let raster = directory.join("delivery.png");
    fs::write(&source, svg("BEFORE", "#111827"))?;
    fs::write(
        &editable,
        svg(
            "APPROVED",
            if undeclared_change { "#991b1b" } else { "#111827" },
        ),
    )?;
    write_png(&raster, 240, 300)?;

    let request = SetTextAndExportRequest {
        schema_version: "0.1.0".to_owned(),
        request_id: "request.inkscape-evidence.0001".to_owned(),
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
    let request_digest = canonical_json_sha256(&serde_json::to_value(&request)?)?;
    let mut record = InkscapeExecutionRecord {
        schema_version: "0.1.0".to_owned(),
        request_id: request.request_id.clone(),
        request_digest,
        binary: InkscapeBinaryIdentity {
            application_id: "org.inkscape.Inkscape".to_owned(),
            executable_digest: "a".repeat(64),
            version_text: "Inkscape 1.4".to_owned(),
            version_major: 1,
            version_minor: 4,
            version_patch: 0,
        },
        pre_snapshot_digest: pre.snapshot_digest,
        post_snapshot_digest: post.snapshot_digest,
        editable_output_digest: sha256_file(&editable)?,
        raster_output_digest: png.artifact_digest,
        export_command_digest: "b".repeat(64),
        target_element_id: request.target_element_id.clone(),
        replacement_text: request.replacement_text.clone(),
        export_width: request.export_width,
        export_height: request.export_height,
        verified: true,
        record_digest: String::new(),
    };
    record.record_digest = record_digest(&record)?;
    Ok(Fixture {
        _directory: directory,
        source,
        editable,
        raster,
        request,
        record,
        signing_key: SigningKey::from_bytes(&[61_u8; 32]),
    })
}

fn registry(fixture: &Fixture) -> Result<InkscapeExecutionKeyRegistry, Box<dyn Error>> {
    let mut keys = InkscapeExecutionKeyRegistry::default();
    keys.insert_ed25519(
        ISSUER,
        KEY_ID,
        fixture.signing_key.verifying_key().to_bytes(),
    )?;
    Ok(keys)
}

fn material<'a>(
    fixture: &'a Fixture,
    package: &'a ergaxiom_inkscape_execution_evidence_runtime::SignedInkscapeExecutionRecord,
) -> InkscapeExecutionMaterial<'a> {
    InkscapeExecutionMaterial {
        request: &fixture.request,
        package,
        source_svg: &fixture.source,
        editable_svg: &fixture.editable,
        raster_png: &fixture.raster,
    }
}

#[test]
fn signed_material_is_independently_verified() -> Result<(), Box<dyn Error>> {
    let fixture = fixture(false)?;
    let package = sign_execution_record(&fixture.record, ISSUER, KEY_ID, &fixture.signing_key)?;
    let verified = verify_execution_material(&material(&fixture, &package), &registry(&fixture)?)?;

    assert_eq!(verified.replacement_text, "APPROVED");
    assert_eq!((verified.export_width, verified.export_height), (240, 300));
    assert_eq!(verified.package_digest.len(), 64);
    assert_eq!(verified.record_digest, fixture.record.record_digest);
    Ok(())
}

#[test]
fn signature_mutation_is_rejected() -> Result<(), Box<dyn Error>> {
    let fixture = fixture(false)?;
    let mut package =
        sign_execution_record(&fixture.record, ISSUER, KEY_ID, &fixture.signing_key)?;
    package.record.replacement_text = "TAMPERED".to_owned();

    assert!(matches!(
        verify_execution_material(&material(&fixture, &package), &registry(&fixture)?),
        Err(InkscapeEvidenceError::SignatureVerificationFailed)
    ));
    Ok(())
}

#[test]
fn editable_file_mutation_is_rejected() -> Result<(), Box<dyn Error>> {
    let fixture = fixture(false)?;
    let package = sign_execution_record(&fixture.record, ISSUER, KEY_ID, &fixture.signing_key)?;
    fs::write(&fixture.editable, svg("TAMPERED", "#111827"))?;

    assert!(matches!(
        verify_execution_material(&material(&fixture, &package), &registry(&fixture)?),
        Err(InkscapeEvidenceError::EditableDigestMismatch)
    ));
    Ok(())
}

#[test]
fn signed_but_undeclared_svg_change_is_rejected() -> Result<(), Box<dyn Error>> {
    let fixture = fixture(true)?;
    let package = sign_execution_record(&fixture.record, ISSUER, KEY_ID, &fixture.signing_key)?;

    assert!(matches!(
        verify_execution_material(&material(&fixture, &package), &registry(&fixture)?),
        Err(InkscapeEvidenceError::UndeclaredSvgChange)
    ));
    Ok(())
}

fn record_digest(record: &InkscapeExecutionRecord) -> Result<String, Box<dyn Error>> {
    let mut value = serde_json::to_value(record)?;
    let object = value.as_object_mut().ok_or("record must be an object")?;
    object.insert("record_digest".to_owned(), Value::String(String::new()));
    Ok(canonical_json_sha256(&value)?)
}

fn svg(text: &str, background: &str) -> String {
    format!(
        r##"<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="240" height="300" viewBox="0 0 240 300" id="root">
  <rect id="background" x="0" y="0" width="240" height="300" fill="{background}" />
  <text id="headline" x="24" y="100">{text}</text>
</svg>
"##
    )
}

fn write_png(path: &Path, width: u32, height: u32) -> Result<(), Box<dyn Error>> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"\x89PNG\r\n\x1a\n");
    bytes.extend_from_slice(&13_u32.to_be_bytes());
    bytes.extend_from_slice(b"IHDR");
    bytes.extend_from_slice(&width.to_be_bytes());
    bytes.extend_from_slice(&height.to_be_bytes());
    fs::write(path, bytes)?;
    Ok(())
}

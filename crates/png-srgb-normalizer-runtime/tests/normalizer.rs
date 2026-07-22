use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use ergaxiom_png_artifact_validator_runtime::{PngColorProfileEvidence, inspect_png};
use ergaxiom_png_srgb_normalizer_runtime::{
    PngSrgbNormalizationError, PngSrgbNormalizationRequest, SrgbRenderingIntent,
    inspect_svg_srgb, normalize_png_srgb,
};
use sha2::{Digest, Sha256};

struct TestDirectory {
    path: PathBuf,
}

impl TestDirectory {
    fn create(name: &str) -> Result<Self, Box<dyn Error>> {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let path = std::env::temp_dir().join(format!(
            "ergaxiom-png-srgb-{name}-{}-{nonce}",
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

#[test]
fn profileless_png_is_normalized_without_idat_mutation() -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::create("success")?;
    let source = directory.join("source.svg");
    let input = directory.join("input.png");
    let output = directory.join("output.png");
    fs::write(&source, safe_svg())?;
    fs::write(&input, png_bytes(&[]))?;

    let record = normalize_png_srgb(&request(&source, &input, &output)?)?;
    let report = inspect_png(&output)?;

    assert!(record.verified);
    assert_eq!(record.input_idat_payload_digest, record.output_idat_payload_digest);
    assert_eq!(record.record_digest.len(), 64);
    assert_eq!(
        report.color_profile,
        PngColorProfileEvidence::Srgb {
            rendering_intent: 1
        }
    );
    assert_eq!(record.output_png_digest, report.artifact_digest);
    assert_eq!(fs::metadata(&output)?.len(), fs::metadata(&input)?.len() + 13);
    Ok(())
}

#[test]
fn source_svg_profile_is_measured_deterministically() -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::create("svg-evidence")?;
    let source = directory.join("source.svg");
    fs::write(&source, safe_svg_with_gradient())?;

    let evidence = inspect_svg_srgb(&source)?;
    assert_eq!(evidence.element_count, 6);
    assert_eq!(evidence.color_declaration_count, 4);
    assert_eq!(evidence.internal_paint_server_reference_count, 1);
    assert_eq!(evidence.evidence_digest.len(), 64);
    Ok(())
}

#[test]
fn unsupported_svg_color_spaces_fail_closed() -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::create("unsupported-color")?;
    let source = directory.join("source.svg");
    fs::write(
        &source,
        r#"<svg xmlns="http://www.w3.org/2000/svg"><rect fill="color(display-p3 1 0 0)" /></svg>"#,
    )?;

    assert!(matches!(
        inspect_svg_srgb(&source),
        Err(PngSrgbNormalizationError::UnsupportedSvgColorSpace(_))
    ));
    Ok(())
}

#[test]
fn embedded_raster_and_external_resources_fail_closed() -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::create("external")?;
    let image = directory.join("image.svg");
    let external_use = directory.join("external-use.svg");
    fs::write(
        &image,
        r#"<svg xmlns="http://www.w3.org/2000/svg"><image href="data:image/png;base64,AAAA" /></svg>"#,
    )?;
    fs::write(
        &external_use,
        r#"<svg xmlns="http://www.w3.org/2000/svg"><use href="https://example.invalid/a.svg#x" /></svg>"#,
    )?;

    assert!(matches!(
        inspect_svg_srgb(&image),
        Err(PngSrgbNormalizationError::ForbiddenSvgElement(element)) if element == "image"
    ));
    assert!(matches!(
        inspect_svg_srgb(&external_use),
        Err(PngSrgbNormalizationError::ExternalSvgResource)
    ));
    Ok(())
}

#[test]
fn existing_png_color_signals_are_not_overwritten() -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::create("existing-profile")?;
    let source = directory.join("source.svg");
    let input = directory.join("input.png");
    let output = directory.join("output.png");
    fs::write(&source, safe_svg())?;
    fs::write(&input, png_bytes(&[(b"gAMA", &45455_u32.to_be_bytes())]))?;

    assert!(matches!(
        normalize_png_srgb(&request(&source, &input, &output)?),
        Err(PngSrgbNormalizationError::ExistingColorSignal(signal)) if signal == "gAMA"
    ));
    assert!(!output.exists());
    Ok(())
}

#[test]
fn existing_srgb_chunk_is_not_duplicated() -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::create("existing-srgb")?;
    let source = directory.join("source.svg");
    let input = directory.join("input.png");
    let output = directory.join("output.png");
    fs::write(&source, safe_svg())?;
    fs::write(&input, png_bytes(&[(b"sRGB", &[1])]))?;

    assert!(matches!(
        normalize_png_srgb(&request(&source, &input, &output)?),
        Err(PngSrgbNormalizationError::ExistingColorSignal(_))
    ));
    assert!(!output.exists());
    Ok(())
}

#[test]
fn trusted_digest_mismatch_and_existing_output_fail_before_write() -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::create("preconditions")?;
    let source = directory.join("source.svg");
    let input = directory.join("input.png");
    let output = directory.join("output.png");
    fs::write(&source, safe_svg())?;
    fs::write(&input, png_bytes(&[]))?;

    let mut bad_request = request(&source, &input, &output)?;
    bad_request.expected_input_png_digest = "0".repeat(64);
    assert!(matches!(
        normalize_png_srgb(&bad_request),
        Err(PngSrgbNormalizationError::InputPngDigestMismatch)
    ));
    assert!(!output.exists());

    fs::write(&output, b"existing")?;
    assert!(matches!(
        normalize_png_srgb(&request(&source, &input, &output)?),
        Err(PngSrgbNormalizationError::OutputAlreadyExists)
    ));
    Ok(())
}

fn request(
    source: &Path,
    input: &Path,
    output: &Path,
) -> Result<PngSrgbNormalizationRequest, Box<dyn Error>> {
    Ok(PngSrgbNormalizationRequest {
        schema_version: "0.1.0".to_owned(),
        request_id: "request.png-srgb-normalizer.0001".to_owned(),
        source_svg: source.to_path_buf(),
        expected_source_svg_digest: sha256_file(source)?,
        input_png: input.to_path_buf(),
        expected_input_png_digest: sha256_file(input)?,
        output_png: output.to_path_buf(),
        rendering_intent: SrgbRenderingIntent::RelativeColorimetric,
    })
}

fn safe_svg() -> &'static str {
    r##"<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="240" height="300" viewBox="0 0 240 300">
  <rect width="240" height="300" fill="#111827" />
  <text x="24" y="100" fill="rgb(255, 255, 255)">APPROVED</text>
</svg>
"##
}

fn safe_svg_with_gradient() -> &'static str {
    r##"<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="240" height="300" viewBox="0 0 240 300">
  <defs>
    <linearGradient id="g"><stop stop-color="#111827"/><stop stop-color="#ffffff"/></linearGradient>
  </defs>
  <rect width="240" height="300" fill="url(#g)" stroke="#000000" />
</svg>
"##
}

fn png_bytes(extra_chunks: &[(&[u8; 4], &[u8])]) -> Vec<u8> {
    let mut bytes = Vec::from(*b"\x89PNG\r\n\x1a\n");
    let mut ihdr = Vec::new();
    ihdr.extend_from_slice(&240_u32.to_be_bytes());
    ihdr.extend_from_slice(&300_u32.to_be_bytes());
    ihdr.extend_from_slice(&[8, 6, 0, 0, 0]);
    append_chunk(&mut bytes, b"IHDR", &ihdr);
    for (chunk_type, data) in extra_chunks {
        append_chunk(&mut bytes, chunk_type, data);
    }
    append_chunk(&mut bytes, b"IDAT", b"pixel-payload-is-preserved");
    append_chunk(&mut bytes, b"IEND", &[]);
    bytes
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

fn sha256_file(path: &Path) -> Result<String, Box<dyn Error>> {
    Ok(format!("{:x}", Sha256::digest(fs::read(path)?)))
}

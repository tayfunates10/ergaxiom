use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;
use ergaxiom_png_srgb_normalizer_runtime::{
    NormalizationEvidenceError, NormalizationKeyRegistry, PngSrgbNormalizationMaterial,
    PngSrgbNormalizationRequest, SignedPngSrgbNormalizationRecord, SrgbRenderingIntent,
    normalize_png_srgb, sign_normalization_record, verify_normalization_material,
};
use sha2::{Digest, Sha256};

const ISSUER: &str = "ergaxiom.png-normalization-authority";
const KEY_ID: &str = "png-normalization-key-01";

struct Directory(PathBuf);

impl Directory {
    fn new() -> Result<Self, Box<dyn Error>> {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let path = std::env::temp_dir().join(format!(
            "ergaxiom-signed-png-normalization-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&path)?;
        Ok(Self(path))
    }

    fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Fixture {
    _directory: Directory,
    source: PathBuf,
    input: PathBuf,
    output: PathBuf,
    request: PngSrgbNormalizationRequest,
    package: SignedPngSrgbNormalizationRecord,
    keys: NormalizationKeyRegistry,
}

fn fixture() -> Result<Fixture, Box<dyn Error>> {
    let directory = Directory::new()?;
    let source = directory.join("source.svg");
    let input = directory.join("input.png");
    let output = directory.join("output.png");
    fs::write(
        &source,
        r##"<svg xmlns="http://www.w3.org/2000/svg" width="240" height="300"><rect width="240" height="300" fill="#111827"/></svg>"##,
    )?;
    fs::write(&input, png_bytes())?;
    let request = PngSrgbNormalizationRequest {
        schema_version: "0.1.0".to_owned(),
        request_id: "request.signed-normalization.0001".to_owned(),
        source_svg: source.clone(),
        expected_source_svg_digest: sha256_file(&source)?,
        input_png: input.clone(),
        expected_input_png_digest: sha256_file(&input)?,
        output_png: output.clone(),
        rendering_intent: SrgbRenderingIntent::RelativeColorimetric,
    };
    let record = normalize_png_srgb(&request)?;
    let signing_key = SigningKey::from_bytes(&[97_u8; 32]);
    let package = sign_normalization_record(&record, ISSUER, KEY_ID, &signing_key)?;
    let mut keys = NormalizationKeyRegistry::default();
    keys.insert_ed25519(ISSUER, KEY_ID, signing_key.verifying_key().to_bytes())?;
    Ok(Fixture {
        _directory: directory,
        source,
        input,
        output,
        request,
        package,
        keys,
    })
}

fn material<'a>(
    fixture: &'a Fixture,
    package: &'a SignedPngSrgbNormalizationRecord,
) -> PngSrgbNormalizationMaterial<'a> {
    PngSrgbNormalizationMaterial {
        request: &fixture.request,
        package,
        source_svg: &fixture.source,
        input_png: &fixture.input,
        output_png: &fixture.output,
    }
}

#[test]
fn signed_normalization_material_is_independently_verified() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let verified =
        verify_normalization_material(&material(&fixture, &fixture.package), &fixture.keys)?;
    assert_eq!(
        verified.input_idat_payload_digest,
        verified.output_idat_payload_digest
    );
    assert_eq!(
        verified.rendering_intent,
        SrgbRenderingIntent::RelativeColorimetric
    );
    assert_eq!(verified.package_digest.len(), 64);
    Ok(())
}

#[test]
fn signed_record_mutation_is_rejected() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let mut package = fixture.package.clone();
    package.record.output_png_digest = "0".repeat(64);
    assert!(matches!(
        verify_normalization_material(&material(&fixture, &package), &fixture.keys),
        Err(NormalizationEvidenceError::SignatureVerificationFailed)
    ));
    Ok(())
}

#[test]
fn normalized_file_mutation_is_rejected() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    fs::write(&fixture.output, b"tampered")?;
    assert!(matches!(
        verify_normalization_material(&material(&fixture, &fixture.package), &fixture.keys),
        Err(NormalizationEvidenceError::OutputDigestMismatch)
    ));
    Ok(())
}

#[test]
fn material_path_substitution_is_rejected() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let substituted = fixture._directory.join("substituted.png");
    fs::copy(&fixture.output, &substituted)?;
    let material = PngSrgbNormalizationMaterial {
        request: &fixture.request,
        package: &fixture.package,
        source_svg: &fixture.source,
        input_png: &fixture.input,
        output_png: &substituted,
    };
    assert!(matches!(
        verify_normalization_material(&material, &fixture.keys),
        Err(NormalizationEvidenceError::MaterialPathMismatch(
            "output_png"
        ))
    ));
    Ok(())
}

fn png_bytes() -> Vec<u8> {
    let mut bytes = Vec::from(*b"\x89PNG\r\n\x1a\n");
    let mut ihdr = Vec::new();
    ihdr.extend_from_slice(&240_u32.to_be_bytes());
    ihdr.extend_from_slice(&300_u32.to_be_bytes());
    ihdr.extend_from_slice(&[8, 6, 0, 0, 0]);
    append_chunk(&mut bytes, b"IHDR", &ihdr);
    append_chunk(&mut bytes, b"IDAT", b"preserved-payload");
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

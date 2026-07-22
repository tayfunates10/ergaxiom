use std::error::Error;

use ergaxiom_png_artifact_validator_runtime::{
    PngArtifactError, PngColorProfileEvidence, PngColorType, PngPolicyViolation,
    PngProfileRequirement, PngValidationPolicy, inspect_png_bytes, validate_report,
};

#[test]
fn valid_srgb_png_is_structurally_verified_and_accepted() -> Result<(), Box<dyn Error>> {
    let bytes = png_bytes(240, 300, Profile::Srgb);
    let report = inspect_png_bytes(&bytes)?;

    assert_eq!((report.width, report.height), (240, 300));
    assert_eq!(report.bit_depth, 8);
    assert_eq!(report.color_type, PngColorType::TruecolorAlpha);
    assert!(matches!(
        report.color_profile,
        PngColorProfileEvidence::Srgb {
            rendering_intent: 0
        }
    ));
    assert_eq!(report.idat_chunk_count, 1);
    assert_eq!(report.report_digest.len(), 64);

    let result = validate_report(
        report,
        &policy(240, 300, PngProfileRequirement::SrgbChunk),
    )?;
    assert!(result.accepted);
    assert!(result.violations.is_empty());
    assert_eq!(result.decision_digest.len(), 64);
    Ok(())
}

#[test]
fn crc_mutation_is_rejected_before_policy_evaluation() {
    let mut bytes = png_bytes(240, 300, Profile::Srgb);
    let last_crc_byte = bytes.len() - 1;
    bytes[last_crc_byte] ^= 0x01;

    assert!(matches!(
        inspect_png_bytes(&bytes),
        Err(PngArtifactError::CrcMismatch { .. })
    ));
}

#[test]
fn dimension_and_profile_mismatches_are_explicit_violations() -> Result<(), Box<dyn Error>> {
    let report = inspect_png_bytes(&png_bytes(200, 100, Profile::None))?;
    let result = validate_report(
        report,
        &policy(240, 300, PngProfileRequirement::AnyEmbedded),
    )?;

    assert!(!result.accepted);
    assert!(result.violations.contains(&PngPolicyViolation::WidthMismatch {
        expected: 240,
        actual: 200,
    }));
    assert!(result.violations.contains(&PngPolicyViolation::HeightMismatch {
        expected: 300,
        actual: 100,
    }));
    assert!(
        result
            .violations
            .contains(&PngPolicyViolation::MissingColorProfile)
    );
    Ok(())
}

#[test]
fn conflicting_srgb_and_icc_profiles_fail_closed() {
    let bytes = png_bytes(240, 300, Profile::Conflicting);
    assert!(matches!(
        inspect_png_bytes(&bytes),
        Err(PngArtifactError::ConflictingColorProfiles)
    ));
}

#[test]
fn unknown_critical_chunk_fails_closed() {
    let mut bytes = Vec::from(*b"\x89PNG\r\n\x1a\n");
    append_chunk(&mut bytes, b"IHDR", &ihdr(240, 300));
    append_chunk(&mut bytes, b"ABCD", b"unknown-critical");
    append_chunk(&mut bytes, b"IDAT", b"non-empty-image-data");
    append_chunk(&mut bytes, b"IEND", &[]);

    assert!(matches!(
        inspect_png_bytes(&bytes),
        Err(PngArtifactError::UnknownCriticalChunk(chunk)) if chunk == "ABCD"
    ));
}

#[test]
fn nonconsecutive_idat_and_trailing_bytes_fail_closed() {
    let mut nonconsecutive = Vec::from(*b"\x89PNG\r\n\x1a\n");
    append_chunk(&mut nonconsecutive, b"IHDR", &ihdr(240, 300));
    append_chunk(&mut nonconsecutive, b"IDAT", b"first");
    append_chunk(&mut nonconsecutive, b"tEXt", b"key\0value");
    append_chunk(&mut nonconsecutive, b"IDAT", b"second");
    append_chunk(&mut nonconsecutive, b"IEND", &[]);
    assert!(matches!(
        inspect_png_bytes(&nonconsecutive),
        Err(PngArtifactError::NonConsecutiveImageData)
    ));

    let mut trailing = png_bytes(240, 300, Profile::None);
    trailing.extend_from_slice(b"trailing");
    assert!(matches!(
        inspect_png_bytes(&trailing),
        Err(PngArtifactError::TrailingBytes)
    ));
}

#[test]
fn icc_profile_name_policy_is_exact() -> Result<(), Box<dyn Error>> {
    let report = inspect_png_bytes(&png_bytes(240, 300, Profile::Icc))?;
    let accepted = validate_report(
        report.clone(),
        &policy(
            240,
            300,
            PngProfileRequirement::IccProfile {
                profile_name: "Ergaxiom Test ICC".to_owned(),
            },
        ),
    )?;
    assert!(accepted.accepted);

    let rejected = validate_report(
        report,
        &policy(
            240,
            300,
            PngProfileRequirement::IccProfile {
                profile_name: "Another ICC".to_owned(),
            },
        ),
    )?;
    assert!(!rejected.accepted);
    assert!(matches!(
        rejected.violations.as_slice(),
        [PngPolicyViolation::IccProfileNameMismatch { expected, actual }]
            if expected == "Another ICC" && actual == "Ergaxiom Test ICC"
    ));
    Ok(())
}

fn policy(
    width: u32,
    height: u32,
    profile_requirement: PngProfileRequirement,
) -> PngValidationPolicy {
    PngValidationPolicy {
        expected_width: width,
        expected_height: height,
        expected_bit_depth: Some(8),
        allowed_color_types: vec![PngColorType::Truecolor, PngColorType::TruecolorAlpha],
        profile_requirement,
    }
}

#[derive(Clone, Copy)]
enum Profile {
    None,
    Srgb,
    Icc,
    Conflicting,
}

fn png_bytes(width: u32, height: u32, profile: Profile) -> Vec<u8> {
    let mut bytes = Vec::from(*b"\x89PNG\r\n\x1a\n");
    append_chunk(&mut bytes, b"IHDR", &ihdr(width, height));
    if matches!(profile, Profile::Srgb | Profile::Conflicting) {
        append_chunk(&mut bytes, b"sRGB", &[0]);
    }
    if matches!(profile, Profile::Icc | Profile::Conflicting) {
        let mut data = b"Ergaxiom Test ICC\0\0".to_vec();
        data.extend_from_slice(b"compressed-profile-placeholder");
        append_chunk(&mut bytes, b"iCCP", &data);
    }
    append_chunk(&mut bytes, b"IDAT", b"non-empty-image-data");
    append_chunk(&mut bytes, b"IEND", &[]);
    bytes
}

fn ihdr(width: u32, height: u32) -> Vec<u8> {
    let mut data = Vec::with_capacity(13);
    data.extend_from_slice(&width.to_be_bytes());
    data.extend_from_slice(&height.to_be_bytes());
    data.extend_from_slice(&[8, 6, 0, 0, 0]);
    data
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

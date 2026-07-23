use std::error::Error;

use ergaxiom_svg_approved_copy_runtime::{
    ApprovedCopyError, ApprovedCopyPolicy, ApprovedCopyViolation, validate_approved_copy,
};

#[test]
fn exact_approved_copy_is_accepted() -> Result<(), Box<dyn Error>> {
    let result = validate_approved_copy(
        b"Launch now",
        br#"<svg xmlns="http://www.w3.org/2000/svg"><text id="headline">Launch now</text></svg>"#,
        &policy(),
    )?;

    assert!(result.accepted);
    assert!(result.violations.is_empty());
    assert!(result.report.exact_match);
    assert_eq!(result.report.approved_copy_byte_count, 10);
    assert_eq!(result.report.extracted_copy_byte_count, 10);
    assert_eq!(result.report.target_element_name, "text");
    assert_eq!(result.report.report_digest.len(), 64);
    assert_eq!(result.decision_digest.len(), 64);
    Ok(())
}

#[test]
fn changed_copy_is_rejected_with_bound_digests() -> Result<(), Box<dyn Error>> {
    let result = validate_approved_copy(
        b"Launch now",
        br#"<svg><text id="headline">Launch later</text></svg>"#,
        &policy(),
    )?;

    assert!(!result.accepted);
    assert!(!result.report.exact_match);
    assert_ne!(
        result.report.approved_copy_digest,
        result.report.extracted_copy_digest
    );
    assert!(result.violations.iter().any(|violation| matches!(
        violation,
        ApprovedCopyViolation::CopyMismatch {
            approved_byte_count: 10,
            extracted_byte_count: 12,
            ..
        }
    )));
    Ok(())
}

#[test]
fn xml_entities_are_compared_as_rendered_text_content() -> Result<(), Box<dyn Error>> {
    let result = validate_approved_copy(
        b"A & B",
        br#"<svg><text id="headline">A &amp; B</text></svg>"#,
        &policy(),
    )?;

    assert!(result.accepted);
    Ok(())
}

#[test]
fn nested_text_content_is_rejected_instead_of_guessed() {
    let error = match validate_approved_copy(
        b"Launch now",
        br#"<svg><text id="headline"><tspan>Launch now</tspan></text></svg>"#,
        &policy(),
    ) {
        Ok(_) => panic!("nested text must not be guessed"),
        Err(error) => error,
    };

    assert!(matches!(error, ApprovedCopyError::NestedTargetContent));
}

#[test]
fn duplicate_ids_are_rejected() {
    let error = match validate_approved_copy(
        b"Launch now",
        br#"<svg><text id="headline">Launch now</text><text id="headline">Other</text></svg>"#,
        &policy(),
    ) {
        Ok(_) => panic!("duplicate ids must fail closed"),
        Err(error) => error,
    };

    assert!(matches!(
        error,
        ApprovedCopyError::DuplicateElementId(ref id) if id == "headline"
    ));
}

#[test]
fn non_text_target_and_missing_target_are_rejected() {
    let non_text = match validate_approved_copy(
        b"Launch now",
        br#"<svg><rect id="headline" width="10" height="10"/></svg>"#,
        &policy(),
    ) {
        Ok(_) => panic!("a non-text target must fail"),
        Err(error) => error,
    };
    assert!(matches!(non_text, ApprovedCopyError::TargetIsNotText));

    let missing = match validate_approved_copy(
        b"Launch now",
        br#"<svg><text id="other">Launch now</text></svg>"#,
        &policy(),
    ) {
        Ok(_) => panic!("a missing target must fail"),
        Err(error) => error,
    };
    assert!(matches!(
        missing,
        ApprovedCopyError::TargetNotFound(ref id) if id == "headline"
    ));
}

#[test]
fn dtd_and_invalid_utf8_are_rejected() {
    let dtd = match validate_approved_copy(
        b"Launch now",
        br#"<!DOCTYPE svg [<!ENTITY copy "Launch now">]><svg><text id="headline">&copy;</text></svg>"#,
        &policy(),
    ) {
        Ok(_) => panic!("DTD material must fail"),
        Err(error) => error,
    };
    assert!(matches!(dtd, ApprovedCopyError::DocumentTypeForbidden));

    let invalid_copy = match validate_approved_copy(
        &[0xff],
        br#"<svg><text id="headline">Launch now</text></svg>"#,
        &policy(),
    ) {
        Ok(_) => panic!("invalid UTF-8 approved copy must fail"),
        Err(error) => error,
    };
    assert!(matches!(
        invalid_copy,
        ApprovedCopyError::InvalidApprovedCopyUtf8
    ));
}

#[test]
fn identical_inputs_produce_identical_evidence() -> Result<(), Box<dyn Error>> {
    let svg = br#"<svg><text id="headline">Launch now</text></svg>"#;
    let first = validate_approved_copy(b"Launch now", svg, &policy())?;
    let second = validate_approved_copy(b"Launch now", svg, &policy())?;

    assert_eq!(first, second);
    Ok(())
}

fn policy() -> ApprovedCopyPolicy {
    ApprovedCopyPolicy {
        target_element_id: "headline".to_owned(),
    }
}

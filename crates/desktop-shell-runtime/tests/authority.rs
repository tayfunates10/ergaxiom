use std::error::Error;

use ergaxiom_desktop_shell_runtime::{
    AuthorityStatus, CertificateVerification, DesktopShellError, DesktopShellMaterial, DigestItem,
    ResolutionItem, StageStatus, build_desktop_shell_snapshot, verify_desktop_shell_snapshot,
};
use serde_json::{Value, json};

#[test]
fn unresolved_material_cannot_display_acceptance() -> Result<(), Box<dyn Error>> {
    let snapshot = build_desktop_shell_snapshot(DesktopShellMaterial {
        generated_at: "2026-07-23T14:00:00Z".to_owned(),
        job_id: None,
        unresolved: vec![ResolutionItem {
            field: "approved_logo.sha256".to_owned(),
            question: "Which immutable logo digest is approved?".to_owned(),
            mandatory: true,
            status: StageStatus::Blocked,
        }],
        staged_inputs: Vec::new(),
        contract: None,
        approval: None,
        plan: None,
        steps: Vec::new(),
        validators: Vec::new(),
        evidence_bundle: None,
        replay_manifest: None,
        certificate: None,
        profession_capsules: Vec::new(),
        adapters: Vec::new(),
        trusted_keys: Vec::new(),
        metadata: json!({"source": "test"}),
    })?;

    assert_eq!(snapshot.authority_status, AuthorityStatus::Unresolved);
    assert!(verify_desktop_shell_snapshot(&snapshot)?);
    Ok(())
}

#[test]
fn accepted_status_requires_verified_certificate_and_bundle() -> Result<(), Box<dyn Error>> {
    let snapshot = build_desktop_shell_snapshot(accepted_material())?;

    assert_eq!(snapshot.authority_status, AuthorityStatus::VerifiedAccepted);
    assert!(verify_desktop_shell_snapshot(&snapshot)?);
    Ok(())
}

#[test]
fn contradictory_accepted_certificate_fails_closed() {
    let mut material = accepted_material();
    let certificate = material.certificate.as_mut().expect("certificate fixture");
    certificate.signature_verified = false;

    assert!(matches!(
        build_desktop_shell_snapshot(material),
        Err(DesktopShellError::ContradictoryAcceptedCertificate)
    ));
}

#[test]
fn frontend_json_mutation_cannot_forge_accepted_snapshot() -> Result<(), Box<dyn Error>> {
    let unresolved = build_desktop_shell_snapshot(DesktopShellMaterial {
        generated_at: "2026-07-23T14:00:00Z".to_owned(),
        job_id: None,
        unresolved: vec![ResolutionItem {
            field: "approved_copy.sha256".to_owned(),
            question: "Which copy digest is approved?".to_owned(),
            mandatory: true,
            status: StageStatus::Blocked,
        }],
        staged_inputs: Vec::new(),
        contract: None,
        approval: None,
        plan: None,
        steps: Vec::new(),
        validators: Vec::new(),
        evidence_bundle: None,
        replay_manifest: None,
        certificate: None,
        profession_capsules: Vec::new(),
        adapters: Vec::new(),
        trusted_keys: Vec::new(),
        metadata: Value::Null,
    })?;
    let mut value = serde_json::to_value(&unresolved)?;
    value["authority_status"] = json!("verified_accepted");
    let forged = serde_json::from_value(value)?;

    assert!(!verify_desktop_shell_snapshot(&forged)?);
    Ok(())
}

#[test]
fn malformed_display_digest_is_rejected() {
    let mut material = accepted_material();
    material.contract = Some(DigestItem {
        id: "contract.example".to_owned(),
        media_type: Some("application/json".to_owned()),
        digest: "NOT-A-DIGEST".to_owned(),
        status: StageStatus::Passed,
    });

    assert!(matches!(
        build_desktop_shell_snapshot(material),
        Err(DesktopShellError::InvalidDigest("contract.digest"))
    ));
}

fn accepted_material() -> DesktopShellMaterial {
    DesktopShellMaterial {
        generated_at: "2026-07-23T14:00:00Z".to_owned(),
        job_id: Some("job.desktop.0001".to_owned()),
        unresolved: Vec::new(),
        staged_inputs: vec![DigestItem {
            id: "approved_logo".to_owned(),
            media_type: Some("image/png".to_owned()),
            digest: "a".repeat(64),
            status: StageStatus::Passed,
        }],
        contract: Some(DigestItem {
            id: "contract.desktop.0001".to_owned(),
            media_type: Some("application/json".to_owned()),
            digest: "b".repeat(64),
            status: StageStatus::Passed,
        }),
        approval: None,
        plan: Some(DigestItem {
            id: "plan.desktop.0001".to_owned(),
            media_type: Some("application/json".to_owned()),
            digest: "c".repeat(64),
            status: StageStatus::Passed,
        }),
        steps: Vec::new(),
        validators: Vec::new(),
        evidence_bundle: Some(DigestItem {
            id: "bundle.desktop.0001".to_owned(),
            media_type: Some("application/json".to_owned()),
            digest: "d".repeat(64),
            status: StageStatus::Passed,
        }),
        replay_manifest: Some(DigestItem {
            id: "manifest.desktop.0001".to_owned(),
            media_type: Some("application/json".to_owned()),
            digest: "e".repeat(64),
            status: StageStatus::Passed,
        }),
        certificate: Some(CertificateVerification {
            certificate_id: "certificate.desktop.0001".to_owned(),
            certificate_digest: "f".repeat(64),
            evidence_bundle_digest: "d".repeat(64),
            signature_verified: true,
            bundle_verified: true,
            decision_accepted: true,
            mandatory_unknowns: 0,
            mandatory_failures: 0,
        }),
        profession_capsules: Vec::new(),
        adapters: Vec::new(),
        trusted_keys: Vec::new(),
        metadata: json!({"source": "verified_backend"}),
    }
}

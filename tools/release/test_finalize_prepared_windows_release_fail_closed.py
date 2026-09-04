from pathlib import Path


SCRIPT = Path(__file__).with_name("finalize_prepared_windows_release.ps1").read_text(encoding="utf-8")


def test_stage_b_requires_cryptographically_verified_oidc_provenance() -> None:
    assert "verify_github_oidc_provenance.py" in SCRIPT
    assert "GITHUB_OIDC_PROTECTED_ENVIRONMENT_PROVENANCE_REJECTED" in SCRIPT
    assert "github-oidc-provenance.json" in SCRIPT
    assert "Signed claims bind repository" in SCRIPT


def test_environment_markers_are_only_defense_in_depth() -> None:
    assert "mutable runner markers are not provenance" in SCRIPT
    assert "PROTECTED_ENVIRONMENT_REQUIRED" in SCRIPT
    assert "PROTECTED_REF_REQUIRED" in SCRIPT
    assert "CONTROLLED_PRODUCTION_ENVIRONMENT_MARKER_REQUIRED" in SCRIPT
    assert "PROTECTED_ENVIRONMENT_SOURCE_COMMIT_MISMATCH" in SCRIPT


def test_structural_hardware_gate_cannot_promote_release() -> None:
    assert "structural consistency only" in SCRIPT
    assert "Structural PASS is not cryptographic hardware-origin proof" in SCRIPT
    assert "TPM_KEY_ATTESTATION_NOT_VERIFIED" in SCRIPT
    assert "structural evidence is insufficient for hardware-origin assurance" in SCRIPT


def test_no_legacy_escape_hatch_is_present() -> None:
    forbidden = (
        "AllowLegacyUnattestedHardware",
        "SkipHardwareAttestation",
        "BypassHardwareAttestation",
        "ForceReleaseEligible",
        "SkipOidcProvenance",
        "AllowUnverifiedOidc",
    )
    for marker in forbidden:
        assert marker not in SCRIPT

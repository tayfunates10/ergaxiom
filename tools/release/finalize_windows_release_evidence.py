#!/usr/bin/env python3
"""Fail-closed Windows production release decision for Issue #78."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Any

H64 = re.compile(r"^[0-9a-f]{64}$")
H40 = re.compile(r"^[0-9a-f]{40}$")


class ReleaseError(RuntimeError):
    pass


def canon(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def sha(value: Any) -> str:
    return hashlib.sha256(canon(value)).hexdigest()


def load(path: Path | None):
    if path is None:
        return None
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ReleaseError(f"object required: {path}")
    return value


def h64(value: Any, name: str) -> str:
    if not isinstance(value, str) or not H64.fullmatch(value):
        raise ReleaseError(f"invalid sha256: {name}")
    return value


def policy_ok(policy: dict) -> None:
    if policy.get("schema_version") != "0.1.0" or policy.get("policy_id") != "ergaxiom.windows-production-release":
        raise ReleaseError("policy identity")
    signing = policy.get("signing", {})
    packaging = policy.get("packaging", {})
    inventory = policy.get("shipping_inventory", {})
    if (
        policy.get("canonical_installer") != "nsis"
        or packaging.get("targets") != ["nsis"]
        or packaging.get("install_mode") != "perMachine"
        or packaging.get("install_root") != r"%ProgramFiles%\Ergaxiom"
        or packaging.get("allow_downgrades") is not False
    ):
        raise ReleaseError("installer policy")
    if (
        packaging.get("service_name") != "ErgaxiomProductionSigner"
        or packaging.get("production_state_root") != r"%ProgramData%\Ergaxiom"
        or packaging.get("uninstall_preserves_production_state") is not True
    ):
        raise ReleaseError("service/state policy")
    if (
        signing.get("certificate_store_location") not in {"CurrentUser", "LocalMachine"}
        or signing.get("certificate_store_name") != "My"
        or signing.get("code_signing_eku_oid") != "1.3.6.1.5.5.7.3.3"
        or signing.get("digest_algorithm") != "SHA256"
        or signing.get("timestamp_digest_algorithm") != "SHA256"
        or signing.get("timestamp_protocol") != "RFC3161"
        or not str(signing.get("timestamp_url", "")).startswith("https://")
    ):
        raise ReleaseError("signing policy")
    if signing.get("require_online_revocation") is not True or signing.get("reject_self_signed") is not True:
        raise ReleaseError("chain policy")
    pe = {
        (item.get("artifact_id"), item.get("name"), item.get("build_input"), item.get("disposition"))
        for item in inventory.get("signed_pe_artifacts", []) if isinstance(item, dict)
    }
    if pe != {
        ("desktop", "ergaxiom-desktop.exe", "apps/desktop/src-tauri", "SHIPPED_EXECUTABLE"),
        ("production_signer_service", "ergaxiom-windows-production-signer-service.exe", "apps/windows-production-signer-service", "SHIPPED_EXECUTABLE"),
    }:
        raise ReleaseError("PE inventory")
    linked = {
        (item.get("artifact_id"), item.get("build_input"), item.get("disposition"))
        for item in inventory.get("linked_runtime_inputs", []) if isinstance(item, dict)
    }
    if linked != {
        ("windows_uia_client", "crates/windows-uia-client-runtime", "LINKED_INTO_DESKTOP"),
        ("windows_bridge", "crates/windows-bridge-runtime", "LINKED_INTO_DESKTOP"),
        ("inkscape_adapter", "crates/inkscape-adapter-runtime", "LINKED_RUNTIME"),
    }:
        raise ReleaseError("linked inventory")
    if inventory.get("installer") != {
        "artifact_id": "windows_installer", "format": "NSIS", "filename_glob": "*-setup.exe", "disposition": "SHIPPED_INSTALLER"
    }:
        raise ReleaseError("installer inventory")


def artifacts(base: dict, policy: dict) -> tuple[dict[str, str], str]:
    if base.get("release_eligible") is not False:
        raise ReleaseError("base manifest must be fail-closed")
    commit = base.get("source", {}).get("commit")
    if not isinstance(commit, str) or not H40.fullmatch(commit):
        raise ReleaseError("source commit")
    result: dict[str, str] = {}
    for artifact in base.get("artifacts", []):
        if not isinstance(artifact, dict) or not isinstance(artifact.get("name"), str) or artifact["name"] in result:
            raise ReleaseError("artifact inventory")
        result[artifact["name"]] = h64(artifact.get("sha256"), artifact.get("name", "artifact"))
    setups = [name for name in result if name.lower().endswith("-setup.exe")]
    required = {item["name"] for item in policy["shipping_inventory"]["signed_pe_artifacts"]}
    if len(setups) != 1 or set(result) != (required | {setups[0]}):
        raise ReleaseError("partial/substituted release inventory")
    return result, setups[0]


def signing(evidence: dict | None, policy: dict, artifact_digests: dict[str, str]) -> tuple[bool, dict | None]:
    if evidence is None:
        return False, None
    if evidence.get("schema_version") != "0.1.0" or evidence.get("policy_sha256") != sha(policy):
        raise ReleaseError("signature evidence binding")
    records = evidence.get("artifacts", [])
    mapping = {r.get("name"): r for r in records if isinstance(r, dict) and isinstance(r.get("name"), str)}
    if len(mapping) != len(records) or set(mapping) != set(artifact_digests):
        raise ReleaseError("signature inventory")
    for name, digest in artifact_digests.items():
        if h64(mapping[name].get("sha256"), name) != digest:
            raise ReleaseError(f"post-sign mutation: {name}")
    p = policy["signing"]
    resolved = (
        p.get("identity_status") == "OWNER_APPROVED_PINNED"
        and isinstance(p.get("expected_subject"), str) and bool(p.get("expected_subject"))
        and H64.fullmatch(str(p.get("expected_certificate_sha256", ""))) is not None
    )
    ok = bool(resolved and evidence.get("mode") == "production" and evidence.get("test_identity") is False and evidence.get("signtool_available") is True)
    for r in mapping.values():
        ok &= all([
            r.get("authenticode_valid") is True, r.get("signtool_verify_ok") is True,
            r.get("code_signing_eku_present") is True, r.get("certificate_chain_valid") is True,
            r.get("revocation_checked_online") is True, r.get("timestamp_present") is True,
            r.get("timestamp_chain_valid") is True, r.get("self_signed") is False,
            r.get("signer_subject") == p.get("expected_subject"),
            r.get("signer_certificate_sha256") == p.get("expected_certificate_sha256"),
            r.get("timestamp_url") == p.get("timestamp_url"),
        ])
    return bool(ok), {"verified": bool(ok), "test_identity": evidence.get("test_identity"), "signtool_available": evidence.get("signtool_available"), "evidence_sha256": sha(evidence)}


def lifecycle(evidence: dict | None, commit: str, installer_name: str, installer_digest: str) -> tuple[bool, dict | None]:
    if evidence is None:
        return False, None
    if (
        evidence.get("schema_version") != "0.1.0" or evidence.get("source_commit") != commit
        or evidence.get("installer_name") != installer_name or evidence.get("installer_sha256") != installer_digest
    ):
        raise ReleaseError("lifecycle binding")
    required = [
        "clean_install", "service_installed_local_system", "service_validated_running", "protected_state_acl_verified",
        "upgrade", "downgrade_rejected", "interrupted_upgrade_preserved_state", "rollback_recovery",
        "recovery_install", "uninstall", "production_state_preserved",
    ]
    ok = evidence.get("test_mode") is False and all(evidence.get("phases", {}).get(name) is True for name in required)
    return bool(ok), {"verified": bool(ok), "test_mode": evidence.get("test_mode"), "required_phases": required, "evidence_sha256": sha(evidence)}


def production_chain(evidence: dict | None, commit: str) -> tuple[bool, dict | None]:
    """Issue #75 currently exposes no canonical standalone verifier.

    A caller-supplied JSON summary must never promote a production release. The gate
    remains closed until the exact #75 certified-chain verifier is integrated here.
    """
    if evidence is None:
        return False, None
    # Parse/basic bind only for diagnostics; these fields are explicitly insufficient.
    source_bound = evidence.get("source_commit") == commit
    return False, {
        "verified": False,
        "source_bound": bool(source_bound),
        "canonical_verifier_available": False,
        "rejected_summary_only_evidence": True,
        "evidence_sha256": sha(evidence),
    }


def _controlled_trust_module():
    path = Path(__file__).resolve().parents[1] / "windows" / "controlled_trust_gate.py"
    if not path.is_file():
        raise ReleaseError("canonical controlled trust verifier missing")
    spec = importlib.util.spec_from_file_location("ergaxiom_controlled_trust_gate", path)
    if spec is None or spec.loader is None:
        raise ReleaseError("canonical controlled trust verifier load failed")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def hardware(
    paths: dict[str, Path | None] | None,
    service_digest: str,
    legacy_summary: dict | None = None,
) -> tuple[bool, dict | None]:
    if legacy_summary is not None:
        # A pre-computed `verified:true` JSON is not authority. Raw ceremony evidence
        # must be re-verified by the canonical #77 verifier below.
        return False, {
            "verified": False,
            "rejected_summary_only_evidence": True,
            "evidence_sha256": sha(legacy_summary),
        }
    if not paths or any(path is None for path in paths.values()):
        return False, None
    concrete = {name: path for name, path in paths.items() if path is not None}
    gate = _controlled_trust_module()
    try:
        summary, code = gate.make_gate_summary(
            concrete["physical"], concrete["governance"], concrete["installation"], concrete["recovery"],
            concrete["capability"], concrete["attestation"],
        )
    except Exception as exc:
        expected = getattr(gate, "EvidenceError", Exception)
        if isinstance(exc, expected):
            raise ReleaseError(f"hardware operational evidence rejected: {exc}") from exc
        raise
    if code != 0 or summary.get("hardware_operational_eligible") is not True or summary.get("hardware_operational_gate") != getattr(gate, "PROVEN", "PROVEN_HARDWARE_BACKED"):
        return False, {"verified": False, "canonical_verifier": "tools/windows/controlled_trust_gate.py", "verifier_result": summary}
    installation = load(concrete["installation"])
    recovery = load(concrete["recovery"])
    observed = installation.get("service_snapshot", {}).get("process_executable_sha256")
    if observed != service_digest:
        raise ReleaseError("hardware installation signer-service digest does not match signed release artifact")
    for side in ("before", "after"):
        digest = recovery.get(side, {}).get("service_snapshot", {}).get("process_executable_sha256")
        if digest != service_digest:
            raise ReleaseError(f"hardware recovery {side} signer-service digest does not match signed release artifact")
    return True, {
        "verified": True,
        "canonical_verifier": "tools/windows/controlled_trust_gate.py",
        "ceremony_id": summary.get("ceremony_id"),
        "machine_identity_digest": summary.get("machine_identity_digest"),
        "signer_service_sha256": service_digest,
        "evidence_digests": summary.get("evidence_digests", {}),
    }


def license_gate(evidence: dict | None, policy: dict, commit: str) -> tuple[bool, dict | None]:
    p = policy.get("license", {})
    resolved = p.get("owner_decision_status") == "APPROVED" and bool(p.get("spdx_expression"))
    ok = bool(resolved and evidence and evidence.get("schema_version") == "0.1.0" and evidence.get("source_commit") == commit and evidence.get("owner_approved") is True and evidence.get("spdx_expression") == p.get("spdx_expression"))
    return ok, None if evidence is None else {"verified": bool(ok), "spdx_expression": evidence.get("spdx_expression"), "evidence_sha256": sha(evidence)}


def build(base, policy, sig=None, life=None, prod=None, hw=None, lic=None, hw_paths=None):
    policy_ok(policy)
    artifact_digests, installer_name = artifacts(base, policy)
    commit = base["source"]["commit"]
    signing_ok, signing_summary = signing(sig, policy, artifact_digests)
    lifecycle_ok, lifecycle_summary = lifecycle(life, commit, installer_name, artifact_digests[installer_name])
    production_ok, production_summary = production_chain(prod, commit)
    hardware_ok, hardware_summary = hardware(hw_paths, artifact_digests["ergaxiom-windows-production-signer-service.exe"], hw)
    license_ok, license_summary = license_gate(lic, policy, commit)
    blockers: list[str] = []
    if policy["signing"].get("identity_status") != "OWNER_APPROVED_PINNED": blockers.append("SIGNING_IDENTITY_POLICY_UNRESOLVED")
    if not signing_ok:
        blockers += ["AUTHENTICODE_NOT_VERIFIED", "TRUSTED_TIMESTAMP_NOT_VERIFIED", "CERTIFICATE_CHAIN_NOT_VERIFIED", "SIGNING_IDENTITY_NOT_VERIFIED"]
    if not lifecycle_ok: blockers.append("INSTALLER_LIFECYCLE_NOT_VERIFIED")
    if not production_ok:
        blockers += ["PRODUCTION_CHAIN_EVIDENCE_NOT_VERIFIED", "PRODUCTION_CHAIN_CANONICAL_VERIFIER_NOT_INTEGRATED"]
    if not hardware_ok: blockers.append("HARDWARE_OPERATIONAL_EVIDENCE_NOT_VERIFIED")
    if not license_ok: blockers.append("DISTRIBUTION_LICENSE_NOT_APPROVED")
    blockers = sorted(set(blockers))
    final_artifacts = []
    for artifact in base["artifacts"]:
        item = dict(artifact); item["authenticode_status"] = "VERIFIED" if signing_ok else "NOT_VERIFIED"; final_artifacts.append(item)
    return {
        "schema_version": "0.2.0", "product": base.get("product"), "source": base["source"], "toolchain": base.get("toolchain"),
        "artifacts": final_artifacts, "sbom": base.get("sbom"),
        "windows_release_policy": {"policy_id": policy["policy_id"], "sha256": sha(policy), "canonical_installer": "nsis"},
        "signing": signing_summary,
        "installer_provenance": {"installer_name": installer_name, "installer_sha256": artifact_digests[installer_name], "verified": bool(signing_ok and lifecycle_ok)},
        "installer_lifecycle": lifecycle_summary, "production_chain": production_summary, "hardware_operational": hardware_summary,
        "distribution_license": license_summary, "release_eligible": not blockers, "blocking_reasons": blockers,
    }


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-manifest", type=Path, required=True); parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--signature-evidence", type=Path); parser.add_argument("--lifecycle-evidence", type=Path)
    parser.add_argument("--production-chain-evidence", type=Path)
    parser.add_argument("--hardware-operational-evidence", type=Path, help="legacy summary; deliberately cannot satisfy the gate")
    parser.add_argument("--capability-provisioning-evidence", type=Path); parser.add_argument("--attestation-provisioning-evidence", type=Path)
    parser.add_argument("--physical-tpm-promotion-evidence", type=Path); parser.add_argument("--governance-recovery-receipt", type=Path)
    parser.add_argument("--signer-installation-receipt", type=Path); parser.add_argument("--signer-restart-recovery-receipt", type=Path)
    parser.add_argument("--license-decision", type=Path); parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        hw_paths = {
            "capability": args.capability_provisioning_evidence, "attestation": args.attestation_provisioning_evidence,
            "physical": args.physical_tpm_promotion_evidence, "governance": args.governance_recovery_receipt,
            "installation": args.signer_installation_receipt, "recovery": args.signer_restart_recovery_receipt,
        }
        output = build(load(args.base_manifest), load(args.policy), load(args.signature_evidence), load(args.lifecycle_evidence),
                       load(args.production_chain_evidence), load(args.hardware_operational_evidence), load(args.license_decision), hw_paths)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(output, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        return 0
    except (OSError, json.JSONDecodeError, ReleaseError) as error:
        print(f"final Windows release evidence failed: {error}", file=sys.stderr); return 1


if __name__ == "__main__":
    raise SystemExit(main())

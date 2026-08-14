#!/usr/bin/env python3
"""Fail-closed Windows production release decision for Issue #78."""
from __future__ import annotations

import argparse
import hashlib
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
        for item in inventory.get("signed_pe_artifacts", [])
        if isinstance(item, dict)
    }
    if pe != {
        ("desktop", "ergaxiom-desktop.exe", "apps/desktop/src-tauri", "SHIPPED_EXECUTABLE"),
        ("production_signer_service", "ergaxiom-windows-production-signer-service.exe", "apps/windows-production-signer-service", "SHIPPED_EXECUTABLE"),
    }:
        raise ReleaseError("PE inventory")
    linked = {
        (item.get("artifact_id"), item.get("build_input"), item.get("disposition"))
        for item in inventory.get("linked_runtime_inputs", [])
        if isinstance(item, dict)
    }
    if linked != {
        ("windows_uia_client", "crates/windows-uia-client-runtime", "LINKED_INTO_DESKTOP"),
        ("windows_bridge", "crates/windows-bridge-runtime", "LINKED_INTO_DESKTOP"),
        ("inkscape_adapter", "crates/inkscape-adapter-runtime", "LINKED_RUNTIME"),
    }:
        raise ReleaseError("linked inventory")
    if inventory.get("installer") != {
        "artifact_id": "windows_installer",
        "format": "NSIS",
        "filename_glob": "*-setup.exe",
        "disposition": "SHIPPED_INSTALLER",
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
    mapping = {record.get("name"): record for record in records if isinstance(record, dict) and isinstance(record.get("name"), str)}
    if len(mapping) != len(records) or set(mapping) != set(artifact_digests):
        raise ReleaseError("signature inventory")
    for name, digest in artifact_digests.items():
        if h64(mapping[name].get("sha256"), name) != digest:
            raise ReleaseError(f"post-sign mutation: {name}")
    signing_policy = policy["signing"]
    resolved = (
        signing_policy.get("identity_status") == "OWNER_APPROVED_PINNED"
        and isinstance(signing_policy.get("expected_subject"), str)
        and bool(signing_policy.get("expected_subject"))
        and H64.fullmatch(str(signing_policy.get("expected_certificate_sha256", ""))) is not None
    )
    ok = bool(
        resolved
        and evidence.get("mode") == "production"
        and evidence.get("test_identity") is False
        and evidence.get("signtool_available") is True
    )
    for record in mapping.values():
        ok &= all(
            [
                record.get("authenticode_valid") is True,
                record.get("signtool_verify_ok") is True,
                record.get("code_signing_eku_present") is True,
                record.get("certificate_chain_valid") is True,
                record.get("revocation_checked_online") is True,
                record.get("timestamp_present") is True,
                record.get("timestamp_chain_valid") is True,
                record.get("self_signed") is False,
                record.get("signer_subject") == signing_policy.get("expected_subject"),
                record.get("signer_certificate_sha256") == signing_policy.get("expected_certificate_sha256"),
                record.get("timestamp_url") == signing_policy.get("timestamp_url"),
            ]
        )
    return bool(ok), {
        "verified": bool(ok),
        "test_identity": evidence.get("test_identity"),
        "signtool_available": evidence.get("signtool_available"),
        "evidence_sha256": sha(evidence),
    }


def lifecycle(evidence: dict | None, commit: str, installer_name: str, installer_digest: str) -> tuple[bool, dict | None]:
    if evidence is None:
        return False, None
    if (
        evidence.get("schema_version") != "0.1.0"
        or evidence.get("source_commit") != commit
        or evidence.get("installer_name") != installer_name
        or evidence.get("installer_sha256") != installer_digest
    ):
        raise ReleaseError("lifecycle binding")
    required = [
        "clean_install",
        "upgrade",
        "downgrade_rejected",
        "interrupted_upgrade_preserved_state",
        "recovery_install",
        "uninstall",
        "production_state_preserved",
    ]
    ok = evidence.get("test_mode") is False and all(evidence.get("phases", {}).get(name) is True for name in required)
    return ok, {"verified": bool(ok), "test_mode": evidence.get("test_mode"), "evidence_sha256": sha(evidence)}


def external(evidence: dict | None, gate: str, commit: str) -> tuple[bool, dict | None]:
    if evidence is None:
        return False, None
    ok = (
        evidence.get("schema_version") == "0.1.0"
        and evidence.get("gate") == gate
        and evidence.get("source_commit") == commit
        and evidence.get("verified") is True
        and bool(evidence.get("evidence_artifacts"))
    )
    if ok:
        for artifact in evidence["evidence_artifacts"]:
            h64(artifact.get("sha256"), gate)
    return bool(ok), {"verified": bool(ok), "evidence_sha256": sha(evidence)}


def license_gate(evidence: dict | None, policy: dict, commit: str) -> tuple[bool, dict | None]:
    license_policy = policy.get("license", {})
    resolved = license_policy.get("owner_decision_status") == "APPROVED" and bool(license_policy.get("spdx_expression"))
    ok = bool(
        resolved
        and evidence
        and evidence.get("schema_version") == "0.1.0"
        and evidence.get("source_commit") == commit
        and evidence.get("owner_approved") is True
        and evidence.get("spdx_expression") == license_policy.get("spdx_expression")
    )
    return ok, None if evidence is None else {
        "verified": bool(ok),
        "spdx_expression": evidence.get("spdx_expression"),
        "evidence_sha256": sha(evidence),
    }


def build(base, policy, sig=None, life=None, prod=None, hw=None, lic=None):
    policy_ok(policy)
    artifact_digests, installer_name = artifacts(base, policy)
    commit = base["source"]["commit"]
    signing_ok, signing_summary = signing(sig, policy, artifact_digests)
    lifecycle_ok, lifecycle_summary = lifecycle(life, commit, installer_name, artifact_digests[installer_name])
    production_ok, production_summary = external(prod, "production_chain", commit)
    hardware_ok, hardware_summary = external(hw, "hardware_operational", commit)
    license_ok, license_summary = license_gate(lic, policy, commit)
    blockers: list[str] = []
    if policy["signing"].get("identity_status") != "OWNER_APPROVED_PINNED":
        blockers.append("SIGNING_IDENTITY_POLICY_UNRESOLVED")
    if not signing_ok:
        blockers += [
            "AUTHENTICODE_NOT_VERIFIED",
            "TRUSTED_TIMESTAMP_NOT_VERIFIED",
            "CERTIFICATE_CHAIN_NOT_VERIFIED",
            "SIGNING_IDENTITY_NOT_VERIFIED",
        ]
    if not lifecycle_ok:
        blockers.append("INSTALLER_LIFECYCLE_NOT_VERIFIED")
    if not production_ok:
        blockers.append("PRODUCTION_CHAIN_EVIDENCE_NOT_VERIFIED")
    if not hardware_ok:
        blockers.append("HARDWARE_OPERATIONAL_EVIDENCE_NOT_VERIFIED")
    if not license_ok:
        blockers.append("DISTRIBUTION_LICENSE_NOT_APPROVED")
    blockers = sorted(set(blockers))
    final_artifacts = []
    for artifact in base["artifacts"]:
        item = dict(artifact)
        item["authenticode_status"] = "VERIFIED" if signing_ok else "NOT_VERIFIED"
        final_artifacts.append(item)
    return {
        "schema_version": "0.1.0",
        "product": base.get("product"),
        "source": base["source"],
        "toolchain": base.get("toolchain"),
        "artifacts": final_artifacts,
        "sbom": base.get("sbom"),
        "windows_release_policy": {
            "policy_id": policy["policy_id"],
            "sha256": sha(policy),
            "canonical_installer": "nsis",
        },
        "signing": signing_summary,
        "installer_provenance": {
            "installer_name": installer_name,
            "installer_sha256": artifact_digests[installer_name],
            "verified": bool(signing_ok and lifecycle_ok),
        },
        "installer_lifecycle": lifecycle_summary,
        "production_chain": production_summary,
        "hardware_operational": hardware_summary,
        "distribution_license": license_summary,
        "release_eligible": not blockers,
        "blocking_reasons": blockers,
    }


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-manifest", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--signature-evidence", type=Path)
    parser.add_argument("--lifecycle-evidence", type=Path)
    parser.add_argument("--production-chain-evidence", type=Path)
    parser.add_argument("--hardware-operational-evidence", type=Path)
    parser.add_argument("--license-decision", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        output = build(
            load(args.base_manifest),
            load(args.policy),
            load(args.signature_evidence),
            load(args.lifecycle_evidence),
            load(args.production_chain_evidence),
            load(args.hardware_operational_evidence),
            load(args.license_decision),
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(output, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        return 0
    except (OSError, json.JSONDecodeError, ReleaseError) as error:
        print(f"final Windows release evidence failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

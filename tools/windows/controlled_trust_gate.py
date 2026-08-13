#!/usr/bin/env python3
"""Fail-closed verifier/sealer for Ergaxiom controlled Windows trust evidence.

This tool deliberately does not infer physical TPM assurance from ordinary CI success.
A PROVEN gate requires a sealed controlled-hardware ceremony plus bound governance,
installation and recovery receipts. Missing or incomplete evidence is UNKNOWN.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
PHYSICAL_SCHEMA = "0.1.0"
GOVERNANCE_SCHEMA = "0.1.0"
GATE_SCHEMA = "0.1.0"
PLATFORM_PROVIDER = "Microsoft Platform Crypto Provider"
PROVEN = "PROVEN_HARDWARE_BACKED"
UNKNOWN = "UNKNOWN"
PUBLIC_ONLY_BACKUP = "PUBLIC_ONLY_NO_PRIVATE_KEY_BACKUP"


class EvidenceError(ValueError):
    pass


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def require_sha256(value: Any, field: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise EvidenceError(f"{field}: expected lowercase sha256")
    return value


def require_nonempty(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise EvidenceError(f"{field}: expected non-empty string")
    return value


def require_bool(value: Any, field: str, expected: bool) -> None:
    if value is not expected:
        raise EvidenceError(f"{field}: expected {expected}")


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EvidenceError(f"{path}: invalid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise EvidenceError(f"{path}: top-level value must be an object")
    return value


def sealed_digest(value: dict[str, Any], digest_field: str) -> str:
    clone = dict(value)
    clone[digest_field] = ""
    return sha256_bytes(canonical_bytes(clone))


def seal_document(value: dict[str, Any], digest_field: str) -> dict[str, Any]:
    sealed = dict(value)
    sealed[digest_field] = ""
    sealed[digest_field] = sealed_digest(sealed, digest_field)
    return sealed


def verify_document_seal(value: dict[str, Any], digest_field: str) -> None:
    actual = require_sha256(value.get(digest_field), digest_field)
    expected = sealed_digest(value, digest_field)
    if actual != expected:
        raise EvidenceError(f"{digest_field}: digest mismatch")


def verify_governance_receipt(value: dict[str, Any]) -> None:
    if value.get("schema_version") != GOVERNANCE_SCHEMA:
        raise EvidenceError("governance.schema_version: unsupported")
    require_nonempty(value.get("ceremony_id"), "governance.ceremony_id")
    require_nonempty(value.get("reason"), "governance.reason")
    role = value.get("role")
    if role not in {"CAPABILITY", "ATTESTATION"}:
        raise EvidenceError("governance.role: unsupported")
    previous_generation = value.get("previous_generation")
    replacement_generation = value.get("replacement_generation")
    if not isinstance(previous_generation, int) or previous_generation < 1:
        raise EvidenceError("governance.previous_generation: invalid")
    if not isinstance(replacement_generation, int) or replacement_generation <= previous_generation:
        raise EvidenceError("governance.replacement_generation: must increase")
    if value.get("backup_policy") != PUBLIC_ONLY_BACKUP:
        raise EvidenceError("governance.backup_policy: private-key backup is forbidden")
    require_bool(value.get("private_key_material_present"), "governance.private_key_material_present", False)
    for field in ("previous_key_record_digest", "replacement_provisioning_evidence_sha256", "replacement_public_key_digest", "previous_trust_state_digest", "replacement_trust_state_digest", "signed_distribution_digest"):
        require_sha256(value.get(field), f"governance.{field}")
    quorum = value.get("recovery_quorum")
    if not isinstance(quorum, dict):
        raise EvidenceError("governance.recovery_quorum: missing")
    threshold = quorum.get("threshold")
    approvals = quorum.get("approvals")
    if not isinstance(threshold, int) or threshold < 2:
        raise EvidenceError("governance.recovery_quorum.threshold: must be >= 2")
    if not isinstance(approvals, list) or len(approvals) < threshold:
        raise EvidenceError("governance.recovery_quorum.approvals: threshold not met")
    participant_ids: set[str] = set()
    approval_digests: set[str] = set()
    for index, approval in enumerate(approvals):
        if not isinstance(approval, dict):
            raise EvidenceError(f"governance.recovery_quorum.approvals[{index}]: invalid")
        participant = require_nonempty(approval.get("participant_id"), f"governance.recovery_quorum.approvals[{index}].participant_id")
        digest = require_sha256(approval.get("approval_digest"), f"governance.recovery_quorum.approvals[{index}].approval_digest")
        if participant in participant_ids or digest in approval_digests:
            raise EvidenceError("governance.recovery_quorum: duplicate approval")
        participant_ids.add(participant)
        approval_digests.add(digest)
    verify_document_seal(value, "receipt_digest")


def verify_physical_evidence(value: dict[str, Any]) -> None:
    if value.get("schema_version") != PHYSICAL_SCHEMA:
        raise EvidenceError("physical.schema_version: unsupported")
    if value.get("promotion_status") != PROVEN:
        raise EvidenceError("physical.promotion_status: not proven")
    require_nonempty(value.get("ceremony_id"), "physical.ceremony_id")
    recorded = value.get("recorded_at_epoch_s")
    if not isinstance(recorded, int) or recorded < 1:
        raise EvidenceError("physical.recorded_at_epoch_s: invalid")
    if value.get("execution_context") != "CONTROLLED_WINDOWS_MACHINE":
        raise EvidenceError("physical.execution_context: controlled machine required")
    if value.get("platform") != "windows":
        raise EvidenceError("physical.platform: Windows required")
    require_bool(value.get("hosted_ci"), "physical.hosted_ci", False)
    runner_environment = value.get("runner_environment")
    if runner_environment not in {"outside-ci", "self-hosted"}:
        raise EvidenceError("physical.runner_environment: hosted runner cannot promote")
    if runner_environment == "self-hosted":
        require_bool(value.get("controlled_hardware_runner"), "physical.controlled_hardware_runner", True)
    require_bool(value.get("elevated_administrator"), "physical.elevated_administrator", True)
    require_sha256(value.get("machine_identity_digest"), "physical.machine_identity_digest")
    require_sha256(value.get("machine_inventory_digest"), "physical.machine_inventory_digest")
    require_sha256(value.get("physical_hardware_attestation_digest"), "physical.physical_hardware_attestation_digest")
    require_sha256(value.get("operator_quorum_digest"), "physical.operator_quorum_digest")
    tpm = value.get("tpm")
    if not isinstance(tpm, dict):
        raise EvidenceError("physical.tpm: missing")
    for field in ("present", "ready", "enabled", "activated"):
        require_bool(tpm.get(field), f"physical.tpm.{field}", True)
    provider = value.get("cng_provider")
    if not isinstance(provider, dict):
        raise EvidenceError("physical.cng_provider: missing")
    if provider.get("name") != PLATFORM_PROVIDER:
        raise EvidenceError("physical.cng_provider.name: provider substitution")
    require_bool(provider.get("hardware_flag_present"), "physical.cng_provider.hardware_flag_present", True)
    require_bool(provider.get("software_flag_present"), "physical.cng_provider.software_flag_present", False)
    flags = provider.get("implementation_flags")
    if not isinstance(flags, int) or flags < 1:
        raise EvidenceError("physical.cng_provider.implementation_flags: invalid")
    roles = value.get("roles")
    if not isinstance(roles, dict) or set(roles) != {"capability", "attestation"}:
        raise EvidenceError("physical.roles: capability and attestation are required")
    public_keys: set[str] = set()
    for role in ("capability", "attestation"):
        item = roles.get(role)
        if not isinstance(item, dict):
            raise EvidenceError(f"physical.roles.{role}: missing")
        generation = item.get("generation")
        if not isinstance(generation, int) or generation < 1:
            raise EvidenceError(f"physical.roles.{role}.generation: invalid")
        if item.get("provider") != PLATFORM_PROVIDER:
            raise EvidenceError(f"physical.roles.{role}.provider: substitution")
        if item.get("export_policy") != "non-exportable":
            raise EvidenceError(f"physical.roles.{role}.export_policy: must be non-exportable")
        require_bool(item.get("key_possession_verified"), f"physical.roles.{role}.key_possession_verified", True)
        for field in ("provisioning_evidence_sha256", "public_key_digest", "receipt_digest", "evidence_digest"):
            require_sha256(item.get(field), f"physical.roles.{role}.{field}")
        public_key = item["public_key_digest"]
        if public_key in public_keys:
            raise EvidenceError("physical.roles: public-key reuse across roles")
        public_keys.add(public_key)
    for field in ("installation_receipt_sha256", "recovery_receipt_sha256", "governance_recovery_receipt_sha256"):
        require_sha256(value.get(field), f"physical.{field}")
    verify_document_seal(value, "ceremony_digest")


def verify_installation_binding(value: dict[str, Any], physical: dict[str, Any]) -> None:
    if value.get("schema_version") != "0.1.0":
        raise EvidenceError("installation.schema_version: unsupported")
    if value.get("machine_identity_digest") != physical.get("machine_identity_digest"):
        raise EvidenceError("installation.machine_identity_digest: machine substitution")
    require_sha256(value.get("receipt_digest"), "installation.receipt_digest")
    service = value.get("service_snapshot")
    if not isinstance(service, dict):
        raise EvidenceError("installation.service_snapshot: missing")
    if service.get("service_account") != "LocalSystem":
        raise EvidenceError("installation.service_account: LocalSystem required")
    if service.get("runtime_state") != "RUNNING":
        raise EvidenceError("installation.runtime_state: service not running")
    require_sha256(service.get("process_executable_sha256"), "installation.process_executable_sha256")
    if not isinstance(value.get("trust_state_binding"), dict):
        raise EvidenceError("installation.trust_state_binding: missing")
    require_sha256(value.get("governance_policy_digest"), "installation.governance_policy_digest")


def verify_recovery_binding(value: dict[str, Any], installation: dict[str, Any]) -> None:
    if value.get("schema_version") != "0.1.0":
        raise EvidenceError("recovery.schema_version: unsupported")
    require_sha256(value.get("receipt_digest"), "recovery.receipt_digest")
    before = value.get("before")
    after = value.get("after")
    if not isinstance(before, dict) or not isinstance(after, dict):
        raise EvidenceError("recovery.before/after: missing")
    for field in ("deployment_id", "machine_identity_digest", "governance_policy_digest"):
        if before.get(field) != after.get(field):
            raise EvidenceError(f"recovery.{field}: substitution across restart")
    if after.get("machine_identity_digest") != installation.get("machine_identity_digest"):
        raise EvidenceError("recovery.machine_identity_digest: installation mismatch")
    before_service = before.get("service_snapshot")
    after_service = after.get("service_snapshot")
    if not isinstance(before_service, dict) or not isinstance(after_service, dict):
        raise EvidenceError("recovery.service_snapshot: missing")
    same_process = before_service.get("process_id") == after_service.get("process_id") and before_service.get("process_creation_time_100ns") == after_service.get("process_creation_time_100ns")
    if same_process:
        raise EvidenceError("recovery.service_process: restart not proven")
    for field in ("binary_path", "process_executable_sha256", "service_account"):
        if before_service.get(field) != after_service.get(field):
            raise EvidenceError(f"recovery.service_snapshot.{field}: substitution")


def make_gate_summary(physical_path: Path, governance_path: Path, installation_path: Path, recovery_path: Path) -> tuple[dict[str, Any], int]:
    paths = {"physical_tpm_evidence": physical_path, "governance_recovery_receipt": governance_path, "installation_receipt": installation_path, "recovery_receipt": recovery_path}
    missing = [name for name, path in paths.items() if not path.is_file()]
    if missing:
        return ({"schema_version": GATE_SCHEMA, "hardware_operational_gate": UNKNOWN, "hardware_operational_eligible": False, "blockers": [f"missing:{name}" for name in sorted(missing)], "evidence_digests": {}}, 2)
    physical = load_json(physical_path)
    governance = load_json(governance_path)
    installation = load_json(installation_path)
    recovery = load_json(recovery_path)
    verify_physical_evidence(physical)
    verify_governance_receipt(governance)
    verify_installation_binding(installation, physical)
    verify_recovery_binding(recovery, installation)
    digests = {name: sha256_file(path) for name, path in paths.items()}
    if physical["governance_recovery_receipt_sha256"] != digests["governance_recovery_receipt"]:
        raise EvidenceError("physical.governance_recovery_receipt_sha256: binding mismatch")
    governance_role = governance["role"].lower()
    promoted_role = physical["roles"][governance_role]
    if governance["replacement_public_key_digest"] != promoted_role["public_key_digest"]:
        raise EvidenceError("governance.replacement_public_key_digest: promoted key mismatch")
    if governance["replacement_provisioning_evidence_sha256"] != promoted_role["provisioning_evidence_sha256"]:
        raise EvidenceError("governance.replacement_provisioning_evidence_sha256: promoted evidence mismatch")
    if physical["installation_receipt_sha256"] != digests["installation_receipt"]:
        raise EvidenceError("physical.installation_receipt_sha256: binding mismatch")
    if physical["recovery_receipt_sha256"] != digests["recovery_receipt"]:
        raise EvidenceError("physical.recovery_receipt_sha256: binding mismatch")
    return ({"schema_version": GATE_SCHEMA, "hardware_operational_gate": PROVEN, "hardware_operational_eligible": True, "blockers": [], "ceremony_id": physical["ceremony_id"], "machine_identity_digest": physical["machine_identity_digest"], "evidence_digests": digests}, 0)


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def cmd_seal(args: argparse.Namespace, kind: str) -> int:
    value = load_json(args.input)
    field = "ceremony_digest" if kind == "physical" else "receipt_digest"
    value = seal_document(value, field)
    if kind == "physical":
        verify_physical_evidence(value)
    else:
        verify_governance_receipt(value)
    write_json(args.output, value)
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    try:
        summary, code = make_gate_summary(args.physical, args.governance, args.installation, args.recovery)
    except EvidenceError as exc:
        summary = {"schema_version": GATE_SCHEMA, "hardware_operational_gate": UNKNOWN, "hardware_operational_eligible": False, "blockers": [f"invalid:{exc}"], "evidence_digests": {}}
        code = 3
    if args.output is not None:
        write_json(args.output, summary)
    print(json.dumps(summary, sort_keys=True))
    return code


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("seal-physical", "seal-governance"):
        item = sub.add_parser(name)
        item.add_argument("--input", type=Path, required=True)
        item.add_argument("--output", type=Path, required=True)
    verify = sub.add_parser("verify")
    verify.add_argument("--physical", type=Path, required=True)
    verify.add_argument("--governance", type=Path, required=True)
    verify.add_argument("--installation", type=Path, required=True)
    verify.add_argument("--recovery", type=Path, required=True)
    verify.add_argument("--output", type=Path)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        if args.command == "seal-physical":
            return cmd_seal(args, "physical")
        if args.command == "seal-governance":
            return cmd_seal(args, "governance")
        if args.command == "verify":
            return cmd_verify(args)
    except EvidenceError as exc:
        print(f"controlled trust evidence rejected: {exc}", file=sys.stderr)
        return 3
    raise AssertionError("unreachable")


if __name__ == "__main__":
    raise SystemExit(main())

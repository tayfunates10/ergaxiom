#!/usr/bin/env python3
"""Fail-closed verifier/sealer for Ergaxiom controlled Windows trust evidence.

Ordinary hosted CI can validate this policy but can never satisfy it. A PROVEN
hardware-operational gate requires exact Capability and Attestation provisioning
evidence, a controlled physical-TPM ceremony, governance recovery evidence, an
installed LocalSystem signer receipt, and a restart/recovery receipt. All public
evidence is digest-bound and the CNG key-possession signatures are independently
verified with a platform-neutral P-256 verifier.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
PHYSICAL_SCHEMA = "0.1.0"
GOVERNANCE_SCHEMA = "0.1.0"
PROVISIONING_SCHEMA = "0.1.0"
GATE_SCHEMA = "0.1.0"
PLATFORM_PROVIDER = "Microsoft Platform Crypto Provider"
PROVEN = "PROVEN_HARDWARE_BACKED"
UNKNOWN = "UNKNOWN"
PUBLIC_ONLY_BACKUP = "PUBLIC_ONLY_NO_PRIVATE_KEY_BACKUP"
POLICY_SCHEMA = "0.1.0"
ALGORITHM = "ecdsa-p256-sha256"
PUBLIC_ENCODING = "sec1-uncompressed-p256"
SIGNATURE_ENCODING = "p1363-fixed-64"
EXPORT_POLICY = "non-exportable"
KEY_NAME_PREFIX = "Ergaxiom.Production"

ROLE_IDENTITIES = {
    "capability": {
        "role": "CAPABILITY",
        "issuer_id": "ergaxiom.policy-authority",
        "key_id": "capability-key-v1",
    },
    "attestation": {
        "role": "ATTESTATION",
        "issuer_id": "ergaxiom.attestation-authority",
        "key_id": "attestation-key-v1",
    },
}

# NIST P-256 / secp256r1 constants.
P256_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
P256_A = P256_P - 3
P256_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
P256_G = (
    0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
    0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
)


class EvidenceError(ValueError):
    pass


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


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


def decode_base64url(value: Any, field: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise EvidenceError(f"{field}: invalid base64url")
    if "=" in value:
        raise EvidenceError(f"{field}: padding is not canonical")
    padding = "=" * ((4 - len(value) % 4) % 4)
    try:
        return base64.urlsafe_b64decode((value + padding).encode("ascii"))
    except (ValueError, UnicodeEncodeError) as exc:
        raise EvidenceError(f"{field}: invalid base64url") from exc


def p256_is_on_curve(point: tuple[int, int] | None) -> bool:
    if point is None:
        return True
    x, y = point
    return 0 <= x < P256_P and 0 <= y < P256_P and (
        y * y - (x * x * x + P256_A * x + P256_B)
    ) % P256_P == 0


def p256_add(
    left: tuple[int, int] | None,
    right: tuple[int, int] | None,
) -> tuple[int, int] | None:
    if left is None:
        return right
    if right is None:
        return left
    x1, y1 = left
    x2, y2 = right
    if x1 == x2 and (y1 + y2) % P256_P == 0:
        return None
    if left == right:
        if y1 == 0:
            return None
        slope = ((3 * x1 * x1 + P256_A) * pow(2 * y1, -1, P256_P)) % P256_P
    else:
        slope = ((y2 - y1) * pow((x2 - x1) % P256_P, -1, P256_P)) % P256_P
    x3 = (slope * slope - x1 - x2) % P256_P
    y3 = (slope * (x1 - x3) - y1) % P256_P
    return x3, y3


def p256_mul(scalar: int, point: tuple[int, int] | None) -> tuple[int, int] | None:
    if scalar < 0:
        raise EvidenceError("negative elliptic-curve scalar")
    result = None
    addend = point
    while scalar:
        if scalar & 1:
            result = p256_add(result, addend)
        addend = p256_add(addend, addend)
        scalar >>= 1
    return result


def verify_p256_prehash(
    public_key_base64url: Any,
    signature_base64url: Any,
    digest_hex: Any,
) -> None:
    digest = require_sha256(digest_hex, "key_possession.digest")
    public_key = decode_base64url(public_key_base64url, "receipt.public_key_base64url")
    signature = decode_base64url(signature_base64url, "key_possession.signature_base64url")
    if len(public_key) != 65 or public_key[0] != 0x04:
        raise EvidenceError("receipt.public_key_base64url: invalid SEC1 P-256 key")
    if len(signature) != 64:
        raise EvidenceError("key_possession.signature_base64url: invalid P1363 signature length")
    point = (
        int.from_bytes(public_key[1:33], "big"),
        int.from_bytes(public_key[33:65], "big"),
    )
    if not p256_is_on_curve(point) or p256_mul(P256_N, point) is not None:
        raise EvidenceError("receipt.public_key_base64url: point is not valid P-256")
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    if not (1 <= r < P256_N and 1 <= s < P256_N):
        raise EvidenceError("key_possession.signature_base64url: invalid ECDSA scalar")
    z = int.from_bytes(bytes.fromhex(digest), "big")
    inverse = pow(s, -1, P256_N)
    candidate = p256_add(
        p256_mul((z * inverse) % P256_N, P256_G),
        p256_mul((r * inverse) % P256_N, point),
    )
    if candidate is None or candidate[0] % P256_N != r:
        raise EvidenceError("key_possession.signature_base64url: signature verification failed")


def production_policy(role: str) -> dict[str, Any]:
    identity = ROLE_IDENTITIES[role]
    return {
        "schema_version": POLICY_SCHEMA,
        "identity": identity,
        "provider": PLATFORM_PROVIDER,
        "algorithm": ALGORITHM,
        "public_key_encoding": PUBLIC_ENCODING,
        "signature_encoding": SIGNATURE_ENCODING,
        "export_policy": EXPORT_POLICY,
        "require_hardware_backing": True,
    }


def key_name_for(role: str, generation: int) -> str:
    identity_digest = sha256_bytes(canonical_bytes(ROLE_IDENTITIES[role]))
    base = f"{KEY_NAME_PREFIX}.{identity_digest}"
    return base if generation == 1 else f"{base}.g{generation:020d}"


def verify_provisioning_evidence(value: dict[str, Any], role: str) -> dict[str, Any]:
    if value.get("schema_version") != PROVISIONING_SCHEMA:
        raise EvidenceError(f"{role}.provisioning.schema_version: unsupported")
    statement = value.get("statement")
    receipt = value.get("receipt")
    possession = value.get("key_possession")
    if not isinstance(statement, dict) or not isinstance(receipt, dict) or not isinstance(possession, dict):
        raise EvidenceError(f"{role}.provisioning: statement/receipt/key_possession required")
    expected_identity = ROLE_IDENTITIES[role]
    expected_policy = production_policy(role)
    expected_policy_digest = sha256_bytes(canonical_bytes(expected_policy))

    if statement.get("schema_version") != PROVISIONING_SCHEMA:
        raise EvidenceError(f"{role}.statement.schema_version: unsupported")
    if statement.get("domain") != "ergaxiom.windows-production-signer.provisioning.v1":
        raise EvidenceError(f"{role}.statement.domain: substitution")
    if statement.get("identity") != expected_identity or receipt.get("identity") != expected_identity:
        raise EvidenceError(f"{role}.identity: substitution")
    generation = statement.get("generation", 1)
    if not isinstance(generation, int) or generation < 1:
        raise EvidenceError(f"{role}.generation: invalid")

    if receipt.get("schema_version") != PROVISIONING_SCHEMA:
        raise EvidenceError(f"{role}.receipt.schema_version: unsupported")
    if receipt.get("provider") != PLATFORM_PROVIDER:
        raise EvidenceError(f"{role}.receipt.provider: substitution")
    if receipt.get("algorithm") != ALGORITHM:
        raise EvidenceError(f"{role}.receipt.algorithm: substitution")
    if receipt.get("public_key_encoding") != PUBLIC_ENCODING:
        raise EvidenceError(f"{role}.receipt.public_key_encoding: substitution")
    if receipt.get("signature_encoding") != SIGNATURE_ENCODING:
        raise EvidenceError(f"{role}.receipt.signature_encoding: substitution")
    if receipt.get("export_policy") != EXPORT_POLICY:
        raise EvidenceError(f"{role}.receipt.export_policy: substitution")
    if receipt.get("assurance") != "UNPROVEN":
        raise EvidenceError(f"{role}.receipt.assurance: provisioning must remain UNPROVEN")
    if receipt.get("policy_digest") != expected_policy_digest:
        raise EvidenceError(f"{role}.receipt.policy_digest: mismatch")
    flags = receipt.get("provider_implementation_flags")
    if not isinstance(flags, int) or flags < 1:
        raise EvidenceError(f"{role}.receipt.provider_implementation_flags: invalid")
    provisioned_at = receipt.get("provisioned_at_epoch_s")
    if not isinstance(provisioned_at, int) or provisioned_at < 1:
        raise EvidenceError(f"{role}.receipt.provisioned_at_epoch_s: invalid")
    public_key = decode_base64url(receipt.get("public_key_base64url"), f"{role}.receipt.public_key_base64url")
    if len(public_key) != 65 or public_key[0] != 0x04:
        raise EvidenceError(f"{role}.receipt.public_key_base64url: invalid")
    public_key_digest = require_sha256(receipt.get("public_key_digest"), f"{role}.receipt.public_key_digest")
    if sha256_bytes(public_key) != public_key_digest:
        raise EvidenceError(f"{role}.receipt.public_key_digest: mismatch")
    verify_document_seal(receipt, "receipt_digest")

    if statement.get("receipt_digest") != receipt.get("receipt_digest"):
        raise EvidenceError(f"{role}.statement.receipt_digest: mismatch")
    if statement.get("public_key_digest") != public_key_digest:
        raise EvidenceError(f"{role}.statement.public_key_digest: mismatch")
    if statement.get("policy_digest") != expected_policy_digest:
        raise EvidenceError(f"{role}.statement.policy_digest: mismatch")
    expected_key_name_digest = sha256_bytes(key_name_for(role, generation).encode("utf-8"))
    if statement.get("key_name_digest") != expected_key_name_digest:
        raise EvidenceError(f"{role}.statement.key_name_digest: mismatch")
    if not isinstance(statement.get("created"), bool):
        raise EvidenceError(f"{role}.statement.created: invalid")

    statement_digest = sha256_bytes(canonical_bytes(statement))
    if possession.get("digest_algorithm") != "sha256":
        raise EvidenceError(f"{role}.key_possession.digest_algorithm: substitution")
    if possession.get("signature_encoding") != SIGNATURE_ENCODING:
        raise EvidenceError(f"{role}.key_possession.signature_encoding: substitution")
    if possession.get("digest") != statement_digest:
        raise EvidenceError(f"{role}.key_possession.digest: mismatch")
    if possession.get("public_key_digest") != public_key_digest:
        raise EvidenceError(f"{role}.key_possession.public_key_digest: mismatch")
    if possession.get("key_policy_digest") != expected_policy_digest:
        raise EvidenceError(f"{role}.key_possession.key_policy_digest: mismatch")
    verify_p256_prehash(
        receipt.get("public_key_base64url"),
        possession.get("signature_base64url"),
        possession.get("digest"),
    )
    verify_document_seal(value, "evidence_digest")
    return {
        "identity": expected_identity,
        "generation": generation,
        "provider": PLATFORM_PROVIDER,
        "export_policy": EXPORT_POLICY,
        "public_key_digest": public_key_digest,
        "policy_digest": expected_policy_digest,
        "receipt_digest": receipt["receipt_digest"],
        "evidence_digest": value["evidence_digest"],
    }


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
    for field in (
        "previous_key_record_digest",
        "replacement_provisioning_evidence_sha256",
        "replacement_public_key_digest",
        "previous_trust_state_digest",
        "replacement_trust_state_digest",
        "signed_distribution_digest",
    ):
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
        participant = require_nonempty(
            approval.get("participant_id"),
            f"governance.recovery_quorum.approvals[{index}].participant_id",
        )
        digest = require_sha256(
            approval.get("approval_digest"),
            f"governance.recovery_quorum.approvals[{index}].approval_digest",
        )
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
    require_sha256(
        value.get("physical_hardware_attestation_digest"),
        "physical.physical_hardware_attestation_digest",
    )
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
        if item.get("export_policy") != EXPORT_POLICY:
            raise EvidenceError(f"physical.roles.{role}.export_policy: must be non-exportable")
        require_bool(item.get("key_possession_verified"), f"physical.roles.{role}.key_possession_verified", True)
        for field in (
            "provisioning_evidence_sha256",
            "public_key_digest",
            "receipt_digest",
            "evidence_digest",
        ):
            require_sha256(item.get(field), f"physical.roles.{role}.{field}")
        public_key = item["public_key_digest"]
        if public_key in public_keys:
            raise EvidenceError("physical.roles: public-key reuse across roles")
        public_keys.add(public_key)
    for field in (
        "installation_receipt_sha256",
        "recovery_receipt_sha256",
        "governance_recovery_receipt_sha256",
    ):
        require_sha256(value.get(field), f"physical.{field}")
    verify_document_seal(value, "ceremony_digest")


def verify_installation_binding(
    value: dict[str, Any],
    physical: dict[str, Any],
    provisioning: dict[str, dict[str, Any]],
) -> None:
    if value.get("schema_version") != "0.1.0":
        raise EvidenceError("installation.schema_version: unsupported")
    if value.get("machine_identity_digest") != physical.get("machine_identity_digest"):
        raise EvidenceError("installation.machine_identity_digest: machine substitution")
    require_sha256(value.get("receipt_digest"), "installation.receipt_digest")
    verify_document_seal(value, "receipt_digest")
    service = value.get("service_snapshot")
    if not isinstance(service, dict):
        raise EvidenceError("installation.service_snapshot: missing")
    if service.get("service_account") != "LocalSystem":
        raise EvidenceError("installation.service_account: LocalSystem required")
    if service.get("runtime_state") != "RUNNING":
        raise EvidenceError("installation.runtime_state: service not running")
    require_sha256(service.get("process_executable_sha256"), "installation.process_executable_sha256")
    verify_document_seal(service, "snapshot_digest")
    if not isinstance(value.get("trust_state_binding"), dict):
        raise EvidenceError("installation.trust_state_binding: missing")
    require_sha256(value.get("governance_policy_digest"), "installation.governance_policy_digest")
    active_keys = value.get("active_keys")
    if not isinstance(active_keys, list):
        raise EvidenceError("installation.active_keys: missing")
    observed: dict[str, dict[str, Any]] = {}
    for index, item in enumerate(active_keys):
        if not isinstance(item, dict):
            raise EvidenceError(f"installation.active_keys[{index}]: invalid")
        identity = item.get("identity")
        if not isinstance(identity, dict):
            raise EvidenceError(f"installation.active_keys[{index}].identity: missing")
        role_name = str(identity.get("role", "")).lower()
        if role_name not in ROLE_IDENTITIES or identity != ROLE_IDENTITIES[role_name]:
            raise EvidenceError(f"installation.active_keys[{index}].identity: substitution")
        if role_name in observed:
            raise EvidenceError("installation.active_keys: duplicate role")
        if not isinstance(item.get("generation"), int) or item["generation"] < 1:
            raise EvidenceError(f"installation.active_keys[{index}].generation: invalid")
        for field in (
            "public_key_digest",
            "key_record_digest",
            "policy_digest",
            "descriptor_digest",
            "observation_digest",
        ):
            require_sha256(item.get(field), f"installation.active_keys[{index}].{field}")
        require_bool(
            item.get("provider_hardware_flag_present"),
            f"installation.active_keys[{index}].provider_hardware_flag_present",
            True,
        )
        require_bool(
            item.get("provider_software_flag_present"),
            f"installation.active_keys[{index}].provider_software_flag_present",
            False,
        )
        if item.get("provider_implementation_flags") != physical["cng_provider"]["implementation_flags"]:
            raise EvidenceError(f"installation.active_keys[{index}].provider_implementation_flags: mismatch")
        verify_document_seal(item, "observation_digest")
        observed[role_name] = item
    if set(observed) != set(ROLE_IDENTITIES):
        raise EvidenceError("installation.active_keys: capability and attestation are required")
    for role, expected in provisioning.items():
        item = observed[role]
        physical_role = physical["roles"][role]
        if item["generation"] != expected["generation"] or item["generation"] != physical_role["generation"]:
            raise EvidenceError(f"installation.active_keys.{role}.generation: mismatch")
        if item["public_key_digest"] != expected["public_key_digest"] or item["public_key_digest"] != physical_role["public_key_digest"]:
            raise EvidenceError(f"installation.active_keys.{role}.public_key_digest: mismatch")
        if item["policy_digest"] != expected["policy_digest"]:
            raise EvidenceError(f"installation.active_keys.{role}.policy_digest: mismatch")


def verify_recovery_binding(
    value: dict[str, Any],
    installation: dict[str, Any],
    physical: dict[str, Any],
    provisioning: dict[str, dict[str, Any]],
) -> None:
    if value.get("schema_version") != "0.1.0":
        raise EvidenceError("recovery.schema_version: unsupported")
    timeline = [
        value.get("started_at_epoch_s"),
        value.get("service_stopped_at_epoch_s"),
        value.get("service_restarted_at_epoch_s"),
        value.get("completed_at_epoch_s"),
    ]
    if not all(isinstance(item, int) and item > 0 for item in timeline):
        raise EvidenceError("recovery.timeline: invalid")
    if timeline != sorted(timeline):
        raise EvidenceError("recovery.timeline: out of order")
    before = value.get("before")
    after = value.get("after")
    if not isinstance(before, dict) or not isinstance(after, dict):
        raise EvidenceError("recovery.before/after: missing")
    verify_installation_binding(before, physical, provisioning)
    verify_installation_binding(after, physical, provisioning)
    for field in (
        "deployment_id",
        "machine_identity_digest",
        "manifest",
        "manifest_digest",
        "governance_policy_digest",
        "trust_state_binding",
        "enabled_identities",
        "active_keys",
    ):
        if before.get(field) != after.get(field):
            raise EvidenceError(f"recovery.{field}: substitution across restart")
        if before.get(field) != installation.get(field):
            raise EvidenceError(f"recovery.{field}: installation mismatch")
    before_service = before.get("service_snapshot")
    after_service = after.get("service_snapshot")
    if not isinstance(before_service, dict) or not isinstance(after_service, dict):
        raise EvidenceError("recovery.service_snapshot: missing")
    same_process = (
        before_service.get("process_id") == after_service.get("process_id")
        and before_service.get("process_creation_time_100ns")
        == after_service.get("process_creation_time_100ns")
    )
    if same_process:
        raise EvidenceError("recovery.service_process: restart not proven")
    for field in ("binary_path", "process_executable_sha256", "service_account"):
        if before_service.get(field) != after_service.get(field):
            raise EvidenceError(f"recovery.service_snapshot.{field}: substitution")
    verify_document_seal(value, "receipt_digest")


def verify_role_bindings(
    physical: dict[str, Any],
    provisioning: dict[str, dict[str, Any]],
    digests: dict[str, str],
) -> None:
    for role, verified in provisioning.items():
        physical_role = physical["roles"][role]
        if physical_role["provisioning_evidence_sha256"] != digests[f"{role}_provisioning_evidence"]:
            raise EvidenceError(f"physical.roles.{role}.provisioning_evidence_sha256: mismatch")
        for field in (
            "generation",
            "provider",
            "export_policy",
            "public_key_digest",
            "receipt_digest",
            "evidence_digest",
        ):
            if physical_role.get(field) != verified.get(field):
                raise EvidenceError(f"physical.roles.{role}.{field}: provisioning mismatch")


def make_gate_summary(
    physical_path: Path,
    governance_path: Path,
    installation_path: Path,
    recovery_path: Path,
    capability_provisioning_path: Path,
    attestation_provisioning_path: Path,
) -> tuple[dict[str, Any], int]:
    paths = {
        "physical_tpm_evidence": physical_path,
        "governance_recovery_receipt": governance_path,
        "installation_receipt": installation_path,
        "recovery_receipt": recovery_path,
        "capability_provisioning_evidence": capability_provisioning_path,
        "attestation_provisioning_evidence": attestation_provisioning_path,
    }
    missing = [name for name, path in paths.items() if not path.is_file()]
    if missing:
        return (
            {
                "schema_version": GATE_SCHEMA,
                "hardware_operational_gate": UNKNOWN,
                "hardware_operational_eligible": False,
                "blockers": [f"missing:{name}" for name in sorted(missing)],
                "evidence_digests": {},
            },
            2,
        )
    physical = load_json(physical_path)
    governance = load_json(governance_path)
    installation = load_json(installation_path)
    recovery = load_json(recovery_path)
    provisioning = {
        "capability": verify_provisioning_evidence(load_json(capability_provisioning_path), "capability"),
        "attestation": verify_provisioning_evidence(load_json(attestation_provisioning_path), "attestation"),
    }
    verify_physical_evidence(physical)
    verify_governance_receipt(governance)
    verify_installation_binding(installation, physical, provisioning)
    verify_recovery_binding(recovery, installation, physical, provisioning)
    digests = {name: sha256_file(path) for name, path in paths.items()}
    verify_role_bindings(physical, provisioning, digests)
    if physical["governance_recovery_receipt_sha256"] != digests["governance_recovery_receipt"]:
        raise EvidenceError("physical.governance_recovery_receipt_sha256: binding mismatch")
    governance_role = governance["role"].lower()
    promoted_role = physical["roles"][governance_role]
    if governance["replacement_public_key_digest"] != promoted_role["public_key_digest"]:
        raise EvidenceError("governance.replacement_public_key_digest: promoted key mismatch")
    if governance["replacement_generation"] != promoted_role["generation"]:
        raise EvidenceError("governance.replacement_generation: promoted generation mismatch")
    if governance["replacement_provisioning_evidence_sha256"] != promoted_role["provisioning_evidence_sha256"]:
        raise EvidenceError("governance.replacement_provisioning_evidence_sha256: promoted evidence mismatch")
    if physical["installation_receipt_sha256"] != digests["installation_receipt"]:
        raise EvidenceError("physical.installation_receipt_sha256: binding mismatch")
    if physical["recovery_receipt_sha256"] != digests["recovery_receipt"]:
        raise EvidenceError("physical.recovery_receipt_sha256: binding mismatch")
    return (
        {
            "schema_version": GATE_SCHEMA,
            "hardware_operational_gate": PROVEN,
            "hardware_operational_eligible": True,
            "blockers": [],
            "ceremony_id": physical["ceremony_id"],
            "machine_identity_digest": physical["machine_identity_digest"],
            "evidence_digests": dict(sorted(digests.items())),
        },
        0,
    )


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )


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
        summary, code = make_gate_summary(
            args.physical,
            args.governance,
            args.installation,
            args.recovery,
            args.capability_provisioning,
            args.attestation_provisioning,
        )
    except EvidenceError as exc:
        summary = {
            "schema_version": GATE_SCHEMA,
            "hardware_operational_gate": UNKNOWN,
            "hardware_operational_eligible": False,
            "blockers": [f"invalid:{exc}"],
            "evidence_digests": {},
        }
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
    verify.add_argument("--capability-provisioning", type=Path, required=True)
    verify.add_argument("--attestation-provisioning", type=Path, required=True)
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

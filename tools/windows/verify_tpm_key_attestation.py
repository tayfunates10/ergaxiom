#!/usr/bin/env python3
"""Fail-closed TPM production-key attestation verifier.

Production trust anchors are repository-pinned. Caller supplied roots and
self-asserted verification flags are rejected. A structural controlled trust
PASS is intentionally not consumed as hardware-origin proof.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
POLICY_PATH = ROOT / "tools/windows/tpm_key_attestation_policy.json"
SCHEMA = "0.1.0"
TPM_GENERATED_VALUE = 0xFF544347
TPM_ST_ATTEST_CERTIFY = 0x8017
TPM_ALG_ECC = 0x0023
TPM_ALG_SHA256 = 0x000B
TPM_ALG_NULL = 0x0010
ATTR_FIXED_TPM = 1 << 1
ATTR_FIXED_PARENT = 1 << 4
ATTR_SENSITIVE_DATA_ORIGIN = 1 << 5
ATTR_SIGN_ENCRYPT = 1 << 18


class AttestationError(ValueError):
    pass


def _b64u(value: Any, field: str) -> bytes:
    if not isinstance(value, str) or not value or "=" in value:
        raise AttestationError(f"{field}: invalid canonical base64url")
    try:
        return base64.urlsafe_b64decode(value + "=" * ((4 - len(value) % 4) % 4))
    except Exception as exc:
        raise AttestationError(f"{field}: invalid base64url") from exc


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise AttestationError(f"{path}: invalid JSON") from exc
    if not isinstance(value, dict):
        raise AttestationError(f"{path}: top-level object required")
    return value


def load_pinned_policy() -> dict[str, Any]:
    policy = _load_json(POLICY_PATH)
    if policy.get("schema_version") != SCHEMA:
        raise AttestationError("TPM_ATTESTATION_POLICY_SCHEMA_REJECTED")
    trust = policy.get("trust_model")
    if not isinstance(trust, dict):
        raise AttestationError("TPM_ATTESTATION_TRUST_MODEL_MISSING")
    if trust.get("caller_supplied_trust_roots_allowed") is not False:
        raise AttestationError("CALLER_SUPPLIED_TRUST_ROOTS_POLICY_REJECTED")
    if trust.get("self_asserted_verification_flags_allowed") is not False:
        raise AttestationError("SELF_ASSERTED_VERIFICATION_POLICY_REJECTED")
    return policy


def reject_untrusted_claims(value: Any, path: str = "$") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            lowered = key.lower()
            if lowered in {"trust_roots", "trusted_roots", "manufacturer_roots", "root_certificates"}:
                raise AttestationError(f"{path}.{key}: caller-supplied trust roots forbidden")
            if lowered in {"verified", "hardware_verified", "tpm_verified", "attestation_verified"}:
                raise AttestationError(f"{path}.{key}: self-asserted verification flag forbidden")
            reject_untrusted_claims(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            reject_untrusted_claims(child, f"{path}[{index}]")


def _read_u16(data: bytes, offset: int) -> tuple[int, int]:
    if offset + 2 > len(data):
        raise AttestationError("TPM_STRUCTURE_TRUNCATED")
    return int.from_bytes(data[offset:offset + 2], "big"), offset + 2


def _read_u32(data: bytes, offset: int) -> tuple[int, int]:
    if offset + 4 > len(data):
        raise AttestationError("TPM_STRUCTURE_TRUNCATED")
    return int.from_bytes(data[offset:offset + 4], "big"), offset + 4


def _read_tpm2b(data: bytes, offset: int) -> tuple[bytes, int]:
    size, offset = _read_u16(data, offset)
    end = offset + size
    if end > len(data):
        raise AttestationError("TPM2B_TRUNCATED")
    return data[offset:end], end


def parse_ecc_public_area(public_area: bytes) -> tuple[bytes, int, bytes]:
    offset = 0
    object_type, offset = _read_u16(public_area, offset)
    name_alg, offset = _read_u16(public_area, offset)
    attrs, offset = _read_u32(public_area, offset)
    _, offset = _read_tpm2b(public_area, offset)
    if object_type != TPM_ALG_ECC or name_alg != TPM_ALG_SHA256:
        raise AttestationError("TPM_PUBLIC_ALGORITHM_REJECTED")

    symmetric, offset = _read_u16(public_area, offset)
    if symmetric != TPM_ALG_NULL:
        _, offset = _read_u16(public_area, offset)
        _, offset = _read_u16(public_area, offset)
    scheme, offset = _read_u16(public_area, offset)
    if scheme != TPM_ALG_NULL:
        _, offset = _read_u16(public_area, offset)
    _, offset = _read_u16(public_area, offset)
    kdf, offset = _read_u16(public_area, offset)
    if kdf != TPM_ALG_NULL:
        _, offset = _read_u16(public_area, offset)
    x, offset = _read_tpm2b(public_area, offset)
    y, offset = _read_tpm2b(public_area, offset)
    if offset != len(public_area) or len(x) != 32 or len(y) != 32:
        raise AttestationError("TPM_ECC_UNIQUE_REJECTED")
    sec1 = b"\x04" + x + y
    name = TPM_ALG_SHA256.to_bytes(2, "big") + hashlib.sha256(public_area).digest()
    return sec1, attrs, name


def parse_certify_attestation(attest: bytes) -> tuple[bytes, bytes]:
    offset = 0
    magic, offset = _read_u32(attest, offset)
    tag, offset = _read_u16(attest, offset)
    if magic != TPM_GENERATED_VALUE or tag != TPM_ST_ATTEST_CERTIFY:
        raise AttestationError("TPM_CERTIFY_ATTESTATION_HEADER_REJECTED")
    _, offset = _read_tpm2b(attest, offset)
    extra, offset = _read_tpm2b(attest, offset)
    if offset + 17 + 8 > len(attest):
        raise AttestationError("TPM_CERTIFY_ATTESTATION_TRUNCATED")
    offset += 17 + 8
    object_name, offset = _read_tpm2b(attest, offset)
    _, offset = _read_tpm2b(attest, offset)
    if offset != len(attest):
        raise AttestationError("TPM_CERTIFY_ATTESTATION_TRAILING_DATA")
    return extra, object_name


def _p1363_to_der(signature: bytes) -> bytes:
    if len(signature) != 64:
        raise AttestationError("TPM_CERTIFY_SIGNATURE_LENGTH_REJECTED")

    def integer(raw: bytes) -> bytes:
        raw = raw.lstrip(b"\0") or b"\0"
        if raw[0] & 0x80:
            raw = b"\0" + raw
        return b"\x02" + bytes([len(raw)]) + raw

    body = integer(signature[:32]) + integer(signature[32:])
    return b"\x30" + bytes([len(body)]) + body


def _run_openssl(args: list[str], *, data: bytes | None = None) -> bytes:
    try:
        completed = subprocess.run(["openssl", *args], input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    except OSError as exc:
        raise AttestationError("OPENSSL_REQUIRED_FOR_TPM_ATTESTATION") from exc
    if completed.returncode != 0:
        raise AttestationError("TPM_ATTESTATION_CRYPTOGRAPHIC_VERIFICATION_FAILED")
    return completed.stdout


def verify_cert_chain(chain: list[str], pinned_roots: list[Path]) -> bytes:
    if not chain or not pinned_roots:
        raise AttestationError("TPM_MANUFACTURER_TRUST_ROOTS_NOT_PINNED")
    with tempfile.TemporaryDirectory() as temp:
        base = Path(temp)
        leaf = base / "leaf.pem"
        leaf.write_text(chain[0], encoding="ascii")
        roots = base / "roots.pem"
        roots.write_text("\n".join(path.read_text(encoding="ascii") for path in pinned_roots), encoding="ascii")
        args = ["verify", "-CAfile", str(roots)]
        if len(chain) > 1:
            inter = base / "intermediates.pem"
            inter.write_text("\n".join(chain[1:]), encoding="ascii")
            args += ["-untrusted", str(inter)]
        args.append(str(leaf))
        _run_openssl(args)
        return _run_openssl(["x509", "-in", str(leaf), "-pubkey", "-noout"])


def pinned_root_paths(policy: dict[str, Any]) -> list[Path]:
    trust = policy["trust_model"]
    allow = trust.get("manufacturer_root_sha256_allowlist")
    files = trust.get("manufacturer_root_files", {})
    if not isinstance(allow, list) or not allow:
        raise AttestationError(policy.get("blocking_reason", "TPM_MANUFACTURER_TRUST_ROOTS_NOT_PINNED"))
    if not isinstance(files, dict):
        raise AttestationError("TPM_MANUFACTURER_ROOT_FILE_MAP_REJECTED")
    result: list[Path] = []
    for digest in allow:
        rel = files.get(digest)
        if not isinstance(digest, str) or not isinstance(rel, str):
            raise AttestationError("TPM_MANUFACTURER_ROOT_PIN_REJECTED")
        path = (ROOT / rel).resolve()
        if ROOT.resolve() not in path.parents or not path.is_file():
            raise AttestationError("TPM_MANUFACTURER_ROOT_PATH_REJECTED")
        der = _run_openssl(["x509", "-in", str(path), "-outform", "DER"])
        if _sha256(der) != digest:
            raise AttestationError("TPM_MANUFACTURER_ROOT_DIGEST_MISMATCH")
        result.append(path)
    return result


def verify_role(role: str, item: dict[str, Any], expected_digest: str, ak_public_key_pem: bytes, policy: dict[str, Any]) -> None:
    if item.get("key_origin") == "software":
        raise AttestationError(f"{role}: SOFTWARE_GENERATED_KEY_FORBIDDEN")
    if item.get("public_key_digest") != expected_digest:
        raise AttestationError(f"{role}: PUBLIC_KEY_DIGEST_MISMATCH")

    public_area = _b64u(item.get("tpm_public_area_base64url"), f"{role}.tpm_public_area_base64url")
    sec1, attrs, object_name = parse_ecc_public_area(public_area)
    required_attrs = ATTR_FIXED_TPM | ATTR_FIXED_PARENT | ATTR_SENSITIVE_DATA_ORIGIN | ATTR_SIGN_ENCRYPT
    if attrs & required_attrs != required_attrs:
        raise AttestationError(f"{role}: TPM_OBJECT_ATTRIBUTES_REJECTED")
    if _sha256(sec1) != expected_digest:
        raise AttestationError(f"{role}: TPM_PUBLIC_KEY_DIGEST_MISMATCH")

    attest = _b64u(item.get("certify_attestation_base64url"), f"{role}.certify_attestation_base64url")
    extra, certified_name = parse_certify_attestation(attest)
    expected_extra = hashlib.sha256(b"ergaxiom.tpm-key-certify.v1\0" + role.encode("ascii") + bytes.fromhex(expected_digest)).digest()
    if extra != expected_extra or certified_name != object_name:
        raise AttestationError(f"{role}: TPM_CERTIFY_BINDING_MISMATCH")

    signature = _p1363_to_der(_b64u(item.get("certify_signature_p1363_base64url"), f"{role}.certify_signature"))
    with tempfile.TemporaryDirectory() as temp:
        pub = Path(temp) / "ak.pub.pem"
        sig = Path(temp) / "sig.der"
        msg = Path(temp) / "attest.bin"
        pub.write_bytes(ak_public_key_pem)
        sig.write_bytes(signature)
        msg.write_bytes(attest)
        _run_openssl(["dgst", "-sha256", "-verify", str(pub), "-signature", str(sig), str(msg)])


def provisioning_digest(path: Path, role: str) -> str:
    value = _load_json(path)
    receipt = value.get("receipt")
    if not isinstance(receipt, dict):
        raise AttestationError(f"{role}: provisioning receipt missing")
    digest = receipt.get("public_key_digest")
    if not isinstance(digest, str) or len(digest) != 64:
        raise AttestationError(f"{role}: provisioning public key digest rejected")
    return digest


def verify_ek_ak_binding(bundle: dict[str, Any], ek_public_key_pem: bytes, ak_public_key_pem: bytes) -> None:
    """Require a cryptographic EK->AK same-TPM proof before any production acceptance.

    Independent validation of an EK certificate chain and an AK certificate chain does not
    establish that the AK belongs to the same physical TPM as the EK. Only the reserved
    TPM2 ActivateCredential contract is structurally recognized here, and even a correctly
    shaped claim remains rejected until a repository-grounded transcript verifier exists.
    """
    binding = bundle.get("ek_ak_binding")
    if not isinstance(binding, dict):
        raise AttestationError("TPM_EK_AK_BINDING_REQUIRED")

    # Define the narrow future evidence identity contract without treating it as proof.
    # These digests bind a future credential-activation transcript to the exact EK/AK
    # certificate public keys already validated against repository-pinned roots.
    if binding.get("type") != "tpm2_activatecredential_v1":
        raise AttestationError("TPM_EK_AK_BINDING_TYPE_REJECTED")
    if binding.get("ek_public_key_digest") != _sha256(ek_public_key_pem):
        raise AttestationError("TPM_EK_AK_BINDING_EK_DIGEST_MISMATCH")
    if binding.get("ak_public_key_digest") != _sha256(ak_public_key_pem):
        raise AttestationError("TPM_EK_AK_BINDING_AK_DIGEST_MISMATCH")

    # No permissive fallback: matching identity claims are still not cryptographic
    # same-TPM evidence. A real TPM2 MakeCredential/ActivateCredential transcript
    # verifier must land before this boundary may return success.
    raise AttestationError("TPM_EK_AK_BINDING_NOT_VERIFIED")


def verify(bundle: dict[str, Any], capability_path: Path, attestation_path: Path) -> dict[str, Any]:
    reject_untrusted_claims(bundle)
    policy = load_pinned_policy()
    roots = pinned_root_paths(policy)
    if bundle.get("schema_version") != SCHEMA:
        raise AttestationError("TPM_KEY_ATTESTATION_SCHEMA_REJECTED")
    ek_chain = bundle.get("ek_certificate_chain_pem")
    ak_chain = bundle.get("ak_certificate_chain_pem")
    roles = bundle.get("roles")
    if not isinstance(ek_chain, list) or not all(isinstance(x, str) for x in ek_chain):
        raise AttestationError("EK_CERTIFICATE_CHAIN_REQUIRED")
    if not isinstance(ak_chain, list) or not all(isinstance(x, str) for x in ak_chain):
        raise AttestationError("AK_CERTIFICATE_CHAIN_REQUIRED")
    if not isinstance(roles, dict):
        raise AttestationError("TPM_KEY_ATTESTATION_ROLES_REQUIRED")

    ek_public_key_pem = verify_cert_chain(ek_chain, roots)
    ak_public_key_pem = verify_cert_chain(ak_chain, roots)
    verify_ek_ak_binding(bundle, ek_public_key_pem, ak_public_key_pem)
    expected = {
        "capability": provisioning_digest(capability_path, "capability"),
        "attestation": provisioning_digest(attestation_path, "attestation"),
    }
    for role in policy["key_certification"]["required_roles"]:
        item = roles.get(role)
        if not isinstance(item, dict):
            raise AttestationError(f"{role}: TPM key certification required")
        verify_role(role, item, expected[role], ak_public_key_pem, policy)

    return {
        "schema_version": SCHEMA,
        "verified": True,
        "gate": "TPM_PRODUCTION_KEY_ATTESTATION_VERIFIED",
        "policy_id": policy["policy_id"],
        "public_key_digests": expected,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--capability-provisioning", required=True, type=Path)
    parser.add_argument("--attestation-provisioning", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        result = verify(_load_json(args.evidence), args.capability_provisioning, args.attestation_provisioning)
    except AttestationError as exc:
        print(f"TPM_KEY_ATTESTATION_REJECTED: {exc}")
        return 2
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

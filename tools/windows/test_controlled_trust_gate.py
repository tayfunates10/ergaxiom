from __future__ import annotations

import base64
import hashlib
import importlib.util
import sys
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("controlled_trust_gate.py")
SPEC = importlib.util.spec_from_file_location("controlled_trust_gate", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("controlled trust gate could not be loaded")
GATE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = GATE
SPEC.loader.exec_module(GATE)


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def sign_fixture_prehash(digest_hex: str, private_key: int = 1, nonce: int = 2) -> bytes:
    point = GATE.p256_mul(nonce, GATE.P256_G)
    if point is None:
        raise RuntimeError("fixture nonce produced infinity")
    r = point[0] % GATE.P256_N
    z = int(digest_hex, 16)
    s = (pow(nonce, -1, GATE.P256_N) * (z + r * private_key)) % GATE.P256_N
    if r == 0 or s == 0:
        raise RuntimeError("fixture signature scalar is zero")
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def fixture_provisioning(role: str = "capability", generation: int = 1) -> dict[str, object]:
    identity = GATE.ROLE_IDENTITIES[role]
    policy = GATE.production_policy(role)
    policy_digest = GATE.sha256_bytes(GATE.canonical_bytes(policy))
    public_point = GATE.P256_G  # private fixture scalar = 1
    public_key = b"\x04" + public_point[0].to_bytes(32, "big") + public_point[1].to_bytes(32, "big")
    public_key_digest = hashlib.sha256(public_key).hexdigest()
    receipt: dict[str, object] = {
        "schema_version": GATE.PROVISIONING_SCHEMA,
        "identity": identity,
        "provider": GATE.PLATFORM_PROVIDER,
        "algorithm": GATE.ALGORITHM,
        "public_key_encoding": GATE.PUBLIC_ENCODING,
        "public_key_base64url": b64url(public_key),
        "public_key_digest": public_key_digest,
        "signature_encoding": GATE.SIGNATURE_ENCODING,
        "export_policy": GATE.EXPORT_POLICY,
        "provider_implementation_flags": 1,
        "assurance": "UNPROVEN",
        "policy_digest": policy_digest,
        "provisioned_at_epoch_s": 100,
        "receipt_digest": "",
    }
    receipt = GATE.seal_document(receipt, "receipt_digest")
    statement: dict[str, object] = {
        "schema_version": GATE.PROVISIONING_SCHEMA,
        "domain": "ergaxiom.windows-production-signer.provisioning.v1",
        "identity": identity,
        "generation": generation,
        "receipt_digest": receipt["receipt_digest"],
        "key_name_digest": hashlib.sha256(GATE.key_name_for(role, generation).encode("utf-8")).hexdigest(),
        "public_key_digest": public_key_digest,
        "policy_digest": policy_digest,
        "created": True,
    }
    statement_digest = GATE.sha256_bytes(GATE.canonical_bytes(statement))
    possession = {
        "digest_algorithm": "sha256",
        "digest": statement_digest,
        "signature_encoding": GATE.SIGNATURE_ENCODING,
        "signature_base64url": b64url(sign_fixture_prehash(statement_digest)),
        "public_key_digest": public_key_digest,
        "key_policy_digest": policy_digest,
    }
    evidence: dict[str, object] = {
        "schema_version": GATE.PROVISIONING_SCHEMA,
        "statement": statement,
        "receipt": receipt,
        "key_possession": possession,
        "evidence_digest": "",
    }
    return GATE.seal_document(evidence, "evidence_digest")


class ControlledTrustGateTests(unittest.TestCase):
    def test_platform_neutral_key_possession_verification(self) -> None:
        evidence = fixture_provisioning()
        verified = GATE.verify_provisioning_evidence(evidence, "capability")
        self.assertEqual(1, verified["generation"])
        self.assertEqual(evidence["receipt"]["public_key_digest"], verified["public_key_digest"])

    def test_mutated_key_possession_signature_is_rejected(self) -> None:
        evidence = fixture_provisioning()
        possession = dict(evidence["key_possession"])
        signature = bytearray(GATE.decode_base64url(possession["signature_base64url"], "fixture"))
        signature[-1] ^= 1
        possession["signature_base64url"] = b64url(bytes(signature))
        evidence["key_possession"] = possession
        evidence = GATE.seal_document(evidence, "evidence_digest")
        with self.assertRaises(GATE.EvidenceError):
            GATE.verify_provisioning_evidence(evidence, "capability")

    def test_provisioning_cannot_self_promote_hardware_assurance(self) -> None:
        evidence = fixture_provisioning()
        receipt = dict(evidence["receipt"])
        receipt["assurance"] = GATE.PROVEN
        receipt = GATE.seal_document(receipt, "receipt_digest")
        evidence["receipt"] = receipt
        statement = dict(evidence["statement"])
        statement["receipt_digest"] = receipt["receipt_digest"]
        evidence["statement"] = statement
        evidence = GATE.seal_document(evidence, "evidence_digest")
        with self.assertRaises(GATE.EvidenceError):
            GATE.verify_provisioning_evidence(evidence, "capability")

    def test_generation_is_bound_into_cng_key_name(self) -> None:
        evidence = fixture_provisioning(generation=7)
        verified = GATE.verify_provisioning_evidence(evidence, "capability")
        self.assertEqual(7, verified["generation"])
        statement = dict(evidence["statement"])
        statement["key_name_digest"] = "0" * 64
        evidence["statement"] = statement
        evidence = GATE.seal_document(evidence, "evidence_digest")
        with self.assertRaises(GATE.EvidenceError):
            GATE.verify_provisioning_evidence(evidence, "capability")


if __name__ == "__main__":
    unittest.main()

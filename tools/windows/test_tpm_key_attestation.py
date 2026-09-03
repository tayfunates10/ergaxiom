#!/usr/bin/env python3
"""Negative regressions for the production TPM key-attestation boundary."""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import tempfile
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("verify_tpm_key_attestation.py")
SPEC = importlib.util.spec_from_file_location("verify_tpm_key_attestation", MODULE_PATH)
assert SPEC and SPEC.loader
mod = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mod)


def b64u(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def ecc_public_area(x: bytes, y: bytes, attrs: int) -> bytes:
    return b"".join(
        [
            mod.TPM_ALG_ECC.to_bytes(2, "big"),
            mod.TPM_ALG_SHA256.to_bytes(2, "big"),
            attrs.to_bytes(4, "big"),
            b"\x00\x00",  # authPolicy
            mod.TPM_ALG_NULL.to_bytes(2, "big"),  # symmetric
            mod.TPM_ALG_NULL.to_bytes(2, "big"),  # scheme
            b"\x00\x03",  # curveID: NIST P-256
            mod.TPM_ALG_NULL.to_bytes(2, "big"),  # kdf
            len(x).to_bytes(2, "big"),
            x,
            len(y).to_bytes(2, "big"),
            y,
        ]
    )


def certify_attestation(role: str, digest: str, object_name: bytes) -> bytes:
    extra = hashlib.sha256(
        b"ergaxiom.tpm-key-certify.v1\0" + role.encode("ascii") + bytes.fromhex(digest)
    ).digest()
    return b"".join(
        [
            mod.TPM_GENERATED_VALUE.to_bytes(4, "big"),
            mod.TPM_ST_ATTEST_CERTIFY.to_bytes(2, "big"),
            b"\x00\x00",  # qualifiedSigner
            len(extra).to_bytes(2, "big"),
            extra,
            b"\x00" * 17,  # clockInfo
            b"\x00" * 8,  # firmwareVersion
            len(object_name).to_bytes(2, "big"),
            object_name,
            b"\x00\x00",  # qualifiedName
        ]
    )


def der_ecdsa_to_p1363(signature: bytes) -> bytes:
    if len(signature) < 8 or signature[0] != 0x30:
        raise AssertionError("unexpected DER ECDSA signature")
    offset = 2
    if signature[offset] != 0x02:
        raise AssertionError("missing DER r")
    r_len = signature[offset + 1]
    r = signature[offset + 2:offset + 2 + r_len]
    offset += 2 + r_len
    if signature[offset] != 0x02:
        raise AssertionError("missing DER s")
    s_len = signature[offset + 1]
    s = signature[offset + 2:offset + 2 + s_len]
    r = r.lstrip(b"\x00").rjust(32, b"\x00")
    s = s.lstrip(b"\x00").rjust(32, b"\x00")
    if len(r) != 32 or len(s) != 32:
        raise AssertionError("unexpected P-256 ECDSA integer size")
    return r + s


class TpmKeyAttestationFailClosedTests(unittest.TestCase):
    def test_repository_policy_is_unconfigured_and_fail_closed(self) -> None:
        policy = mod.load_pinned_policy()
        self.assertEqual(policy["status"], "UNCONFIGURED_FAIL_CLOSED")
        self.assertFalse(policy["trust_model"]["caller_supplied_trust_roots_allowed"])
        self.assertFalse(policy["trust_model"]["self_asserted_verification_flags_allowed"])
        with self.assertRaisesRegex(mod.AttestationError, "TPM_MANUFACTURER_TRUST_ROOTS_NOT_PINNED"):
            mod.pinned_root_paths(policy)

    def test_caller_supplied_trust_roots_are_rejected(self) -> None:
        with self.assertRaisesRegex(mod.AttestationError, "caller-supplied trust roots forbidden"):
            mod.reject_untrusted_claims({"nested": {"trust_roots": ["forged-root"]}})

    def test_self_asserted_verified_flag_is_rejected(self) -> None:
        with self.assertRaisesRegex(mod.AttestationError, "self-asserted verification flag forbidden"):
            mod.reject_untrusted_claims({"attestation": {"verified": True}})

    def test_software_generated_p256_is_rejected_before_crypto(self) -> None:
        policy = mod.load_pinned_policy()
        with self.assertRaisesRegex(mod.AttestationError, "SOFTWARE_GENERATED_KEY_FORBIDDEN"):
            mod.verify_role("capability", {"key_origin": "software", "public_key_digest": "0" * 64}, "0" * 64, b"", policy)

    def test_uploaded_forge_shape_cannot_self_assert_hardware_origin(self) -> None:
        policy = mod.load_pinned_policy()
        forged = {
            "key_origin": "software",
            "public_key_digest": "a" * 64,
            "tpm_public_area_base64url": b64u(b"software-p256-is-not-a-tpm-public-area"),
            "certify_attestation_base64url": b64u(b"self-consistent-local-claim"),
            "certify_signature_p1363_base64url": b64u(b"\x01" * 64),
        }
        with self.assertRaisesRegex(mod.AttestationError, "SOFTWARE_GENERATED_KEY_FORBIDDEN"):
            mod.verify_role("capability", forged, "a" * 64, b"", policy)

    def test_wrong_public_key_digest_fails_closed(self) -> None:
        policy = mod.load_pinned_policy()
        with self.assertRaisesRegex(mod.AttestationError, "PUBLIC_KEY_DIGEST_MISMATCH"):
            mod.verify_role("attestation", {"key_origin": "tpm", "public_key_digest": "1" * 64}, "2" * 64, b"", policy)

    def test_tpm_public_area_must_match_provisioned_key_digest(self) -> None:
        policy = mod.load_pinned_policy()
        attrs = mod.ATTR_FIXED_TPM | mod.ATTR_FIXED_PARENT | mod.ATTR_SENSITIVE_DATA_ORIGIN | mod.ATTR_SIGN_ENCRYPT
        area = ecc_public_area(b"\x11" * 32, b"\x22" * 32, attrs)
        claimed_digest = hashlib.sha256(b"\x04" + b"\x33" * 32 + b"\x44" * 32).hexdigest()
        item = {
            "key_origin": "tpm",
            "public_key_digest": claimed_digest,
            "tpm_public_area_base64url": b64u(area),
        }
        with self.assertRaisesRegex(mod.AttestationError, "TPM_PUBLIC_KEY_DIGEST_MISMATCH"):
            mod.verify_role("capability", item, claimed_digest, b"", policy)

    def test_required_non_exportable_tpm_attributes_are_enforced(self) -> None:
        policy = mod.load_pinned_policy()
        attrs = mod.ATTR_SIGN_ENCRYPT  # deliberately omits fixedTPM/fixedParent/sensitiveDataOrigin
        x = b"\x55" * 32
        y = b"\x66" * 32
        area = ecc_public_area(x, y, attrs)
        digest = hashlib.sha256(b"\x04" + x + y).hexdigest()
        item = {
            "key_origin": "tpm",
            "public_key_digest": digest,
            "tpm_public_area_base64url": b64u(area),
        }
        with self.assertRaisesRegex(mod.AttestationError, "TPM_OBJECT_ATTRIBUTES_REJECTED"):
            mod.verify_role("attestation", item, digest, b"", policy)

    def test_mutated_certify_header_is_rejected(self) -> None:
        with self.assertRaisesRegex(mod.AttestationError, "TPM_CERTIFY_ATTESTATION_HEADER_REJECTED"):
            mod.parse_certify_attestation(b"\x00\x00\x00\x00\x80\x17")

    def test_certify_trailing_data_is_rejected(self) -> None:
        attest = b"".join(
            [
                mod.TPM_GENERATED_VALUE.to_bytes(4, "big"),
                mod.TPM_ST_ATTEST_CERTIFY.to_bytes(2, "big"),
                b"\x00\x00",  # qualifiedSigner
                b"\x00\x00",  # extraData
                b"\x00" * 25,  # clockInfo + firmwareVersion
                b"\x00\x00",  # certified name
                b"\x00\x00",  # qualified name
                b"\xff",       # forbidden trailing mutation
            ]
        )
        with self.assertRaisesRegex(mod.AttestationError, "TPM_CERTIFY_ATTESTATION_TRAILING_DATA"):
            mod.parse_certify_attestation(attest)

    def test_mutated_certify_signature_shape_is_rejected(self) -> None:
        with self.assertRaisesRegex(mod.AttestationError, "TPM_CERTIFY_SIGNATURE_LENGTH_REJECTED"):
            mod._p1363_to_der(b"\x01" * 63)

    def test_cryptographically_mutated_certify_signature_is_rejected(self) -> None:
        policy = mod.load_pinned_policy()
        attrs = mod.ATTR_FIXED_TPM | mod.ATTR_FIXED_PARENT | mod.ATTR_SENSITIVE_DATA_ORIGIN | mod.ATTR_SIGN_ENCRYPT
        x = b"\x77" * 32
        y = b"\x88" * 32
        area = ecc_public_area(x, y, attrs)
        digest = hashlib.sha256(b"\x04" + x + y).hexdigest()
        _, _, object_name = mod.parse_ecc_public_area(area)
        attest = certify_attestation("capability", digest, object_name)

        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            key = base / "ak.key.pem"
            pub = base / "ak.pub.pem"
            msg = base / "attest.bin"
            sig = base / "sig.der"
            mod._run_openssl(["ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(key)])
            mod._run_openssl(["pkey", "-in", str(key), "-pubout", "-out", str(pub)])
            msg.write_bytes(attest)
            mod._run_openssl(["dgst", "-sha256", "-sign", str(key), "-out", str(sig), str(msg)])
            p1363 = bytearray(der_ecdsa_to_p1363(sig.read_bytes()))
            p1363[-1] ^= 0x01
            item = {
                "key_origin": "tpm",
                "public_key_digest": digest,
                "tpm_public_area_base64url": b64u(area),
                "certify_attestation_base64url": b64u(attest),
                "certify_signature_p1363_base64url": b64u(bytes(p1363)),
            }
            with self.assertRaisesRegex(mod.AttestationError, "TPM_ATTESTATION_CRYPTOGRAPHIC_VERIFICATION_FAILED"):
                mod.verify_role("capability", item, digest, pub.read_bytes(), policy)

    def test_forged_ak_certificate_chain_is_rejected_cryptographically(self) -> None:
        forged_cert = "-----BEGIN CERTIFICATE-----\nZm9yZ2Vk\n-----END CERTIFICATE-----\n"
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "root.pem"
            root.write_text(forged_cert, encoding="ascii")
            with self.assertRaisesRegex(mod.AttestationError, "TPM_ATTESTATION_CRYPTOGRAPHIC_VERIFICATION_FAILED"):
                mod.verify_cert_chain([forged_cert], [root])

    def test_truncated_public_area_is_rejected(self) -> None:
        with self.assertRaisesRegex(mod.AttestationError, "TPM_STRUCTURE_TRUNCATED"):
            mod.parse_ecc_public_area(b"\x00\x23")


if __name__ == "__main__":
    unittest.main()

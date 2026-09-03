#!/usr/bin/env python3
"""Negative regressions for the production TPM key-attestation boundary."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("verify_tpm_key_attestation.py")
SPEC = importlib.util.spec_from_file_location("verify_tpm_key_attestation", MODULE_PATH)
assert SPEC and SPEC.loader
mod = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mod)


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

    def test_wrong_public_key_digest_fails_closed(self) -> None:
        policy = mod.load_pinned_policy()
        with self.assertRaisesRegex(mod.AttestationError, "PUBLIC_KEY_DIGEST_MISMATCH"):
            mod.verify_role("attestation", {"key_origin": "tpm", "public_key_digest": "1" * 64}, "2" * 64, b"", policy)

    def test_mutated_certify_header_is_rejected(self) -> None:
        with self.assertRaisesRegex(mod.AttestationError, "TPM_CERTIFY_ATTESTATION_HEADER_REJECTED"):
            mod.parse_certify_attestation(b"\x00\x00\x00\x00\x80\x17")

    def test_truncated_public_area_is_rejected(self) -> None:
        with self.assertRaisesRegex(mod.AttestationError, "TPM_STRUCTURE_TRUNCATED"):
            mod.parse_ecc_public_area(b"\x00\x23")


if __name__ == "__main__":
    unittest.main()

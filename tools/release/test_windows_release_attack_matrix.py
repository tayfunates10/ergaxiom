from __future__ import annotations

import unittest

from tools.release import finalize_windows_release_evidence as release
from tools.release.test_finalize_windows_release_evidence import base, gate, lic, life, policy, sig


class WindowsReleaseAttackMatrixTests(unittest.TestCase):
    def finalize(self, *, signature=None, lifecycle=None):
        candidate = base()
        release_policy = policy()
        return release.build(
            candidate,
            release_policy,
            signature,
            lifecycle,
            gate("production_chain"),
            gate("hardware_operational"),
            lic(),
        )

    def test_unsigned_candidate_is_rejected(self) -> None:
        result = self.finalize(signature=None, lifecycle=life())
        self.assertFalse(result["release_eligible"])
        self.assertIn("AUTHENTICODE_NOT_VERIFIED", result["blocking_reasons"])

    def test_partially_signed_inventory_is_rejected(self) -> None:
        release_policy = policy()
        evidence = sig(release_policy)
        evidence["artifacts"].pop()
        with self.assertRaises(release.ReleaseError):
            release.build(
                base(),
                release_policy,
                evidence,
                life(),
                gate("production_chain"),
                gate("hardware_operational"),
                lic(),
            )

    def test_self_signed_identity_is_rejected(self) -> None:
        release_policy = policy()
        evidence = sig(release_policy)
        evidence["artifacts"][0]["self_signed"] = True
        result = release.build(base(), release_policy, evidence, life(), gate("production_chain"), gate("hardware_operational"), lic())
        self.assertFalse(result["release_eligible"])

    def test_missing_online_revocation_check_is_rejected(self) -> None:
        release_policy = policy()
        evidence = sig(release_policy)
        evidence["artifacts"][0]["revocation_checked_online"] = False
        result = release.build(base(), release_policy, evidence, life(), gate("production_chain"), gate("hardware_operational"), lic())
        self.assertFalse(result["release_eligible"])

    def test_untrusted_or_revoked_chain_is_rejected(self) -> None:
        release_policy = policy()
        evidence = sig(release_policy)
        evidence["artifacts"][0]["certificate_chain_valid"] = False
        result = release.build(base(), release_policy, evidence, life(), gate("production_chain"), gate("hardware_operational"), lic())
        self.assertFalse(result["release_eligible"])

    def test_missing_or_untrusted_timestamp_is_rejected(self) -> None:
        for field in ("timestamp_present", "timestamp_chain_valid"):
            release_policy = policy()
            evidence = sig(release_policy)
            evidence["artifacts"][0][field] = False
            result = release.build(base(), release_policy, evidence, life(), gate("production_chain"), gate("hardware_operational"), lic())
            self.assertFalse(result["release_eligible"], field)

    def test_wrong_timestamp_endpoint_is_rejected(self) -> None:
        release_policy = policy()
        evidence = sig(release_policy)
        evidence["artifacts"][0]["timestamp_url"] = "https://invalid.example/timestamp"
        result = release.build(base(), release_policy, evidence, life(), gate("production_chain"), gate("hardware_operational"), lic())
        self.assertFalse(result["release_eligible"])

    def test_wrong_signer_subject_is_rejected(self) -> None:
        release_policy = policy()
        evidence = sig(release_policy)
        evidence["artifacts"][0]["signer_subject"] = "CN=Substituted"
        result = release.build(base(), release_policy, evidence, life(), gate("production_chain"), gate("hardware_operational"), lic())
        self.assertFalse(result["release_eligible"])

    def test_substituted_artifact_name_is_rejected(self) -> None:
        release_policy = policy()
        evidence = sig(release_policy)
        evidence["artifacts"][0]["name"] = "substituted.exe"
        with self.assertRaises(release.ReleaseError):
            release.build(base(), release_policy, evidence, life(), gate("production_chain"), gate("hardware_operational"), lic())

    def test_post_signature_mutation_is_rejected(self) -> None:
        release_policy = policy()
        evidence = sig(release_policy)
        evidence["artifacts"][0]["sha256"] = "f" * 64
        with self.assertRaises(release.ReleaseError):
            release.build(base(), release_policy, evidence, life(), gate("production_chain"), gate("hardware_operational"), lic())

    def test_test_mode_lifecycle_never_satisfies_production(self) -> None:
        release_policy = policy()
        result = release.build(base(), release_policy, sig(release_policy), life(True), gate("production_chain"), gate("hardware_operational"), lic())
        self.assertFalse(result["release_eligible"])
        self.assertIn("INSTALLER_LIFECYCLE_NOT_VERIFIED", result["blocking_reasons"])


if __name__ == "__main__":
    unittest.main()

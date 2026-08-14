from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("bind_controlled_trust_gate.py")
SPEC = importlib.util.spec_from_file_location("bind_controlled_trust_gate", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("controlled trust release binder could not be loaded")
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class ControlledTrustReleaseBindingTests(unittest.TestCase):
    def base_manifest(self) -> dict[str, object]:
        return {
            "schema_version": "0.1.0",
            "release_eligible": False,
            "blocking_reasons": [
                "AUTHENTICODE_NOT_VERIFIED",
                "HARDWARE_BACKED_PRIVATE_KEY_NOT_VERIFIED",
                "INSTALLER_PROVENANCE_NOT_VERIFIED",
            ],
        }

    def test_missing_physical_evidence_is_first_class_unknown_blocker(self) -> None:
        bound = MODULE.bind_manifest(self.base_manifest(), MODULE.unknown_hardware_gate())
        self.assertIs(bound["release_eligible"], False)
        self.assertEqual("UNKNOWN", bound["hardware_operational"]["status"])
        self.assertIs(bound["hardware_operational"]["eligible"], False)
        self.assertEqual({}, bound["hardware_operational"]["evidence_digests"])
        self.assertIn(MODULE.HARDWARE_BLOCKER, bound["blocking_reasons"])

    def test_proven_operational_gate_never_promotes_release_by_itself(self) -> None:
        digest = "a" * 64
        proven = {
            "status": MODULE.PROVEN,
            "eligible": True,
            "blockers": [],
            "ceremony_id": "controlled-ceremony-1",
            "machine_identity_digest": digest,
            "evidence_digests": {
                "physical_tpm_evidence": digest,
                "governance_recovery_receipt": digest,
                "installation_receipt": digest,
                "recovery_receipt": digest,
                "capability_provisioning_evidence": digest,
                "attestation_provisioning_evidence": digest,
            },
        }
        self.assertEqual(
            MODULE.EXPECTED_EVIDENCE_DIGEST_KEYS,
            set(proven["evidence_digests"]),
        )
        bound = MODULE.bind_manifest(self.base_manifest(), proven)
        self.assertIs(bound["release_eligible"], False)
        self.assertNotIn(MODULE.HARDWARE_BLOCKER, bound["blocking_reasons"])
        self.assertIn("AUTHENTICODE_NOT_VERIFIED", bound["blocking_reasons"])
        self.assertIn("INSTALLER_PROVENANCE_NOT_VERIFIED", bound["blocking_reasons"])

    def test_cli_without_evidence_is_deterministic_and_rebinds_checksum(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source.json"
            source.write_text(json.dumps(self.base_manifest()), encoding="utf-8")
            first = root / "first.json"
            second = root / "second.json"
            checksum_a = root / "SHA256SUMS-a"
            checksum_b = root / "SHA256SUMS-b"
            checksum_a.write_text(
                f"{'0' * 64}  first.json\n{'1' * 64}  artifact.exe\n",
                encoding="utf-8",
            )
            checksum_b.write_text(
                f"{'0' * 64}  second.json\n{'1' * 64}  artifact.exe\n",
                encoding="utf-8",
            )
            self.assertEqual(
                0,
                MODULE.main(
                    [
                        "--manifest",
                        str(source),
                        "--output",
                        str(first),
                        "--checksums",
                        str(checksum_a),
                    ]
                ),
            )
            self.assertEqual(
                0,
                MODULE.main(
                    [
                        "--manifest",
                        str(source),
                        "--output",
                        str(second),
                        "--checksums",
                        str(checksum_b),
                    ]
                ),
            )
            self.assertEqual(first.read_bytes(), second.read_bytes())
            expected_first = hashlib.sha256(first.read_bytes()).hexdigest()
            expected_second = hashlib.sha256(second.read_bytes()).hexdigest()
            self.assertIn(
                f"{expected_first}  first.json",
                checksum_a.read_text(encoding="utf-8"),
            )
            self.assertIn(
                f"{expected_second}  second.json",
                checksum_b.read_text(encoding="utf-8"),
            )
            self.assertIn(
                f"{'1' * 64}  artifact.exe",
                checksum_a.read_text(encoding="utf-8"),
            )

    def test_partial_controlled_evidence_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = root / "manifest.json"
            physical = root / "physical.json"
            output = root / "output.json"
            manifest.write_text(json.dumps(self.base_manifest()), encoding="utf-8")
            physical.write_text("{}", encoding="utf-8")
            self.assertEqual(
                1,
                MODULE.main(
                    [
                        "--manifest",
                        str(manifest),
                        "--output",
                        str(output),
                        "--physical",
                        str(physical),
                    ]
                ),
            )
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

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
            },
        }
        bound = MODULE.bind_manifest(self.base_manifest(), proven)
        self.assertIs(bound["release_eligible"], False)
        self.assertNotIn(MODULE.HARDWARE_BLOCKER, bound["blocking_reasons"])
        self.assertIn("AUTHENTICODE_NOT_VERIFIED", bound["blocking_reasons"])
        self.assertIn("INSTALLER_PROVENANCE_NOT_VERIFIED", bound["blocking_reasons"])

    def test_cli_without_evidence_is_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = root / "manifest.json"
            manifest.write_text(json.dumps(self.base_manifest()), encoding="utf-8")
            first = root / "first.json"
            second = root / "second.json"
            self.assertEqual(0, MODULE.main(["--manifest", str(manifest), "--output", str(first)]))
            self.assertEqual(0, MODULE.main(["--manifest", str(manifest), "--output", str(second)]))
            self.assertEqual(first.read_bytes(), second.read_bytes())

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

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("generate_release_evidence.py")
SPEC = importlib.util.spec_from_file_location("generate_release_evidence", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("release evidence module could not be loaded")
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class ReleaseEvidenceTests(unittest.TestCase):
    def write_json(self, path: Path, value: object) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")

    def repository(self, root: Path) -> tuple[Path, dict[str, object]]:
        (root / "apps" / "desktop").mkdir(parents=True)
        (root / "professions" / "video-editor").mkdir(parents=True)
        (root / "examples" / "work-contracts").mkdir(parents=True)
        (root / "schemas").mkdir()
        (root / "Cargo.lock").write_text(
            """version = 4

[[package]]
name = "alpha"
version = "1.2.3"

[[package]]
name = "beta"
version = "4.5.6"
""",
            encoding="utf-8",
        )
        self.write_json(
            root / "apps" / "desktop" / "package-lock.json",
            {
                "lockfileVersion": 3,
                "packages": {
                    "": {"name": "ergaxiom-desktop", "version": "0.1.0"},
                    "node_modules/react": {"version": "19.0.0"},
                    "node_modules/@scope/tool": {
                        "name": "@scope/tool",
                        "version": "2.0.0",
                    },
                },
            },
        )
        capsule = {
            "schema_version": "0.1.0",
            "capsule_id": "ergaxiom.profession.video-editor",
            "version": "0.1.0",
            "profession": {
                "name": "video_editor",
                "display_name": "Video Editor",
                "description": "Test profession",
            },
            "job_types": [{"id": "basic_video_edit"}],
            "operators": [],
            "validators": [],
            "policies": {"default_network": "denied"},
        }
        self.write_json(root / "professions" / "video-editor" / "profession.json", capsule)
        catalog = {
            "schema_version": "0.1.0",
            "catalog_id": "ergaxiom.profession-catalog",
            "catalog_version": "0.1.0",
            "entries": [
                {
                    "capsule_id": capsule["capsule_id"],
                    "capsule_version": capsule["version"],
                    "capsule_path": "video-editor/profession.json",
                    "capsule_digest": MODULE.sha256_bytes(MODULE.canonical_json_bytes(capsule)),
                    "certification_level": "draft",
                    "production_enabled": False,
                    "job_types": [{"id": "basic_video_edit", "status": "planned"}],
                }
            ],
        }
        self.write_json(root / "professions" / "catalog.json", catalog)
        self.write_json(
            root / "examples" / "work-contracts" / "basic-video-edit.json",
            {
                "schema_version": "0.2.0",
                "contract_id": "example.video-edit.0001",
                "profession": {
                    "capsule_id": capsule["capsule_id"],
                    "capsule_version": capsule["version"],
                },
                "job_type": "basic_video_edit",
            },
        )
        self.write_json(
            root / "schemas" / "test.schema.json",
            {"$schema": "https://json-schema.org/draft/2020-12/schema", "type": "object"},
        )
        artifact = root / "ergaxiom-desktop.exe"
        artifact.write_bytes(b"deterministic-windows-candidate")
        return artifact, catalog

    def arguments(self, root: Path, artifact: Path, output: Path) -> list[str]:
        return [
            "--repo-root",
            str(root),
            "--artifact",
            str(artifact),
            "--source-commit",
            "1" * 40,
            "--rustc-version",
            "rustc 1.85.0 test",
            "--node-version",
            "v24.0.0",
            "--npm-version",
            "11.0.0",
            "--output-dir",
            str(output),
        ]

    def test_outputs_are_reproducible_foundation_bound_and_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifact, catalog = self.repository(root)
            output_a = root / "evidence-a"
            output_b = root / "evidence-b"
            self.assertEqual(0, MODULE.main(self.arguments(root, artifact, output_a)))
            self.assertEqual(0, MODULE.main(self.arguments(root, artifact, output_b)))

            for filename in [
                "ergaxiom-release.spdx.json",
                "ergaxiom-release-manifest.json",
                "SHA256SUMS",
            ]:
                self.assertEqual(
                    (output_a / filename).read_bytes(),
                    (output_b / filename).read_bytes(),
                )

            manifest = json.loads(
                (output_a / "ergaxiom-release-manifest.json").read_text(encoding="utf-8")
            )
            self.assertIs(manifest["release_eligible"], False)
            self.assertEqual(manifest["schema_version"], "0.2.0")
            self.assertEqual(
                MODULE.sha256_bytes(MODULE.canonical_json_bytes(catalog)),
                manifest["source"]["profession_catalog_sha256"],
            )
            self.assertEqual(
                manifest["foundation"]["sha256"],
                manifest["source"]["foundation_inventory_sha256"],
            )
            self.assertEqual(1, len(manifest["foundation"]["capsules"]))
            self.assertEqual(1, len(manifest["foundation"]["work_contracts"]))
            self.assertEqual(1, len(manifest["foundation"]["schemas"]))
            self.assertEqual(
                [
                    "AUTHENTICODE_NOT_VERIFIED",
                    "HARDWARE_BACKED_PRIVATE_KEY_NOT_VERIFIED",
                    "INSTALLER_PROVENANCE_NOT_VERIFIED",
                ],
                manifest["blocking_reasons"],
            )

    def test_catalog_digest_mismatch_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifact, _ = self.repository(root)
            capsule_path = root / "professions" / "video-editor" / "profession.json"
            capsule = json.loads(capsule_path.read_text(encoding="utf-8"))
            capsule["profession"]["display_name"] = "Changed"
            self.write_json(capsule_path, capsule)
            self.assertEqual(
                1,
                MODULE.main(self.arguments(root, artifact, root / "evidence")),
            )

    def test_duplicate_artifact_basenames_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            left = root / "left"
            right = root / "right"
            left.mkdir()
            right.mkdir()
            (left / "candidate.exe").write_bytes(b"left")
            (right / "candidate.exe").write_bytes(b"right")
            with self.assertRaises(MODULE.ReleaseEvidenceError):
                MODULE.normalized_artifacts(
                    [left / "candidate.exe", right / "candidate.exe"]
                )


if __name__ == "__main__":
    unittest.main()

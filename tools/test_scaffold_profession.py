from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from tools.scaffold_profession import ScaffoldError, scaffold_profession
from tools.validate_foundation import canonical_json_sha256


class ProfessionScaffoldTests(unittest.TestCase):
    def repository(self, root: Path) -> None:
        professions = root / "professions"
        professions.mkdir()
        (professions / "catalog.json").write_text(
            json.dumps(
                {
                    "schema_version": "0.1.0",
                    "catalog_id": "ergaxiom.profession-catalog",
                    "catalog_version": "0.1.0",
                    "entries": [],
                }
            ),
            encoding="utf-8",
        )

    def arguments(self, root: Path) -> dict[str, object]:
        return {
            "repository_root": root,
            "slug": "video-editor",
            "display_name": "Video Editor",
            "job_type": "basic_video_edit",
        }

    def test_scaffold_is_draft_registered_digest_bound_and_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.repository(root)
            capsule_path, catalog_path = scaffold_profession(**self.arguments(root))

            capsule = json.loads(capsule_path.read_text(encoding="utf-8"))
            catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
            entry = catalog["entries"][0]
            job = capsule["job_types"][0]
            policies = capsule["policies"]
            self.assertEqual(entry["capsule_id"], "ergaxiom.profession.video-editor")
            self.assertEqual(entry["capsule_digest"], canonical_json_sha256(capsule))
            self.assertEqual(entry["certification_level"], "draft")
            self.assertFalse(entry["production_enabled"])
            self.assertEqual(entry["job_types"][0]["status"], "planned")
            self.assertEqual(catalog["catalog_version"], "0.1.1")
            self.assertEqual(capsule["metadata"]["status"], "draft")
            self.assertEqual(capsule["metadata"]["maturity"], "planned")
            self.assertEqual(job["minimum_assurance_level"], "E0")
            self.assertEqual(policies["minimum_assurance_by_job_type"][job["id"]], "E0")
            self.assertEqual(policies["default_network"], "denied")
            self.assertFalse(policies["self_verification_allowed"])
            self.assertTrue(policies["irreversible_actions_require_approval"])
            self.assertFalse(capsule["training"]["live_learning_allowed"])

    def test_existing_profession_is_never_overwritten(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.repository(root)
            arguments = self.arguments(root)
            scaffold_profession(**arguments)
            with self.assertRaisesRegex(ScaffoldError, "already registered"):
                scaffold_profession(**arguments)

    def test_invalid_identifiers_are_rejected_before_writes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.repository(root)
            with self.assertRaisesRegex(ScaffoldError, "Profession slug"):
                scaffold_profession(
                    repository_root=root,
                    slug="../video-editor",
                    display_name="Video Editor",
                    job_type="basic_video_edit",
                )
            self.assertEqual(
                sorted(path.name for path in (root / "professions").iterdir()),
                ["catalog.json"],
            )

    def test_duplicate_json_keys_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.repository(root)
            catalog_path = root / "professions" / "catalog.json"
            catalog_path.write_text(
                '{"schema_version":"0.1.0","catalog_id":"ergaxiom.profession-catalog",'
                '"catalog_version":"0.1.0","entries":[],"entries":[]}\n',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ScaffoldError, "Duplicate JSON object key"):
                scaffold_profession(**self.arguments(root))
            self.assertFalse((root / "professions" / "video-editor").exists())

    def test_catalog_digest_substitution_is_rejected_before_writes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.repository(root)
            capsule_path, _ = scaffold_profession(**self.arguments(root))
            capsule = json.loads(capsule_path.read_text(encoding="utf-8"))
            capsule["profession"]["display_name"] = "Substituted"
            capsule_path.write_text(json.dumps(capsule), encoding="utf-8")

            with self.assertRaisesRegex(ScaffoldError, "digest mismatch"):
                scaffold_profession(
                    repository_root=root,
                    slug="audio-editor",
                    display_name="Audio Editor",
                    job_type="basic_audio_edit",
                )
            self.assertFalse((root / "professions" / "audio-editor").exists())

    def test_duplicate_catalog_path_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.repository(root)
            _, catalog_path = scaffold_profession(**self.arguments(root))
            catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
            duplicate = dict(catalog["entries"][0])
            duplicate["capsule_id"] = "ergaxiom.profession.alias"
            catalog["entries"].append(duplicate)
            catalog_path.write_text(json.dumps(catalog), encoding="utf-8")

            with self.assertRaisesRegex(ScaffoldError, "Duplicate catalog capsule_path"):
                scaffold_profession(
                    repository_root=root,
                    slug="audio-editor",
                    display_name="Audio Editor",
                    job_type="basic_audio_edit",
                )


if __name__ == "__main__":
    unittest.main()

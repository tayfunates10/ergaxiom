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

    def test_scaffold_is_draft_registered_and_digest_bound(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.repository(root)
            capsule_path, catalog_path = scaffold_profession(
                repository_root=root,
                slug="video-editor",
                display_name="Video Editor",
                job_type="basic_video_edit",
            )

            capsule = json.loads(capsule_path.read_text(encoding="utf-8"))
            catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
            entry = catalog["entries"][0]
            self.assertEqual(entry["capsule_id"], "ergaxiom.profession.video-editor")
            self.assertEqual(entry["capsule_digest"], canonical_json_sha256(capsule))
            self.assertEqual(entry["certification_level"], "draft")
            self.assertFalse(entry["production_enabled"])
            self.assertEqual(entry["job_types"][0]["status"], "planned")
            self.assertEqual(catalog["catalog_version"], "0.1.1")
            self.assertFalse(capsule["training"]["live_learning_allowed"])
            self.assertEqual(
                capsule["training"]["certification_suite"],
                "profession-learning-lab/v1",
            )
            self.assertEqual(capsule["training"]["minimum_pass_rate"], 1.0)
            self.assertIn(
                "property_fuzz", capsule["training"]["required_zero_failure_tests"]
            )
            self.assertIn(
                "revocation_rollback",
                capsule["training"]["required_zero_failure_tests"],
            )

    def test_existing_profession_is_never_overwritten(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.repository(root)
            arguments = {
                "repository_root": root,
                "slug": "video-editor",
                "display_name": "Video Editor",
                "job_type": "basic_video_edit",
            }
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


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import copy
import unittest

from tools import validate_foundation as foundation


class FoundationCatalogTests(unittest.TestCase):
    def setUp(self) -> None:
        self.catalog = foundation.load_json(foundation.CATALOG_PATH)
        self.profession = foundation.load_json(
            foundation.PROFESSIONS_DIRECTORY / "graphic-designer" / "profession.json"
        )
        self.capsules = {
            entry["capsule_path"]: foundation.load_json(
                foundation.PROFESSIONS_DIRECTORY / entry["capsule_path"]
            )
            for entry in self.catalog["entries"]
        }

    def catalog_entry(self, capsule_id: str) -> dict:
        return next(
            entry
            for entry in self.catalog["entries"]
            if entry["capsule_id"] == capsule_id
        )

    def test_repository_validates_every_registered_contract(self) -> None:
        result = foundation.validate_repository()
        self.assertEqual(len(result["professions"]), len(self.catalog["entries"]))
        self.assertEqual(len(result["professions"]), 2)
        self.assertEqual(len(result["contracts"]), 4)
        self.assertEqual(result["hard_constraint_count"], 51)
        self.assertEqual(result["proof_obligation_count"], 51)

    def test_catalog_digest_substitution_fails_closed(self) -> None:
        catalog = copy.deepcopy(self.catalog)
        entry = next(
            item
            for item in catalog["entries"]
            if item["capsule_id"] == "ergaxiom.profession.graphic-designer"
        )
        entry["capsule_digest"] = "0" * 64
        with self.assertRaisesRegex(
            foundation.FoundationValidationError, "capsule digest does not match"
        ):
            foundation.validate_catalog_invariants(catalog, self.capsules)

    def test_unregistered_capsule_fails_closed(self) -> None:
        capsules = dict(self.capsules)
        capsules["video-editor/profession.json"] = self.profession
        with self.assertRaisesRegex(
            foundation.FoundationValidationError, "unregistered capsules"
        ):
            foundation.validate_catalog_invariants(self.catalog, capsules)

    def test_catalog_job_inventory_must_match_capsule(self) -> None:
        catalog = copy.deepcopy(self.catalog)
        entry = next(
            item
            for item in catalog["entries"]
            if item["capsule_id"] == "ergaxiom.profession.graphic-designer"
        )
        entry["job_types"].pop()
        with self.assertRaisesRegex(
            foundation.FoundationValidationError, "job inventory does not match"
        ):
            foundation.validate_catalog_invariants(catalog, self.capsules)

    def test_profession_alpha_cannot_downgrade_a_job(self) -> None:
        catalog = copy.deepcopy(self.catalog)
        entry = next(
            item
            for item in catalog["entries"]
            if item["capsule_id"] == "ergaxiom.profession.graphic-designer"
        )
        entry["job_types"][0]["status"] = "experimental"
        with self.assertRaisesRegex(
            foundation.FoundationValidationError, "contains a non-certified job"
        ):
            foundation.validate_catalog_invariants(catalog, self.capsules)

    def test_draft_capsule_cannot_enable_production(self) -> None:
        catalog = copy.deepcopy(self.catalog)
        entry = next(
            item
            for item in catalog["entries"]
            if item["capsule_id"] == "ergaxiom.profession.technical-writer"
        )
        entry["production_enabled"] = True
        with self.assertRaisesRegex(
            foundation.FoundationValidationError, "is not profession_alpha"
        ):
            foundation.validate_catalog_invariants(catalog, self.capsules)

    def test_job_operator_reference_must_resolve(self) -> None:
        profession = copy.deepcopy(self.profession)
        profession["job_types"][0]["operator_ids"].append("missing.operator")
        with self.assertRaisesRegex(
            foundation.FoundationValidationError, "references missing operators"
        ):
            foundation.validate_profession_invariants(profession)

    def test_required_constraint_must_have_capsule_validator(self) -> None:
        profession = copy.deepcopy(self.profession)
        profession["job_types"][0]["required_constraints"].append(
            "unsupported.constraint"
        )
        with self.assertRaisesRegex(
            foundation.FoundationValidationError, "no capsule validator"
        ):
            foundation.validate_profession_invariants(profession)

    def test_certified_job_requires_example_contract(self) -> None:
        with self.assertRaisesRegex(
            foundation.FoundationValidationError,
            "Certified jobs without an example Work Contract",
        ):
            foundation.validate_certified_job_coverage(self.catalog, set())

    def test_catalog_path_cannot_escape_professions_directory(self) -> None:
        with self.assertRaisesRegex(
            foundation.FoundationValidationError, "not a confined profession path"
        ):
            foundation.resolve_catalog_capsule_path("../outside/profession.json")


if __name__ == "__main__":
    unittest.main()

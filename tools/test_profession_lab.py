from __future__ import annotations

import copy
import json
import random
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator

from tools.profession_lab import (
    LabValidationError,
    certify_candidate,
    generate_synthetic_cases,
    revoke_version,
    synthesize_candidate,
    validate_expert_demonstration,
)

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples" / "profession-learning"
SCHEMAS = ROOT / "schemas"


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


class ProfessionLearningLabTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.demo = load(EXAMPLES / "technical-writer-demo.json")
        cls.expected_candidate = load(EXAMPLES / "technical-writer-candidate.json")
        cls.certification = load(EXAMPLES / "technical-writer-certification.json")
        cls.lifecycle = load(EXAMPLES / "technical-writer-lifecycle.json")

    def test_canonical_records_validate_against_schemas(self) -> None:
        bindings = [
            ("expert-demonstration.schema.json", self.demo),
            ("operator-candidate.schema.json", self.expected_candidate),
            ("operator-certification.schema.json", self.certification),
            ("capsule-lifecycle.schema.json", self.lifecycle),
        ]
        for schema_name, instance in bindings:
            schema = load(SCHEMAS / schema_name)
            errors = list(Draft202012Validator(schema).iter_errors(instance))
            self.assertEqual(errors, [], schema_name)

    def test_candidate_synthesis_is_deterministic_and_replayable(self) -> None:
        first = synthesize_candidate(
            [copy.deepcopy(self.demo)],
            candidate_id="candidate.technical-writer.001",
            capsule_id="ergaxiom.profession.technical-writer",
            job_type="plain_text_revision",
        )
        second = synthesize_candidate(
            [copy.deepcopy(self.demo)],
            candidate_id="candidate.technical-writer.001",
            capsule_id="ergaxiom.profession.technical-writer",
            job_type="plain_text_revision",
        )
        self.assertEqual(first, second)
        self.assertEqual(first, self.expected_candidate)
        self.assertTrue(first["proposal_only"])
        self.assertFalse(first["signing"]["production_key_access"])
        self.assertFalse(first["promotion"]["automatic_production_allowed"])

    def test_missing_provenance_or_license_is_rejected(self) -> None:
        missing = copy.deepcopy(self.demo)
        del missing["provenance"]["license"]
        with self.assertRaises(LabValidationError):
            validate_expert_demonstration(missing)

    def test_scope_escalation_and_unknown_cases_are_generated(self) -> None:
        cases = generate_synthetic_cases(self.expected_candidate)
        by_id = {case["case_id"]: case for case in cases}
        self.assertEqual(by_id["synthetic.scope-escalation"]["expected"], "DENY")
        self.assertEqual(
            by_id["synthetic.unknown-observation"]["expected"], "BLOCK_PROMOTION"
        )
        self.assertEqual(by_id["synthetic.production-execution"]["expected"], "DENY")

    def test_full_certification_still_does_not_auto_promote_to_production(self) -> None:
        decision = certify_candidate(
            copy.deepcopy(self.expected_candidate), copy.deepcopy(self.certification)
        )
        self.assertTrue(decision["zero_failure_invariants"])
        self.assertTrue(decision["eligible_for_canary"])
        self.assertFalse(decision["eligible_for_production"])
        self.assertFalse(decision["automatic_production_allowed"])
        self.assertTrue(decision["manual_release_required"])
        self.assertEqual(decision["required_next_authority"], "production-capsule")

    def test_unknown_failure_live_work_and_production_escape_fail_closed(self) -> None:
        mutations = []

        unknown = copy.deepcopy(self.certification)
        unknown["suites"][0]["unknowns"] = 1
        mutations.append(unknown)

        failed = copy.deepcopy(self.certification)
        failed["suites"][1]["failures"] = 1
        mutations.append(failed)

        live = copy.deepcopy(self.certification)
        live["isolation"]["live_user_work_used"] = True
        mutations.append(live)

        escaped = copy.deepcopy(self.certification)
        escaped["isolation"]["executed_environments"].append("production")
        mutations.append(escaped)

        for mutation in mutations:
            with self.subTest(mutation=mutation):
                with self.assertRaises(LabValidationError):
                    certify_candidate(copy.deepcopy(self.expected_candidate), mutation)

    def test_seeded_property_fuzz_preserves_scope_and_production_invariants(self) -> None:
        rng = random.Random(79)
        declared = set(self.demo["declared_capability_scope"])
        for index in range(512):
            mutated = copy.deepcopy(self.demo)
            if rng.random() < 0.5:
                mutated["decision_points"][-1]["action"]["parameters"][
                    f"noise_{index % 7}"
                ] = rng.randint(0, 10_000)
                candidate = synthesize_candidate(
                    [mutated],
                    candidate_id=f"candidate.fuzz.{index}",
                    capsule_id=mutated["capsule_id"],
                    job_type=mutated["job_type"],
                )
                self.assertTrue(
                    set(candidate["operator"]["capability_scope"]).issubset(declared)
                )
                self.assertFalse(candidate["signing"]["production_key_access"])
                self.assertFalse(
                    candidate["promotion"]["automatic_production_allowed"]
                )
            else:
                mutated["decision_points"][-1]["action"][
                    "capability"
                ] = f"undeclared.{index}"
                with self.assertRaises(LabValidationError):
                    synthesize_candidate(
                        [mutated],
                        candidate_id=f"candidate.fuzz.{index}",
                        capsule_id=mutated["capsule_id"],
                        job_type=mutated["job_type"],
                    )

    def test_revocation_rolls_active_canary_back_and_never_selects_revoked_target(self) -> None:
        rolled_back = revoke_version(
            copy.deepcopy(self.lifecycle),
            "0.2.0-canary.1",
            "adversarial regression",
        )
        self.assertEqual(rolled_back["current_version"], "0.1.0")
        self.assertIn("0.2.0-canary.1", rolled_back["revoked_versions"])
        self.assertTrue(rolled_back["last_action"]["rollback_applied"])

        unsafe = copy.deepcopy(self.lifecycle)
        unsafe["revoked_versions"] = ["0.1.0"]
        with self.assertRaises(LabValidationError):
            revoke_version(
                unsafe,
                "0.2.0-canary.1",
                "cannot safely roll back",
            )


if __name__ == "__main__":
    unittest.main()

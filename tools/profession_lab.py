#!/usr/bin/env python3
"""Isolated Profession Learning Laboratory primitives.

This module is deliberately proposal-only: it can synthesize and certify candidate
operators, but it has no code path that writes production capsules or enables catalog
entries for production.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Iterable

ALLOWED_LAB_ENVIRONMENTS = {"occupational_twin", "isolated_test"}
REQUIRED_CERTIFICATION_SUITES = {"regression", "property_fuzz", "adversarial"}
CANDIDATE_SIGNING_ROLE = "candidate-operator"
PRODUCTION_SIGNING_ROLE = "production-capsule"
UNKNOWN = "UNKNOWN"


class LabValidationError(RuntimeError):
    """Raised when a learning-laboratory safety invariant is violated."""


def canonical_json_sha256(value: Any) -> str:
    encoded = json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _require_nonempty_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise LabValidationError(f"{label} must be a non-empty string")
    return value.strip()


def _stable_unique(values: Iterable[str]) -> list[str]:
    return sorted(set(values))


def validate_expert_demonstration(demonstration: dict[str, Any]) -> None:
    demonstration_id = _require_nonempty_string(
        demonstration.get("demonstration_id"), "demonstration_id"
    )
    provenance = demonstration.get("provenance")
    if not isinstance(provenance, dict):
        raise LabValidationError(f"{demonstration_id}: provenance is required")
    for field in ("source_id", "license", "content_sha256"):
        _require_nonempty_string(
            provenance.get(field), f"{demonstration_id}: provenance.{field}"
        )
    digest = provenance["content_sha256"]
    if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
        raise LabValidationError(
            f"{demonstration_id}: provenance.content_sha256 must be lowercase sha256"
        )

    environment = demonstration.get("environment")
    if not isinstance(environment, dict):
        raise LabValidationError(f"{demonstration_id}: environment is required")
    mode = environment.get("mode")
    if mode not in ALLOWED_LAB_ENVIRONMENTS:
        raise LabValidationError(
            f"{demonstration_id}: demonstration environment must be isolated"
        )
    _require_nonempty_string(
        environment.get("identity"), f"{demonstration_id}: environment.identity"
    )

    application = demonstration.get("application")
    if not isinstance(application, dict):
        raise LabValidationError(f"{demonstration_id}: application identity is required")
    for field in ("application_id", "version", "identity_digest"):
        _require_nonempty_string(
            application.get(field), f"{demonstration_id}: application.{field}"
        )

    declared_scope = demonstration.get("declared_capability_scope")
    if not isinstance(declared_scope, list) or not declared_scope:
        raise LabValidationError(
            f"{demonstration_id}: declared capability scope is required"
        )
    declared = {
        _require_nonempty_string(item, f"{demonstration_id}: scope")
        for item in declared_scope
    }

    decision_points = demonstration.get("decision_points")
    if not isinstance(decision_points, list) or not decision_points:
        raise LabValidationError(
            f"{demonstration_id}: at least one decision point is required"
        )
    for index, point in enumerate(decision_points):
        if not isinstance(point, dict):
            raise LabValidationError(
                f"{demonstration_id}: decision point {index} must be an object"
            )
        _require_nonempty_string(
            point.get("decision_id"), f"{demonstration_id}: decision_id"
        )
        preconditions = point.get("preconditions")
        postconditions = point.get("postconditions")
        if not isinstance(preconditions, list) or not isinstance(postconditions, list):
            raise LabValidationError(
                f"{demonstration_id}: decision point pre/postconditions must be arrays"
            )
        if point.get("observation") == UNKNOWN:
            raise LabValidationError(
                f"{demonstration_id}: expert demonstrations may not treat UNKNOWN as known evidence"
            )
        action = point.get("action")
        if not isinstance(action, dict):
            raise LabValidationError(
                f"{demonstration_id}: decision point action is required"
            )
        capability = _require_nonempty_string(
            action.get("capability"), f"{demonstration_id}: action.capability"
        )
        if capability not in declared:
            raise LabValidationError(
                f"{demonstration_id}: action capability {capability!r} exceeds declared scope"
            )


def synthesize_candidate(
    demonstrations: list[dict[str, Any]],
    *,
    candidate_id: str,
    capsule_id: str,
    job_type: str,
) -> dict[str, Any]:
    _require_nonempty_string(candidate_id, "candidate_id")
    _require_nonempty_string(capsule_id, "capsule_id")
    _require_nonempty_string(job_type, "job_type")
    if not demonstrations:
        raise LabValidationError("at least one expert demonstration is required")

    for demonstration in demonstrations:
        validate_expert_demonstration(demonstration)
        if demonstration.get("capsule_id") != capsule_id:
            raise LabValidationError(
                "expert demonstration capsule_id does not match candidate capsule"
            )
        if demonstration.get("job_type") != job_type:
            raise LabValidationError(
                "expert demonstration job_type does not match candidate job type"
            )

    ordered = sorted(demonstrations, key=lambda item: item["demonstration_id"])
    scopes: list[str] = []
    preconditions: list[str] = []
    postconditions: list[str] = []
    actions: list[dict[str, Any]] = []
    source_digests: list[str] = []

    for demonstration in ordered:
        scopes.extend(demonstration["declared_capability_scope"])
        source_digests.append(canonical_json_sha256(demonstration))
        for point in demonstration["decision_points"]:
            preconditions.extend(str(value) for value in point["preconditions"])
            postconditions.extend(str(value) for value in point["postconditions"])
            action = point["action"]
            actions.append(
                {
                    "capability": action["capability"],
                    "operation": action["operation"],
                    "parameter_names": sorted(action.get("parameters", {}).keys()),
                }
            )

    actions = sorted(
        {json.dumps(item, sort_keys=True): item for item in actions}.values(),
        key=lambda item: (
            item["capability"],
            item["operation"],
            item["parameter_names"],
        ),
    )

    candidate = {
        "schema_version": "0.1.0",
        "candidate_id": candidate_id,
        "capsule_id": capsule_id,
        "job_type": job_type,
        "proposal_only": True,
        "source_demonstration_digests": sorted(source_digests),
        "operator": {
            "operator_id": f"{candidate_id}.operator",
            "version": "0.1.0-candidate",
            "capability_scope": _stable_unique(scopes),
            "preconditions": _stable_unique(preconditions),
            "postconditions": _stable_unique(postconditions),
            "actions": actions,
            "unsupported_observation_policy": UNKNOWN,
        },
        "execution_boundary": {
            "allowed_environments": sorted(ALLOWED_LAB_ENVIRONMENTS),
            "live_user_work_allowed": False,
        },
        "signing": {
            "role": CANDIDATE_SIGNING_ROLE,
            "production_key_access": False,
            "production_signing_role": PRODUCTION_SIGNING_ROLE,
        },
        "promotion": {
            "automatic_production_allowed": False,
            "manual_release_required": True,
        },
    }
    candidate["candidate_digest"] = canonical_json_sha256(candidate)
    return candidate


def generate_synthetic_cases(candidate: dict[str, Any]) -> list[dict[str, Any]]:
    scope = candidate["operator"]["capability_scope"]
    positive = {
        "case_id": "synthetic.nominal",
        "expected": "ALLOW_IN_TWIN",
        "observation": "KNOWN",
        "requested_capability": scope[0] if scope else "",
    }
    unknown = {
        "case_id": "synthetic.unknown-observation",
        "expected": "BLOCK_PROMOTION",
        "observation": UNKNOWN,
        "requested_capability": scope[0] if scope else "",
    }
    escalation = {
        "case_id": "synthetic.scope-escalation",
        "expected": "DENY",
        "observation": "KNOWN",
        "requested_capability": "__undeclared_capability__",
    }
    production = {
        "case_id": "synthetic.production-execution",
        "expected": "DENY",
        "observation": "KNOWN",
        "requested_environment": "production",
    }
    return [positive, unknown, escalation, production]


def certify_candidate(
    candidate: dict[str, Any], certification: dict[str, Any]
) -> dict[str, Any]:
    expected_digest = candidate.get("candidate_digest")
    if not isinstance(expected_digest, str):
        raise LabValidationError("candidate digest is missing")
    unsigned_candidate = copy.deepcopy(candidate)
    unsigned_candidate.pop("candidate_digest", None)
    actual_digest = canonical_json_sha256(unsigned_candidate)
    if expected_digest != actual_digest:
        raise LabValidationError("candidate digest does not match candidate contents")

    if candidate.get("proposal_only") is not True:
        raise LabValidationError("candidate must remain proposal-only")
    signing = candidate.get("signing", {})
    if signing.get("role") != CANDIDATE_SIGNING_ROLE:
        raise LabValidationError("candidate must use the candidate signing role")
    if signing.get("production_key_access") is not False:
        raise LabValidationError("candidate may not have production key access")
    if candidate.get("promotion", {}).get("automatic_production_allowed") is not False:
        raise LabValidationError("automatic production promotion is forbidden")

    if certification.get("candidate_digest") != expected_digest:
        raise LabValidationError("certification is bound to a different candidate")

    isolation = certification.get("isolation", {})
    executed = set(isolation.get("executed_environments", []))
    if not executed or not executed.issubset(ALLOWED_LAB_ENVIRONMENTS):
        raise LabValidationError(
            "candidate certification escaped the isolated laboratory"
        )
    if isolation.get("live_user_work_used") is not False:
        raise LabValidationError("live user work may not certify a candidate")

    suites = certification.get("suites")
    if not isinstance(suites, list):
        raise LabValidationError("certification suites are required")
    suite_kinds = [
        suite.get("kind") for suite in suites if isinstance(suite, dict)
    ]
    if len(suite_kinds) != len(suites):
        raise LabValidationError("certification suites must be objects")
    if len(suite_kinds) != len(set(suite_kinds)):
        raise LabValidationError("duplicate certification suite kinds are forbidden")
    unsupported = set(suite_kinds) - REQUIRED_CERTIFICATION_SUITES
    if unsupported:
        raise LabValidationError(
            "unsupported certification suites: " + ", ".join(sorted(unsupported))
        )
    by_kind = {suite["kind"]: suite for suite in suites}
    missing = REQUIRED_CERTIFICATION_SUITES - set(by_kind)
    if missing:
        raise LabValidationError(
            "missing required certification suites: " + ", ".join(sorted(missing))
        )
    for kind in REQUIRED_CERTIFICATION_SUITES:
        suite = by_kind[kind]
        if suite.get("failures") != 0:
            raise LabValidationError(f"{kind} suite has failures")
        if suite.get("unknowns") != 0:
            raise LabValidationError(
                f"{kind} suite has unsupported UNKNOWN observations"
            )
        if not isinstance(suite.get("total"), int) or suite["total"] <= 0:
            raise LabValidationError(f"{kind} suite must execute at least one case")

    review = certification.get("human_review", {})
    if review.get("decision") != "approve":
        raise LabValidationError("human review approval is required")
    if review.get("independent_from_candidate_signer") is not True:
        raise LabValidationError(
            "human reviewer must be independent from candidate signer"
        )
    _require_nonempty_string(review.get("reviewer"), "human_review.reviewer")

    lifecycle = certification.get("lifecycle", {})
    if lifecycle.get("canary_required") is not True:
        raise LabValidationError("canary installation is required")
    if lifecycle.get("rollback_supported") is not True:
        raise LabValidationError("rollback support is required")
    _require_nonempty_string(lifecycle.get("from_version"), "lifecycle.from_version")
    _require_nonempty_string(lifecycle.get("to_version"), "lifecycle.to_version")
    _require_nonempty_string(
        lifecycle.get("rollback_target"), "lifecycle.rollback_target"
    )
    if lifecycle["rollback_target"] != lifecycle["from_version"]:
        raise LabValidationError(
            "rollback target must be the pre-upgrade capsule version"
        )
    if lifecycle.get("to_version") in set(lifecycle.get("revoked_versions", [])):
        raise LabValidationError("revoked capsule version may not be installed")

    provenance = certification.get("training_provenance")
    if not isinstance(provenance, list) or not provenance:
        raise LabValidationError("training provenance is required")
    for item in provenance:
        if not isinstance(item, dict):
            raise LabValidationError("training provenance entries must be objects")
        _require_nonempty_string(
            item.get("source_id"), "training_provenance.source_id"
        )
        _require_nonempty_string(item.get("license"), "training_provenance.license")

    return {
        "candidate_digest": expected_digest,
        "zero_failure_invariants": True,
        "eligible_for_canary": True,
        "eligible_for_production": False,
        "automatic_production_allowed": False,
        "manual_release_required": True,
        "required_next_authority": PRODUCTION_SIGNING_ROLE,
        "reason": "Certification authorizes only a reviewed canary proposal; production requires a separate explicit release action.",
    }


def revoke_version(
    lifecycle: dict[str, Any], version: str, reason: str
) -> dict[str, Any]:
    _require_nonempty_string(version, "version")
    _require_nonempty_string(reason, "reason")
    updated = copy.deepcopy(lifecycle)
    revoked = set(updated.get("revoked_versions", []))
    revoked.add(version)
    updated["revoked_versions"] = sorted(revoked)

    history = updated.get("history")
    if not isinstance(history, list):
        raise LabValidationError("capsule lifecycle history is required")
    evidence_digest = canonical_json_sha256(
        {"kind": "revoke", "version": version, "reason": reason}
    )
    history.append(
        {
            "kind": "revoke",
            "version": version,
            "evidence_id": f"revocation:{evidence_digest}",
        }
    )

    if updated.get("current_version") == version:
        rollback_target = updated.get("rollback_target")
        if not rollback_target or rollback_target in revoked:
            raise LabValidationError("active revoked version has no safe rollback target")
        updated["current_version"] = rollback_target
        history.append(
            {
                "kind": "rollback",
                "version": rollback_target,
                "evidence_id": f"rollback:{evidence_digest}",
            }
        )
    return updated


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise LabValidationError(f"{path}: JSON root must be an object")
    return value


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Synthesize a proposal-only candidate operator from isolated expert demonstrations."
    )
    parser.add_argument("--demo", action="append", required=True, type=Path)
    parser.add_argument("--candidate-id", required=True)
    parser.add_argument("--capsule-id", required=True)
    parser.add_argument("--job-type", required=True)
    parser.add_argument("--output", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_arguments()
    try:
        demonstrations = [load_json(path) for path in args.demo]
        candidate = synthesize_candidate(
            demonstrations,
            candidate_id=args.candidate_id,
            capsule_id=args.capsule_id,
            job_type=args.job_type,
        )
    except (OSError, json.JSONDecodeError, LabValidationError) as exc:
        print(f"PROFESSION LAB FAILED\n{exc}", file=sys.stderr)
        return 1

    rendered = json.dumps(candidate, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

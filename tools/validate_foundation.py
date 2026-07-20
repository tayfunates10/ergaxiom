#!/usr/bin/env python3
"""Validate Ergaxiom's foundation schemas and cross-document invariants."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[1]

SCHEMA_PATHS = {
    "work_contract": ROOT / "schemas" / "work-contract.schema.json",
    "profession_capsule": ROOT / "schemas" / "profession-capsule.schema.json",
    "evidence_bundle": ROOT / "schemas" / "evidence-bundle.schema.json",
}

PROFESSION_PATH = ROOT / "professions" / "graphic-designer" / "profession.json"
CONTRACT_PATH = ROOT / "examples" / "work-contracts" / "social-media-static-post.json"


class FoundationValidationError(RuntimeError):
    """Raised when a foundation invariant is violated."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as handle:
            value = json.load(handle)
    except FileNotFoundError as exc:
        raise FoundationValidationError(f"Required file is missing: {path}") from exc
    except json.JSONDecodeError as exc:
        raise FoundationValidationError(
            f"Invalid JSON in {path}:{exc.lineno}:{exc.colno}: {exc.msg}"
        ) from exc

    if not isinstance(value, dict):
        raise FoundationValidationError(f"Top-level JSON value must be an object: {path}")
    return value


def validate_schema_definition(name: str, schema: dict[str, Any]) -> None:
    try:
        Draft202012Validator.check_schema(schema)
    except Exception as exc:  # jsonschema exposes several schema error subclasses
        raise FoundationValidationError(f"Schema {name!r} is invalid: {exc}") from exc


def validate_instance(
    *, name: str, instance: dict[str, Any], schema: dict[str, Any]
) -> None:
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    errors = sorted(validator.iter_errors(instance), key=lambda item: list(item.absolute_path))
    if not errors:
        return

    rendered: list[str] = []
    for error in errors:
        location = ".".join(str(part) for part in error.absolute_path) or "<root>"
        rendered.append(f"{name}:{location}: {error.message}")
    raise FoundationValidationError("Schema validation failed:\n- " + "\n- ".join(rendered))


def unique_index(items: list[dict[str, Any]], key: str, label: str) -> dict[str, dict[str, Any]]:
    index: dict[str, dict[str, Any]] = {}
    for item in items:
        identifier = item.get(key)
        if not isinstance(identifier, str) or not identifier:
            raise FoundationValidationError(f"{label} contains an item without a valid {key}")
        if identifier in index:
            raise FoundationValidationError(f"Duplicate {label} identifier: {identifier}")
        index[identifier] = item
    return index


def assurance_rank(level: str) -> int:
    levels = {"E0": 0, "E1": 1, "E2": 2, "E3": 3, "E4": 4, "E5": 5}
    try:
        return levels[level]
    except KeyError as exc:
        raise FoundationValidationError(f"Unknown assurance level: {level}") from exc


def independence_rank(level: str) -> int:
    levels = {"executor": 0, "independent": 1, "diverse": 2}
    try:
        return levels[level]
    except KeyError as exc:
        raise FoundationValidationError(f"Unknown independence class: {level}") from exc


def validate_cross_document_invariants(
    profession: dict[str, Any], contract: dict[str, Any]
) -> None:
    if contract["profession"]["capsule_id"] != profession["capsule_id"]:
        raise FoundationValidationError("Contract references a different profession capsule ID")
    if contract["profession"]["capsule_version"] != profession["version"]:
        raise FoundationValidationError("Contract references a different profession capsule version")

    operators = unique_index(profession["operators"], "id", "operator")
    validators = unique_index(profession["validators"], "id", "validator")
    job_types = unique_index(profession["job_types"], "id", "job type")

    job_type_id = contract["job_type"]
    if job_type_id not in job_types:
        raise FoundationValidationError(f"Unsupported job type: {job_type_id}")
    job_type = job_types[job_type_id]

    missing_operators = sorted(set(job_type["operator_ids"]) - set(operators))
    if missing_operators:
        raise FoundationValidationError(
            "Job type references missing operators: " + ", ".join(missing_operators)
        )

    constraints = unique_index(contract["requirements"]["hard"], "id", "constraint")
    obligations = unique_index(contract["proof_obligations"], "id", "proof obligation")

    missing_required_constraints = sorted(set(job_type["required_constraints"]) - set(constraints))
    if missing_required_constraints:
        raise FoundationValidationError(
            "Contract lacks job-type constraints: " + ", ".join(missing_required_constraints)
        )

    non_mandatory_required_constraints = sorted(
        constraint_id
        for constraint_id in job_type["required_constraints"]
        if not constraints[constraint_id]["mandatory"]
    )
    if non_mandatory_required_constraints:
        raise FoundationValidationError(
            "Job-type constraints must be mandatory: "
            + ", ".join(non_mandatory_required_constraints)
        )

    for obligation in obligations.values():
        constraint_id = obligation["constraint_id"]
        validator_ids = obligation["validator_ids"]
        if constraint_id not in constraints:
            raise FoundationValidationError(
                f"Proof obligation {obligation['id']} references missing constraint {constraint_id}"
            )
        if len(validator_ids) != len(set(validator_ids)):
            raise FoundationValidationError(
                f"Proof obligation {obligation['id']} repeats a validator ID"
            )

        selected_validators: list[dict[str, Any]] = []
        for validator_id in validator_ids:
            if validator_id not in validators:
                raise FoundationValidationError(
                    f"Proof obligation {obligation['id']} references missing validator {validator_id}"
                )
            validator = validators[validator_id]
            if constraint_id not in validator["claims"]:
                raise FoundationValidationError(
                    f"Validator {validator_id} does not declare support for claim {constraint_id}"
                )
            selected_validators.append(validator)

        obligation_class = obligation["independence_class"]
        independent_validators = {
            validator_id
            for validator_id, validator in zip(validator_ids, selected_validators, strict=True)
            if independence_rank(validator["independence_class"])
            >= independence_rank("independent")
        }
        if obligation_class == "independent" and not independent_validators:
            raise FoundationValidationError(
                f"Proof obligation {obligation['id']} lacks an independent validator"
            )
        if obligation_class == "diverse" and len(independent_validators) < 2:
            raise FoundationValidationError(
                f"Proof obligation {obligation['id']} requires two distinct independent validators"
            )

        declared_evidence_types = set(obligation.get("evidence_types", []))
        supported_evidence_types = {
            evidence_type
            for validator in selected_validators
            for evidence_type in validator.get("evidence_types", [])
        }
        unsupported_evidence_types = sorted(
            declared_evidence_types - supported_evidence_types
        )
        if unsupported_evidence_types:
            raise FoundationValidationError(
                f"Proof obligation {obligation['id']} declares unsupported evidence types: "
                + ", ".join(unsupported_evidence_types)
            )

    mandatory_constraints = {
        constraint_id
        for constraint_id, constraint in constraints.items()
        if constraint["mandatory"]
    }
    proven_constraints = {
        obligation["constraint_id"]
        for obligation in obligations.values()
        if obligation["mandatory"]
    }
    missing_proofs = sorted(mandatory_constraints - proven_constraints)
    if missing_proofs:
        raise FoundationValidationError(
            "Mandatory constraints without mandatory proof obligations: "
            + ", ".join(missing_proofs)
        )

    unknowns = contract["requirements"]["unknowns"]
    unresolved_mandatory = [
        item["id"]
        for item in unknowns
        if item["mandatory"] and item["resolution"] == "unresolved"
    ]
    if contract["acceptance"]["unknowns_must_be_empty"] and unresolved_mandatory:
        raise FoundationValidationError(
            "Acceptance forbids unresolved mandatory unknowns: "
            + ", ".join(unresolved_mandatory)
        )

    capsule_minimum = profession["policies"]["minimum_assurance_by_job_type"].get(
        job_type_id, job_type.get("minimum_assurance_level", "E0")
    )
    contract_minimum = contract["acceptance"]["minimum_assurance_level"]
    if assurance_rank(contract_minimum) < assurance_rank(capsule_minimum):
        raise FoundationValidationError(
            f"Contract assurance {contract_minimum} is lower than capsule minimum {capsule_minimum}"
        )

    allowed_output_ids = {item["id"] for item in contract["outputs"]}
    required_output_kinds = set(job_type["required_outputs"])
    actual_output_kinds = {item["kind"] for item in contract["outputs"] if item["required"]}
    missing_output_kinds = sorted(required_output_kinds - actual_output_kinds)
    if missing_output_kinds:
        raise FoundationValidationError(
            "Contract lacks required output kinds: " + ", ".join(missing_output_kinds)
        )
    if len(allowed_output_ids) != len(contract["outputs"]):
        raise FoundationValidationError("Contract contains duplicate output IDs")


def main() -> int:
    try:
        schemas = {name: load_json(path) for name, path in SCHEMA_PATHS.items()}
        for name, schema in schemas.items():
            validate_schema_definition(name, schema)

        profession = load_json(PROFESSION_PATH)
        contract = load_json(CONTRACT_PATH)

        validate_instance(
            name=str(PROFESSION_PATH.relative_to(ROOT)),
            instance=profession,
            schema=schemas["profession_capsule"],
        )
        validate_instance(
            name=str(CONTRACT_PATH.relative_to(ROOT)),
            instance=contract,
            schema=schemas["work_contract"],
        )
        validate_cross_document_invariants(profession, contract)
    except FoundationValidationError as exc:
        print(f"FOUNDATION VALIDATION FAILED\n{exc}", file=sys.stderr)
        return 1

    print("FOUNDATION VALIDATION PASSED")
    print(f"- schemas checked: {len(schemas)}")
    print(f"- profession capsule: {profession['capsule_id']}@{profession['version']}")
    print(f"- example contract: {contract['contract_id']}")
    print(f"- hard constraints: {len(contract['requirements']['hard'])}")
    print(f"- proof obligations: {len(contract['proof_obligations'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

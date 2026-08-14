#!/usr/bin/env python3
"""Validate Ergaxiom's schemas, profession catalog and cross-document invariants."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path, PurePosixPath
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[1]

SCHEMA_PATHS = {
    "work_contract": ROOT / "schemas" / "work-contract.schema.json",
    "profession_capsule": ROOT / "schemas" / "profession-capsule.schema.json",
    "profession_catalog": ROOT / "schemas" / "profession-catalog.schema.json",
    "evidence_bundle": ROOT / "schemas" / "evidence-bundle.schema.json",
}

PROFESSIONS_DIRECTORY = ROOT / "professions"
CATALOG_PATH = PROFESSIONS_DIRECTORY / "catalog.json"
CONTRACT_DIRECTORY = ROOT / "examples" / "work-contracts"


class FoundationValidationError(RuntimeError):
    """Raised when a foundation invariant is violated."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as handle:
            value = json.load(handle)
    except FileNotFoundError as exc:
        raise FoundationValidationError(f"Required file is missing: {path}") from exc
    except OSError as exc:
        raise FoundationValidationError(f"Unable to read required file {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise FoundationValidationError(
            f"Invalid JSON in {path}:{exc.lineno}:{exc.colno}: {exc.msg}"
        ) from exc

    if not isinstance(value, dict):
        raise FoundationValidationError(f"Top-level JSON value must be an object: {path}")
    return value


def canonical_json_sha256(value: dict[str, Any]) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


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


def unique_index(
    items: list[dict[str, Any]], key: str, label: str
) -> dict[str, dict[str, Any]]:
    index: dict[str, dict[str, Any]] = {}
    for item in items:
        identifier = item.get(key)
        if not isinstance(identifier, str) or not identifier:
            raise FoundationValidationError(f"{label} contains an item without a valid {key}")
        if identifier in index:
            raise FoundationValidationError(f"Duplicate {label} identifier: {identifier}")
        index[identifier] = item
    return index


def require_unique_strings(values: list[str], label: str) -> None:
    if len(values) != len(set(values)):
        raise FoundationValidationError(f"{label} contains duplicate values")


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


def validate_profession_invariants(profession: dict[str, Any]) -> None:
    capsule_id = profession["capsule_id"]
    operators = unique_index(profession["operators"], "id", f"{capsule_id} operator")
    validators = unique_index(
        profession["validators"], "id", f"{capsule_id} validator"
    )
    job_types = unique_index(profession["job_types"], "id", f"{capsule_id} job type")

    validator_claims = {
        claim
        for validator in validators.values()
        for claim in validator.get("claims", [])
    }
    for validator_id, validator in validators.items():
        require_unique_strings(
            validator.get("claims", []), f"Validator {validator_id} claims"
        )
        require_unique_strings(
            validator.get("evidence_types", []),
            f"Validator {validator_id} evidence types",
        )

    for operator_id, operator in operators.items():
        for field in (
            "input_types",
            "output_types",
            "preconditions",
            "postconditions",
            "permissions",
            "execution_methods",
        ):
            require_unique_strings(
                operator.get(field, []), f"Operator {operator_id} {field}"
            )

    for job_type_id, job_type in job_types.items():
        for field in (
            "required_inputs",
            "required_outputs",
            "required_constraints",
            "operator_ids",
        ):
            require_unique_strings(
                job_type.get(field, []), f"Job type {job_type_id} {field}"
            )

        missing_operators = sorted(set(job_type["operator_ids"]) - set(operators))
        if missing_operators:
            raise FoundationValidationError(
                f"Job type {job_type_id} references missing operators: "
                + ", ".join(missing_operators)
            )

        unsupported_constraints = sorted(
            set(job_type["required_constraints"]) - validator_claims
        )
        if unsupported_constraints:
            raise FoundationValidationError(
                f"Job type {job_type_id} has required constraints with no capsule validator: "
                + ", ".join(unsupported_constraints)
            )

    policy_minimums = profession["policies"].get(
        "minimum_assurance_by_job_type", {}
    )
    missing_minimums = sorted(set(job_types) - set(policy_minimums))
    unknown_minimums = sorted(set(policy_minimums) - set(job_types))
    if missing_minimums:
        raise FoundationValidationError(
            f"Capsule {capsule_id} lacks policy assurance minimums for: "
            + ", ".join(missing_minimums)
        )
    if unknown_minimums:
        raise FoundationValidationError(
            f"Capsule {capsule_id} declares policy assurance for unknown jobs: "
            + ", ".join(unknown_minimums)
        )
    for job_type_id, policy_level in policy_minimums.items():
        declared_level = job_types[job_type_id].get("minimum_assurance_level", "E0")
        if assurance_rank(policy_level) < assurance_rank(declared_level):
            raise FoundationValidationError(
                f"Capsule policy assurance {policy_level} lowers job {job_type_id} "
                f"minimum {declared_level}"
            )


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
            for validator_id, validator in zip(
                validator_ids, selected_validators, strict=True
            )
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
    actual_output_kinds = {
        item["kind"] for item in contract["outputs"] if item["required"]
    }
    missing_output_kinds = sorted(required_output_kinds - actual_output_kinds)
    if missing_output_kinds:
        raise FoundationValidationError(
            "Contract lacks required output kinds: " + ", ".join(missing_output_kinds)
        )
    if len(allowed_output_ids) != len(contract["outputs"]):
        raise FoundationValidationError("Contract contains duplicate output IDs")


def resolve_catalog_capsule_path(relative_path: str) -> Path:
    pure_path = PurePosixPath(relative_path)
    if pure_path.is_absolute() or len(pure_path.parts) != 2 or ".." in pure_path.parts:
        raise FoundationValidationError(
            f"Catalog capsule path is not a confined profession path: {relative_path}"
        )
    target = PROFESSIONS_DIRECTORY.joinpath(*pure_path.parts)
    root_resolved = PROFESSIONS_DIRECTORY.resolve()
    try:
        target.resolve().relative_to(root_resolved)
    except (OSError, ValueError) as exc:
        raise FoundationValidationError(
            f"Catalog capsule path escapes the professions directory: {relative_path}"
        ) from exc

    cursor = target
    while cursor != PROFESSIONS_DIRECTORY:
        if cursor.is_symlink():
            raise FoundationValidationError(
                f"Catalog capsule path may not traverse a symbolic link: {relative_path}"
            )
        cursor = cursor.parent
    return target


def validate_catalog_invariants(
    catalog: dict[str, Any], capsules_by_path: dict[str, dict[str, Any]]
) -> dict[tuple[str, str], dict[str, Any]]:
    entries = unique_index(catalog["entries"], "capsule_id", "catalog capsule")
    ordered_ids = [entry["capsule_id"] for entry in catalog["entries"]]
    if ordered_ids != sorted(ordered_ids):
        raise FoundationValidationError("Catalog entries must be sorted by capsule_id")

    catalog_paths = [entry["capsule_path"] for entry in catalog["entries"]]
    require_unique_strings(catalog_paths, "Catalog capsule paths")
    if set(catalog_paths) != set(capsules_by_path):
        missing = sorted(set(capsules_by_path) - set(catalog_paths))
        unknown = sorted(set(catalog_paths) - set(capsules_by_path))
        details: list[str] = []
        if missing:
            details.append("unregistered capsules: " + ", ".join(missing))
        if unknown:
            details.append("missing catalog targets: " + ", ".join(unknown))
        raise FoundationValidationError(
            "Profession catalog inventory mismatch: " + "; ".join(details)
        )

    capsules_by_binding: dict[tuple[str, str], dict[str, Any]] = {}
    for entry in catalog["entries"]:
        relative_path = entry["capsule_path"]
        resolve_catalog_capsule_path(relative_path)
        profession = capsules_by_path[relative_path]
        capsule_id = profession["capsule_id"]
        capsule_version = profession["version"]
        if entry["capsule_id"] != capsule_id:
            raise FoundationValidationError(
                f"Catalog capsule ID does not match {relative_path}"
            )
        if entry["capsule_version"] != capsule_version:
            raise FoundationValidationError(
                f"Catalog capsule version does not match {relative_path}"
            )
        actual_digest = canonical_json_sha256(profession)
        if entry["capsule_digest"] != actual_digest:
            raise FoundationValidationError(
                f"Catalog capsule digest does not match {relative_path}: "
                f"expected {entry['capsule_digest']}, computed {actual_digest}"
            )

        catalog_jobs = unique_index(
            entry["job_types"], "id", f"{capsule_id} catalog job type"
        )
        ordered_jobs = [job["id"] for job in entry["job_types"]]
        if ordered_jobs != sorted(ordered_jobs):
            raise FoundationValidationError(
                f"Catalog jobs for {capsule_id} must be sorted by id"
            )
        capsule_jobs = unique_index(
            profession["job_types"], "id", f"{capsule_id} capsule job type"
        )
        if set(catalog_jobs) != set(capsule_jobs):
            raise FoundationValidationError(
                f"Catalog job inventory does not match capsule {capsule_id}"
            )

        level = entry["certification_level"]
        statuses = {job["status"] for job in catalog_jobs.values()}
        if level == "profession_alpha" and statuses != {"certified_path"}:
            raise FoundationValidationError(
                f"Profession-alpha capsule {capsule_id} contains a non-certified job"
            )
        if level == "draft" and "certified_path" in statuses:
            raise FoundationValidationError(
                f"Draft capsule {capsule_id} cannot advertise a certified job"
            )
        if entry["production_enabled"] and level != "profession_alpha":
            raise FoundationValidationError(
                f"Production-enabled capsule {capsule_id} is not profession_alpha"
            )

        binding = (capsule_id, capsule_version)
        if binding in capsules_by_binding:
            raise FoundationValidationError(
                f"Duplicate catalog capsule binding: {capsule_id}@{capsule_version}"
            )
        capsules_by_binding[binding] = profession

    if len(entries) != len(capsules_by_binding):
        raise FoundationValidationError("Profession catalog contains duplicate bindings")
    return capsules_by_binding


def validate_certified_job_coverage(
    catalog: dict[str, Any], covered_jobs: set[tuple[str, str]]
) -> None:
    missing: list[str] = []
    for entry in catalog["entries"]:
        for job in entry["job_types"]:
            binding = (entry["capsule_id"], job["id"])
            if job["status"] == "certified_path" and binding not in covered_jobs:
                missing.append(f"{binding[0]}:{binding[1]}")
    if missing:
        raise FoundationValidationError(
            "Certified jobs without an example Work Contract: "
            + ", ".join(sorted(missing))
        )


def validate_repository() -> dict[str, Any]:
    schemas = {name: load_json(path) for name, path in SCHEMA_PATHS.items()}
    for name, schema in schemas.items():
        validate_schema_definition(name, schema)

    catalog = load_json(CATALOG_PATH)
    validate_instance(
        name=str(CATALOG_PATH.relative_to(ROOT)),
        instance=catalog,
        schema=schemas["profession_catalog"],
    )

    profession_paths = sorted(PROFESSIONS_DIRECTORY.glob("*/profession.json"))
    if not profession_paths:
        raise FoundationValidationError("No profession capsules were found")
    capsules_by_path: dict[str, dict[str, Any]] = {}
    for path in profession_paths:
        relative_path = path.relative_to(PROFESSIONS_DIRECTORY).as_posix()
        profession = load_json(path)
        validate_instance(
            name=str(path.relative_to(ROOT)),
            instance=profession,
            schema=schemas["profession_capsule"],
        )
        validate_profession_invariants(profession)
        capsules_by_path[relative_path] = profession

    capsules_by_binding = validate_catalog_invariants(catalog, capsules_by_path)

    contract_paths = sorted(CONTRACT_DIRECTORY.glob("*.json"))
    if not contract_paths:
        raise FoundationValidationError("No example Work Contracts were found")
    contract_ids: set[str] = set()
    contracts: list[dict[str, Any]] = []
    covered_jobs: set[tuple[str, str]] = set()
    for path in contract_paths:
        contract = load_json(path)
        validate_instance(
            name=str(path.relative_to(ROOT)),
            instance=contract,
            schema=schemas["work_contract"],
        )
        contract_id = contract["contract_id"]
        if contract_id in contract_ids:
            raise FoundationValidationError(f"Duplicate Work Contract ID: {contract_id}")
        contract_ids.add(contract_id)

        binding = (
            contract["profession"]["capsule_id"],
            contract["profession"]["capsule_version"],
        )
        profession = capsules_by_binding.get(binding)
        if profession is None:
            raise FoundationValidationError(
                f"Work Contract {contract_id} references an unregistered capsule "
                f"{binding[0]}@{binding[1]}"
            )
        validate_cross_document_invariants(profession, contract)
        contracts.append(contract)
        covered_jobs.add((binding[0], contract["job_type"]))

    validate_certified_job_coverage(catalog, covered_jobs)
    return {
        "schemas": schemas,
        "catalog": catalog,
        "professions": list(capsules_by_path.values()),
        "contracts": contracts,
        "hard_constraint_count": sum(
            len(contract["requirements"]["hard"]) for contract in contracts
        ),
        "proof_obligation_count": sum(
            len(contract["proof_obligations"]) for contract in contracts
        ),
    }


def main() -> int:
    try:
        result = validate_repository()
    except FoundationValidationError as exc:
        print(f"FOUNDATION VALIDATION FAILED\n{exc}", file=sys.stderr)
        return 1

    print("FOUNDATION VALIDATION PASSED")
    print(f"- schemas checked: {len(result['schemas'])}")
    print(
        f"- profession catalog: {result['catalog']['catalog_id']}@"
        f"{result['catalog']['catalog_version']}"
    )
    print(f"- profession capsules: {len(result['professions'])}")
    for profession in result["professions"]:
        print(f"  - {profession['capsule_id']}@{profession['version']}")
    print(f"- example contracts: {len(result['contracts'])}")
    print(f"- hard constraints: {result['hard_constraint_count']}")
    print(f"- proof obligations: {result['proof_obligation_count']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

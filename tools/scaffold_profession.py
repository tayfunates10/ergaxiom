#!/usr/bin/env python3
"""Create a non-production profession capsule and register it in the catalog."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

DEFAULT_ROOT = Path(__file__).resolve().parents[1]
SLUG_PATTERN = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
JOB_TYPE_PATTERN = re.compile(r"^[a-z0-9]+(?:_[a-z0-9]+)*$")


class ScaffoldError(RuntimeError):
    """Raised when a profession scaffold cannot be created safely."""


def _json_bytes(value: dict[str, Any]) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def _canonical_json_sha256(value: dict[str, Any]) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _load_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ScaffoldError(f"Required catalog is missing: {path}") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise ScaffoldError(f"Unable to load catalog {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ScaffoldError(f"Catalog must contain a JSON object: {path}")
    return value


def _increment_patch(version: str) -> str:
    parts = version.split(".")
    if len(parts) != 3 or any(not part.isdigit() for part in parts):
        raise ScaffoldError(f"Catalog version is not a stable semantic version: {version}")
    major, minor, patch = (int(part) for part in parts)
    return f"{major}.{minor}.{patch + 1}"


def build_draft_capsule(
    *, slug: str, display_name: str, job_type: str, description: str
) -> dict[str, Any]:
    return {
        "schema_version": "0.1.0",
        "capsule_id": f"ergaxiom.profession.{slug}",
        "version": "0.1.0",
        "profession": {
            "name": slug.replace("-", "_"),
            "display_name": display_name,
            "description": description,
            "specializations": [],
        },
        "job_types": [
            {
                "id": job_type,
                "description": f"Draft job boundary for {display_name}.",
                "specialization": None,
                "required_inputs": [],
                "required_outputs": [],
                "required_constraints": [],
                "operator_ids": [],
                "minimum_assurance_level": "E0",
            }
        ],
        "operators": [],
        "validators": [],
        "policies": {
            "default_network": "denied",
            "unknown_handling": "request_resolution",
            "self_verification_allowed": False,
            "irreversible_actions_require_approval": True,
            "minimum_assurance_by_job_type": {job_type: "E0"},
        },
        "training": {
            "live_learning_allowed": False,
            "certification_suite": None,
            "minimum_pass_rate": 1.0,
            "required_zero_failure_tests": [],
        },
        "metadata": {
            "status": "draft",
            "owner": "Ergaxiom core team",
        },
    }


def scaffold_profession(
    *,
    repository_root: Path,
    slug: str,
    display_name: str,
    job_type: str,
    description: str | None = None,
) -> tuple[Path, Path]:
    if not SLUG_PATTERN.fullmatch(slug):
        raise ScaffoldError(
            "Profession slug must use lowercase letters, digits and single hyphens"
        )
    if not JOB_TYPE_PATTERN.fullmatch(job_type):
        raise ScaffoldError(
            "Job type must use lowercase letters, digits and single underscores"
        )
    display_name = display_name.strip()
    if not display_name:
        raise ScaffoldError("Display name may not be empty")
    description = (description or f"Draft {display_name} profession capsule.").strip()
    if not description:
        raise ScaffoldError("Description may not be empty")

    professions_root = repository_root / "professions"
    catalog_path = professions_root / "catalog.json"
    catalog = _load_object(catalog_path)
    entries = catalog.get("entries")
    if not isinstance(entries, list):
        raise ScaffoldError("Catalog entries must be an array")

    capsule_id = f"ergaxiom.profession.{slug}"
    if any(
        isinstance(entry, dict) and entry.get("capsule_id") == capsule_id
        for entry in entries
    ):
        raise ScaffoldError(f"Profession is already registered: {capsule_id}")

    profession_directory = professions_root / slug
    capsule_path = profession_directory / "profession.json"
    if profession_directory.exists():
        raise ScaffoldError(f"Profession directory already exists: {profession_directory}")

    capsule = build_draft_capsule(
        slug=slug,
        display_name=display_name,
        job_type=job_type,
        description=description,
    )
    entry = {
        "capsule_id": capsule_id,
        "capsule_version": capsule["version"],
        "capsule_path": f"{slug}/profession.json",
        "capsule_digest": _canonical_json_sha256(capsule),
        "certification_level": "draft",
        "production_enabled": False,
        "job_types": [{"id": job_type, "status": "planned"}],
    }
    updated_catalog = dict(catalog)
    updated_catalog["catalog_version"] = _increment_patch(
        str(catalog.get("catalog_version", ""))
    )
    updated_catalog["entries"] = sorted(
        [*entries, entry], key=lambda item: str(item.get("capsule_id", ""))
    )

    try:
        profession_directory.mkdir(parents=False, exist_ok=False)
        capsule_path.write_bytes(_json_bytes(capsule))
        temporary_catalog_path = catalog_path.with_name(
            f".{catalog_path.name}.{os.getpid()}.pending"
        )
        with temporary_catalog_path.open("xb") as handle:
            handle.write(_json_bytes(updated_catalog))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_catalog_path, catalog_path)
    except OSError as exc:
        raise ScaffoldError(f"Unable to create profession scaffold: {exc}") from exc

    return capsule_path, catalog_path


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Create a draft, production-disabled profession capsule and add it to "
            "the explicit profession catalog."
        )
    )
    parser.add_argument("--slug", required=True)
    parser.add_argument("--display-name", required=True)
    parser.add_argument("--job-type", required=True)
    parser.add_argument("--description")
    parser.add_argument(
        "--repository-root",
        type=Path,
        default=DEFAULT_ROOT,
        help=argparse.SUPPRESS,
    )
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    try:
        capsule_path, catalog_path = scaffold_profession(
            repository_root=arguments.repository_root.resolve(),
            slug=arguments.slug,
            display_name=arguments.display_name,
            job_type=arguments.job_type,
            description=arguments.description,
        )
    except ScaffoldError as exc:
        print(f"PROFESSION SCAFFOLD FAILED\n{exc}", file=sys.stderr)
        return 1

    print("PROFESSION SCAFFOLD CREATED")
    print(f"- capsule: {capsule_path}")
    print(f"- catalog: {catalog_path}")
    print("- state: draft, planned and production-disabled")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Create a non-production profession capsule and register it in the catalog."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path, PurePosixPath
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


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ScaffoldError(f"Duplicate JSON object key is not allowed: {key}")
        value[key] = item
    return value


def _assert_regular_single_link(path: Path, *, label: str) -> os.stat_result:
    try:
        metadata = path.lstat()
    except FileNotFoundError as exc:
        raise ScaffoldError(f"Required {label} is missing: {path}") from exc
    except OSError as exc:
        raise ScaffoldError(f"Unable to inspect {label} {path}: {exc}") from exc
    if stat.S_ISLNK(metadata.st_mode):
        raise ScaffoldError(f"{label.capitalize()} may not be a symbolic link: {path}")
    if not stat.S_ISREG(metadata.st_mode):
        raise ScaffoldError(f"{label.capitalize()} must be a regular file: {path}")
    if metadata.st_nlink != 1:
        raise ScaffoldError(f"{label.capitalize()} may not be hard-linked: {path}")
    return metadata


def _assert_real_directory(path: Path, *, label: str) -> Path:
    try:
        metadata = path.lstat()
    except FileNotFoundError as exc:
        raise ScaffoldError(f"Required {label} is missing: {path}") from exc
    except OSError as exc:
        raise ScaffoldError(f"Unable to inspect {label} {path}: {exc}") from exc
    if stat.S_ISLNK(metadata.st_mode):
        raise ScaffoldError(f"{label.capitalize()} may not be a symbolic link: {path}")
    if not stat.S_ISDIR(metadata.st_mode):
        raise ScaffoldError(f"{label.capitalize()} must be a directory: {path}")
    return path.resolve(strict=True)


def _load_object(path: Path, *, label: str = "catalog") -> dict[str, Any]:
    _assert_regular_single_link(path, label=label)
    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_strict_object)
    except ScaffoldError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ScaffoldError(f"Unable to load {label} {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ScaffoldError(f"{label.capitalize()} must contain a JSON object: {path}")
    return value


def _increment_patch(version: str) -> str:
    parts = version.split(".")
    if len(parts) != 3 or any(not part.isdigit() for part in parts):
        raise ScaffoldError(f"Catalog version is not a stable semantic version: {version}")
    major, minor, patch = (int(part) for part in parts)
    return f"{major}.{minor}.{patch + 1}"


def _validated_capsule_path(professions_root: Path, raw_path: Any) -> Path:
    if not isinstance(raw_path, str):
        raise ScaffoldError("Catalog capsule_path must be a string")
    relative = PurePosixPath(raw_path)
    if (
        relative.is_absolute()
        or len(relative.parts) != 2
        or relative.parts[1] != "profession.json"
        or not SLUG_PATTERN.fullmatch(relative.parts[0])
        or any(part in {"", ".", ".."} for part in relative.parts)
    ):
        raise ScaffoldError(f"Catalog capsule_path escapes the scaffold boundary: {raw_path}")
    directory = professions_root / relative.parts[0]
    _assert_real_directory(directory, label="profession directory")
    capsule_path = directory / "profession.json"
    _assert_regular_single_link(capsule_path, label="profession capsule")
    resolved = capsule_path.resolve(strict=True)
    try:
        resolved.relative_to(professions_root)
    except ValueError as exc:
        raise ScaffoldError(f"Catalog capsule_path escapes professions root: {raw_path}") from exc
    return resolved


def _validate_catalog_entries(
    *, catalog: dict[str, Any], professions_root: Path
) -> tuple[list[dict[str, Any]], set[str], set[str]]:
    entries = catalog.get("entries")
    if not isinstance(entries, list):
        raise ScaffoldError("Catalog entries must be an array")

    validated: list[dict[str, Any]] = []
    capsule_ids: set[str] = set()
    capsule_paths: set[str] = set()
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise ScaffoldError(f"Catalog entry {index} must be an object")
        capsule_id = entry.get("capsule_id")
        capsule_path_raw = entry.get("capsule_path")
        digest = entry.get("capsule_digest")
        version = entry.get("capsule_version")
        if not isinstance(capsule_id, str) or not capsule_id:
            raise ScaffoldError(f"Catalog entry {index} has an invalid capsule_id")
        if capsule_id in capsule_ids:
            raise ScaffoldError(f"Duplicate catalog capsule_id: {capsule_id}")
        if not isinstance(capsule_path_raw, str):
            raise ScaffoldError(f"Catalog entry {index} has an invalid capsule_path")
        if capsule_path_raw in capsule_paths:
            raise ScaffoldError(f"Duplicate catalog capsule_path: {capsule_path_raw}")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ScaffoldError(f"Catalog entry {index} has an invalid capsule_digest")
        if not isinstance(version, str):
            raise ScaffoldError(f"Catalog entry {index} has an invalid capsule_version")

        capsule_path = _validated_capsule_path(professions_root, capsule_path_raw)
        capsule = _load_object(capsule_path, label="profession capsule")
        if capsule.get("capsule_id") != capsule_id:
            raise ScaffoldError(f"Catalog capsule identity mismatch: {capsule_id}")
        if capsule.get("version") != version:
            raise ScaffoldError(f"Catalog capsule version mismatch: {capsule_id}")
        if _canonical_json_sha256(capsule) != digest:
            raise ScaffoldError(f"Catalog capsule digest mismatch: {capsule_id}")

        capsule_ids.add(capsule_id)
        capsule_paths.add(capsule_path_raw)
        validated.append(entry)

    return validated, capsule_ids, capsule_paths


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
            "maturity": "planned",
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

    repository_root = _assert_real_directory(repository_root, label="repository root")
    professions_root = repository_root / "professions"
    professions_root = _assert_real_directory(professions_root, label="professions root")
    catalog_path = professions_root / "catalog.json"
    _assert_regular_single_link(catalog_path, label="profession catalog")
    try:
        catalog_bytes = catalog_path.read_bytes()
    except OSError as exc:
        raise ScaffoldError(f"Unable to read profession catalog {catalog_path}: {exc}") from exc
    catalog = _load_object(catalog_path, label="profession catalog")
    entries, capsule_ids, capsule_paths = _validate_catalog_entries(
        catalog=catalog, professions_root=professions_root
    )

    capsule_id = f"ergaxiom.profession.{slug}"
    relative_capsule_path = f"{slug}/profession.json"
    if capsule_id in capsule_ids:
        raise ScaffoldError(f"Profession is already registered: {capsule_id}")
    if relative_capsule_path in capsule_paths:
        raise ScaffoldError(f"Profession path is already registered: {relative_capsule_path}")

    profession_directory = professions_root / slug
    capsule_path = profession_directory / "profession.json"
    if profession_directory.exists() or profession_directory.is_symlink():
        raise ScaffoldError(f"Profession directory already exists: {profession_directory}")
    if profession_directory.resolve(strict=False).parent != professions_root:
        raise ScaffoldError("Profession directory escapes professions root")

    capsule = build_draft_capsule(
        slug=slug,
        display_name=display_name,
        job_type=job_type,
        description=description,
    )
    entry = {
        "capsule_id": capsule_id,
        "capsule_version": capsule["version"],
        "capsule_path": relative_capsule_path,
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

    temporary_capsule_path = capsule_path.with_name(
        f".{capsule_path.name}.{os.getpid()}.pending"
    )
    temporary_catalog_path = catalog_path.with_name(
        f".{catalog_path.name}.{os.getpid()}.pending"
    )
    created_directory = False
    committed_capsule = False
    try:
        profession_directory.mkdir(parents=False, exist_ok=False)
        created_directory = True
        with temporary_capsule_path.open("xb") as handle:
            handle.write(_json_bytes(capsule))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_capsule_path, capsule_path)
        committed_capsule = True

        with temporary_catalog_path.open("xb") as handle:
            handle.write(_json_bytes(updated_catalog))
            handle.flush()
            os.fsync(handle.fileno())

        _assert_regular_single_link(catalog_path, label="profession catalog")
        if catalog_path.read_bytes() != catalog_bytes:
            raise ScaffoldError(
                "Profession catalog changed during scaffold; refusing a lost update"
            )
        os.replace(temporary_catalog_path, catalog_path)
    except (OSError, ScaffoldError) as exc:
        with contextlib.suppress(OSError):
            temporary_capsule_path.unlink()
        with contextlib.suppress(OSError):
            temporary_catalog_path.unlink()
        if committed_capsule:
            with contextlib.suppress(OSError):
                capsule_path.unlink()
        if created_directory:
            with contextlib.suppress(OSError):
                profession_directory.rmdir()
        if isinstance(exc, ScaffoldError):
            raise
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
            repository_root=arguments.repository_root,
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

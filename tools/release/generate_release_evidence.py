#!/usr/bin/env python3
"""Generate deterministic unsigned release evidence for Ergaxiom.

This tool deliberately does not claim Authenticode or installer provenance. It
produces an SPDX 2.3 dependency inventory, a source/toolchain/artifact manifest,
and SHA-256 checksums. Release eligibility remains false until a later
hardware-backed signing gate independently verifies the binaries and installer.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

SCHEMA_VERSION = "0.2.0"
FIXED_CREATED_AT = "1970-01-01T00:00:00Z"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
CAPSULE_ID_RE = re.compile(r"^[a-z0-9]+(?:[._-][a-z0-9]+)*$")


class ReleaseEvidenceError(RuntimeError):
    """Raised when deterministic release evidence cannot be produced safely."""


@dataclass(frozen=True, order=True)
class Dependency:
    ecosystem: str
    name: str
    version: str

    @property
    def spdx_id(self) -> str:
        identity = f"{self.ecosystem}:{self.name}:{self.version}".encode("utf-8")
        return f"SPDXRef-Package-{hashlib.sha256(identity).hexdigest()[:20]}"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ReleaseEvidenceError(f"duplicate JSON object key is not allowed: {key}")
        value[key] = item
    return value


def _assert_regular_file(path: Path, *, label: str) -> os.stat_result:
    try:
        metadata = path.lstat()
    except FileNotFoundError as error:
        raise ReleaseEvidenceError(f"required {label} is missing: {path}") from error
    except OSError as error:
        raise ReleaseEvidenceError(f"failed to inspect {label} {path}: {error}") from error
    if stat.S_ISLNK(metadata.st_mode):
        raise ReleaseEvidenceError(f"{label} may not be a symbolic link: {path}")
    if not stat.S_ISREG(metadata.st_mode):
        raise ReleaseEvidenceError(f"{label} must be a regular file: {path}")
    if metadata.st_nlink != 1:
        raise ReleaseEvidenceError(f"{label} may not be hard-linked: {path}")
    return metadata


def _load_json_object(path: Path, *, label: str) -> dict[str, Any]:
    _assert_regular_file(path, label=label)
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=_strict_object
        )
    except ReleaseEvidenceError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReleaseEvidenceError(f"failed to parse {label} {path}: {error}") from error
    if not isinstance(value, dict):
        raise ReleaseEvidenceError(f"{label} must contain a JSON object: {path}")
    return value


def canonical_json_file_sha256(path: Path) -> str:
    return sha256_bytes(canonical_json_bytes(_load_json_object(path, label="canonical JSON")))


def write_json(path: Path, value: Any) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def command_version(command: list[str]) -> str:
    try:
        completed = subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise ReleaseEvidenceError(
            f"toolchain command failed: {' '.join(command)}: {error}"
        ) from error
    output = completed.stdout.strip() or completed.stderr.strip()
    if not output:
        raise ReleaseEvidenceError(f"toolchain command returned no version: {command[0]}")
    return output.replace("\r\n", "\n").replace("\r", "\n")


def verify_source_identity(repo_root: Path, source_commit: str) -> None:
    if not (repo_root / ".git").exists():
        return
    try:
        completed = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repo_root,
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise ReleaseEvidenceError(f"failed to resolve checked-out source commit: {error}") from error
    actual = completed.stdout.strip().lower()
    if actual != source_commit:
        raise ReleaseEvidenceError(
            f"source commit substitution detected: checkout={actual} evidence={source_commit}"
        )


def cargo_dependencies(cargo_lock: Path) -> list[Dependency]:
    _assert_regular_file(cargo_lock, label="Cargo.lock")
    try:
        parsed = tomllib.loads(cargo_lock.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise ReleaseEvidenceError(f"failed to parse {cargo_lock}: {error}") from error
    dependencies: set[Dependency] = set()
    for package in parsed.get("package", []):
        name = str(package.get("name", "")).strip()
        version = str(package.get("version", "")).strip()
        if not name or not version:
            raise ReleaseEvidenceError("Cargo.lock contains a package without name/version")
        dependencies.add(Dependency("cargo", name, version))
    return sorted(dependencies)


def npm_dependencies(package_lock: Path) -> list[Dependency]:
    parsed = _load_json_object(package_lock, label="package-lock.json")
    dependencies: set[Dependency] = set()
    packages = parsed.get("packages")
    if not isinstance(packages, dict):
        raise ReleaseEvidenceError("package-lock.json is missing the packages object")
    for package_path, metadata in packages.items():
        if package_path == "" or not isinstance(metadata, dict):
            continue
        version = str(metadata.get("version", "")).strip()
        if not version:
            continue
        name = str(metadata.get("name", "")).strip()
        if not name:
            marker = "node_modules/"
            if marker not in package_path:
                continue
            name = package_path.rsplit(marker, 1)[-1]
        dependencies.add(Dependency("npm", name, version))
    return sorted(dependencies)


def spdx_package(dependency: Dependency) -> dict[str, Any]:
    return {
        "SPDXID": dependency.spdx_id,
        "copyrightText": "NOASSERTION",
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": "NOASSERTION",
        "name": dependency.name,
        "primaryPackagePurpose": "LIBRARY",
        "supplier": "NOASSERTION",
        "versionInfo": dependency.version,
        "externalRefs": [
            {
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceLocator": (
                    f"pkg:cargo/{dependency.name}@{dependency.version}"
                    if dependency.ecosystem == "cargo"
                    else f"pkg:npm/{dependency.name}@{dependency.version}"
                ),
                "referenceType": "purl",
            }
        ],
    }


def build_spdx(source_commit: str, dependencies: list[Dependency]) -> dict[str, Any]:
    identity = {
        "source_commit": source_commit,
        "dependencies": [dependency.__dict__ for dependency in dependencies],
    }
    namespace_digest = sha256_bytes(canonical_json_bytes(identity))
    packages = [spdx_package(dependency) for dependency in dependencies]
    relationships = [
        {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": package["SPDXID"],
        }
        for package in packages
    ]
    return {
        "SPDXID": "SPDXRef-DOCUMENT",
        "creationInfo": {
            "created": FIXED_CREATED_AT,
            "creators": ["Tool: ergaxiom-release-evidence/0.1.0"],
            "licenseListVersion": "3.25",
        },
        "dataLicense": "CC0-1.0",
        "documentNamespace": (
            "https://ergaxiom.invalid/spdx/release/" + namespace_digest
        ),
        "name": f"ergaxiom-release-dependencies-{source_commit[:12]}",
        "packages": packages,
        "relationships": relationships,
        "spdxVersion": "SPDX-2.3",
    }


def _foundation_path(repo_root: Path, relative_path: str, *, label: str) -> Path:
    relative = PurePosixPath(relative_path)
    if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
        raise ReleaseEvidenceError(f"{label} path escapes repository root: {relative_path}")
    candidate = repo_root.joinpath(*relative.parts)
    _assert_regular_file(candidate, label=label)
    resolved = candidate.resolve(strict=True)
    try:
        resolved.relative_to(repo_root)
    except ValueError as error:
        raise ReleaseEvidenceError(f"{label} path escapes repository root: {relative_path}") from error
    return resolved


def _inventory_entry(repo_root: Path, path: Path, value: dict[str, Any]) -> dict[str, Any]:
    return {
        "path": path.relative_to(repo_root).as_posix(),
        "sha256": sha256_bytes(canonical_json_bytes(value)),
    }


def build_foundation_inventory(
    *, repo_root: Path, profession_catalog: Path
) -> dict[str, Any]:
    catalog = _load_json_object(profession_catalog, label="profession catalog")
    if catalog.get("schema_version") != "0.1.0":
        raise ReleaseEvidenceError("profession catalog schema_version must be 0.1.0")
    if catalog.get("catalog_id") != "ergaxiom.profession-catalog":
        raise ReleaseEvidenceError("unexpected profession catalog identity")
    catalog_version = catalog.get("catalog_version")
    if not isinstance(catalog_version, str) or not re.fullmatch(r"\d+\.\d+\.\d+", catalog_version):
        raise ReleaseEvidenceError("profession catalog has an invalid catalog_version")
    entries = catalog.get("entries")
    if not isinstance(entries, list) or not entries:
        raise ReleaseEvidenceError("profession catalog must contain at least one capsule entry")

    capsule_items: list[dict[str, Any]] = []
    registered_paths: set[str] = set()
    capsule_jobs: dict[tuple[str, str], set[str]] = {}
    capsule_ids: set[str] = set()
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise ReleaseEvidenceError(f"profession catalog entry {index} must be an object")
        capsule_id = entry.get("capsule_id")
        capsule_version = entry.get("capsule_version")
        capsule_path_raw = entry.get("capsule_path")
        capsule_digest = entry.get("capsule_digest")
        if not isinstance(capsule_id, str) or not CAPSULE_ID_RE.fullmatch(capsule_id):
            raise ReleaseEvidenceError(f"profession catalog entry {index} has invalid capsule_id")
        if capsule_id in capsule_ids:
            raise ReleaseEvidenceError(f"duplicate profession catalog capsule_id: {capsule_id}")
        if not isinstance(capsule_version, str) or not capsule_version:
            raise ReleaseEvidenceError(f"profession catalog entry {index} has invalid capsule_version")
        if not isinstance(capsule_path_raw, str) or capsule_path_raw in registered_paths:
            raise ReleaseEvidenceError(f"duplicate or invalid profession capsule path: {capsule_path_raw}")
        if not isinstance(capsule_digest, str) or not SHA256_RE.fullmatch(capsule_digest):
            raise ReleaseEvidenceError(f"profession catalog entry {index} has invalid capsule_digest")
        relative = PurePosixPath(capsule_path_raw)
        if len(relative.parts) != 2 or relative.parts[1] != "profession.json":
            raise ReleaseEvidenceError(f"invalid profession capsule path: {capsule_path_raw}")
        capsule_path = _foundation_path(
            repo_root,
            f"professions/{capsule_path_raw}",
            label="profession capsule",
        )
        capsule = _load_json_object(capsule_path, label="profession capsule")
        if capsule.get("capsule_id") != capsule_id:
            raise ReleaseEvidenceError(f"profession capsule identity mismatch: {capsule_id}")
        if capsule.get("version") != capsule_version:
            raise ReleaseEvidenceError(f"profession capsule version mismatch: {capsule_id}")
        actual_digest = sha256_bytes(canonical_json_bytes(capsule))
        if actual_digest != capsule_digest:
            raise ReleaseEvidenceError(f"profession capsule digest mismatch: {capsule_id}")
        jobs = entry.get("job_types")
        if not isinstance(jobs, list) or not jobs:
            raise ReleaseEvidenceError(f"profession catalog entry has no job types: {capsule_id}")
        job_ids: set[str] = set()
        for job in jobs:
            if not isinstance(job, dict) or not isinstance(job.get("id"), str):
                raise ReleaseEvidenceError(f"invalid catalog job type for {capsule_id}")
            job_id = job["id"]
            if job_id in job_ids:
                raise ReleaseEvidenceError(f"duplicate catalog job type {job_id} for {capsule_id}")
            job_ids.add(job_id)
        capsule_ids.add(capsule_id)
        registered_paths.add(capsule_path_raw)
        capsule_jobs[(capsule_id, capsule_version)] = job_ids
        capsule_item = _inventory_entry(repo_root, capsule_path, capsule)
        capsule_item.update({"capsule_id": capsule_id, "version": capsule_version})
        capsule_items.append(capsule_item)

    professions_root = repo_root / "professions"
    discovered_paths = {
        path.relative_to(professions_root).as_posix()
        for path in professions_root.glob("*/profession.json")
        if path.is_file() or path.is_symlink()
    }
    if discovered_paths != registered_paths:
        missing = sorted(registered_paths - discovered_paths)
        orphaned = sorted(discovered_paths - registered_paths)
        raise ReleaseEvidenceError(
            f"profession catalog/file inventory mismatch: missing={missing} orphaned={orphaned}"
        )

    contracts_root = repo_root / "examples" / "work-contracts"
    if not contracts_root.is_dir() or contracts_root.is_symlink():
        raise ReleaseEvidenceError("examples/work-contracts must be a real directory")
    contract_paths = sorted(contracts_root.glob("*.json"), key=lambda path: path.name)
    if not contract_paths:
        raise ReleaseEvidenceError("at least one example work contract is required")
    contract_items: list[dict[str, Any]] = []
    contract_ids: set[str] = set()
    for contract_path in contract_paths:
        contract = _load_json_object(contract_path, label="example work contract")
        contract_id = contract.get("contract_id")
        profession = contract.get("profession")
        job_type = contract.get("job_type")
        if not isinstance(contract_id, str) or not contract_id:
            raise ReleaseEvidenceError(f"example work contract lacks contract_id: {contract_path}")
        if contract_id in contract_ids:
            raise ReleaseEvidenceError(f"duplicate example work contract id: {contract_id}")
        if not isinstance(profession, dict) or not isinstance(job_type, str):
            raise ReleaseEvidenceError(f"example work contract lacks profession/job type: {contract_path}")
        identity = (profession.get("capsule_id"), profession.get("capsule_version"))
        if identity not in capsule_jobs:
            raise ReleaseEvidenceError(f"example work contract references unknown capsule: {contract_id}")
        if job_type not in capsule_jobs[identity]:
            raise ReleaseEvidenceError(f"example work contract references unknown job type: {contract_id}")
        contract_ids.add(contract_id)
        item = _inventory_entry(repo_root, contract_path, contract)
        item.update({"contract_id": contract_id, "job_type": job_type})
        contract_items.append(item)

    schemas_root = repo_root / "schemas"
    if not schemas_root.is_dir() or schemas_root.is_symlink():
        raise ReleaseEvidenceError("schemas must be a real directory")
    schema_paths = sorted(schemas_root.glob("*.json"), key=lambda path: path.name)
    if not schema_paths:
        raise ReleaseEvidenceError("at least one foundation schema is required")
    schema_items = [
        _inventory_entry(repo_root, path, _load_json_object(path, label="foundation schema"))
        for path in schema_paths
    ]

    inventory = {
        "catalog": _inventory_entry(repo_root, profession_catalog, catalog),
        "capsules": sorted(capsule_items, key=lambda item: item["path"]),
        "work_contracts": sorted(contract_items, key=lambda item: item["path"]),
        "schemas": sorted(schema_items, key=lambda item: item["path"]),
    }
    inventory["sha256"] = sha256_bytes(canonical_json_bytes(inventory))
    return inventory


def normalized_artifacts(paths: Iterable[Path]) -> list[dict[str, Any]]:
    artifacts: list[dict[str, Any]] = []
    seen_names: set[str] = set()
    for path in paths:
        _assert_regular_file(path, label="release artifact")
        resolved = path.resolve(strict=True)
        if resolved.name in seen_names:
            raise ReleaseEvidenceError(
                f"artifact basenames must be unique: {resolved.name}"
            )
        seen_names.add(resolved.name)
        artifacts.append(
            {
                "authenticode_status": "NOT_VERIFIED",
                "name": resolved.name,
                "sha256": sha256_file(resolved),
                "size_bytes": resolved.stat().st_size,
            }
        )
    if not artifacts:
        raise ReleaseEvidenceError("at least one release artifact is required")
    return sorted(artifacts, key=lambda item: item["name"])


def validate_source_commit(value: str) -> str:
    normalized = value.strip().lower()
    if not COMMIT_RE.fullmatch(normalized):
        raise ReleaseEvidenceError("source commit must be a 40-character lowercase SHA-1")
    return normalized


def signing_blockers(signing: dict[str, bool]) -> list[str]:
    blockers: list[str] = []
    if not signing["authenticode_verified"]:
        blockers.append("AUTHENTICODE_NOT_VERIFIED")
    if not signing["hardware_backed_private_key_verified"]:
        blockers.append("HARDWARE_BACKED_PRIVATE_KEY_NOT_VERIFIED")
    if not signing["installer_provenance_verified"]:
        blockers.append("INSTALLER_PROVENANCE_NOT_VERIFIED")
    return blockers


def build_manifest(
    *,
    source_commit: str,
    cargo_lock: Path,
    package_lock: Path,
    profession_catalog: Path,
    foundation_inventory: dict[str, Any],
    sbom_path: Path,
    artifacts: list[dict[str, Any]],
    rustc_version: str,
    node_version: str,
    npm_version: str,
) -> dict[str, Any]:
    signing = {
        "authenticode_verified": False,
        "hardware_backed_private_key_verified": False,
        "installer_provenance_verified": False,
    }
    blocking_reasons = signing_blockers(signing)
    return {
        "schema_version": SCHEMA_VERSION,
        "product": "ergaxiom-desktop",
        "source": {
            "commit": source_commit,
            "cargo_lock_sha256": sha256_file(cargo_lock),
            "desktop_package_lock_sha256": sha256_file(package_lock),
            "profession_catalog_sha256": canonical_json_file_sha256(
                profession_catalog
            ),
            "foundation_inventory_sha256": foundation_inventory["sha256"],
        },
        "foundation": foundation_inventory,
        "toolchain": {
            "node": node_version,
            "npm": npm_version,
            "rustc": rustc_version,
        },
        "artifacts": artifacts,
        "sbom": {
            "format": "SPDX-2.3",
            "name": sbom_path.name,
            "sha256": sha256_file(sbom_path),
        },
        "signing": signing,
        "release_eligible": not blocking_reasons,
        "blocking_reasons": blocking_reasons,
    }


def write_checksums(
    path: Path,
    artifact_paths: Iterable[Path],
    evidence_paths: Iterable[Path],
) -> None:
    entries: list[tuple[str, str]] = []
    for candidate in [*artifact_paths, *evidence_paths]:
        resolved = candidate.resolve(strict=True)
        entries.append((resolved.name, sha256_file(resolved)))
    entries.sort(key=lambda item: item[0])
    path.write_text(
        "".join(f"{digest}  {name}\n" for name, digest in entries),
        encoding="utf-8",
        newline="\n",
    )


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--artifact", type=Path, action="append", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument(
        "--source-commit",
        default=os.environ.get("GITHUB_SHA", ""),
    )
    parser.add_argument("--rustc-version")
    parser.add_argument("--node-version")
    parser.add_argument("--npm-version")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        repo_root = args.repo_root.resolve(strict=True)
        cargo_lock = repo_root / "Cargo.lock"
        package_lock = repo_root / "apps" / "desktop" / "package-lock.json"
        profession_catalog = repo_root / "professions" / "catalog.json"
        _assert_regular_file(cargo_lock, label="Cargo.lock")
        _assert_regular_file(package_lock, label="package-lock.json")
        _assert_regular_file(profession_catalog, label="profession catalog")
        source_commit = validate_source_commit(args.source_commit)
        verify_source_identity(repo_root, source_commit)
        foundation_inventory = build_foundation_inventory(
            repo_root=repo_root,
            profession_catalog=profession_catalog,
        )
        dependencies = sorted(
            set(cargo_dependencies(cargo_lock) + npm_dependencies(package_lock))
        )
        artifacts = normalized_artifacts(args.artifact)
        output_dir = args.output_dir.resolve()
        output_dir.mkdir(parents=True, exist_ok=True)
        sbom_path = output_dir / "ergaxiom-release.spdx.json"
        manifest_path = output_dir / "ergaxiom-release-manifest.json"
        checksums_path = output_dir / "SHA256SUMS"

        write_json(sbom_path, build_spdx(source_commit, dependencies))
        manifest = build_manifest(
            source_commit=source_commit,
            cargo_lock=cargo_lock,
            package_lock=package_lock,
            profession_catalog=profession_catalog,
            foundation_inventory=foundation_inventory,
            sbom_path=sbom_path,
            artifacts=artifacts,
            rustc_version=args.rustc_version or command_version(["rustc", "-Vv"]),
            node_version=args.node_version or command_version(["node", "--version"]),
            npm_version=args.npm_version or command_version(["npm", "--version"]),
        )
        write_json(manifest_path, manifest)
        write_checksums(
            checksums_path,
            args.artifact,
            [sbom_path, manifest_path],
        )
        if manifest["release_eligible"] is not False:
            raise ReleaseEvidenceError("unsigned release evidence must fail closed")
        return 0
    except (OSError, ReleaseEvidenceError) as error:
        print(f"release evidence generation failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

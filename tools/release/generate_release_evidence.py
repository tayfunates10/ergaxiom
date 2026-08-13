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
import subprocess
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

SCHEMA_VERSION = "0.2.0"
FIXED_CREATED_AT = "1970-01-01T00:00:00Z"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")


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


def canonical_json_file_sha256(path: Path) -> str:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ReleaseEvidenceError(f"failed to parse canonical JSON {path}: {error}") from error
    if not isinstance(value, dict):
        raise ReleaseEvidenceError(f"canonical JSON input must be an object: {path}")
    return sha256_bytes(canonical_json_bytes(value))


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


def cargo_dependencies(cargo_lock: Path) -> list[Dependency]:
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
    try:
        parsed = json.loads(package_lock.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ReleaseEvidenceError(f"failed to parse {package_lock}: {error}") from error
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


def normalized_artifacts(paths: Iterable[Path]) -> list[dict[str, Any]]:
    artifacts: list[dict[str, Any]] = []
    seen_names: set[str] = set()
    for path in paths:
        resolved = path.resolve(strict=True)
        if not resolved.is_file():
            raise ReleaseEvidenceError(f"artifact is not a file: {path}")
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


def build_manifest(
    *,
    source_commit: str,
    cargo_lock: Path,
    package_lock: Path,
    profession_catalog: Path,
    sbom_path: Path,
    artifacts: list[dict[str, Any]],
    rustc_version: str,
    node_version: str,
    npm_version: str,
) -> dict[str, Any]:
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
        },
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
        "signing": {
            "authenticode_verified": False,
            "hardware_backed_private_key_verified": False,
            "installer_provenance_verified": False,
        },
        "release_eligible": False,
        "blocking_reasons": [
            "AUTHENTICODE_NOT_VERIFIED",
            "HARDWARE_BACKED_PRIVATE_KEY_NOT_VERIFIED",
            "INSTALLER_PROVENANCE_NOT_VERIFIED",
        ],
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
        if (
            not cargo_lock.is_file()
            or not package_lock.is_file()
            or not profession_catalog.is_file()
        ):
            raise ReleaseEvidenceError(
                "Cargo.lock, apps/desktop/package-lock.json and "
                "professions/catalog.json are required"
            )
        source_commit = validate_source_commit(args.source_commit)
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

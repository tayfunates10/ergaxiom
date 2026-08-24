#!/usr/bin/env python3
"""Generate source-commit-bound owner distribution-license evidence.

This tool records the already-approved repository policy decision for the exact
checked-out commit. It does not invent or change the owner's license choice.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path

H40 = re.compile(r"^[0-9a-f]{40}$")


class LicenseDecisionError(RuntimeError):
    pass


def canonical_bytes(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def git(repo: Path, *args: str) -> str:
    process = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    if process.returncode != 0:
        raise LicenseDecisionError(process.stderr.strip() or "git command failed")
    return process.stdout.strip()


def build_decision(repo: Path, policy_path: Path) -> dict:
    repo = repo.resolve()
    policy_path = policy_path.resolve()
    if not policy_path.is_file():
        raise LicenseDecisionError(f"policy missing: {policy_path}")

    commit = git(repo, "rev-parse", "HEAD")
    if H40.fullmatch(commit) is None:
        raise LicenseDecisionError("invalid source commit")
    if git(repo, "status", "--porcelain", "--untracked-files=no"):
        raise LicenseDecisionError("tracked worktree must be clean")

    policy = json.loads(policy_path.read_text(encoding="utf-8"))
    if policy.get("schema_version") != "0.1.0" or policy.get("policy_id") != "ergaxiom.windows-production-release":
        raise LicenseDecisionError("release policy identity mismatch")

    license_policy = policy.get("license", {})
    expression = license_policy.get("spdx_expression")
    if license_policy.get("owner_decision_status") != "APPROVED" or not isinstance(expression, str) or not expression:
        raise LicenseDecisionError("owner distribution license is not approved")
    if expression != "LicenseRef-Ergaxiom-Proprietary":
        raise LicenseDecisionError("unexpected owner license expression")

    license_file = repo / "LICENSE"
    if not license_file.is_file():
        raise LicenseDecisionError("LICENSE file missing")
    license_bytes = license_file.read_bytes()
    marker = f"SPDX-License-Identifier: {expression}".encode("utf-8")
    if marker not in license_bytes or b"All rights reserved." not in license_bytes:
        raise LicenseDecisionError("LICENSE file does not match approved proprietary decision")

    decision = {
        "schema_version": "0.1.0",
        "source_commit": commit,
        "owner_approved": True,
        "distribution_model": "PROPRIETARY_ALL_RIGHTS_RESERVED",
        "spdx_expression": expression,
        "policy_sha256": sha256_bytes(canonical_bytes(policy)),
        "license_file_sha256": sha256_bytes(license_bytes),
    }
    decision["decision_sha256"] = sha256_bytes(canonical_bytes(decision))
    return decision


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--policy", default="tools/release/windows_release_policy.json")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    repo = Path(args.repo_root)
    policy = Path(args.policy)
    if not policy.is_absolute():
        policy = repo / policy
    output = Path(args.output)

    try:
        decision = build_decision(repo, policy)
    except (OSError, ValueError, json.JSONDecodeError, LicenseDecisionError) as exc:
        raise SystemExit(f"OWNER_LICENSE_DECISION_REJECTED: {exc}") from exc

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(decision, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote owner license decision for {decision['source_commit']} to {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

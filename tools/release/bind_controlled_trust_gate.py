#!/usr/bin/env python3
"""Bind verified controlled-Windows hardware evidence into a release manifest.

This tool never infers physical TPM assurance from CI success. With no controlled
hardware evidence it records an UNKNOWN hardware-operational gate. When evidence
files are supplied, it re-runs the repository verifier over the exact physical
TPM, governance, installation and recovery receipts before binding their digests.
It never promotes top-level release eligibility.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

UNKNOWN = "UNKNOWN"
PROVEN = "PROVEN_HARDWARE_BACKED"
HARDWARE_BLOCKER = "CONTROLLED_WINDOWS_HARDWARE_OPERATIONAL_GATE_NOT_PROVEN"


class BindingError(RuntimeError):
    pass


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BindingError(f"{path}: invalid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise BindingError(f"{path}: top-level value must be an object")
    return value


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def load_controlled_gate_module():
    module_path = Path(__file__).resolve().parents[1] / "windows" / "controlled_trust_gate.py"
    spec = importlib.util.spec_from_file_location("ergaxiom_controlled_trust_gate", module_path)
    if spec is None or spec.loader is None:
        raise BindingError("controlled trust verifier could not be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def unknown_hardware_gate() -> dict[str, Any]:
    return {
        "status": UNKNOWN,
        "eligible": False,
        "blockers": ["physical-tpm-ceremony-not-provided"],
        "evidence_digests": {},
    }


def verified_hardware_gate(
    physical: Path,
    governance: Path,
    installation: Path,
    recovery: Path,
) -> dict[str, Any]:
    gate = load_controlled_gate_module()
    try:
        summary, code = gate.make_gate_summary(physical, governance, installation, recovery)
    except Exception as exc:  # verifier owns the detailed fail-closed error type
        raise BindingError(f"controlled hardware evidence rejected: {exc}") from exc
    if code != 0:
        raise BindingError("controlled hardware evidence did not prove the gate")
    if summary.get("hardware_operational_gate") != PROVEN:
        raise BindingError("controlled hardware gate is not PROVEN_HARDWARE_BACKED")
    if summary.get("hardware_operational_eligible") is not True:
        raise BindingError("controlled hardware gate is not eligible")
    if summary.get("blockers") != []:
        raise BindingError("controlled hardware gate contains blockers")
    evidence_digests = summary.get("evidence_digests")
    if not isinstance(evidence_digests, dict) or set(evidence_digests) != {
        "physical_tpm_evidence",
        "governance_recovery_receipt",
        "installation_receipt",
        "recovery_receipt",
    }:
        raise BindingError("controlled hardware evidence digest set is incomplete")
    return {
        "status": PROVEN,
        "eligible": True,
        "blockers": [],
        "ceremony_id": summary.get("ceremony_id"),
        "machine_identity_digest": summary.get("machine_identity_digest"),
        "evidence_digests": dict(sorted(evidence_digests.items())),
    }


def bind_manifest(manifest: dict[str, Any], hardware_gate: dict[str, Any]) -> dict[str, Any]:
    if manifest.get("release_eligible") is not False:
        raise BindingError("controlled trust binder may only extend a fail-closed candidate")
    blocking_reasons = manifest.get("blocking_reasons")
    if not isinstance(blocking_reasons, list) or not all(
        isinstance(item, str) and item for item in blocking_reasons
    ):
        raise BindingError("release manifest blocking_reasons are invalid")

    result = dict(manifest)
    result["hardware_operational"] = hardware_gate
    reasons = [item for item in blocking_reasons if item != HARDWARE_BLOCKER]
    if hardware_gate.get("status") != PROVEN or hardware_gate.get("eligible") is not True:
        reasons.append(HARDWARE_BLOCKER)
    result["blocking_reasons"] = reasons
    result["release_eligible"] = False
    return result


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--physical", type=Path)
    parser.add_argument("--governance", type=Path)
    parser.add_argument("--installation", type=Path)
    parser.add_argument("--recovery", type=Path)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    evidence = [args.physical, args.governance, args.installation, args.recovery]
    try:
        if any(item is not None for item in evidence) and not all(item is not None for item in evidence):
            raise BindingError("all four controlled hardware evidence paths are required together")
        hardware_gate = (
            verified_hardware_gate(
                args.physical,
                args.governance,
                args.installation,
                args.recovery,
            )
            if all(item is not None for item in evidence)
            else unknown_hardware_gate()
        )
        manifest = load_json(args.manifest)
        write_json(args.output, bind_manifest(manifest, hardware_gate))
        return 0
    except (OSError, BindingError) as exc:
        print(f"controlled trust release binding failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

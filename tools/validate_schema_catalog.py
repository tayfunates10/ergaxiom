#!/usr/bin/env python3
"""Validate every JSON Schema file in the Ergaxiom schema catalog."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_DIRECTORY = ROOT / "schemas"


def main() -> int:
    schema_paths = sorted(SCHEMA_DIRECTORY.glob("*.schema.json"))
    if not schema_paths:
        print("SCHEMA CATALOG VALIDATION FAILED\nNo schema files found.", file=sys.stderr)
        return 1

    failures: list[str] = []
    for path in schema_paths:
        try:
            with path.open("r", encoding="utf-8") as handle:
                schema = json.load(handle)
            Draft202012Validator.check_schema(schema)
        except (OSError, json.JSONDecodeError, Exception) as exc:
            failures.append(f"{path.relative_to(ROOT)}: {exc}")

    if failures:
        print("SCHEMA CATALOG VALIDATION FAILED", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1

    print("SCHEMA CATALOG VALIDATION PASSED")
    print(f"- schemas checked: {len(schema_paths)}")
    for path in schema_paths:
        print(f"- {path.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

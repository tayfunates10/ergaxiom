#!/usr/bin/env python3
"""Fail-closed verifier for controlled Windows trust evidence.

Physical hardware assurance is never inferred from hosted CI success.
"""

from __future__ import annotations

import hashlib
import json


def canonical_digest(value: object) -> str:
    data = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(data).hexdigest()

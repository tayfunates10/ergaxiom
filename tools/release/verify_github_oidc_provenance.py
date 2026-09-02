#!/usr/bin/env python3
"""Cryptographically verify canonical Stage B GitHub Actions provenance.

Production verification is anchored to GitHub's fixed OIDC issuer and JWKS
endpoint over platform-trusted HTTPS. No caller-supplied JWKS or issuer is
accepted by the CLI.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

ISSUER = "https://token.actions.githubusercontent.com"
DISCOVERY_URL = f"{ISSUER}/.well-known/openid-configuration"
JWKS_URL = f"{ISSUER}/.well-known/jwks"
AUDIENCE = "ergaxiom-stage-b"
REPOSITORY = "tayfunates10/ergaxiom"
ENVIRONMENT = "controlled-windows-production"
WORKFLOW_PATH = ".github/workflows/controlled-windows-trust.yml"
EXPECTED_SUBJECT = f"repo:{REPOSITORY}:environment:{ENVIRONMENT}"
SHA256_DIGEST_INFO_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")
CLOCK_SKEW_SECONDS = 60


class OidcVerificationError(ValueError):
    pass


def _b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _json_part(value: str, label: str) -> dict[str, Any]:
    try:
        decoded = json.loads(_b64url_decode(value))
    except Exception as exc:  # noqa: BLE001 - fail closed on malformed JWT
        raise OidcVerificationError(f"malformed {label}") from exc
    if not isinstance(decoded, dict):
        raise OidcVerificationError(f"{label} must be an object")
    return decoded


def _verify_rs256(signing_input: bytes, signature: bytes, jwk: dict[str, Any]) -> None:
    if jwk.get("kty") != "RSA" or jwk.get("use") not in (None, "sig"):
        raise OidcVerificationError("signing key is not an RSA signing key")
    if jwk.get("alg") not in (None, "RS256"):
        raise OidcVerificationError("signing key algorithm mismatch")
    try:
        n = int.from_bytes(_b64url_decode(str(jwk["n"])), "big")
        e = int.from_bytes(_b64url_decode(str(jwk["e"])), "big")
    except Exception as exc:  # noqa: BLE001
        raise OidcVerificationError("malformed RSA JWK") from exc
    if n <= 0 or e <= 1:
        raise OidcVerificationError("invalid RSA JWK")
    k = (n.bit_length() + 7) // 8
    if len(signature) != k:
        raise OidcVerificationError("invalid RSA signature length")
    encoded = pow(int.from_bytes(signature, "big"), e, n).to_bytes(k, "big")
    digest_info = SHA256_DIGEST_INFO_PREFIX + hashlib.sha256(signing_input).digest()
    padding_len = k - len(digest_info) - 3
    if padding_len < 8:
        raise OidcVerificationError("RSA key is too small for RS256")
    expected = b"\x00\x01" + (b"\xff" * padding_len) + b"\x00" + digest_info
    if encoded != expected:
        raise OidcVerificationError("OIDC JWT signature verification failed")


def _audience_matches(claim: Any) -> bool:
    if isinstance(claim, str):
        return claim == AUDIENCE
    if isinstance(claim, list):
        return AUDIENCE in claim and all(isinstance(v, str) for v in claim)
    return False


def verify_token(token: str, jwks: dict[str, Any], source_commit: str, now_epoch_s: int) -> dict[str, Any]:
    parts = token.split(".")
    if len(parts) != 3:
        raise OidcVerificationError("OIDC token is not a three-part JWT")
    header = _json_part(parts[0], "JWT header")
    claims = _json_part(parts[1], "JWT claims")
    if header.get("alg") != "RS256" or header.get("typ") not in (None, "JWT"):
        raise OidcVerificationError("OIDC JWT must use RS256")
    kid = header.get("kid")
    if not isinstance(kid, str) or not kid:
        raise OidcVerificationError("OIDC JWT kid is missing")
    keys = [k for k in jwks.get("keys", []) if isinstance(k, dict) and k.get("kid") == kid]
    if len(keys) != 1:
        raise OidcVerificationError("OIDC JWT signing key is not uniquely trusted")
    _verify_rs256(f"{parts[0]}.{parts[1]}".encode("ascii"), _b64url_decode(parts[2]), keys[0])

    if claims.get("iss") != ISSUER or not _audience_matches(claims.get("aud")):
        raise OidcVerificationError("OIDC issuer or audience mismatch")
    if claims.get("repository") != REPOSITORY or claims.get("sha") != source_commit:
        raise OidcVerificationError("OIDC repository or source SHA mismatch")
    if claims.get("environment") != ENVIRONMENT or claims.get("sub") != EXPECTED_SUBJECT:
        raise OidcVerificationError("OIDC protected-environment identity mismatch")
    if claims.get("ref_protected") not in (True, "true"):
        raise OidcVerificationError("OIDC ref is not protected")
    if claims.get("runner_environment") != "self-hosted":
        raise OidcVerificationError("OIDC runner is not self-hosted")
    if claims.get("event_name") != "workflow_dispatch":
        raise OidcVerificationError("OIDC event is not canonical workflow_dispatch")
    ref = claims.get("ref")
    workflow_ref = claims.get("workflow_ref")
    if not isinstance(ref, str) or not ref.startswith("refs/"):
        raise OidcVerificationError("OIDC ref is missing")
    expected_workflow_ref = f"{REPOSITORY}/{WORKFLOW_PATH}@{ref}"
    if workflow_ref != expected_workflow_ref:
        raise OidcVerificationError("OIDC workflow identity mismatch")

    try:
        exp = int(claims["exp"])
        nbf = int(claims["nbf"])
        iat = int(claims["iat"])
    except Exception as exc:  # noqa: BLE001
        raise OidcVerificationError("OIDC temporal claims are missing") from exc
    if exp < now_epoch_s - CLOCK_SKEW_SECONDS:
        raise OidcVerificationError("OIDC token expired")
    if nbf > now_epoch_s + CLOCK_SKEW_SECONDS or iat > now_epoch_s + CLOCK_SKEW_SECONDS:
        raise OidcVerificationError("OIDC token is not yet valid")
    if iat < now_epoch_s - 600:
        raise OidcVerificationError("OIDC token is too old for Stage B")

    return {
        "verified": True,
        "issuer": ISSUER,
        "audience": AUDIENCE,
        "kid": kid,
        "repository": REPOSITORY,
        "source_commit": source_commit,
        "environment": ENVIRONMENT,
        "ref": ref,
        "workflow_ref": workflow_ref,
        "runner_environment": "self-hosted",
        "token_sha256": hashlib.sha256(token.encode("ascii")).hexdigest(),
        "verified_at_epoch_s": now_epoch_s,
    }


def _fetch_json(url: str, headers: dict[str, str] | None = None) -> dict[str, Any]:
    request = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(request, timeout=15) as response:  # noqa: S310 - URL is pinned/validated
        if response.status != 200:
            raise OidcVerificationError(f"OIDC HTTPS request failed with {response.status}")
        value = json.load(response)
    if not isinstance(value, dict):
        raise OidcVerificationError("OIDC endpoint returned non-object JSON")
    return value


def validate_discovery(document: dict[str, Any]) -> None:
    if document.get("issuer") != ISSUER or document.get("jwks_uri") != JWKS_URL:
        raise OidcVerificationError("GitHub OIDC discovery root mismatch")
    if "RS256" not in document.get("id_token_signing_alg_values_supported", []):
        raise OidcVerificationError("GitHub OIDC discovery does not advertise RS256")


def request_token() -> str:
    raw_url = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL", "")
    bearer = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
    if not raw_url or not bearer:
        raise OidcVerificationError("GitHub OIDC request capability is unavailable")
    parsed = urllib.parse.urlsplit(raw_url)
    host = (parsed.hostname or "").lower()
    if parsed.scheme != "https" or not host.endswith(".actions.githubusercontent.com") or parsed.username or parsed.password or parsed.fragment:
        raise OidcVerificationError("GitHub OIDC request URL is not trusted")
    separator = "&" if parsed.query else "?"
    response = _fetch_json(
        f"{raw_url}{separator}audience={urllib.parse.quote(AUDIENCE, safe='')}",
        {"Authorization": f"Bearer {bearer}"},
    )
    token = response.get("value")
    if not isinstance(token, str) or not token:
        raise OidcVerificationError("GitHub OIDC response did not contain a JWT")
    return token


def verify_github_provenance(source_commit: str, now_epoch_s: int | None = None) -> dict[str, Any]:
    if len(source_commit) != 40 or any(c not in "0123456789abcdef" for c in source_commit):
        raise OidcVerificationError("source commit must be a lowercase full SHA-1")
    discovery = _fetch_json(DISCOVERY_URL)
    validate_discovery(discovery)
    jwks = _fetch_json(JWKS_URL)
    token = request_token()
    return verify_token(token, jwks, source_commit, int(time.time()) if now_epoch_s is None else now_epoch_s)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    try:
        result = verify_github_provenance(args.source_commit)
    except (OidcVerificationError, OSError, ValueError) as exc:
        print(f"GITHUB_OIDC_PROVENANCE_REJECTED: {exc}")
        return 2
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    print(f"GITHUB_OIDC_PROVENANCE_VERIFIED: {result['source_commit']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

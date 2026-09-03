import base64
import hashlib
import json
import os
import unittest
from pathlib import Path
from unittest import mock

from tools.release import verify_github_oidc_provenance as oidc

N = 118906418939498400923724249355189567018426633138594172897538882087070864159874408113336445707270237626513198002397315750260206823097850278909511590900031311364376430221447564780968778075776760886970844764839612401222114560676468731199088953825044286366145221464763698623537791109200861585489507611393259425459
E = 65537
D = 94429154220137232013612955764532953980820491452633967417265188475268782459752863949627060336612704083334694954495486450982540005110864330319124162839053183623246192489333390310264825024136588432507911680436037443686727439031995444300085919854652030571699746084590603253304920289311494571688947647614740784305
KID = "offline-fixture"
NOW = 2_000_000_000
SHA = "a" * 40
REF = "refs/heads/claude/ergaxiom-windows-production-release-bq2z43"
WORKFLOW = Path(__file__).parents[2] / ".github" / "workflows" / "controlled-windows-trust.yml"


def b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def integer_b64(value: int) -> str:
    return b64(value.to_bytes((value.bit_length() + 7) // 8, "big"))


def fixture_jwks() -> dict:
    return {"keys": [{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": KID, "n": integer_b64(N), "e": integer_b64(E)}]}


def claims() -> dict:
    return {
        "iss": oidc.ISSUER,
        "aud": oidc.AUDIENCE,
        "sub": oidc.EXPECTED_SUBJECT,
        "repository": oidc.REPOSITORY,
        "sha": SHA,
        "environment": oidc.ENVIRONMENT,
        "ref": REF,
        "ref_protected": True,
        "runner_environment": "self-hosted",
        "event_name": "workflow_dispatch",
        "workflow_ref": f"{oidc.REPOSITORY}/{oidc.WORKFLOW_PATH}@{REF}",
        "iat": NOW - 10,
        "nbf": NOW - 10,
        "exp": NOW + 300,
    }


def sign(payload: dict) -> str:
    header = {"alg": "RS256", "typ": "JWT", "kid": KID}
    encoded_header = b64(json.dumps(header, sort_keys=True, separators=(",", ":")).encode())
    encoded_payload = b64(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode())
    signing_input = f"{encoded_header}.{encoded_payload}".encode("ascii")
    digest_info = oidc.SHA256_DIGEST_INFO_PREFIX + hashlib.sha256(signing_input).digest()
    k = (N.bit_length() + 7) // 8
    encoded = b"\x00\x01" + b"\xff" * (k - len(digest_info) - 3) + b"\x00" + digest_info
    signature = pow(int.from_bytes(encoded, "big"), D, N).to_bytes(k, "big")
    return f"{encoded_header}.{encoded_payload}.{b64(signature)}"


class GithubOidcProvenanceTests(unittest.TestCase):
    def test_valid_signed_protected_environment_claims_are_accepted(self) -> None:
        result = oidc.verify_token(sign(claims()), fixture_jwks(), SHA, NOW)
        self.assertTrue(result["verified"])
        self.assertEqual(result["source_commit"], SHA)
        self.assertEqual(result["environment"], oidc.ENVIRONMENT)

    def test_forged_payload_with_original_signature_is_rejected(self) -> None:
        token = sign(claims())
        header, _, signature = token.split(".")
        forged = claims()
        forged["environment"] = "local-shell"
        payload = b64(json.dumps(forged, sort_keys=True, separators=(",", ":")).encode())
        with self.assertRaises(oidc.OidcVerificationError):
            oidc.verify_token(f"{header}.{payload}.{signature}", fixture_jwks(), SHA, NOW)

    def test_signed_local_or_wrong_identity_claims_are_rejected(self) -> None:
        mutations = {
            "repository": "attacker/fork",
            "sha": "b" * 40,
            "environment": "local-shell",
            "sub": "repo:tayfunates10/ergaxiom:ref:refs/heads/main",
            "ref_protected": False,
            "runner_environment": "github-hosted",
            "event_name": "pull_request",
            "workflow_ref": f"{oidc.REPOSITORY}/.github/workflows/other.yml@{REF}",
        }
        for key, value in mutations.items():
            with self.subTest(key=key):
                candidate = claims()
                candidate[key] = value
                with self.assertRaises(oidc.OidcVerificationError):
                    oidc.verify_token(sign(candidate), fixture_jwks(), SHA, NOW)

    def test_discovery_cannot_redirect_trust_to_local_jwks(self) -> None:
        with self.assertRaises(oidc.OidcVerificationError):
            oidc.validate_discovery({
                "issuer": oidc.ISSUER,
                "jwks_uri": "https://attacker.invalid/jwks",
                "id_token_signing_alg_values_supported": ["RS256"],
            })

    def test_cli_has_no_caller_supplied_issuer_or_jwks_escape_hatch(self) -> None:
        source = open(oidc.__file__, encoding="utf-8").read()
        self.assertNotIn("--jwks-file", source)
        self.assertNotIn("--issuer", source)
        self.assertIn("ACTIONS_ID_TOKEN_REQUEST_URL", source)
        self.assertIn(oidc.JWKS_URL, source)

    def test_missing_oidc_request_capability_fails_closed_before_network(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(oidc.OidcVerificationError, "request capability is unavailable"):
                oidc.request_token()

    def test_oidc_minting_permission_is_scoped_to_controlled_hardware_job(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertEqual(workflow.count("id-token: write"), 1)
        controlled_job = workflow.split("  controlled-hardware-ceremony:\n", 1)[1]
        self.assertIn("    environment: controlled-windows-production\n", controlled_job)
        self.assertIn("    permissions:\n      contents: read\n      id-token: write\n", controlled_job)
        prefix = workflow.split("  controlled-hardware-ceremony:\n", 1)[0]
        self.assertNotIn("id-token: write", prefix)


if __name__ == "__main__":
    unittest.main()

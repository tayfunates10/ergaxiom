import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

P = Path(__file__).with_name("generate_owner_license_decision.py")
S = importlib.util.spec_from_file_location("license_decision", P)
M = importlib.util.module_from_spec(S)
sys.modules[S.name] = M
S.loader.exec_module(M)


class OwnerLicenseDecisionTests(unittest.TestCase):
    def make_repo(self):
        temp = tempfile.TemporaryDirectory()
        root = Path(temp.name)
        subprocess.run(["git", "init", "-q", str(root)], check=True)
        subprocess.run(["git", "-C", str(root), "config", "user.email", "test@example.invalid"], check=True)
        subprocess.run(["git", "-C", str(root), "config", "user.name", "Ergaxiom Test"], check=True)
        policy_dir = root / "tools" / "release"
        policy_dir.mkdir(parents=True)
        policy = {
            "schema_version": "0.1.0",
            "policy_id": "ergaxiom.windows-production-release",
            "license": {
                "owner_decision_status": "APPROVED",
                "spdx_expression": "LicenseRef-Ergaxiom-Proprietary",
            },
        }
        (policy_dir / "windows_release_policy.json").write_text(json.dumps(policy), encoding="utf-8")
        (root / "LICENSE").write_text(
            "Ergaxiom Proprietary License\n\n"
            "Copyright (c) 2026. All rights reserved.\n\n"
            "SPDX-License-Identifier: LicenseRef-Ergaxiom-Proprietary\n",
            encoding="utf-8",
        )
        subprocess.run(["git", "-C", str(root), "add", "."], check=True)
        subprocess.run(["git", "-C", str(root), "commit", "-q", "-m", "fixture"], check=True)
        return temp, root, policy_dir / "windows_release_policy.json"

    def test_exact_clean_commit_is_bound(self):
        temp, root, policy = self.make_repo()
        self.addCleanup(temp.cleanup)
        result = M.build_decision(root, policy)
        head = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        self.assertEqual(result["source_commit"], head)
        self.assertTrue(result["owner_approved"])
        self.assertEqual(result["distribution_model"], "PROPRIETARY_ALL_RIGHTS_RESERVED")
        self.assertEqual(result["spdx_expression"], "LicenseRef-Ergaxiom-Proprietary")
        self.assertRegex(result["policy_sha256"], r"^[0-9a-f]{64}$")
        self.assertRegex(result["license_file_sha256"], r"^[0-9a-f]{64}$")
        self.assertRegex(result["decision_sha256"], r"^[0-9a-f]{64}$")

    def test_unapproved_policy_is_rejected(self):
        temp, root, policy = self.make_repo()
        self.addCleanup(temp.cleanup)
        value = json.loads(policy.read_text(encoding="utf-8"))
        value["license"]["owner_decision_status"] = "REQUIRED"
        policy.write_text(json.dumps(value), encoding="utf-8")
        subprocess.run(["git", "-C", str(root), "add", str(policy)], check=True)
        subprocess.run(["git", "-C", str(root), "commit", "-q", "-m", "unapproved"], check=True)
        with self.assertRaises(M.LicenseDecisionError):
            M.build_decision(root, policy)

    def test_tracked_dirty_worktree_is_rejected(self):
        temp, root, policy = self.make_repo()
        self.addCleanup(temp.cleanup)
        (root / "LICENSE").write_text("changed", encoding="utf-8")
        with self.assertRaises(M.LicenseDecisionError):
            M.build_decision(root, policy)

    def test_wrong_license_marker_is_rejected(self):
        temp, root, policy = self.make_repo()
        self.addCleanup(temp.cleanup)
        (root / "LICENSE").write_text(
            "All rights reserved.\nSPDX-License-Identifier: LicenseRef-Wrong\n",
            encoding="utf-8",
        )
        subprocess.run(["git", "-C", str(root), "add", "LICENSE"], check=True)
        subprocess.run(["git", "-C", str(root), "commit", "-q", "-m", "wrong marker"], check=True)
        with self.assertRaises(M.LicenseDecisionError):
            M.build_decision(root, policy)


if __name__ == "__main__":
    unittest.main()

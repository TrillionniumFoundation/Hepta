"""Recovery cannot rewrite the protocol or reuse an unrelated approval."""
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest

from experiments.hia_agent_local_recovery_20261103 import run_study as recovery


class RecoveryControls(unittest.TestCase):
    def test_changed_budget_model_order_or_hidden_feedback_refuses(self):
        original = (recovery.PARENT / "PROTOCOL.json").read_bytes()
        recovery.check_protocol((recovery.HERE / "PROTOCOL.json").read_bytes(), original)
        for key, value in (("attempts_per_cell", 3), ("max_output_tokens", 4096),
                           ("model_order", ["granite2b", "qwen_coder1_5b"]),
                           ("hidden", {"feedback": "supply after failure"})):
            changed = json.loads(original); changed[key] = value
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "exact v4"):
                recovery.check_protocol(json.dumps(changed).encode(), original)

    def test_owner_output_cannot_alias_the_measured_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); alias = root / "alias"
            alias.symlink_to(recovery.ROOT, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "outside source"):
                recovery.owner_path(alias / "registry")
            with self.assertRaisesRegex(ValueError, "absolute"):
                recovery.owner_path("relative-registry")
            self.assertEqual(recovery.owner_path(root / "registry"), root / "registry")

    def test_review_cannot_authorize_changed_registration_source_or_task_count(self):
        registration = {"source_commit": "a" * 40, "protocol_sha256": "b" * 64}
        good = {"decision": "allow_generation", "registration_sha256": "c" * 64,
                "source_commit": registration["source_commit"],
                "protocol_sha256": registration["protocol_sha256"],
                "model_task_requests_by_reviewer": 0}
        recovery.check_review(good, registration, "c" * 64)
        for key, value in (("decision", "deny"), ("registration_sha256", "d" * 64),
                           ("source_commit", "d" * 40), ("protocol_sha256", "d" * 64),
                           ("model_task_requests_by_reviewer", 1),
                           ("model_task_requests_by_reviewer", False)):
            changed = deepcopy(good); changed[key] = value
            with self.subTest(key=key, value=value), self.assertRaisesRegex(ValueError, "independent review"):
                recovery.check_review(changed, registration, "c" * 64)


if __name__ == "__main__":
    unittest.main()

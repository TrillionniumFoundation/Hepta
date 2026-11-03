"""Recovery cannot rewrite the protocol or reuse an unrelated approval."""
from copy import deepcopy
from contextlib import ExitStack
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

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

    def freeze_fixture(self, root):
        files = {"unit_controls": "UNIT_CONTROLS.json",
                 "reference_controls": "DEVELOPMENT_CONTROLS.json",
                 "hostile_controls": "HOSTILE_CONTROLS.json",
                 "tokenizer_capacity": "TOKENIZER_CAPACITY.json"}
        value = {"passed": True, "model_requests": 0, "source_commit": "a" * 40,
                 "source_tree": "b" * 40, "sources": {"fixture.py": "c" * 64}}
        for key, name in files.items():
            (root / name).write_text('{"fixture":"prepared"}\n')
            value[key] = recovery.file_identity(root / name)
        return value, files

    def freeze_with_controls(self, root, value, *, reject=False):
        (root / "PREPARATION.json").write_text(json.dumps(value))
        with ExitStack() as stack:
            stack.enter_context(patch.object(recovery, "activate", return_value=root))
            stack.enter_context(patch.object(recovery, "git", side_effect=lambda *args:
                "b" * 40 if args[-1] == "HEAD^{tree}" else "a" * 40))
            stack.enter_context(patch.object(recovery.inherited, "check_bindings", return_value=True))
            stack.enter_context(patch.object(recovery, "require_committed_sources"))
            register = stack.enter_context(patch.object(recovery.inherited, "register", return_value={}))
            stack.enter_context(patch.object(recovery, "validate_registration", return_value={"passed": True}))
            if reject:
                with self.assertRaises(ValueError):
                    recovery.freeze(root)
                register.assert_not_called()
                self.assertFalse((root / "REGISTRATION.json").exists())
            else:
                self.assertTrue(recovery.freeze(root)["passed"])
                register.assert_called_once_with()

    def test_exact_preparation_receipts_can_be_frozen(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            value, _ = self.freeze_fixture(root)
            self.freeze_with_controls(root, value)

    def test_changed_preparation_receipts_refuse_before_registration(self):
        for key in ("unit_controls", "reference_controls", "hostile_controls", "tokenizer_capacity"):
            with self.subTest(receipt=key), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                value, files = self.freeze_fixture(root)
                (root / files[key]).write_text('{"fixture":"replaced"}\n')
                self.freeze_with_controls(root, value, reject=True)

    def test_missing_or_rebound_preparation_identity_refuses(self):
        for mutation in (lambda v: v.pop("unit_controls"),
                         lambda v: v["reference_controls"].update(path="/different/DEVELOPMENT_CONTROLS.json"),
                         lambda v: v["hostile_controls"].update(bytes=1)):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                value, _ = self.freeze_fixture(root)
                mutation(value)
                self.freeze_with_controls(root, value, reject=True)

    def test_real_registration_preserves_preparation_receipts(self):
        # Synthetic passing controls exercise the real registration and replay
        # code. No compiler, tokenizer, model, or generation process is run.
        for changed in (False, True):
            with self.subTest(changed=changed), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                (root / "PROTOCOL.json").write_bytes((recovery.HERE / "PROTOCOL.json").read_bytes())
                payloads = {
                    "unit_controls": ("UNIT_CONTROLS.json", {"tests_run": 10,
                        "test_ids": ["fixture-" + str(i) for i in range(10)],
                        "failures": 0, "errors": 0, "skipped": 0, "passed": True,
                        "source_sha256": {}}),
                    "reference_controls": ("DEVELOPMENT_CONTROLS.json", {"count": 36, "passed": 36}),
                    "hostile_controls": ("HOSTILE_CONTROLS.json", {"count": 9, "passed": 9}),
                    "tokenizer_capacity": ("TOKENIZER_CAPACITY.json", {
                        "passed": True, "model_requests": 0, "models": [{}, {}]})}
                preparation = {"passed": True, "model_requests": 0,
                    "source_commit": "a" * 40, "source_tree": "b" * 40,
                    "sources": recovery.source_bindings()}
                for key, (name, payload) in payloads.items():
                    (root / name).write_text(json.dumps(payload))
                    preparation[key] = recovery.file_identity(root / name)
                (root / "PREPARATION.json").write_text(json.dumps(preparation))
                if changed:
                    name, payload = payloads["reference_controls"]
                    # Passing counters and JSON meaning stay unchanged, but
                    # these are not the exact bytes prepared for freezing.
                    (root / name).write_text(json.dumps(payload, indent=2))
                with ExitStack() as stack:
                    for name in ("HERE", "SCHEMA", "source_bindings", "validate_registration"):
                        stack.enter_context(patch.object(recovery.inherited, name,
                            getattr(recovery.inherited, name)))
                    stack.enter_context(patch.object(recovery, "git", side_effect=lambda *args:
                        "b" * 40 if args[-1] == "HEAD^{tree}" else "a" * 40))
                    stack.enter_context(patch.object(recovery, "require_committed_sources"))
                    if changed:
                        with self.assertRaisesRegex(ValueError, "prepared recovery receipt"):
                            recovery.freeze(root)
                        self.assertFalse((root / "REGISTRATION.json").exists())
                    else:
                        result = recovery.freeze(root)
                        self.assertEqual(result["campaign"], recovery.CAMPAIGN)
                        self.assertEqual(result["model_requests"], 0)
                        self.assertEqual(result["reference_controls_sha256"],
                            preparation["reference_controls"]["sha256"])
                        before = (root / "REGISTRATION.json").read_bytes()
                        fixtures_before = (root / "FIXTURES.json").read_bytes()
                        with self.assertRaisesRegex(ValueError, "registration already exists"):
                            recovery.freeze(root)
                        self.assertEqual((root / "REGISTRATION.json").read_bytes(), before)
                        self.assertEqual((root / "FIXTURES.json").read_bytes(), fixtures_before)

    def test_publisher_restored_and_failed_evidence_retained(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            value, _ = self.freeze_fixture(root)
            (root / "PREPARATION.json").write_text(json.dumps(value))
            original_publish = recovery.evaluator.save
            def fail_registration():
                recovery.evaluator.save(root / "FIXTURES.json", {"retained": "failure evidence"})
                raise RuntimeError("fixture registration failure")
            with ExitStack() as stack:
                stack.enter_context(patch.object(recovery, "activate", return_value=root))
                stack.enter_context(patch.object(recovery, "git", side_effect=lambda *args:
                    "b" * 40 if args[-1] == "HEAD^{tree}" else "a" * 40))
                stack.enter_context(patch.object(recovery.inherited, "check_bindings", return_value=True))
                stack.enter_context(patch.object(recovery, "require_committed_sources"))
                stack.enter_context(patch.object(recovery.inherited, "register", side_effect=fail_registration))
                with self.assertRaisesRegex(RuntimeError, "fixture registration failure"):
                    recovery.freeze(root)
            self.assertIs(recovery.evaluator.save, original_publish)
            self.assertFalse((root / "REGISTRATION.json").exists())
            self.assertEqual(json.loads((root / "FIXTURES.json").read_bytes()),
                             {"retained": "failure evidence"})

    def test_existing_registration_is_preserved_before_preparation_reads(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            registration = root / "REGISTRATION.json"
            registration.write_bytes(b"retained existing or partial registration\n")
            before = registration.read_bytes()
            with patch.object(recovery, "activate", return_value=root), \
                    patch.object(recovery.inherited, "register", side_effect=AssertionError("must not register")):
                with self.assertRaisesRegex(ValueError, "registration already exists"):
                    recovery.freeze(root)
            self.assertEqual(registration.read_bytes(), before)

    def test_preparation_requires_exact_tree_and_integer_zero_requests(self):
        for key, replacement in (("source_tree", "d" * 40), ("source_tree", None),
                                 ("model_requests", False), ("model_requests", 0.0)):
            with self.subTest(key=key, value=replacement), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                value, _ = self.freeze_fixture(root)
                value[key] = replacement
                self.freeze_with_controls(root, value, reject=True)

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

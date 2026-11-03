"""Recovery cannot rewrite the protocol or reuse an unrelated approval."""
from copy import deepcopy
from contextlib import ExitStack, contextmanager
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from experiments.hia_agent_local_recovery_20261103 import run_study as recovery


class RecoveryControls(unittest.TestCase):
    @contextmanager
    def prepared_registry(self):
        """Non-model evidence fixture; exercise the real v4 register and save."""
        with tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
            folder = Path(tmp) / "registry"; folder.mkdir()
            (folder / "PROTOCOL.json").write_bytes((recovery.PARENT / "PROTOCOL.json").read_bytes())
            source = recovery.PARENT / "fixtures.py"
            bindings = {str(source.relative_to(recovery.ROOT)): recovery.file_identity(source)["sha256"]}
            for name, value in {
                "UNIT_CONTROLS.json": {"tests_run": 10, "test_ids": list(range(10)),
                    "failures": 0, "errors": 0, "skipped": 0, "passed": True,
                    "source_sha256": {str(source): recovery.file_identity(source)["sha256"]}},
                "DEVELOPMENT_CONTROLS.json": {"count": 36, "passed": 36},
                "HOSTILE_CONTROLS.json": {"count": 9, "passed": 9},
                "TOKENIZER_CAPACITY.json": {"passed": True, "model_requests": 0, "models": [{}, {}]},
                "PREPARATION.json": {"passed": True, "model_requests": 0,
                    "source_commit": "a" * 40, "sources": bindings},
            }.items():
                recovery.evaluator.save(folder / name, value)
            # Restore globals so controls cannot retarget a real preparation.
            for name in ("HERE", "SCHEMA", "source_bindings", "validate_registration"):
                stack.enter_context(patch.object(recovery.inherited, name, getattr(recovery.inherited, name)))
            stack.enter_context(patch.object(recovery, "git", side_effect=lambda *args:
                "b" * 40 if args[-1] == "HEAD^{tree}" else "a" * 40))
            stack.enter_context(patch.object(recovery, "source_bindings", return_value=bindings))
            stack.enter_context(patch.object(recovery, "require_committed_sources"))
            yield folder

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


    def test_real_registration_publishes_all_metadata_once_and_refuses_existing(self):
        with self.prepared_registry() as folder:
            writer = recovery.evaluator.save
            with patch.object(recovery.inherited, "register", wraps=recovery.inherited.register) as register:
                value = recovery.freeze(folder)
                register.assert_called_once_with()
            self.assertIs(recovery.evaluator.save, writer)
            raw = (folder / "REGISTRATION.json").read_bytes()
            self.assertEqual(json.loads(raw), value)
            self.assertFalse((folder / "REGISTRATION.candidate.json").exists())
            self.assertEqual(value["campaign"], recovery.CAMPAIGN)
            self.assertEqual(value["source_commit"], "a" * 40)
            self.assertEqual(value["source_tree"], "b" * 40)
            self.assertEqual(value["inherited_protocol_sha256"], recovery.file_identity(recovery.PARENT / "PROTOCOL.json")["sha256"])
            self.assertEqual(value["preparation"], recovery.file_identity(folder / "PREPARATION.json"))
            self.assertFalse(value["original_campaigns_replaced"])
            self.assertFalse(value["frontier_model_cohort_completed"])
            self.assertTrue(value["before_any_model_requests"])
            self.assertEqual(value["model_requests"], 0)
            with self.assertRaisesRegex(ValueError, "registration already exists"):
                recovery.freeze(folder)
            self.assertEqual((folder / "REGISTRATION.json").read_bytes(), raw)

    def test_registration_serialization_failure_restores_writer_without_final_file(self):
        with self.prepared_registry() as folder:
            writer = recovery.evaluator.save
            with patch.object(recovery, "canonical", side_effect=TypeError("unserializable metadata")):
                with self.assertRaisesRegex(TypeError, "unserializable"):
                    recovery.freeze(folder)
            self.assertIs(recovery.evaluator.save, writer)
            self.assertTrue((folder / "FIXTURES.json").is_file())
            self.assertFalse((folder / "REGISTRATION.json").exists())
            self.assertFalse((folder / "REGISTRATION.candidate.json").exists())
            with self.assertRaises(FileNotFoundError):
                recovery.validate_registration()

    def test_registration_publication_failure_or_race_cannot_admit_partial_state(self):
        for owner_race in (False, True):
            with self.subTest(owner_race=owner_race), self.prepared_registry() as folder:
                writer, real_link = recovery.evaluator.save, recovery.os.link
                def fail_or_race(source, target):
                    if owner_race:
                        Path(target).write_bytes(b"existing owner file\n")
                        return real_link(source, target)
                    raise OSError("publication unavailable")
                with patch.object(recovery.os, "link", side_effect=fail_or_race):
                    with self.assertRaises(OSError):
                        recovery.freeze(folder)
                self.assertIs(recovery.evaluator.save, writer)
                candidate = json.loads((folder / "REGISTRATION.candidate.json").read_bytes())
                self.assertEqual(candidate["campaign"], recovery.CAMPAIGN)
                self.assertEqual(candidate["source_commit"], "a" * 40)
                if owner_race:
                    self.assertEqual((folder / "REGISTRATION.json").read_bytes(), b"existing owner file\n")
                else:
                    self.assertFalse((folder / "REGISTRATION.json").exists())
                with self.assertRaises((FileNotFoundError, ValueError)):
                    recovery.validate_registration()


if __name__ == "__main__":
    unittest.main()

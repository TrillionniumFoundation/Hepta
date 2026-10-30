"""Maintenance evidence must reject changed upstreams, integration, or samples."""
import copy
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from tools.qualify_ring_maintenance import (
    FIXTURE, PROTOCOL_PATH, Trial, identity, make_wrapper, qualify, tail_oracle,
    validate_observation, verify_upstream,
)


class RingMaintenanceQualificationTests(unittest.TestCase):
    def test_whole_git_tree_rejects_changed_executable_mode(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory) / "fixture"
            shutil.copytree(FIXTURE, fixture)
            manifest = json.loads((fixture / "UPSTREAM.json").read_text())
            row = next(x for x in manifest["versions"][0]["files"] if x["mode"] == "100755")
            row["mode"] = "100644"
            (fixture / "UPSTREAM.json").write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError, "Git tree mismatch"):
                verify_upstream(fixture)

    def test_upstream_blob_change_cannot_be_hidden_by_unchanged_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory) / "fixture"
            shutil.copytree(FIXTURE, fixture)
            blob = fixture / "blobs/86ef21324dd9323129f761c0f18e8ca6cb864399"
            blob.write_bytes(blob.read_bytes().replace(b"int c;", b"char c;"))
            with self.assertRaisesRegex(ValueError, "blob mismatch"):
                verify_upstream(fixture)

    def test_historical_bug_is_not_silently_corrected(self):
        self.assertEqual(tail_oracle(b"a\xffb", "before"), b"a")
        self.assertEqual(tail_oracle(b"a\xffb", "after"), b"a\xffb")
        self.assertEqual(tail_oracle(bytes(range(32)), "after"), bytes(range(17, 32)))
        with self.assertRaisesRegex(ValueError, "unknown upstream revision"):
            tail_oracle(b"a", "invented-release")

    def integration(self, root):
        compiler = root / "compiler"
        compiler.write_text("#!" + sys.executable + "\nimport json,sys\nprint(json.dumps(sys.argv[1:]))\n")
        compiler.chmod(0o700)
        original, library = root / "ringbuffer.c", root / "translated.so"
        original.write_text("original C implementation")
        library.write_bytes(b"translated implementation identity")
        wrapper, _ = make_wrapper(root, cc=compiler, original=original, library=library)
        return wrapper, original, library

    def test_cc_integration_preserves_client_and_flags_and_replaces_only_implementation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            wrapper, original, library = self.integration(root)
            result = subprocess.run([sys.executable, str(wrapper), "-Wall", "-g", "-O2", "-std=c99",
                "-o", "tail", "tail.c", str(original)], cwd=root, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            arguments = json.loads(result.stdout)
            self.assertEqual(arguments[:-2], ["-Wall", "-g", "-O2", "-std=c99", "-o", "tail", "tail.c"])
            self.assertEqual(arguments[-2], str(library))
            self.assertNotIn(str(original), arguments)
            receipt = json.loads((root / "cc-invocations.jsonl").read_text())
            self.assertEqual(receipt["replacement"], identity(library))

    def test_changed_translated_library_is_refused_before_compiler_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            wrapper, original, library = self.integration(root)
            library.write_bytes(b"substituted code")
            result = subprocess.run([sys.executable, str(wrapper), "-o", "tail", "tail.c", str(original)],
                                    cwd=root, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("identity changed", result.stderr)
            self.assertFalse((root / "cc-invocations.jsonl").exists())

    def test_duplicate_implementation_input_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            wrapper, original, _ = self.integration(root)
            result = subprocess.run([sys.executable, str(wrapper), "-o", "tail", str(original), str(original)],
                                    cwd=root, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("exactly one", result.stderr)
            self.assertFalse((root / "cc-invocations.jsonl").exists())

    def test_incomplete_or_wrong_work_cannot_enter_host_summary(self):
        protocol = json.loads(PROTOCOL_PATH.read_text())
        profile = protocol["concurrency_profiles"][0]
        expected = ([1234], [5678])
        observation = {"threads": 1, "shared": False, "batches_per_thread": 128,
            "transactions_per_batch": 128, "transactions": 16384, "checksums": [1234],
            "bytes_per_thread": [5678], "batch_ns": [99] * 128, "whole_run_ns": 99999}
        validate_observation(observation, profile, protocol, expected)
        for key, value in (("transactions", 0), ("checksums", [0]), ("batch_ns", [99] * 127), ("threads", True)):
            with self.subTest(key=key):
                wrong = copy.deepcopy(observation)
                wrong[key] = value
                with self.assertRaises(ValueError):
                    validate_observation(wrong, profile, protocol, expected)

    def test_wrong_source_head_retains_failure_and_no_completed_claims(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "qualification.json"
            with self.assertRaisesRegex(ValueError, "source-sha"):
                qualify(output, clang="missing-clang", rustc="missing-rustc", source_sha="0" * 40)
            report = json.loads(output.read_text())
            self.assertFalse(report["ok"])
            self.assertEqual(report["stage"], "failed")
            self.assertTrue(all(value is False for value in report["claims"].values()))
            self.assertEqual(report["host_samples"], [])
            self.assertEqual(report["versions"], {})

    def test_late_failure_resets_completed_claims(self):
        def fail_after_observations(trial):
            trial.report["ok"] = True
            trial.report["claims"]["real_upstream_upgrade_executed"] = True
            raise ValueError("late source revalidation failed")
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "qualification.json"
            with mock.patch.object(Trial, "run", fail_after_observations):
                with self.assertRaisesRegex(ValueError, "late source"):
                    qualify(output, clang="missing-clang", rustc="missing-rustc")
            report = json.loads(output.read_text())
            self.assertFalse(report["ok"])
            self.assertTrue(all(value is False for value in report["claims"].values()))


if __name__ == "__main__":
    unittest.main()

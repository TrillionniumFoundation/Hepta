"""Finite foreign-process checkpoints, actual destructor faults and refusal."""
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import pickle
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import hepta.cpp_json_checkpoint as checkpoint
from hepta.clang_capture import CaptureFailure, CaptureRejected, CaptureResult, run_bounded
import tools.qualify_cpp_json_checkpoint as qualifier
from tools.qualify_cpp_json_checkpoint import qualify, validate_report, _validate_call


def fake_image():
    # Unit protocol tests only. Production images are issued by the real bridge
    # builder; this private test fixture is never counted as a native result.
    data = bytearray(64)
    data[:6] = b"\x7fELF\x02\x01"
    struct.pack_into("<HH", data, 16, 2, 62)
    return checkpoint._issue_worker_image(bytes(data), "3.12.0", "a" * 64)


def response(options, change=None, *, stderr=b"", returncode=0):
    launch = json.loads(options["input_text"])
    request = launch["request"]
    values = request["values"].copy(); values[request["index"]] = request["value"]
    result = {"schema": checkpoint.WORKER_SCHEMA, "version": request["version"],
              "nonce": request["nonce"], "request_sha256": launch["request_sha256"],
              "revision": request["revision"], "sequence": request["sequence"],
              "status": 0, "result": sum(values), "allocation_attempts": 17,
              "failure_injected": False, "live_delta": 0}
    if change:
        change(result)
    raw = json.dumps(result).encode() + b"\n"
    return CaptureResult(returncode, raw.decode(), stderr.decode(), raw, stderr)


class JsonCheckpointProtocolTests(unittest.TestCase):
    def test_exact_input_domain_and_stale_revision_reject_before_launch(self):
        with patch.object(checkpoint, "run_bounded") as launch:
            for values in ([], [0] * 65, [True], [1.0], [1000001], [-1000001], iter([1])):
                with self.subTest(values=repr(values)), self.assertRaises(checkpoint.CheckpointRejected):
                    checkpoint.JsonCheckpoint(fake_image(), values)
            owner = checkpoint.JsonCheckpoint(fake_image(), [1, 2, 3])
            for index, value, revision, site in ((True, 1, 0, 0), (3, 1, 0, 0), (0, True, 0, 0),
                                                (0, 1000001, 0, 0), (0, 1, True, 0), (0, 1, 1, 0),
                                                (0, 1, 0, True), (0, 1, 0, 128)):
                with self.subTest(index=index, value=value, revision=revision, site=site), self.assertRaises(checkpoint.CheckpointRejected):
                    owner.prepare(index, value, revision=revision, fault_site=site)
            launch.assert_not_called()

    def test_identity_one_use_and_diagnostic_snapshots_do_not_grant_authority(self):
        values = [1, 2, 3]
        owner = checkpoint.JsonCheckpoint(fake_image(), values)
        values[0] = 99
        diagnostic = owner.snapshot(); diagnostic["values"][0] = 88
        request = owner.prepare(1, 5, revision=0)
        other = checkpoint.JsonCheckpoint(fake_image(), [1, 2, 3])
        with self.assertRaises(checkpoint.CheckpointRejected):
            other.execute(request)
        with patch.object(checkpoint, "run_bounded", side_effect=lambda argv, **kw: response(kw)) as launch:
            observed = owner.execute(request)
            self.assertEqual(observed["after"]["values"], [1, 5, 3])
            for token in (request, observed, observed["request"]):
                with self.assertRaises(checkpoint.CheckpointRejected):
                    owner.execute(token)
            with self.assertRaises(checkpoint.CheckpointRejected):
                owner.prepare(0, 7, revision=0)
            launch.assert_called_once()

    def test_owner_request_and_image_cannot_be_deserialized_as_authority(self):
        image = fake_image()
        owner = checkpoint.JsonCheckpoint(image, [1])
        request = owner.prepare(0, 2, revision=0)
        for value in (owner, request):
            for action in (copy.copy, copy.deepcopy, pickle.dumps):
                with self.subTest(value=type(value).__name__, action=action.__name__), self.assertRaises(TypeError):
                    action(value)
        with self.assertRaises(TypeError):
            pickle.dumps(image)
        with self.assertRaises(checkpoint.CheckpointRejected):
            checkpoint.JsonWorkerImage(image._bytes, image.version, image.build_sha256)
        with self.assertRaises(checkpoint.CheckpointRejected):
            checkpoint.CheckpointRequest(object(), b"{}")

    def test_changed_pending_request_is_rejected_without_execution(self):
        owner = checkpoint.JsonCheckpoint(fake_image(), [1, 2, 3])
        request = owner.prepare(1, 5, revision=0)
        object.__setattr__(request, "_body", b"{}")
        with patch.object(checkpoint, "run_bounded") as launch, self.assertRaises(checkpoint.CheckpointRejected):
            owner.execute(request)
        launch.assert_not_called()
        self.assertEqual(owner.snapshot()["revision"], 0)

    def test_cancelled_requests_still_consume_the_finite_lifetime_budget(self):
        owner = checkpoint.JsonCheckpoint(fake_image(), [1])
        first = None
        for _ in range(checkpoint.MAX_REQUESTS):
            request = owner.prepare(0, 2, revision=0)
            first = first or request
            owner.cancel(request)
        with self.assertRaises(checkpoint.CheckpointRejected):
            owner.prepare(0, 2, revision=0)
        with self.assertRaises(checkpoint.CheckpointRejected):
            owner.execute(first)
        self.assertEqual(owner.snapshot()["issued_requests"], 128)
        self.assertEqual(owner.history(), [])

    def test_reentrant_mutation_is_refused_before_revising_or_reusing_a_request(self):
        owner = checkpoint.JsonCheckpoint(fake_image(), [1, 2, 3])
        request = owner.prepare(1, 5, revision=0)
        def reenter(argv, **options):
            for action in (lambda: owner.prepare(0, 9, revision=0), lambda: owner.cancel(request),
                           lambda: owner.execute(request), owner.close):
                with self.assertRaises(checkpoint.CheckpointRejected):
                    action()
            self.assertEqual(owner.snapshot()["values"], [1, 2, 3])
            return response(options)
        with patch.object(checkpoint, "run_bounded", side_effect=reenter) as launch:
            result = owner.execute(request)
        self.assertTrue(result["committed"])
        self.assertEqual(owner.snapshot()["issued_requests"], 1)
        launch.assert_called_once()

    def test_malformed_wrong_stale_noisy_or_untyped_frames_never_commit(self):
        changes = {
            "result": lambda r: r.update(result=999), "bool_result": lambda r: r.update(result=True),
            "nonce": lambda r: r.update(nonce="0" * 32), "request": lambda r: r.update(request_sha256="0" * 64),
            "revision": lambda r: r.update(revision=1), "sequence": lambda r: r.update(sequence=2),
            "version": lambda r: r.update(version="3.11.3"), "status": lambda r: r.update(status=False),
            "allocation": lambda r: r.update(allocation_attempts=True), "leak": lambda r: r.update(live_delta=1),
            "injected_success": lambda r: r.update(failure_injected=True), "new_claim": lambda r: r.update(safe=True),
        }
        for name, change in changes.items():
            owner = checkpoint.JsonCheckpoint(fake_image(), [1, 2, 3])
            with self.subTest(name=name), patch.object(checkpoint, "run_bounded", side_effect=lambda argv, _change=change, **kw: response(kw, _change)):
                observed = owner.execute(owner.prepare(1, 5, revision=0))
                self.assertEqual(observed["status"], "protocol_refused")
                self.assertTrue(observed["state_preserved"] and observed["poisoned"])
        for mode in ("partial", "duplicate", "stderr", "boolean_wait"):
            owner = checkpoint.JsonCheckpoint(fake_image(), [1, 2, 3])
            def malformed(argv, **kw):
                result = response(kw, stderr=b"unexpected\n" if mode == "stderr" else b"",
                                  returncode=False if mode == "boolean_wait" else 0)
                if mode == "partial":
                    return CaptureResult(0, "{", "", b"{", b"")
                if mode == "duplicate":
                    raw = result.raw_stdout[:-2] + b',"result":9}\n'
                    return CaptureResult(0, raw.decode(), "", raw, b"")
                return result
            with self.subTest(mode=mode), patch.object(checkpoint, "run_bounded", side_effect=malformed):
                observed = owner.execute(owner.prepare(1, 5, revision=0))
                self.assertFalse(observed["committed"])
                self.assertTrue(observed["state_preserved"] and observed["poisoned"])

    def test_cleanup_uncertainty_poison_is_not_downgraded_by_partial_bytes(self):
        owner = checkpoint.JsonCheckpoint(fake_image(), [1, 2, 3])
        error = CaptureRejected("E_CAPTURE_TIMEOUT", "actual ownership is uncertain")
        error.capture = CaptureFailure(("owned",), -9, b'{"partial":', b"", 11, 0)
        error.capture_error = "E_CAPTURE_CLEANUP: leader reap unconfirmed"
        with patch.object(checkpoint, "run_bounded", side_effect=error) as launch:
            observed = owner.execute(owner.prepare(1, 5, revision=0))
            self.assertTrue(observed["poisoned"] and observed["state_preserved"])
            self.assertFalse(observed["direct_child_reaped"])
            with self.assertRaises(checkpoint.CheckpointRejected):
                owner.prepare(1, 5, revision=0)
            launch.assert_called_once()

    def test_interruption_retains_attempt_and_cost_and_requires_fail_closed_owner(self):
        owner = checkpoint.JsonCheckpoint(fake_image(), [1, 2, 3])
        with patch.object(checkpoint, "run_bounded", side_effect=KeyboardInterrupt), self.assertRaises(KeyboardInterrupt):
            owner.execute(owner.prepare(1, 5, revision=0))
        record = owner.history()[0]
        self.assertEqual(record["status"], "interrupted")
        self.assertGreater(record["wall_ns"], 0)
        self.assertTrue(owner.snapshot()["poisoned"])
        with self.assertRaises(checkpoint.CheckpointRejected):
            owner.prepare(1, 5, revision=0)
        owner.close()

    def test_publication_failure_preserves_commit_and_marks_same_history_poisoned(self):
        owner = checkpoint.JsonCheckpoint(fake_image(), [1, 2, 3])
        request = owner.prepare(1, 5, revision=0)
        wire = checkpoint._wire
        def fail_publication(value):
            if type(value) is dict and value.get("status") == "committed" and "after" in value:
                raise RuntimeError("injected return-value publication failure")
            return wire(value)
        with patch.object(checkpoint, "run_bounded", side_effect=lambda argv, **kw: response(kw)) as launch:
            with patch.object(checkpoint, "_wire", side_effect=fail_publication), self.assertRaises(RuntimeError):
                owner.execute(request)
            record = owner.history()[0]
            self.assertEqual(record["status"], "committed")
            self.assertTrue(record["committed"] and record["poisoned"])
            self.assertFalse(record["state_preserved"])
            self.assertEqual(record["after"]["revision"], 1)
            self.assertEqual(record["after"]["values"], [1, 5, 3])
            self.assertEqual(record["publication_failure"],
                             {"type": "RuntimeError", "checkpoint_committed": True})
            self.assertGreater(record["wall_ns"], 0)
            self.assertTrue(owner.snapshot()["poisoned"])
            self.assertEqual(owner.snapshot()["values"], record["after"]["values"])
            for action in (lambda: owner.prepare(1, 6, revision=1), lambda: owner.execute(request)):
                with self.assertRaises(checkpoint.CheckpointRejected):
                    action()
            launch.assert_called_once()

    @unittest.skipUnless(sys.platform == "linux", "qualified Linux process owner required")
    def test_actual_complete_frame_followed_by_nonzero_exit_cannot_commit(self):
        owner = checkpoint.JsonCheckpoint(fake_image(), [1, 2, 3])
        def exit_after_frame(argv, **options):
            raw = response(options).raw_stdout
            script = "import os,resource,sys;resource.setrlimit(resource.RLIMIT_CORE,(0,0));sys.stdout.buffer.write(" + repr(raw) + ");sys.stdout.flush();os.abort()"
            # This control must actually reach os.abort(), not confuse a
            # 3-second overloaded-runner startup timeout with SIGABRT. The
            # separate partial-frame test below exercises the production
            # 3-second timeout without widening JsonCheckpoint's budget.
            return run_bounded([sys.executable, "-I", "-c", script],
                               **{**options, "timeout": 12})
        with patch.object(checkpoint, "run_bounded", side_effect=exit_after_frame):
            observed = owner.execute(owner.prepare(1, 5, revision=0))
        self.assertEqual(observed["returncode"], -6)
        self.assertEqual(observed["status"], "process_failed")
        self.assertTrue(observed["direct_child_reaped"])
        self.assertGreater(observed["stdout"]["bytes"], 0)
        self.assertTrue(observed["state_preserved"])
        self.assertTrue(observed["poisoned"])
        self.assertFalse(observed["committed"])

    @unittest.skipUnless(sys.platform == "linux", "qualified Linux process owner required")
    def test_actual_timeout_keeps_partial_bytes_and_only_fresh_request_can_continue(self):
        owner = checkpoint.JsonCheckpoint(fake_image(), [1, 2, 3])
        def partial(argv, **options):
            script = 'import sys,time;sys.stdout.write(' + repr('{"schema":') + ');sys.stdout.flush();time.sleep(10)'
            return run_bounded([sys.executable, "-I", "-c", script], **options)
        request = owner.prepare(1, 5, revision=0)
        with patch.object(checkpoint, "run_bounded", side_effect=partial):
            observed = owner.execute(request)
        self.assertEqual(observed["capture_code"], "E_CAPTURE_TIMEOUT")
        self.assertGreater(observed["stdout"]["bytes"], 0)
        self.assertTrue(observed["state_preserved"] and observed["direct_child_reaped"])
        self.assertFalse(observed["poisoned"])
        with self.assertRaises(checkpoint.CheckpointRejected):
            owner.execute(request)
        with patch.object(checkpoint, "run_bounded", side_effect=lambda argv, **kw: response(kw)):
            resumed = owner.execute(owner.prepare(1, 5, revision=0))
        self.assertTrue(resumed["committed"])
        self.assertNotEqual(resumed["request_sha256"], observed["request_sha256"])

    def test_false_formal_source_identity_refuses_before_native_builder(self):
        with tempfile.TemporaryDirectory() as temp, patch("tools.qualify_cpp_json_checkpoint.build_json_checkpoint_image") as build:
            result = qualify(Path(temp) / "rejected", expected_head="0" * 40)
        self.assertFalse(result["ok"])
        self.assertEqual(result["versions"], [])
        build.assert_not_called()

    def test_original_source_audit_accepts_docs_child_but_rejects_changed_raw_ledger(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            def git(*args):
                return subprocess.check_output(["git", *args], cwd=root, stderr=subprocess.PIPE).decode().strip()
            git("init", "-q")
            for name in ("hepta/cpp_json_checkpoint.py", "tools/qualify_cpp_json_checkpoint.py",
                         "examples/cpp/upgrade/recovery_worker.cpp", "tests/fixtures/cpp_upgrade/lock.json"):
                path = root / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_text("original source bytes\n")
            git("add", ".")
            git("-c", "user.name=Hepta Test", "-c", "user.email=hepta-test@example.invalid", "commit", "-qm", "original source")
            original = git("rev-parse", "HEAD")
            with patch.object(qualifier, "ROOT", root):
                snapshot = qualifier.source_state(original)
                (root / "delivery.md").write_text("documentation only\n")
                git("add", "delivery.md")
                git("-c", "user.name=Hepta Test", "-c", "user.email=hepta-test@example.invalid", "commit", "-qm", "documentation child")
                with self.assertRaises(ValueError):
                    qualifier.source_state(original)
                accepted = qualifier._original_source_objects(snapshot, original)
                self.assertEqual(accepted["head"], original)
                self.assertNotEqual(git("rev-parse", "HEAD"), original)
                for change in (lambda r: r["files"].update({"hepta/cpp_json_checkpoint.py": "0" * 64}),
                               lambda r: r["files"].pop("hepta/cpp_json_checkpoint.py"),
                               lambda r: r.update(tree="0" * 40),
                               lambda r: r.update(raw_tree_binding_checked=False)):
                    bad = copy.deepcopy(snapshot); change(bad)
                    with self.assertRaises(ValueError):
                        qualifier._original_source_objects(bad, original)


NATIVE = sys.platform == "linux" and shutil.which("g++") and shutil.which(os.environ.get("RUSTC", "rustc"))


@unittest.skipUnless(NATIVE, "actual pinned native C++/Rust tools required")
class JsonCheckpointNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        retained = os.environ.get("HEPTA_CPP_JSON_CHECKPOINT_EVIDENCE")
        if retained:
            cls.root = Path(retained)
            cls.root.mkdir(parents=True, exist_ok=False)
        else:
            temporary = tempfile.TemporaryDirectory(prefix="hepta-json-checkpoint-")
            cls.addClassCleanup(temporary.cleanup)
            cls.root = Path(temporary.name)
        cls.report = qualify(cls.root / "qualification", rustc=os.environ.get("RUSTC"))
        cls.extra = []
        if not cls.report["ok"]:
            raise AssertionError(json.dumps({k: v for k, v in cls.report.items() if k in {"status", "error", "versions"}}))

    @classmethod
    def tearDownClass(cls):
        (cls.root / "additional-native.json").write_text(json.dumps(cls.extra, sort_keys=True, indent=2) + "\n")

    def test_real_two_versions_keep_every_foreign_failure_and_reconstruct_parent_state(self):
        result = validate_report(self.report)
        self.assertEqual(result["actual_allocation_sites"], 34)
        self.assertEqual(result["foreign_sigabrt"], 6)
        self.assertEqual(result["fresh_request_reconstructions"], 34)
        self.assertEqual(result["worker_processes"], 146)
        for version in self.report["versions"]:
            self.assertEqual(version["counts"]["foreign_caught_exceptions"], 14)
            terminating = [r for r in version["faults"] if r["foreign_outcome"] == "foreign_noexcept_termination"]
            self.assertEqual([r["site"] for r in terminating], [15, 16, 17])
            self.assertTrue(all(r["foreign_recovery_qualified"] is False for r in terminating))

    def test_actual_build_retains_scoped_abi_and_destructor_before_output(self):
        for version in self.report["versions"]:
            checks = version["build"]["bridge"]["scoped_lifetime_checks"]
            self.assertEqual(len(checks), 1)
            self.assertTrue(checks[0]["output_published_after_destructor"])
            self.assertFalse(checks[0]["object_handle_exported"])
            self.assertFalse(checks[0]["foreign_implementation_rewritten"])

    def test_real_immutable_worker_snapshot_survives_mutation_of_untrusted_copy_path(self):
        build = self.report["versions"][1]["build"]
        data = (Path(build["directory"]) / "json-checkpoint-worker").read_bytes()
        self.assertEqual(hashlib.sha256(data).hexdigest(), build["image_sha256"])
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "copy"
            path.write_bytes(data)
            image = checkpoint._issue_worker_image(path.read_bytes(), "3.12.0", build["build_sha256"])
            path.write_bytes(b"replaced, never executable authority")
            owner = checkpoint.JsonCheckpoint(image, [1, 2, 3])
            result = owner.execute(owner.prepare(1, 5, revision=0))
            self.extra.append(result)
            self.assertTrue(result["committed"])
            self.assertEqual(result["after"]["values"], [1, 5, 3])
            owner.close()

    def test_readback_rejects_count_source_state_request_raw_or_scope_mutations(self):
        mutate = {
            "missing_version": lambda r: r["versions"].pop(),
            "missing_site": lambda r: r["versions"][0]["faults"].pop(),
            "invented_recovery": lambda r: r["versions"][0]["faults"][-1].update(foreign_recovery_qualified=True),
            "lost_abort": lambda r: r["versions"][0]["counts"].update(foreign_sigabrt=0),
            "source_changed": lambda r: r["source_after"].update(head="0" * 40),
            "false_formal": lambda r: r.update(development_only=False),
            "unknown_claim": lambda r: r.update(all_foreign_safe=True),
            "cpp_rewrite": lambda r: r["claims"].update(foreign_library_rewritten=True),
            "zero_human_cost": lambda r: r.update(human_effort=0),
            "negative_cost": lambda r: r["versions"][0].update(wall_ns=-1),
            "lost_measured_cost": lambda r: r.update(wall_ns=1),
            "wrong_worker": lambda r: r["versions"][0]["build"].update(image_sha256="0" * 64),
            "duplicate_call_credit": lambda r: r["versions"][0]["faults"][0].update(recovery=r["versions"][0]["faults"][1]["recovery"]),
            "forged_summary": lambda r: r["readback"].update(foreign_sigabrt=0),
            "changed_state": lambda r: r["versions"][0]["calls"][0]["execution"]["after"]["values"].__setitem__(0, 99),
            "changed_nonce": lambda r: r["versions"][0]["calls"][0]["execution"]["request"].update(nonce="0" * 32),
        }
        for name, change in mutate.items():
            with self.subTest(name=name):
                candidate = copy.deepcopy(self.report); change(candidate)
                with self.assertRaises((ValueError, KeyError, TypeError)):
                    validate_report(candidate)

    def test_embedded_raw_frame_binding_is_checked_without_rerunning_native(self):
        row = self.report["versions"][0]
        original = row["calls"][0]["execution"]
        for field, value in (("nonce", "0" * 32), ("revision", 99), ("result", True),
                             ("status", False), ("live_delta", False), ("request_sha256", "0" * 64)):
            with self.subTest(field=field):
                candidate = copy.deepcopy(original)
                candidate["observation"][field] = value
                raw = json.dumps(candidate["observation"]).encode()
                candidate["stdout"] = {"base64": base64.b64encode(raw).decode(), "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
                with self.assertRaises((ValueError, KeyError, TypeError)):
                    _validate_call(candidate, row["build"]["image_sha256"], row["build"]["build_sha256"], row["version"])


if __name__ == "__main__":
    unittest.main()

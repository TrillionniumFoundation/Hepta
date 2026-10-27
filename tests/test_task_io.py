import base64
import copy
from pathlib import Path
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

from hepta.backend import find_rustc
from hepta.ast import HeptaError
from hepta.pipeline import analyze, analyze_project, concurrent_ir_analysis, resource_ir_analysis
from tools import qualify_task_io as q


def rust_path():
    try:
        return find_rustc(os.environ.get("RUSTC"))
    except (ValueError, OSError, RuntimeError, HeptaError):
        return None


RUSTC = rust_path()


class TaskIoSourceTests(unittest.TestCase):
    def test_source_examples_use_existing_checker_and_explicit_pool_contract(self):
        for name in q.SCENARIOS:
            with self.subTest(name=name):
                checked = analyze_project(q.ROOT / f"examples/task_io/{name}.hepta", native=False, crate_type="bin")
                self.assertTrue(checked.report["ok"], checked.report)
                contracts = checked.report["resource_contracts"]
                pool = next(x for x in contracts if x["kind"] == "task_tree_io_pool")
                attach = next(x for x in contracts if x["kind"] == "task_worker_io_attachment")
                self.assertIn("reserved_endpoint_slots_including_wake_pair", pool["limits"])
                self.assertTrue(pool["includes_completed_uncollected_requests"])
                self.assertEqual(attach["authority"], "nonconstructible_read_Sender_u64")
                self.assertIn("process_RSS", pool["excludes"])
                self.assertIn("async_await", attach["excludes"])
                self.assertIn("impl Drop for HeptaIoReactor", checked.rust)

    def test_unsafe_ownership_effect_and_authority_examples_are_rejected(self):
        for name, (source, code) in q.REJECTIONS.items():
            with self.subTest(name=name):
                report = analyze(source, native=False).report
                self.assertFalse(report["ok"])
                self.assertIn(code, [row["code"] for row in report["diagnostics"]])

    def test_new_protocol_is_not_silently_admitted_to_old_independent_ir(self):
        sources = ["struct Snapshot{value:GroupIoReport} fn f()->Unit effects {}{}",
                   (q.ROOT / "examples/task_io/pipeline.hepta").read_text()]
        for source in sources:
            with self.subTest(source=source[:35]):
                analysis = analyze(source, native=False)
                self.assertTrue(analysis.report["ok"], analysis.report)
                resource = resource_ir_analysis(analysis)
                concurrent = concurrent_ir_analysis(analysis)
                self.assertFalse(resource["ok"]); self.assertIsNone(resource["resource_ir"])
                self.assertFalse(concurrent["ok"]); self.assertIsNone(concurrent["concurrent_ir"])
                self.assertFalse(analyze(source, backend="c", native=False).report["ok"])

    def test_task_binding_is_inserted_only_with_both_runtime_profiles(self):
        io = analyze("fn main()->Unit effects {alloc,block,panic,io,write}{let io=io_reactor(2,1,8);io_shutdown(move io);}", native=False)
        self.assertTrue(io.report["ok"], io.report)
        self.assertNotIn("struct IoWorkerBinding", io.rust)
        group = analyze("fn main()->Unit effects {alloc,block,panic,write}{let g=task_group(0,0,1);group_tree_join(move g);}", native=False)
        self.assertTrue(group.report["ok"], group.report)
        self.assertNotIn("mod __hepta_io_runtime", group.rust)


class TaskIoFailureRetentionTests(unittest.TestCase):
    def test_timeout_keeps_non_utf8_partial_bytes_and_actual_plan(self):
        with tempfile.TemporaryDirectory() as directory:
            row = {}; checkpoints = []
            failure = subprocess.TimeoutExpired(["fixture"], 2, output=b"started\xff", stderr=b"error\xfe")
            with mock.patch.object(q.subprocess, "run", side_effect=failure):
                q._run(["fixture"], Path(directory) / "stage", row, lambda: checkpoints.append(copy.deepcopy(row)), 2)
            self.assertEqual(row["status"], "timed_out")
            self.assertTrue(row["timed_out"]); self.assertIsNone(row["returncode"])
            self.assertEqual(row["argv"], ["fixture"])
            self.assertEqual(base64.b64decode(row["stdout"]["base64"]), b"started\xff")
            self.assertEqual(Path(row["stderr"]["path"]).read_bytes(), b"error\xfe")
            self.assertIsNone(row["stdout"]["text"])
            self.assertEqual(checkpoints[0]["status"], "running")
            self.assertEqual(checkpoints[-1], row)

    def test_middle_compile_timeout_retains_all_case_denominators_and_continues(self):
        # These tools are explicit synthetic unit-test bytes, never executed.
        # The deliberately failed report cannot become native-pass evidence.
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory); rust = directory / "rustc"; cc = directory / "gcc"
            rust.write_bytes(b"unit-test-compiler"); cc.write_bytes(b"unit-test-c-compiler")
            target = directory / "report.json"; observed = []

            def process(command, **kwargs):
                observed.append(command)
                if command[-1] == "-vV":
                    return subprocess.CompletedProcess(command, 0, b"rustc 1.90.0 (test)\nhost: x86_64-unknown-linux-gnu\n", b"")
                if command[-1] == "--version":
                    return subprocess.CompletedProcess(command, 0, b"unit-test C compiler\n", b"")
                if command[0] == str(cc):
                    Path(command[-1]).write_bytes(b"synthetic-object")
                    return subprocess.CompletedProcess(command, 0, b"", b"")
                if any(str(item).endswith("pipeline.rs") for item in command):
                    raise subprocess.TimeoutExpired(command, 30, output=b"compile-prefix\xff", stderr=b"timed-out\xfe")
                raise OSError("injected later compiler failure")

            with mock.patch.object(q, "find_rustc", return_value=str(rust)), mock.patch.object(q.shutil, "which", return_value=str(cc)), mock.patch.object(q.subprocess, "run", side_effect=process):
                with self.assertRaises(q.QualificationFailed):
                    q.run_qualification(output=target, repeats=2)
            report = json.loads(target.read_text())
            self.assertFalse(report["ok"]); self.assertEqual(report["status"], "failed")
            self.assertEqual([row["name"] for row in report["cases"]], [row["name"] for row in q._plan()])
            self.assertTrue(all(row["status"] == "failed" for row in report["cases"]))
            first = report["cases"][0]
            self.assertEqual(first["build"]["status"], "timed_out")
            self.assertEqual(Path(first["build"]["stdout"]["path"]).read_bytes(), b"compile-prefix\xff")
            self.assertEqual(len(first["runs"]), 2)
            self.assertEqual(report["cases"][-1]["build"]["status"], "start_failed")
            self.assertEqual(len(report["rejections"]), len(q.REJECTIONS))
            self.assertTrue(any(str(arg).endswith("native_alias.rs") for command in observed for arg in command))
            original = target.read_bytes()
            with self.assertRaises(FileExistsError):
                q.run_qualification(output=target, repeats=2)
            self.assertEqual(target.read_bytes(), original)


@unittest.skipUnless(RUSTC and shutil.which("gcc"), "pinned native Rust and C compiler required")
class TaskIoNativeQualificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix="hepta-task-io-tests-")
        cls.report = q.run_qualification(output=Path(cls.directory.name) / "qualification.json", rustc=RUSTC, repeats=1)

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def test_actual_sources_races_faults_and_wrong_runtimes(self):
        q.validate_report(self.report, minimum_repeats=1)
        self.assertEqual(len(self.report["cases"]), 10)
        controls = self.report["cases"][3]["runs"][0]["metrics"]
        self.assertEqual(controls["parent_child_cancel_failure_races"], 64)
        self.assertEqual(controls["shared_byte_admission_races"], 32)
        self.assertEqual(controls["refused_subtree_cleanup_recovery_cases"], 1)
        self.assertEqual(controls["wake_nonblocking_refusals"], 2)
        self.assertEqual(controls["final_canceller_arc_cleanup_cases"], 1)
        self.assertEqual(controls["tracked_allocations"], controls["tracked_frees"])
        self.assertEqual(controls["live_buffers"], 0)
        self.assertTrue(self.report["cases"][4]["runs"][0]["process"]["timed_out"])
        for row in self.report["cases"][5:8]:
            self.assertNotEqual(row["runs"][0]["process"]["returncode"], 0)
        self.assertTrue(self.report["cases"][8]["runs"][0]["process"]["timed_out"])
        self.assertIn("E0499", self.report["cases"][-1]["build"]["stderr"]["text"])
        self.assertEqual(self.report["cases"][-1]["runs"], [])

    def test_receipt_rejects_contradictory_scope_commands_and_missing_runs(self):
        mutations = [
            lambda r: r.update(ok=1),
            lambda r: r.update(repeats=True),
            lambda r: r.update(extra_unclaimed_execution=True),
            lambda r: r.update(compiler_sha256="0" * 64),
            lambda r: r["claims"].update(async_await_or_background_executor=True),
            lambda r: r["profile"].update(maximum_group_registrations=True),
            lambda r: r["cases"].pop(),
            lambda r: r["cases"][0]["runs"].clear(),
            lambda r: r["cases"][0]["runs"][0]["process"].update(returncode=False),
            lambda r: r["cases"][0]["runs"][0]["process"].update(elapsed_ns=True),
            lambda r: r["cases"][0]["runs"][0]["process"].update(status="not_run"),
            lambda r: r["cases"][0]["build"]["argv"].append("--emit=metadata"),
            lambda r: r["cases"][3]["build"]["argv"].pop(),
            lambda r: r["cases"][3]["runs"][0]["metrics"].update(partial_cancel_cases=True),
            lambda r: r["cases"][4]["runs"][0]["process"].update(timed_out=False, returncode=0),
            lambda r: r["cases"][0]["analysis"].update(resource_contracts=[]),
            lambda r: r["cases"][0]["runs"][0]["binary_after"].update(sha256="0" * 64),
            lambda r: r["rejections"].pop(),
            lambda r: r["tools"]["rust"]["version"]["argv"].append("--fake"),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                changed = copy.deepcopy(self.report); mutate(changed)
                with self.assertRaises(ValueError):
                    q.validate_report(changed, minimum_repeats=1)

    def test_rehashed_unrelated_rust_source_cannot_replace_checked_source(self):
        changed = copy.deepcopy(self.report); row = changed["cases"][0]
        path = Path(row["source"]["path"]); original = path.read_bytes()
        try:
            path.write_text("fn main(){}\n"); row["source"] = q.artifact(path)
            with self.assertRaisesRegex(ValueError, "exact current render"):
                q.validate_report(changed, minimum_repeats=1)
        finally:
            path.write_bytes(original)

    def test_rehashed_native_summary_cannot_omit_failed_race_denominator(self):
        changed = copy.deepcopy(self.report); run = changed["cases"][3]["runs"][0]
        stream = run["process"]["stdout"]; path = Path(stream["path"]); original = path.read_bytes()
        try:
            metrics = json.loads(original); metrics["parent_child_cancel_failure_races"] = 63
            raw = json.dumps(metrics).encode() + b"\n"
            run["process"]["stdout"] = q._stream(path, raw); run["metrics"] = metrics
            with self.assertRaisesRegex(ValueError, "denominator incomplete"):
                q.validate_report(changed, minimum_repeats=1)
        finally:
            path.write_bytes(original)

    def test_artifact_bytes_and_raw_stream_bytes_are_rechecked(self):
        for row, key in ((self.report["cases"][0], "binary"), (self.report["c_build"], "object")):
            path = Path(row[key]["path"]); original = path.read_bytes()
            try:
                path.write_bytes(original + b"changed")
                with self.assertRaisesRegex(ValueError, "artifact bytes differ"):
                    q.validate_report(self.report, minimum_repeats=1)
            finally:
                path.write_bytes(original)
        q.validate_report(self.report, minimum_repeats=1)


if __name__ == "__main__":
    unittest.main()

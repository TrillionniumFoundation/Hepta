"""Actual native signals must leave failed qualification and call-prefix evidence."""
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import subprocess
import sys
import tempfile
import unittest

from tools.qualify_hia_filecheck import (NATIVE_REQUEST_SCHEMA, NATIVE_WORKER, PROTOCOL,
                                         Trial, cases, identity, update)

CLANG = os.environ.get("CLANG") or shutil.which("clang")
SOURCE = r'''
#include <stddef.h>
#include <stdint.h>
#include <signal.h>
static uint64_t calculate(size_t count, uint64_t packed, uint32_t state, uint32_t polynomial) {
    if (count > 8) return UINT64_C(4294967296);
    for (size_t i = 0; i < count; ++i) {
        state ^= (unsigned char)(packed >> (i * 8));
        for (unsigned bit = 0; bit < 8; ++bit)
            state = (state >> 1) ^ ((state & 1) ? polynomial : 0);
    }
    return state;
}
uint64_t checksum_chunk(size_t count, uint64_t packed, uint32_t state, uint32_t polynomial) {
#ifdef FAULT_SIGILL
    if (count == 1) raise(SIGILL);
#endif
    return calculate(count, packed, state, polynomial);
}
uint64_t c_checksum_chunk(size_t count, uint64_t packed, uint32_t state, uint32_t polynomial) {
    return checksum_chunk(count, packed, state, polynomial);
}
uint64_t checksum_chunk_v2(size_t count, uint64_t packed, uint32_t state, uint32_t algorithm) {
#ifdef FAULT_SIGABRT
    if (algorithm == 2) raise(SIGABRT);
#endif
    if (algorithm == 1) return calculate(count, packed, state, UINT32_C(0xedb88320));
    if (algorithm == 2) return calculate(count, packed, state, UINT32_C(0x82f63b78));
    return UINT64_C(12884901888);
}
uint64_t c_checksum_chunk_v2(size_t count, uint64_t packed, uint32_t state, uint32_t algorithm) {
    return checksum_chunk_v2(count, packed, state, algorithm);
}
'''


class FixtureTrial(Trial):
    """Real native fixtures around unchanged Trial.run and differential.

    Build/capture/resource/performance qualification is deliberately outside this
    test fixture. The separate real prepare-only regression exercises those paths.
    """
    def __init__(self, directory, fault=None):
        self.fault = fault
        super().__init__(directory, clang=CLANG, clangxx=CLANG, rustc="rustc",
                         profdata="llvm-profdata", linker="ld.lld")

    def build(self):
        source = self.out / "fixture.c"
        source.write_text(SOURCE)
        self.good = self.out / "normal.so"
        self.bad = self.out / "fault.so"
        self.command([CLANG, "-O2", "-fPIC", "-shared", source, "-o", self.good], "actual_fixture_build")
        flags = ["-DFAULT_" + self.fault] if self.fault else []
        self.command([CLANG, "-O2", "-fPIC", "-shared", *flags, source, "-o", self.bad], "actual_fixture_build")
        self.libraries = {arm: self.bad if arm == "hia_native_lto" else self.good for arm in PROTOCOL["arms"]}
        self.runtime_images = {str(path): identity(path) for path in self.libraries.values()}
        self.report.update(diagnostic_test_fixture=True,
                           host={"platform": platform.platform(), "machine": platform.machine()},
                           tools={"clang": identity(CLANG)},
                           artifacts={arm: identity(path) for arm, path in self.libraries.items()})

    def resources(self):
        self.report["resource_phase_outside_test_fixture"] = True

    def maintenance(self):
        arguments = [[8, int.from_bytes(b"12345678", "little"), 0xffffffff, algorithm]
                     for algorithm in (1, 2, 0, 3)]
        observed = self.native_validation("maintenance", [("c", self.good, "checksum_chunk_v2"),
                                                            ("hia", self.bad, "c_checksum_chunk_v2")], arguments)
        expected = [update(0xffffffff, b"12345678", polynomial) for polynomial in (0xedb88320, 0x82f63b78)]
        expected.extend([3 << 32, 3 << 32])
        if observed != [{"c": value, "hia": value} for value in expected]:
            raise ValueError("fixture native maintenance differs from independent recurrence")

    def verify_artifacts(self):
        if any(identity(path) != receipt for path, receipt in self.runtime_images.items()):
            raise ValueError("actual native fixture changed")


@unittest.skipUnless(CLANG and os.name == "posix", "actual POSIX Clang native libraries required")
class FilecheckNativeIsolationTests(unittest.TestCase):
    def _run(self, directory, fault=None):
        trial = FixtureTrial(Path(directory) / "trial", fault)
        report = trial.run(prepare_only=True)
        retained = os.environ.get("HEPTA_FILECHECK_NATIVE_EVIDENCE")
        if retained:
            destination = Path(retained)
            destination.mkdir(parents=True, exist_ok=True)
            shutil.copytree(trial.out, destination / (fault.lower() if fault else "normal"))
        saved = json.loads((trial.out / "qualification.json").read_text())
        self.assertEqual(saved, report)
        context = json.loads((trial.out / "native-validation-context.json").read_text())
        self.assertEqual(context["host"]["machine"], platform.machine())
        self.assertEqual(context["tools"]["clang"], identity(CLANG))
        self.assertEqual(context["worker"], identity(NATIVE_WORKER))
        self.assertIn("tools/hia_filecheck_native_worker.py", context["source_bindings"])
        self.assertIn("tools/hia_filecheck_target_profile.py", context["source_bindings"])
        return trial, report

    def _record_refusal(self, run, path, expected):
        retained = os.environ.get("HEPTA_FILECHECK_NATIVE_EVIDENCE")
        if retained:
            destination = Path(retained)
            destination.mkdir(parents=True, exist_ok=True)
            with (destination / "request-refusals.jsonl").open("a") as stream:
                stream.write(json.dumps({"path": str(path), "argv": run.args, "expected": expected,
                                         "returncode": run.returncode, "stdout": run.stdout,
                                         "stderr": run.stderr}, separators=(",", ":")) + "\n")

    def test_sigill_differential_preserves_failed_report_context_and_partial_progress(self):
        with tempfile.TemporaryDirectory(prefix="filecheck-real-sigill-") as directory:
            trial, report = self._run(directory, "SIGILL")
            self.assertFalse(report["ok"])
            self.assertEqual(report["status"], "failed")
            self.assertIn("SIGILL", report["error"]["message"])
            native = report["native_validation"]["differential"]
            self.assertEqual(native["returncode"], -signal.SIGILL)
            self.assertEqual(native["signal"], "SIGILL")
            self.assertTrue(native["artifacts_unchanged"])
            progress = native["progress"]
            self.assertFalse(progress["complete"])
            self.assertEqual(len(progress["completed_cases"]), 1)
            self.assertEqual(progress["calls_returned"], 9)
            self.assertEqual(progress["pending_call"]["index"], 1)
            self.assertEqual(progress["pending_call"]["arm"], "hia_native_lto")
            self.assertEqual(progress["pending_call"]["arguments"], list(cases())[1]["arguments"])
            rows = [json.loads(line) for line in (trial.out / "differential.jsonl").read_text().splitlines()]
            self.assertEqual(len(rows), 1)
            self.assertEqual(set(rows[0]["observed"]), set(PROTOCOL["arms"]))
            self.assertTrue(all(value == rows[0]["expected"] for value in rows[0]["observed"].values()))
            raw = json.loads((trial.out / "processes.jsonl").read_text().splitlines()[-1])
            self.assertEqual(raw["returncode"], -signal.SIGILL)
            self.assertEqual(raw["stdout"], (trial.out / "differential-worker.stdout.jsonl").read_text())
            self.assertNotIn("maintenance", report["native_validation"])

    def test_sigabrt_maintenance_preserves_failed_report_context_and_partial_progress(self):
        with tempfile.TemporaryDirectory(prefix="filecheck-real-sigabrt-") as directory:
            _, report = self._run(directory, "SIGABRT")
            self.assertFalse(report["ok"])
            self.assertEqual(report["status"], "failed")
            self.assertEqual(report["differential"]["native_calls"], 768)
            self.assertIn("SIGABRT", report["error"]["message"])
            native = report["native_validation"]["maintenance"]
            self.assertEqual(native["returncode"], -signal.SIGABRT)
            self.assertTrue(native["artifacts_unchanged"])
            progress = native["progress"]
            self.assertEqual(len(progress["completed_cases"]), 1)
            self.assertEqual(progress["calls_returned"], 3)
            self.assertEqual(progress["pending_call"]["index"], 1)
            self.assertEqual(progress["pending_call"]["arm"], "hia")
            self.assertEqual(progress["pending_call"]["arguments"][-1], 2)
            self.assertFalse(progress["complete"])

    def test_normal_native_differential_preserves_all_96_cases_and_eight_arms(self):
        with tempfile.TemporaryDirectory(prefix="filecheck-real-normal-") as directory:
            trial, report = self._run(directory)
            self.assertTrue(report["ok"], report.get("error"))
            self.assertEqual(report["differential"]["cases"], 96)
            self.assertEqual(report["differential"]["routes"], 8)
            self.assertEqual(report["differential"]["native_calls"], 768)
            rows = [json.loads(line) for line in (trial.out / "differential.jsonl").read_text().splitlines()]
            self.assertEqual([{k: row[k] for k in ("arguments", "expected")} for row in rows], list(cases()))
            for phase, calls in (("differential", 768), ("maintenance", 8)):
                native = report["native_validation"][phase]
                self.assertEqual(native["returncode"], 0)
                self.assertTrue(native["progress"]["complete"])
                self.assertEqual(native["progress"]["calls_returned"], calls)

    def test_worker_rejects_changed_library_and_invalid_requests(self):
        with tempfile.TemporaryDirectory(prefix="filecheck-worker-refusals-") as directory:
            trial = FixtureTrial(Path(directory) / "trial")
            trial.build()
            library = {"arm": "c", "symbol": "checksum_chunk", **identity(trial.good)}
            base = {"schema": NATIVE_REQUEST_SCHEMA, "libraries": [library], "arguments": [[0, 0, 0, 0]]}
            changed = json.loads(json.dumps(base)); changed["libraries"][0]["sha256"] = "0" * 64
            boolean = json.loads(json.dumps(base)); boolean["arguments"][0][0] = True
            overflow = json.loads(json.dumps(base)); overflow["arguments"][0][2] = 1 << 32
            unknown = json.loads(json.dumps(base)); unknown["unreviewed"] = True
            for index, (request, message) in enumerate(((changed, "changed before load"),
                    (boolean, "exact unsigned ABI"), (overflow, "exact unsigned ABI"), (unknown, "request shape"))):
                with self.subTest(refusal=message):
                    path = Path(directory) / (str(index) + ".json")
                    path.write_text(json.dumps(request))
                    run = subprocess.run([sys.executable, "-B", str(NATIVE_WORKER), "--request", str(path)],
                                         capture_output=True, text=True, timeout=10)
                    self._record_refusal(run, path, message)
                    self.assertNotEqual(run.returncode, 0)
                    self.assertIn(message, run.stderr)
                    self.assertEqual(run.stdout, "")
            oversized = Path(directory) / "oversized.json"
            oversized.write_bytes(b" " * (128 * 1024 + 1))
            fifo = Path(directory) / "request.fifo"
            os.mkfifo(fifo)
            symlink = Path(directory) / "request-link.json"
            symlink.symlink_to(oversized)
            for path, message in ((oversized, "finite input bound"), (fifo, "regular no-follow"),
                                  (Path(directory), "regular no-follow"), (symlink, "regular no-follow")):
                with self.subTest(file=path.name):
                    run = subprocess.run([sys.executable, "-B", str(NATIVE_WORKER), "--request", str(path)],
                                         capture_output=True, text=True, timeout=2)
                    self._record_refusal(run, path, message)
                    self.assertNotEqual(run.returncode, 0)
                    self.assertIn(message, run.stderr)
                    self.assertEqual(run.stdout, "")


if __name__ == "__main__":
    unittest.main()

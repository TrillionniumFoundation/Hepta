"""Independent original-source/profile gates and actual atomic-handoff controls.

No old test is replaced. New controls do not stand for the original 44 methods,
the full 17 references/38 phases, or arbitrary Python provider equivalence.
"""
from __future__ import annotations
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
GATES = ROOT / "tests/fixtures/cold_native_transport_original_gates_v3.json"
CONTROLS = ROOT / "tests/fixtures/cold_native_transport_controls_v3.json"


class ColdNativeTransportLibraryPathTests(unittest.TestCase):
    def locate(self, executable, name, libdir):
        from tools import build_hia_cold_native_transport as builder
        values = {"LDLIBRARY": name, "LIBDIR": libdir}
        with patch.object(builder.sys, "executable", str(executable)), \
                patch.object(builder.sysconfig, "get_config_var", side_effect=values.get):
            return builder.current_python_library()

    def interpreter(self, root):
        executable = root / "bin/python3.14"
        executable.parent.mkdir(parents=True)
        executable.write_bytes(b"path-only interpreter fixture")
        return executable

    def library(self, directory, name="libpython3.14.so"):
        directory.mkdir(parents=True, exist_ok=True)
        library = directory / name
        library.write_bytes(b"path-only shared-library fixture")
        return library

    def test_relocated_runtime_library_precedes_stale_build_time_libdir(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = self.interpreter(root / "relocated")
            expected = self.library(root / "relocated/lib")
            stale = self.library(root / "old-prefix/lib")
            self.assertEqual(self.locate(executable, expected.name, str(stale.parent)),
                             expected.resolve())

    def test_distribution_multiarch_libdir_after_missing_prefix_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = self.interpreter(root / "usr")
            expected = self.library(root / "usr/lib/x86_64-linux-gnu")
            self.assertFalse((root / "usr/lib" / expected.name).exists())
            self.assertEqual(self.locate(executable, expected.name, str(expected.parent)),
                             expected.resolve())

    def test_venv_and_library_symlinks_bind_resolved_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = self.interpreter(root / "runtime")
            versioned = self.library(root / "runtime/lib", "libpython3.14.so.1.0")
            declared = versioned.with_name("libpython3.14.so")
            declared.symlink_to(versioned.name)
            venv = root / "venv/bin/python"
            venv.parent.mkdir(parents=True)
            venv.symlink_to(executable)
            self.assertEqual(self.locate(venv, declared.name, str(root / "stale/lib")),
                             versioned.resolve())

    def test_invalid_missing_and_nonfile_candidates_fail_without_searching(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = self.interpreter(root / "runtime")
            for name in (None, "", ".", "..", "../libpython3.14.so",
                         "nested/libpython3.14.so", "libpython\0.so"):
                with self.subTest(name=name), self.assertRaises(ValueError):
                    self.locate(executable, name, str(root / "lib"))
            for libdir in (None, "", "relative/lib", "/bad\0directory"):
                with self.subTest(libdir=libdir), self.assertRaises(ValueError):
                    self.locate(executable, "libpython3.14.so", libdir)
            (root / "runtime/lib/libpython3.14.so").mkdir(parents=True)
            (root / "configured/libpython3.14.so").mkdir(parents=True)
            with self.assertRaisesRegex(ValueError, "shared library is missing"):
                self.locate(executable, "libpython3.14.so", str(root / "configured"))


class ColdNativeTransportSourceTests(unittest.TestCase):
    def test_exact_original_observers_and_complete_original_44_ids(self):
        from tools.hia_cold_native_transport_evidence import (
            regular_bytes, restore_observer_source, observer_source_profile, Captures)
        from tools import read_hia_cold_native_transport as independent
        from tools.run_hia_unittest_gate import load_declared_suite
        plan, current_ids, source_profile = observer_source_profile(ROOT, Captures())
        self.assertEqual(independent.observer_source_profile(ROOT, independent.Raw()),
                         (plan, current_ids, source_profile))
        self.assertEqual(plan["original_method_count"], 44)
        for name, expected in plan["original_tests"].items():
            raw = regular_bytes(ROOT / name)
            original = restore_observer_source(name, raw, expected)
            self.assertEqual({"bytes": len(original), "sha256": sha256(original).hexdigest()}, expected)
        for row in plan["original_observers"]:
            raw = regular_bytes(ROOT / row["path"])
            tail = row["selection_tail"].encode()
            self.assertTrue(raw.endswith(tail))
            before = raw[:-len(tail)]
            before = restore_observer_source(row["path"], before, row["before"])
            self.assertEqual({"bytes": len(before), "sha256": sha256(before).hexdigest()}, row["before"])
            original = row["execute_source"].encode()
            self.assertEqual(before.count(original), 1)
            self.assertEqual({"bytes": len(original), "sha256": sha256(original).hexdigest()}, row["execute"])
        suite, actual = load_declared_suite(plan["original_modules"])
        self.assertEqual(list(actual), current_ids)
        self.assertEqual([identity for identity in actual if identity in plan["original_method_ids"]],
                         plan["original_method_ids"])
        self.assertEqual(suite.countTestCases(), 47)
        self.assertEqual(len(source_profile["additional_method_ids"]), 3)
        self.assertEqual(plan["cold_phase_count"], 38)
        self.assertEqual(plan["independent_reference_count"], 17)
        self.assertEqual(plan["original_caps"]["cold_seconds"], 180)
        self.assertEqual(plan["original_caps"]["cleanup_seconds"], 3)

    def test_complete_current_sources_require_exact_inverse_and_forward_bytes(self):
        from tools import hia_cold_native_transport_evidence as producer
        from tools import read_hia_cold_native_transport as independent
        plan = producer.parse(producer.regular_bytes(GATES))
        observers = {row["path"]: row for row in plan["original_observers"]}
        for name, relation in producer.OBSERVER_SUCCESSORS.items():
            current = (ROOT / name).read_bytes()
            if name in observers:
                tail = observers[name]["selection_tail"].encode()
                self.assertTrue(current.endswith(tail))
                current = current[:-len(tail)]
            restored = producer.restore_observer_source(name, current, relation["old"])
            self.assertEqual(producer.data_pin(restored), relation["old"])
            self.assertEqual(independent.restore_observer_source(name, current, relation["old"]), restored)
            for changed in (current + b"\n", current[:-1], restored):
                with self.subTest(path=name, bytes=len(changed)):
                    with self.assertRaises(ValueError):
                        producer.restore_observer_source(name, changed, relation["old"])
                    with self.assertRaises(ValueError):
                        independent.restore_observer_source(name, changed, relation["old"])
            with self.assertRaises(ValueError):
                producer.restore_observer_source(name, current, relation["current"])
            with self.assertRaises(ValueError):
                independent.restore_observer_source(name, current, relation["current"])

    def test_current47_profile_refuses_old44_source_and_changed_execute_or_selection(self):
        from tools import hia_cold_native_transport_evidence as producer
        from tools import read_hia_cold_native_transport as independent
        plan = producer.parse(producer.regular_bytes(GATES))
        names = {*plan["original_tests"], *(row["path"] for row in plan["original_observers"]),
                 "tests/fixtures/cold_native_transport_original_gates_v3.json"}
        with tempfile.TemporaryDirectory(prefix="hia-observer-source-domain-") as directory:
            root = Path(directory)
            for name in names:
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((ROOT / name).read_bytes())
            self.assertEqual(producer.observer_source_profile(root, producer.Captures()),
                             independent.observer_source_profile(root, independent.Raw()))
            test_name = "tests/test_hia_selfhost_native_observer.py"
            current = (root / test_name).read_bytes()
            old = producer.restore_observer_source(test_name, current, plan["original_tests"][test_name])
            variants = [(test_name, old), (test_name, current + b"\n")]
            observer = plan["original_observers"][0]
            source = (root / observer["path"]).read_bytes()
            variants.extend([
                (observer["path"], source.replace(b"def execute(", b"def changed_execute(", 1)),
                (observer["path"], source + b"\n"),
                ("tests/fixtures/cold_native_transport_original_gates_v3.json", GATES.read_bytes() + b"\n")])
            for name, changed in variants:
                target = root / name
                original = target.read_bytes()
                target.write_bytes(changed)
                try:
                    with self.subTest(path=name), self.assertRaises(ValueError):
                        producer.observer_source_profile(root, producer.Captures())
                    with self.subTest(independent=name), self.assertRaises(ValueError):
                        independent.observer_source_profile(root, independent.Raw())
                finally:
                    target.write_bytes(original)

    def test_actual_generated_policy_retains_complete_original_profile_limits(self):
        from tools.generate_hia_cold_native_transport import document
        from hepta.hia_agent_assembly import assemble_program, render_assembly
        raw = (ROOT / "examples/hia_bootstrap/cold_native_transport.hepta").read_bytes()
        self.assertEqual(render_assembly(document()).encode(), raw)
        value = assemble_program(raw).as_dict()
        functions = value["functions"]
        self.assertLessEqual(len(functions), 128)
        self.assertLessEqual(sum(len(fn["blocks"]) for fn in functions), 1536)
        self.assertLessEqual(sum(len(block["ops"]) for fn in functions for block in fn["blocks"]), 8192)
        self.assertLessEqual(max(len(fn["blocks"]) for fn in functions), 256)
        self.assertLessEqual(max(len(block["params"]) for fn in functions for block in fn["blocks"]), 16)
        self.assertEqual(value["schema"], "hepta.hia.program.v8")


class ColdNativeTransportHandoffTests(unittest.TestCase):
    def test_all_eight_actual_atomic_handoff_controls(self):
        from tools.hia_cold_native_transport_bridge import SELECTOR, DEVELOPMENT, _Captured
        from tools.hia_cold_native_transport_evidence import (Captures, data_pin, parse,
            regular_bytes, run_owned, successful_exit, terminal_owned)
        path = os.environ.get(SELECTOR)
        if not path or os.environ.get(DEVELOPMENT) != "1":
            raise ValueError("explicit current R3 build and development scope are required")
        captured = _Captured(path)
        item = captured.value["handoff_controls"]
        executable = Path(item["path"]).resolve(strict=True)
        raw = regular_bytes(executable)
        self.assertEqual(data_pin(raw), item["pin"])
        cases = parse(regular_bytes(CONTROLS))["handoff_controls"]
        evidence = os.environ.get("HEPTA_HIA_COLD_NATIVE_TRANSPORT_HANDOFF_EVIDENCE")
        if not evidence:
            raise ValueError("a new retained control evidence directory is required")
        output = Path(evidence).resolve()
        output.mkdir(mode=0o700)
        report_path = output / "controls.json"
        command = [str(executable), sys.executable, str(report_path)]
        result = run_owned(command, cwd=ROOT, directory=output / "owned",
                           timeout_seconds=60, environment=dict(os.environ))
        self.assertTrue(successful_exit(result), result)
        read = Captures()
        command_data, actual_result = terminal_owned(
            read, output / "owned", seconds=60, expected_argv=command, cwd=ROOT)
        report = read.json(report_path)
        self.assertEqual(report["schema"], "hepta.cold-native-transport.handoff-controls.r3")
        self.assertEqual(report["planned"], 8)
        self.assertEqual([row["id"] for row in report["controls"]], [row["id"] for row in cases])
        self.assertEqual(len(report["controls"]), 8)
        for row, expected in zip(report["controls"], cases):
            self.assertIs(row["passed"], True, row)
            self.assertIs(type(row["handoff_return"]), int)
            self.assertEqual(row["handoff_return"], expected["expected_return"])
            self.assertIs(row["actual_pending"], expected["expected_pending"])
            self.assertEqual(row["failure_line"], 0)
        for index in (0, 1, 4, 5):
            self.assertIs(report["controls"][index]["real_number_reuse_checked"], True)
        self.assertEqual(report["status"], "CONTROLS_PASS")
        self.assertIs(report["whole_native"], False)
        self.assertEqual(regular_bytes(executable), raw)
        captured.unchanged()
        read.unchanged()
        # This is an additional exact raw control proof, not a replacement for
        # any original product/worker/phase qualification.
        (output / "readback.json").write_text(json.dumps({
            "scope": report["scope"], "controls": [row["id"] for row in cases],
            "consumed": read.pins(), "source_stable": True,
            "whole_native": False, "qualification_complete": False,
        }, sort_keys=True, indent=2) + "\n")


if __name__ == "__main__":
    unittest.main()

"""New explicit div/rem qualifications; all old interpreter files/tests stay intact."""
from __future__ import annotations
import ast
import copy
import ctypes
from hashlib import sha256
import json
import os
from pathlib import Path
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
from tests.hia_vm_integer_divrem_cases import (canonical, pin, decode, cases,
    source_capture, stable, observe, RUNTIME_SHA256, TEST_SHA256)
from tests.hia_vm_integer_divrem_controls import TRANSPORT, ADMISSION, LIVENESS, CONTEXT
from hepta import hia_vm_integer_divrem_protocol as wire


class VmIntegerDivRemSourceTests(unittest.TestCase):
    def test_00_complete_original_source_and_full_hia_core(self):
        from hepta.hia_agent_assembly import assemble_program
        captured = source_capture()
        raw = captured[wire.SOURCE_NAME]
        self.assertEqual(sha256(raw).hexdigest(),
            "31dd3090c25aefb90b4571b4e1a0daeaff03bb8429c1e41488c47f6d44da85d1")
        program = assemble_program(raw)
        document = program.as_dict()
        self.assertEqual([fn["name"] for fn in document["functions"]], ["f0", "f1", "f2", "f3"])
        for fn in document["functions"]:
            entry = next(block for block in fn["blocks"] if block["id"] == fn["entry"])
            self.assertEqual(entry["params"], fn["params"])
            definitions = [p["name"] for block in fn["blocks"] for p in block["params"]]
            definitions += [p["name"] for block in fn["blocks"]
                            for ins in block["ops"] for p in ins["out"]]
            self.assertEqual(len(definitions), len(set(definitions)))
            self.assertLessEqual(len(definitions), 2048)
        from hepta import hia_vm_integer_divrem_runtime as selected
        actual_runtime = captured["hepta/hia_program_runtime.py"]
        retained = selected._retained_runtime_source(actual_runtime)
        self.assertEqual(retained, captured["tests/fixtures/vm_integer_divrem_runtime_ce39.py.txt"])
        self.assertEqual(sha256(retained).hexdigest(), RUNTIME_SHA256)
        self.assertEqual(sha256(actual_runtime).hexdigest(), selected.V9_RUNTIME_SHA256)
        self.assertEqual(selected._retained_runtime_source(retained), retained)
        for changed in (actual_runtime + b"\n", retained + b"\n",
                actual_runtime.replace(b"8 > extent - index", b"7 > extent - index", 1),
                actual_runtime.replace(b'elif op == "bool.not":', b'elif op == "bool.or":', 1)):
            with self.subTest(changed_sha256=sha256(changed).hexdigest()):
                with self.assertRaises(ValueError):
                    selected._retained_runtime_source(changed)
        self.assertEqual(len(selected._word_order_state(actual_runtime)), 2)
        from unittest.mock import patch
        from types import MappingProxyType
        for changed in (dict(selected.original.WORD_LOADS),
                MappingProxyType({**selected.original.WORD_LOADS, "buffer.load.u64.le": "big"})):
            with patch.object(selected.original, 'WORD_LOADS', changed):
                with self.assertRaisesRegex(ValueError, 'byte-order mapping differs'):
                    selected._word_order_state(actual_runtime)
        self.assertEqual(sha256(captured["tests/test_hia_program.py"]).hexdigest(), TEST_SHA256)
        # The independently pinned v9 delta is inverted above. Only the two
        # original integer bodies are replaced by this explicit native profile;
        # Prepared and Arithmetic remain the original implementation.
        source = captured["hepta/hia_vm_integer_divrem_runtime.py"]
        tree = ast.parse(source)
        declarations = {target.id: node.value for node in tree.body if isinstance(node, ast.Assign)
                        for target in node.targets if isinstance(target, ast.Name)}
        body = ast.parse(ast.literal_eval(declarations["_DIV_BODY"]))
        self.assertFalse(any(isinstance(node, ast.BinOp) and
                         isinstance(node.op, (ast.Div, ast.FloorDiv, ast.Mod)) for node in ast.walk(body)))
        stable(captured)

    def test_01_all2500_transport_inputs_and_closed_ack_fields(self):
        _, rows = cases()
        self.assertEqual(len(rows), 2500)
        for ordinal, row in enumerate(rows, 1):
            with self.subTest(id=row["id"]):
                raw = wire.request(row["operation"], row["type"], int(row["lhs"]), int(row["rhs"]), ordinal)
                words = wire._request_words(raw)
                for status in (0, 1, 2):
                    receipt = [wire.REPLY_MAGIC, 1, words[1], words[2], words[3], words[4],
                               status, 0, words[5], words[6], 0, wire.COMPLETION]
                    for index, value in enumerate(receipt):
                        if index != 10:
                            receipt[10] ^= value
                    decoded = wire.reply(raw, struct.pack("<12Q", *receipt), 96)
                    self.assertEqual(decoded["status"], status)
                    self.assertEqual(decoded["nonce"], ordinal)
        raw = wire.request("int.div.checked", "i8", -7, 3, 1)
        for operation, typ, a, b, nonce in (
            ("bad", "i8", -7, 3, 1), ("int.div.checked", "bad", -7, 3, 1),
            ("int.div.checked", "i8", True, 3, 1), ("int.div.checked", "i8", -7, True, 1),
            ("int.div.checked", "i8", -7, 3, True), ("int.div.checked", "i8", -7, 3, 0),
            ("int.div.checked", "i8", -129, 3, 1), ("int.div.checked", "u8", -1, 3, 1)):
            with self.subTest(input=(operation, typ, a, b, nonce)), self.assertRaises((ValueError, OverflowError)):
                wire.request(operation, typ, a, b, nonce)
        for size in (0, 63, 65, 96):
            with self.subTest(request_size=size), self.assertRaises(ValueError):
                wire._request_words(raw[:size] if size < 64 else raw + b"\0" * (size - 64))
        for count in (0, 95, 97, True):
            with self.subTest(receipt_count=count), self.assertRaises(ValueError):
                wire.reply(raw, b"\0" * 96, count)

        # Live-code admission compares real IEEE constant representations, not
        # Python numeric equality (which merges +0.0 and -0.0).
        from hepta import hia_vm_integer_divrem_runtime as selected
        pairs = ((0.0, -0.0),
                 (complex(0.0, 1.0), complex(-0.0, 1.0)),
                 (complex(1.0, 0.0), complex(1.0, -0.0)))
        for before, after in pairs:
            with self.subTest(constant_type=type(before).__name__,
                              before=struct.pack(">dd", complex(before).real, complex(before).imag)):
                self.assertTrue(selected._same_constant(before, before))
                self.assertFalse(selected._same_constant(before, after))
                self.assertFalse(selected._same_constant((before,), (after,)))
        for template, before, after in ((lambda: 0.0, 0.0, -0.0),
                                       (lambda: 1j, 1j, complex(-0.0, 1.0))):
            code = template.__code__
            constants = tuple(after if type(value) is type(before)
                              and selected._same_constant(value, before) else value
                              for value in code.co_consts)
            changed = code.replace(co_consts=constants)
            self.assertTrue(selected._same_code(code, code))
            self.assertFalse(selected._same_code(code, changed))

    def test_02_six_real_hia_vm_witnesses_and_exact_derivation_inverse(self):
        from hepta.hia_agent_assembly import assemble_program
        from hepta import hia_program_runtime as original
        from hepta import hia_vm_integer_divrem_runtime as selected
        from tests.test_hia_program import arithmetic
        raw_source = (ROOT / wire.SOURCE_NAME).read_bytes()
        program = assemble_program(raw_source)
        witnesses = [
            ("int.div.checked", "i8", -7, 3),
            ("int.rem.checked", "i8", -7, 3),
            ("int.div.checked", "u64", (1 << 64) - 1, 3),
            ("int.rem.checked", "i64", -(1 << 63), -1),
            ("int.div.checked", "i32", 1, 0),
            ("int.div.checked", "isize", -(1 << 63), 1),
        ]
        for number, (operation, typ, a, b) in enumerate(witnesses, 1):
            with self.subTest(witness=number):
                expected, _ = observe(original.execute_program, arithmetic(operation, typ),
                                      "calculate", [a, b])
                request = wire.request(operation, typ, a, b, number)
                machine = original._Machine(program, 4_000_000, 16 << 20, None, 128)
                roots = [original._Owner(-1, bytearray(request)),
                         original._Owner(-2, bytearray(b"\xa5" * 96)),
                         original._Owner(-3, bytearray())]
                arguments = [original._View(roots[0], False), original._View(roots[1], True),
                             original._View(roots[2], True)]
                values = machine.invoke(machine.functions["f0"], arguments)
                self.assertEqual(values, [96])
                self.assertEqual(bytes(roots[0].data), request)
                decoded = wire.reply(request, bytes(roots[1].data), values[0])
                if expected["outcome"] == "returned":
                    self.assertEqual((decoded["status"], decoded["value"]),
                                     (0, expected["report"]["result"]))
                else:
                    self.assertEqual(decoded["status"],
                                     {"division_by_zero": 1, "overflow": 2}[expected["error"]["code"]])
                    self.assertIsNone(decoded["value"])
                self.assertEqual(machine.resources()["allocation_attempts"], 0)
        class DefinitionsOnly:
            def evaluate(self, *args):
                raise AssertionError("source-only derivation must not execute arithmetic")
            def guard(self, *args):
                raise AssertionError("source-only derivation must not execute a machine")
            def __call__(self, *args):
                raise AssertionError("source-only derivation must not construct a machine")
        original_raw = (ROOT / "hepta/hia_program_runtime.py").read_bytes()
        operation, invoke, public = selected._derive(original_raw, DefinitionsOnly())
        self.assertIsNot(operation.__code__, original._Machine.operation.__code__)
        self.assertIs(operation.__globals__, original.__dict__)
        self.assertIs(invoke.__globals__, original.__dict__)
        self.assertIs(public.__globals__, original.__dict__)
        self.assertIn("_hia_evaluate", operation.__code__.co_freevars)
        self.assertIn("_hia_guard", invoke.__code__.co_freevars)
        self.assertIn("_hia_factory", public.__code__.co_freevars)
        self.assertEqual(public.__kwdefaults__, original.execute_program.__kwdefaults__)
        self.assertEqual(sha256(selected._retained_runtime_source(original_raw)).hexdigest(), RUNTIME_SHA256)


class VmIntegerDivRemNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        manifest = os.environ.get("HEPTA_HIA_VM_INTEGER_DIVREM_MANIFEST")
        digest = os.environ.get("HEPTA_HIA_VM_INTEGER_DIVREM_SHA256")
        evidence = os.environ.get("HEPTA_HIA_VM_INTEGER_DIVREM_EVIDENCE")
        if not manifest or not digest or not evidence:
            raise unittest.SkipTest("explicit standalone div/rem manifest, digest and fresh evidence required")
        cls.manifest = Path(manifest).resolve(strict=True)
        cls.digest = digest
        cls.directory = Path(evidence).resolve()
        cls.directory.mkdir(mode=0o700)
        cls.sources = source_capture()
        cls.manifest_raw = cls.manifest.read_bytes()
        if sha256(cls.manifest_raw).hexdigest() != digest:
            raise ValueError("new native suite explicit manifest authority differs")
        from tools.qualify_hia_vm_integer_divrem import supervisor
        cls._run, cls.owner_raw = supervisor()
        cls._run = staticmethod(cls._run)
        cls.commands = []

    @classmethod
    def tearDownClass(cls):
        stable(cls.sources)
        if cls.manifest.read_bytes() != cls.manifest_raw:
            raise ValueError("new native suite manifest changed")
        (cls.directory / "commands.json").write_bytes(canonical(cls.commands))
        (cls.directory / "source-after.json").write_bytes(canonical({k: pin(v) for k, v in cls.sources.items()}))

    def owned(self, label, command, seconds):
        env = {k: v for k, v in os.environ.items()
               if not (k.startswith("HEPTA_HIA_") or k.startswith("PYTHON"))}
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        receipt = self._run(command, cwd=ROOT, env=env,
            stdout_path=self.directory / (label + ".stdout.log"),
            stderr_path=self.directory / (label + ".stderr.log"),
            receipt_path=self.directory / (label + ".receipt.json"), seconds=seconds)
        self.commands.append({"label": label, "receipt": receipt})
        self.assertEqual(receipt["status"], "WORKFLOW_STEP_COMPLETED",
                         (label, receipt, (self.directory / (label + ".stderr.log")).read_text()))
        self.assertFalse(receipt["timed_out"])
        self.assertTrue(receipt["cleanup"]["complete"])
        self.assertFalse(receipt["cleanup"]["errors"])
        stable(self.sources)

    def control(self, group, name):
        label = group + "." + name
        output = self.directory / (label + ".json")
        command = [sys.executable, str(ROOT / "tests/hia_vm_integer_divrem_controls.py"),
                   "--group", group, "--case", name, "--manifest", str(self.manifest),
                   "--manifest-sha256", self.digest, "--output", str(output)]
        self.owned(label, command, 180)
        report = decode(output.read_bytes())
        self.assertEqual(report["status"], "PASS_CONTROL")
        self.assertEqual(report["control"], name)
        self.assertEqual(report["source_pins"], {k: pin(v) for k, v in self.sources.items()})

    def test_00_original_first_all2500_native_and_full_data_readback(self):
        command = [sys.executable, str(ROOT / "tools/qualify_hia_vm_integer_divrem.py"),
                   "--output", str(self.directory / "finite"),
                   "--manifest", str(self.manifest), "--manifest-sha256", self.digest]
        self.owned("finite2500", command, 1800)
        report = decode((self.directory / "finite/independent-readback.json").read_bytes())
        self.assertEqual(report["evidence_integrity"], "PASS")
        self.assertEqual(report["qualification"], "PASS_VALUE_TRAP_REPORT_DOMAIN_ONLY")
        self.assertEqual(report["planned"], 2500)
        self.assertFalse(report["semantic_difference_ids"])
        self.assertFalse(report["whole_vm_native"])
        self.assertFalse(report["all_input_equivalence_proved"])

    def test_01_complete_original21_then_explicit_factory21(self):
        for lane in ("original", "native"):
            with self.subTest(lane=lane):
                output = self.directory / ("generic21-" + lane)
                command = [sys.executable, str(ROOT / "tests/hia_vm_integer_divrem_cases.py"),
                           "--mode", "generic", "--lane", lane, "--output", str(output)]
                if lane == "native":
                    command += ["--manifest", str(self.manifest), "--manifest-sha256", self.digest]
                self.owned("generic21-" + lane, command, 600)
                report = decode((output / "report.json").read_bytes())
                self.assertEqual(report["status"], "PASS_COMPLETE_ORIGINAL_METHODS")
                self.assertEqual(report["testsRun"], 21)
                self.assertEqual(report["planned"], report["started"])
                self.assertEqual(report["planned"], report["stopped"])
                self.assertEqual((report["failures"], report["errors"], report["skips"]), (0, 0, 0))

    def test_02_all_invocation_receipt_echo_and_guard_controls(self):
        self.control("raw-abi", "raw-abi")
        for name in TRANSPORT[2:17]:
            with self.subTest(control=name):
                self.control("transport", name)

    def test_03_actual_missing_stale_receipts_and_original_error_identity(self):
        for name in (*TRANSPORT[:2], *TRANSPORT[17:]):
            with self.subTest(control=name):
                self.control("transport", name)

    def test_04_all_manifest_image_and_fresh_source_admission_controls(self):
        for name in ADMISSION:
            with self.subTest(control=name):
                self.control("admission", name)

    def test_05_all_live_derived_original_and_factory_binding_controls(self):
        for name in LIVENESS:
            with self.subTest(control=name):
                self.control("liveness", name)

    def test_06_pid_thread_scope_reentry_ticks_traps_and_stopped_owners(self):
        for name in CONTEXT:
            with self.subTest(control=name):
                self.control("context", name)
        self.control("boundaries", "boundaries")

    def test_07_real_installed_explicit_factory_and_no_worker_bundle_upgrade(self):
        from tests.hia_vm_integer_divrem_controls import INSTALLED_PROBE
        from hepta.hia_agent_contract import installation_manifest
        from hepta.hia_program_runtime import execute_program
        from tests.test_hia_program import arithmetic
        output = self.directory / "installed"
        output.mkdir(mode=0o700)
        wheel_dir, target = output / "wheel", output / "site"
        wheel_dir.mkdir()
        rows = []
        for ident, operation, typ, values in (
            ("signed-div", "int.div.checked", "i64", [-7, 3]),
            ("signed-rem", "int.rem.checked", "i64", [-7, 3]),
            ("zero", "int.div.checked", "u64", [1, 0]),
            ("minimum-rem", "int.rem.checked", "i64", [-(1 << 63), -1])):
            program = arithmetic(operation, typ)
            first, _ = observe(execute_program, program, "calculate", values)
            second, _ = observe(execute_program, program, "calculate", values)
            self.assertEqual(canonical(first), canonical(second))
            rows.append({"id": ident, "program": program, "function": "calculate",
                         "arguments": values, "expected": first})
        frozen = {"installation_manifest": installation_manifest(), "rows": rows}
        input_path = output / "original-inputs.json"
        input_path.write_bytes(canonical(frozen))
        self.owned("installed-wheel", [sys.executable, "-m", "pip", "wheel", "--no-deps",
            "--no-build-isolation", "--wheel-dir", str(wheel_dir), str(ROOT)], 180)
        wheels = list(wheel_dir.glob("*.whl"))
        self.assertEqual(len(wheels), 1)
        self.owned("installed-install", [sys.executable, "-m", "pip", "install", "--no-deps",
            "--target", str(target), str(wheels[0])], 180)
        script, report_path = output / "probe.py", output / "report.json"
        script.write_text(INSTALLED_PROBE)
        self.owned("installed-probe", [sys.executable, "-I", str(script), "--target", str(target),
            "--manifest", str(self.manifest), "--manifest-sha256", self.digest,
            "--inputs", str(input_path), "--output", str(report_path)], 60)
        report = decode(report_path.read_bytes())
        self.assertEqual(report["status"], "PASS_INSTALLED_SLICE")
        self.assertEqual(report["installation_manifest"], frozen["installation_manifest"])
        self.assertEqual(report["input_sha256"], sha256(input_path.read_bytes()).hexdigest())
        self.assertEqual(report["native_returns"], 4)
        self.assertEqual(report["acknowledgements"], 4)
        self.assertTrue(report["source_drift_rejected_before_native"])
        self.assertTrue(report["unselected_worker_scope_rejected_before_native"])
        self.assertEqual([row["id"] for row in report["rows"]], [row["id"] for row in rows])
        for original, actual in zip(rows, report["rows"]):
            self.assertEqual(canonical(original["expected"]), canonical(actual["actual"]))


if __name__ == "__main__":
    unittest.main()

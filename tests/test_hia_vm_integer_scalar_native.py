"""Independent fifteen-operation scalar Source3/Native8; both old profiles remain."""
from __future__ import annotations
import ast
from hashlib import sha256
import json
import os
from pathlib import Path
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
from tests.hia_vm_integer_scalar_cases import (canonical, pin, decode, cases,
    source_capture, stable, observe, operation_program, operation_arguments,
    RUNTIME_SHA256, TEST_SHA256)
from tests.hia_vm_integer_scalar_controls import TRANSPORT, ADMISSION, LIVENESS, CONTEXT, NEW_OPERATIONS
from hepta import hia_vm_integer_divrem_protocol as protocol
wire = protocol.IntegerScalarProtocol

TYPES = ("i8", "u8", "i16", "u16", "i32", "u32", "i64", "u64", "isize", "usize")
OLD_OPERATIONS = ("int.div.checked", "int.rem.checked", "int.add.checked",
                  "int.add.wrap", "int.sub.checked", "int.sub.wrap",
                  "int.mul.checked", "int.mul.wrap")
OPERATIONS = OLD_OPERATIONS + NEW_OPERATIONS


class VmIntegerScalarSourceTests(unittest.TestCase):
    def test_00_complete_sources_and_exact_six_branch_derivation(self):
        from hepta.hia_agent_assembly import assemble_program
        from hepta import hia_program_runtime as original
        from hepta import hia_vm_integer_divrem_runtime as selected
        captured = source_capture()
        self.assertEqual(sha256(captured[wire.SOURCE_NAME]).hexdigest(),
            "6a530f16b377f6e63881e1d37deb1658d099c6cf533f9fd000bd0f4f5874e1be")
        self.assertEqual(sha256(captured[protocol.SOURCE_NAME]).hexdigest(),
            "31dd3090c25aefb90b4571b4e1a0daeaff03bb8429c1e41488c47f6d44da85d1")
        self.assertEqual(sha256(captured[protocol.ARITHMETIC_SOURCE_NAME]).hexdigest(),
            "f71c6433570317f9b7f4b6549b32386f1731be75bc6ee8d3cc076b9665646473")
        program = assemble_program(captured[wire.SOURCE_NAME])
        document = program.as_dict()
        self.assertEqual([fn["name"] for fn in document["functions"]], ["f0", "f1", "f2", "f3"])
        for fn in document["functions"]:
            self.assertLessEqual(len(fn["blocks"]), 256)
            entry = next(block for block in fn["blocks"] if block["id"] == fn["entry"])
            self.assertEqual(entry["params"], fn["params"])
            definitions = [p["name"] for block in fn["blocks"] for p in block["params"]]
            definitions += [p["name"] for block in fn["blocks"]
                            for ins in block["ops"] for p in ins["out"]]
            self.assertEqual(len(definitions), len(set(definitions)))
            self.assertLessEqual(len(definitions), 2048)
        from hepta import hia_vm_integer_divrem_runtime as selected
        raw = captured["hepta/hia_program_runtime.py"]
        retained = selected._retained_runtime_source(raw)
        self.assertEqual(retained, captured["tests/fixtures/vm_integer_divrem_runtime_ce39.py.txt"])
        self.assertEqual(sha256(retained).hexdigest(), RUNTIME_SHA256)
        self.assertEqual(sha256(raw).hexdigest(), selected.V9_RUNTIME_SHA256)
        self.assertEqual(sha256(captured["tests/test_hia_program.py"]).hexdigest(), TEST_SHA256)
        tree = ast.parse(captured["hepta/hia_vm_integer_divrem_runtime.py"])
        declarations = {target.id: node.value for node in tree.body if isinstance(node, ast.Assign)
                        for target in node.targets if isinstance(target, ast.Name)}
        bodies = [ast.literal_eval(declarations[name]) for name in ("_DIV_BODY", "_ARITHMETIC_BODY")]
        replacements = ast.literal_eval(declarations["_SCALAR_REPLACEMENTS"])
        self.assertEqual(len(replacements), 4)
        bodies.extend(body for _, body in replacements)
        for body_source in bodies:
            body = ast.parse(body_source)
            self.assertFalse(any(isinstance(node, ast.BinOp) and isinstance(node.op,
                (ast.Add, ast.Sub, ast.Mult, ast.Div, ast.FloorDiv, ast.Mod,
                 ast.LShift, ast.RShift, ast.BitAnd, ast.BitOr, ast.BitXor))
                or isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.USub, ast.Invert))
                for node in ast.walk(body)))
        class DefinitionsOnly:
            def evaluate(self, *args):
                raise AssertionError("structural derivation must not run arithmetic")
            def guard(self, *args):
                raise AssertionError("structural derivation must not run a machine")
            def __call__(self, *args):
                raise AssertionError("structural derivation must not create a machine")
        before_methods = (original._Machine.operation, original._Machine.invoke, original.execute_program)
        for arithmetic, scalar in ((False, False), (True, False), (True, True)):
            operation, invoke, public = selected._derive(raw, DefinitionsOnly(),
                integer_arithmetic=arithmetic, integer_scalar=scalar)
            self.assertIs(operation.__globals__, original.__dict__)
            self.assertIs(invoke.__globals__, original.__dict__)
            self.assertIs(public.__globals__, original.__dict__)
            self.assertIn("_hia_evaluate", operation.__code__.co_freevars)
            self.assertIn("_hia_guard", invoke.__code__.co_freevars)
            self.assertIn("_hia_factory", public.__code__.co_freevars)
            self.assertEqual(public.__kwdefaults__, original.execute_program.__kwdefaults__)
        self.assertEqual(before_methods,
                         (original._Machine.operation, original._Machine.invoke, original.execute_program))
        stable(captured)

    def test_01_all19118_exact_transport_inputs_and_closed_receipts(self):
        captured = source_capture()
        _, rows = cases()
        self.assertEqual(len(rows), 19118)
        self.assertEqual({row["operation"] for row in rows}, set(OPERATIONS))
        self.assertEqual({row["type"] for row in rows}, set(TYPES))
        for ordinal, row in enumerate(rows, 1):
            with self.subTest(id=row["id"]):
                raw = wire.request(row["operation"], row["type"],
                                   int(row["lhs"]), int(row["rhs"]), ordinal)
                words = protocol._scalar_request_words(raw)
                allowed = ((0, 1, 2) if words[2] in (1, 2) else
                           (0, 3) if words[2] in (3, 5, 7, 11) else
                           (0, 4) if words[2] in (9, 10) else (0,))
                for status in range(6):
                    receipt = [protocol.REPLY_MAGIC, 1, words[1], words[2], words[3], words[4],
                               status, 0, words[5], words[6], 0, protocol.COMPLETION]
                    for index, value in enumerate(receipt):
                        if index != 10:
                            receipt[10] ^= value
                    reply = struct.pack("<12Q", *receipt)
                    if status in allowed:
                        decoded = wire.reply(raw, reply, 96)
                        self.assertEqual((decoded["status"], decoded["nonce"]), (status, ordinal))
                    else:
                        with self.assertRaises(ValueError):
                            wire.reply(raw, reply, 96)
        for operation, typ, a, b, nonce in (
            ("bad", "i8", -7, 3, 1), ("int.mul.checked", "bad", -7, 3, 1),
            ("int.mul.checked", "i8", True, 3, 1), ("int.mul.checked", "i8", -7, True, 1),
            ("int.mul.checked", "i8", -7, 3, True), ("int.mul.checked", "i8", -7, 3, 0),
            ("int.mul.checked", "i8", -129, 3, 1), ("int.mul.checked", "u8", -1, 3, 1),
            ("int.neg.checked", "i8", -7, 1, 1), ("bit.not", "i8", -7, -1, 1)):
            with self.subTest(input=(operation, typ, a, b, nonce)), self.assertRaises((ValueError, OverflowError)):
                wire.request(operation, typ, a, b, nonce)
        raw = wire.request("int.mul.checked", "i8", -7, 3, 1)
        for size in (0, 63, 65, 96):
            with self.subTest(size=size), self.assertRaises(ValueError):
                protocol._scalar_request_words(raw[:size] if size < 64 else raw + b"\0" * (size - 64))
        for count in (0, 95, 97, True):
            with self.subTest(receipt_count=count), self.assertRaises(ValueError):
                wire.reply(raw, b"\0" * 96, count)
        stable(captured)

    def test_02_full600_typed_hia_vm_witnesses_originals_first(self):
        from hepta.hia_agent_assembly import assemble_program
        from hepta import hia_program_runtime as original
        from hepta.hia_program import integer_range, WIDTHS
        captured = source_capture()
        plans = []
        for typ in TYPES:
            lo, hi = integer_range(typ)
            pairs = ((-7, 3), (lo, -1), (hi, 2), (1, 0)) if lo < 0 else (
                    (0, 1), (hi, 2), (hi, hi), (1, 0))
            for operation in OLD_OPERATIONS:
                for a, b in pairs:
                    plans.append((operation, typ, a, b))
        self.assertEqual(len(plans), 320)
        for typ in TYPES:
            lo, hi = integer_range(typ)
            width = WIDTHS[typ]
            for operation in NEW_OPERATIONS:
                if operation in ("int.shl.checked", "int.shr.checked"):
                    pairs = ((-7, 0), (lo, width - 1), (hi, width), (1, -1)) if lo < 0 else (
                             (hi, 0), (hi, width - 1), (1, width), (1, hi))
                elif operation in ("int.neg.checked", "bit.not"):
                    pairs = tuple((a, 0) for a in ((lo, -1, 0, hi) if lo < 0 else (0, 1, hi, hi - 1)))
                else:
                    pairs = ((-7, 3), (lo, -1), (hi, 2), (1, 0)) if lo < 0 else (
                            (0, 1), (hi, 2), (hi, hi), (1, 0))
                for a, b in pairs:
                    plans.append((operation, typ, a, b))
        self.assertEqual(len(plans), 600)
        originals = []
        for operation, typ, a, b in plans:
            arguments = operation_arguments(operation, a, b)
            first, ftb = observe(original.execute_program, operation_program(operation, typ), "calculate", arguments)
            second, stb = observe(original.execute_program, operation_program(operation, typ), "calculate", arguments)
            self.assertEqual(canonical(first), canonical(second))
            self.assertEqual(ftb, stb)
            originals.append(canonical(first))
        program = assemble_program(captured[wire.SOURCE_NAME])
        for ordinal, ((operation, typ, a, b), expected_raw) in enumerate(zip(plans, originals), 1):
            with self.subTest(operation=operation, type=typ, a=a, b=b):
                expected = decode(expected_raw)
                request = wire.request(operation, typ, a, b, ordinal)
                machine = original._Machine(program, 4_000_000, 16 << 20, None, 128)
                roots = [original._Owner(-1, bytearray(request)),
                         original._Owner(-2, bytearray(b"\xa5" * 96)),
                         original._Owner(-3, bytearray())]
                actual = machine.invoke(machine.functions["f0"],
                    [original._View(roots[0], False), original._View(roots[1], True),
                     original._View(roots[2], True)])
                self.assertEqual(actual, [96])
                self.assertEqual(bytes(roots[0].data), request)
                decoded = wire.reply(request, bytes(roots[1].data), actual[0])
                if expected["outcome"] == "returned":
                    self.assertEqual((decoded["status"], decoded["value"]),
                                     (0, expected["report"]["result"]))
                else:
                    code = expected["error"]["code"]
                    status = (1 if code == "division_by_zero" else
                              2 if operation in OLD_OPERATIONS[:2] else
                              4 if operation in ("int.shl.checked", "int.shr.checked") else 3)
                    self.assertEqual(code, "division_by_zero" if status == 1 else "overflow")
                    self.assertEqual(decoded["status"], status)
                    self.assertIsNone(decoded["value"])
                self.assertEqual(machine.resources()["allocation_attempts"], 0)
        stable(captured)


class VmIntegerScalarNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        manifest = os.environ.get("HEPTA_HIA_VM_INTEGER_SCALAR_MANIFEST")
        digest = os.environ.get("HEPTA_HIA_VM_INTEGER_SCALAR_SHA256")
        evidence = os.environ.get("HEPTA_HIA_VM_INTEGER_SCALAR_EVIDENCE")
        if not manifest or not digest or not evidence:
            raise unittest.SkipTest("explicit standalone scalar manifest, digest and fresh evidence required")
        cls.manifest = Path(manifest).resolve(strict=True)
        cls.digest = digest
        cls.directory = Path(evidence).resolve()
        cls.directory.mkdir(mode=0o700)
        cls.sources = source_capture()
        cls.manifest_raw = cls.manifest.read_bytes()
        if sha256(cls.manifest_raw).hexdigest() != digest:
            raise ValueError("new native suite explicit manifest authority differs")
        from tools.qualify_hia_vm_integer_scalar import supervisor
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
        command = [sys.executable, str(ROOT / "tests/hia_vm_integer_scalar_controls.py"),
                   "--group", group, "--case", name, "--manifest", str(self.manifest),
                   "--manifest-sha256", self.digest, "--output", str(output)]
        self.owned(label, command, 180)
        report = decode(output.read_bytes())
        self.assertEqual(report["status"], "PASS_CONTROL")
        self.assertEqual(report["control"], name)
        self.assertEqual(report["source_pins"], {k: pin(v) for k, v in self.sources.items()})

    def test_00_original_first_all19118_native_and_full_data_readback(self):
        command = [sys.executable, str(ROOT / "tools/qualify_hia_vm_integer_scalar.py"),
                   "--output", str(self.directory / "finite"),
                   "--manifest", str(self.manifest), "--manifest-sha256", self.digest]
        self.owned("finite19118", command, 1800)
        report = decode((self.directory / "finite/independent-readback.json").read_bytes())
        self.assertEqual(report["evidence_integrity"], "PASS")
        self.assertEqual(report["qualification"], "PASS_VALUE_TRAP_REPORT_DOMAIN_ONLY")
        self.assertEqual(report["planned"], 19118)
        self.assertFalse(report["semantic_difference_ids"])
        self.assertFalse(report["whole_vm_native"])
        self.assertFalse(report["all_input_equivalence_proved"])

    def test_01_complete_original21_then_explicit_factory21(self):
        for lane in ("original", "native"):
            with self.subTest(lane=lane):
                output = self.directory / ("generic21-" + lane)
                command = [sys.executable, str(ROOT / "tests/hia_vm_integer_scalar_cases.py"),
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

        for operation in NEW_OPERATIONS:
            with self.subTest(operation=operation):
                self.control("operation-custody", operation)

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
        from tests.hia_vm_integer_scalar_controls import INSTALLED_PROBE
        from hepta.hia_agent_contract import installation_manifest
        from hepta.hia_program_runtime import execute_program
        output = self.directory / "installed"
        output.mkdir(mode=0o700)
        wheel_dir, target = output / "wheel", output / "site"
        wheel_dir.mkdir()
        rows = []
        for ident, operation, typ, values in (
            ("signed-div", "int.div.checked", "i64", [-7, 3]),
            ("signed-rem", "int.rem.checked", "i64", [-7, 3]),
            ("zero", "int.div.checked", "u64", [1, 0]),
            ("minimum-rem", "int.rem.checked", "i64", [-(1 << 63), -1]),
            ("checked-add-overflow", "int.add.checked", "i8", [127, 1]),
            ("wrapping-add", "int.add.wrap", "u64", [(1 << 64) - 1, 1]),
            ("checked-sub-overflow", "int.sub.checked", "u64", [0, 1]),
            ("wrapping-sub", "int.sub.wrap", "i8", [-128, 1]),
            ("checked-mul-overflow", "int.mul.checked", "i64", [-(1 << 63), -1]),
            ("wrapping-mul", "int.mul.wrap", "u64", [(1 << 64) - 1, (1 << 64) - 1]),
            ("checked-u64-mul", "int.mul.checked", "u64", [(1 << 32) - 1, (1 << 32) + 1]),
            ("checked-negative-mul", "int.mul.checked", "i64", [-(1 << 62), 2]),
            ("left-shift-wrap", "int.shl.checked", "i8", [-128, 1]),
            ("signed-right-shift", "int.shr.checked", "i64", [-7, 1]),
            ("unsigned-high-right-shift", "int.shr.checked", "u64", [1 << 63, 63]),
            ("negative-shift-count", "int.shl.checked", "i64", [1, -1]),
            ("overshift-count", "int.shr.checked", "u64", [1, 64]),
            ("negative-negation", "int.neg.checked", "i64", [-7]),
            ("minimum-negation", "int.neg.checked", "i64", [-(1 << 63)]),
            ("unsigned-zero-negation", "int.neg.checked", "u64", [0]),
            ("unsigned-nonzero-negation", "int.neg.checked", "u64", [1]),
            ("high-and", "bit.and", "u64", [(1 << 64) - 1, 1 << 63]),
            ("high-or", "bit.or", "u64", [1 << 63, 1]),
            ("high-xor", "bit.xor", "u64", [(1 << 64) - 1, 1 << 63]),
            ("zero-complement", "bit.not", "u64", [0])):
            program = operation_program(operation, typ)
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
        self.assertEqual(report["native_returns"], 25)
        self.assertEqual(report["acknowledgements"], 25)
        self.assertTrue(report["source_drift_rejected_before_native"])
        self.assertTrue(report["unselected_worker_scope_rejected_before_native"])
        self.assertEqual([row["id"] for row in report["rows"]], [row["id"] for row in rows])
        for original, actual in zip(rows, report["rows"]):
            self.assertEqual(canonical(original["expected"]), canonical(actual["actual"]))


if __name__ == "__main__":
    unittest.main()

"""Actual ordinary native builds, pinned-byte refusals and installed execution.

The fixture is a development bootstrap unless its compiler is supplied from a
separate run. It does not manufacture a source-matched cold qualification.
"""
from __future__ import annotations

from contextlib import ExitStack, redirect_stderr, redirect_stdout
import copy
from hashlib import sha256
import io
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from hepta import hia_program_selfhost as native
from tests.test_hia_agent_entry import fixture

ROOT = Path(__file__).resolve().parents[1]


def _write_json(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")
    return sha256(path.read_bytes()).hexdigest()


def _test_executable(code):
    """Explicit synthetic process-owner control, never a compiler observation."""
    raw = bytearray(176) + code
    raw[:16] = b"\x7fELF\x02\x01\x01" + bytes(9)
    struct.pack_into("<HHIQQQIHHHHHH", raw, 16,
        2, 62, 1, 0x4000b0, 64, 0, 0, 64, 56, 2, 0, 0, 0)
    struct.pack_into("<IIQQQQQQ", raw, 64,
        1, 5, 0, 0x400000, 0x400000, len(raw), len(raw), 4096)
    struct.pack_into("<IIQQQQQQ", raw, 120,
        0x6474e551, 6, 0, 0, 0, 0, 0, 16)
    return bytes(raw)


class SelfhostBuildSourceTests(unittest.TestCase):
    def test_cli_rejects_unpaired_and_meaningless_selection_before_input_read(self):
        from hepta.cli import hia_main
        variants = [
            ["--backend", "selfhost"],
            ["--backend", "selfhost", "--selfhost-manifest", "missing"],
            ["--backend", "selfhost", "--selfhost-manifest-sha256", "0" * 64],
            ["--backend", "native", "--selfhost-manifest", "missing"],
            ["--selfhost-manifest-sha256", "0" * 64],
        ]
        for extra in variants:
            with self.subTest(extra=extra), redirect_stderr(io.StringIO()), \
                    patch("hepta.hia_program.verify_program", side_effect=AssertionError("input read")):
                with self.assertRaises(SystemExit) as caught:
                    hia_main(["build", "missing", "-o", "missing-output", *extra])
                self.assertEqual(caught.exception.code, 2)

    def test_profiles_and_nonfinite_budgets_refuse_without_execution(self):
        choices = [dict(kind="shared"), dict(target="aarch64-unknown-linux-gnu"),
                   dict(machine_plan={}), dict(foreign_buffer_exports=(("calculate", 8),)),
                   dict(timeout_seconds=True), dict(timeout_seconds=float("nan")),
                   dict(timeout_seconds=0), dict(timeout_seconds=float("inf"))]
        with patch("subprocess.Popen", side_effect=AssertionError("unexpected child")):
            for kwargs in choices:
                with self.subTest(kwargs=kwargs), self.assertRaises(native.SelfhostBuildRejected):
                    native.build_program_selfhost(fixture(), "/missing/output",
                        manifest="/missing/manifest", manifest_sha256="0" * 64, **kwargs)

    def test_actual_kernel_seals_prevent_executable_mutation(self):
        raw = _test_executable(bytes.fromhex("b83c00000031ff0f05"))
        fd, seals = native._sealed_executable(raw)
        try:
            self.assertEqual(seals & native.REQUIRED_SEALS, native.REQUIRED_SEALS)
            self.assertEqual(os.pread(fd, len(raw) + 1, 0), raw)
            with self.assertRaises(OSError):
                os.pwrite(fd, b"X", 0)
            with self.assertRaises(OSError):
                os.ftruncate(fd, 1)
        finally:
            os.close(fd)

    def test_original_deadline_kills_and_reaps_actual_looping_child(self):
        raw = _test_executable(b"\xeb\xfe")
        fd, _ = native._sealed_executable(raw)
        children = []
        popen = subprocess.Popen
        def launch(*args, **kwargs):
            child = popen(*args, **kwargs)
            children.append(child)
            return child
        try:
            with tempfile.TemporaryDirectory() as temp, patch.object(native.subprocess, "Popen", launch):
                with self.assertRaises(native.SelfhostBuildRejected) as caught:
                    native._run(fd, b"x", 0.05, temp)
            self.assertEqual(caught.exception.code, "E_HIA_SELFHOST_TIMEOUT")
            self.assertTrue(caught.exception.capture["leader_reaped"])
            self.assertEqual(len(children), 1)
            self.assertIsNotNone(children[0].returncode)
            with self.assertRaises(ChildProcessError):
                os.waitpid(children[0].pid, os.WNOHANG)
            with self.assertRaises(ProcessLookupError):
                os.killpg(children[0].pid, 0)
        finally:
            os.close(fd)

    def test_actual_output_limit_is_not_a_successful_truncated_object(self):
        # write(1, payload, 65536) forever. This intentionally is not a compiler.
        code = bytes.fromhex("b801000000bf01000000488d3509000000ba000001000f05eb e6")
        code += bytes(65536)
        raw = _test_executable(code)
        fd, _ = native._sealed_executable(raw)
        try:
            with tempfile.TemporaryDirectory() as temp:
                with self.assertRaises(native.SelfhostBuildRejected) as caught:
                    native._run(fd, b"x", 2, temp)
            self.assertEqual(caught.exception.code, "E_HIA_SELFHOST_OUTPUT_LIMIT")
            self.assertTrue(caught.exception.capture["leader_reaped"])
            self.assertLessEqual(caught.exception.capture["stdout_bytes_retained"], native.MAX_OBJECT_BYTES + 1)
            self.assertFalse(caught.exception.capture["stdout_complete"])
        finally:
            os.close(fd)


class SelfhostBuildNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from hepta.hia_program import execute_program, verify_program
        cls.program = fixture()
        cls.expected = {}
        checked = verify_program(cls.program)
        for function in ("calculate", "caller"):
            for argument in (0, 1, 4294967295):
                result = execute_program(checked, function, [argument])
                if result["status"] != "returned":
                    raise AssertionError(result)
                cls.expected[function, argument] = result["values"][0]
        cls.temporary = tempfile.TemporaryDirectory(prefix="hia-selfhost-build-tests-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.folder = Path(cls.temporary.name)
        from tools.qualify_hia_selfhost import compile_stage, invoke
        cold = os.environ.get("HEPTA_HIA_SOURCE_BUILD_COLD_REPORT")
        provided = os.environ.get("HEPTA_HIA_SELFHOST_BUILD_DEVELOPMENT_COMPILER")
        if cold and provided or not cold and not provided:
            raise ValueError("select exactly one matching HEPTA_HIA_SOURCE_BUILD_COLD_REPORT "
                             "or explicit HEPTA_HIA_SELFHOST_BUILD_DEVELOPMENT_COMPILER")
        cls.cold_report = Path(cold) if cold else None
        if cold:
            from tools.hia_cold_compiler import compiler_from_cold_report
            cls.compiler = compiler_from_cold_report(cls.cold_report)
            from tools.build_hia_core_json_cli import build
            cls.executable = build(cls.folder / "qualified", cls.compiler,
                                   cls.cold_report, output_profile="elf")
            cls.manifest_value = json.loads(
                (cls.executable.parent / "compiler-manifest.json").read_bytes())
            return
        cls.compiler = cls.folder / "provided-development-compiler.bin"
        cls.compiler.write_bytes(Path(provided).read_bytes())
        frontend, _ = compile_stage(cls.folder, "frontend", cls.compiler,
            (ROOT / "examples/hia_bootstrap/core_json_frontend.hepta").read_bytes())
        packer, _ = compile_stage(cls.folder, "packer", cls.compiler,
            (ROOT / "examples/hia_bootstrap/core_json_cli_packer.hepta").read_bytes())
        from tools.generate_hia_core_json_cli import MAGIC
        front, compiler = frontend.read_bytes(), cls.compiler.read_bytes()
        frame = struct.pack("<4Q", MAGIC, len(front), len(compiler), 1) + front + compiler
        result, output = invoke(cls.folder, "pack", packer, frame)
        if result["status"] != "returned" or result["abi_status"] != 0:
            raise AssertionError(result)
        cls.executable = cls.folder / "hia-core-json"
        cls.executable.write_bytes(output[:result["core_u32"]])
        cls.executable.chmod(0o500)
        cls.manifest_value = native.manifest_value(cls.executable,
            compiler_sha256=sha256(compiler).hexdigest(), frontend_sha256=sha256(front).hexdigest(),
            packer_sha256=sha256(packer.read_bytes()).hexdigest(),
            source_sha256={name: sha256((ROOT / name).read_bytes()).hexdigest()
                           for name in native.SOURCE_FILES}, cold_report_sha256=None)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=self.folder, prefix="case-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.manifest = self.root / "compiler-manifest.json"
        shutil.copyfile(self.executable, self.root / self.executable.name)
        self.pin = _write_json(self.manifest, self.manifest_value)

    def build(self, value=None, output=None, **kwargs):
        return native.build_program_selfhost(self.program if value is None else value,
            self.root / "result.o" if output is None else output,
            manifest=self.manifest, manifest_sha256=self.pin, **kwargs)

    def test_actual_native_build_with_python_emitter_forbidden_and_typed_execution(self):
        with (patch("hepta.hia_program_native._Emitter.render", side_effect=AssertionError("Python emitter")),
              patch("hepta.hia_machine_elf.write_elf_object", side_effect=AssertionError("Python ELF"))):
            receipt = self.build()
        data = (self.root / "result.o").read_bytes()
        self.assertEqual(receipt["artifact_sha256"], sha256(data).hexdigest())
        self.assertEqual(receipt["exports"], ["calculate", "caller"])
        self.assertEqual(receipt["profile"], native.PROFILE)
        self.assertEqual(receipt["compiler_cold_report_sha256"],
                         self.manifest_value["cold_report_sha256"])
        self.assertFalse(receipt["claims"]["python_emitter_used"])
        self.assertFalse(receipt["claims"]["whole_native_delivery_qualified"])
        self.assertEqual(receipt["capture"]["returncode"], 0)
        self.assertTrue(receipt["capture"]["stdout_complete"])
        self.assertTrue(receipt["capture"]["stderr_complete"])
        self.assertTrue(receipt["capture"]["leader_reaped"])
        source = self.root / "caller.c"
        checks = []
        for (function, argument), expected in self.expected.items():
            checks.append("if (%s(UINT32_C(%d)) != UINT32_C(%d)) return %d;" %
                          (function, argument, expected, len(checks) + 1))
        source.write_text("#include <stdint.h>\nextern uint32_t calculate(uint32_t);\n"
                          "extern uint32_t caller(uint32_t);\nint main(void) {\n" +
                          "\n".join(checks) + "\nreturn 0;\n}\n")
        executable = self.root / "caller"
        subprocess.run(["cc", "-std=c11", "-Werror", str(source), str(self.root / "result.o"),
                        "-Wl,-z,defs,-z,noexecstack", "-o", str(executable)],
                       check=True, capture_output=True, timeout=20)
        result = subprocess.run([str(executable)], capture_output=True, timeout=5)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, b"", b""))

    def _nominal_selection(self):
        from tests.hia_nominal_program_fixture import build_fixture
        cls = type(self)
        if not hasattr(cls, "_complete_nominal_fixture"):
            cls._complete_nominal_fixture = build_fixture(
                cls.folder / "complete-nominal", cls.compiler, cls.cold_report)
        cls._complete_nominal_fixture.check_custody()
        return cls._complete_nominal_fixture

    def _native_nominal_scope(self, fixture):
        from hepta import hia_program_composite as composite
        from tests.test_hia_composite_outer_integration import HOST, forbidden
        stack = ExitStack()
        stack.enter_context(patch.dict(os.environ, fixture.complete_environment))
        stack.enter_context(patch.object(composite, "_Types", new=forbidden))
        stack.enter_context(patch.object(composite, "elaborate_program", new=forbidden))
        stack.enter_context(patch.object(composite, "elaborate_program_native", new=forbidden))
        for name in (*HOST, "__init__", "lower"):
            stack.enter_context(patch.object(composite._Elaborator, name, new=forbidden))
        stack.enter_context(patch("hepta.hia_program_native._Emitter.render", side_effect=forbidden))
        stack.enter_context(patch("hepta.hia_machine_elf.write_elf_object", side_effect=forbidden))
        return stack

    def _save_nominal_evidence(self, label):
        destination = os.environ.get("HEPTA_HIA_SELFHOST_NOMINAL_EVIDENCE")
        if destination:
            shutil.copytree(self.root, Path(destination) / label)

    def test_native_nominal_original_cases_build_and_execute_without_host_owners(self):
        import ctypes
        from hepta.hia_program import execute_program, verify_program
        from tests import test_hia_composite_returned_loans as loans
        selection = self._nominal_selection()
        rows = []
        cases = [("pair-read", loans.pair_program("read"), "probe",
                  [(3, byte, choose) for choose in (False, True) for byte in (0, 37, 250, 255)]),
                 ("pair-mut", loans.pair_program("mut"), "probe",
                  [(3, byte, choose) for choose in (False, True) for byte in (0, 37, 250, 255)]),
                 ("read-child", loans.direct_downgrade_program(), "entry_read_child",
                  [(3, byte) for byte in (0, 37, 250, 255)]),
                 ("six-result-task", loans.task_program(), "task_probe",
                  [(size, mode) for size in (0, 1, 7) for mode in (0, 1, 2)])]
        from tests import test_hia_program_composite as original
        from tests import test_hia_partial_record as partial
        legacy_cases = [
            (original.stored_loan_program, "stored", [(False,), (True,)]),
            (original.enum_owner_program, "choose", [(flag, size) for flag in (False, True) for size in (0, 1, 7)]),
            (original.task_program, "task_case", [(mode,) for mode in (0, 1, 2)]),
            (original.scalar_task_program, "scalar_task", [()]),
            (original.owned_result_task_program, "owned_result", [(size,) for size in (0, 1, 7)]),
        ]
        for version in (1, 2):
            for factory, entry, arguments in legacy_cases:
                source = factory()
                source["schema"] = "hepta.hia.composite.v" + str(version)
                cases.append(("v" + str(version) + "-" + entry, source, entry, arguments))
        cases.extend([
            ("v3-roundtrip", partial.roundtrip_program(), "roundtrip",
             [(size, cancelled) for size in (0, 1, 7) for cancelled in (False, True)]),
            ("v3-task", partial.task_partial_program(), "partial_task",
             [(size, mode) for size in (0, 1, 7) for mode in (0, 1, 2)]),
            ("v3-chain", partial.chain_partial_program(), "chain_case", [()]),
        ])
        scalar_types = {"usize": ctypes.c_uint64, "u64": ctypes.c_uint64,
                        "u32": ctypes.c_uint32, "u8": ctypes.c_uint8, "bool": ctypes.c_bool}
        for label, source, function, arguments in cases:
            with self.subTest(case=label), patch.dict(os.environ, selection.reference_environment):
                expected = verify_program(source)
                answers = [execute_program(expected, function, list(args)) for args in arguments]
                self.assertTrue(all(row["status"] == "returned" for row in answers))
            submitted = expected if label == "pair-mut" else (
                json.dumps(source).encode() if label == "read-child" else source)
            output = self.root / (label + ".o")
            with self._native_nominal_scope(selection):
                receipt = self.build(submitted, output=output)
            self.assertEqual(receipt["input_sha256"], expected.input_sha256)
            self.assertEqual(receipt["core_sha256"], expected.sha256)
            self.assertEqual(receipt["exports"], sorted(expected.scalar_entrypoints))
            self.assertEqual(receipt["nominal_lowering"], {
                "input_schema": source["schema"], "core_schema": expected.as_dict()["schema"],
                "semantic_owners": "selected-complete-HIA", "host_semantic_fallback": False,
                "primitive_core_reverified": True, "nominal_public_abi_promoted": False})
            library_path = self.root / (label + ".so")
            subprocess.run(["cc", "-shared", str(output), "-Wl,-z,defs,-z,noexecstack", "-o", str(library_path)],
                           check=True, capture_output=True, timeout=20)
            library = ctypes.CDLL(str(library_path))
            entry = getattr(library, function)
            fn = next(row for row in expected.as_dict()["functions"] if row["name"] == function)
            entry.argtypes = [scalar_types[row["type"]] for row in fn["params"]]
            entry.restype = scalar_types[fn["returns"][0]]
            actual = [entry(*args) for args in arguments]
            self.assertEqual(actual, [row["values"][0] for row in answers])
            rows.append({"case": label, "arguments": arguments, "expected": [row["values"][0] for row in answers],
                         "actual": actual, "object_sha256": sha256(output.read_bytes()).hexdigest(),
                         "linked_sha256": sha256(library_path.read_bytes()).hexdigest()})
            (self.root / (label + ".nominal.json")).write_text(json.dumps(source, sort_keys=True) + "\n")
            (self.root / (label + ".core.json")).write_bytes(expected.canonical_bytes)
            _write_json(self.root / (label + ".receipt.json"), receipt)
        selection.check_custody()
        _write_json(self.root / "native-nominal-execution.json", rows)
        self._save_nominal_evidence("native-nominal-execution")

    def test_hosted_selfhost_cli_uses_native_nominal_preverification(self):
        import ctypes
        from hepta.cli import hia_main
        from hepta.hia_program import execute_program, verify_program
        from tests.test_hia_program_composite import scalar_task_program
        from tests.test_hia_partial_record import chain_partial_program
        selection = self._nominal_selection()
        older = scalar_task_program()
        older["schema"] = "hepta.hia.composite.v1"
        cases = [("v1-cli", older, "scalar_task"),
                 ("v3-cli", chain_partial_program(), "chain_case")]
        rows = []
        for label, source, function in cases:
            with patch.dict(os.environ, selection.reference_environment):
                expected = verify_program(source)
                answer = execute_program(expected, function, [])
            self.assertEqual(answer["status"], "returned")
            source_path = self.root / (label + ".json")
            _write_json(source_path, source)
            output = self.root / (label + ".o")
            captured = io.StringIO()
            with self._native_nominal_scope(selection), redirect_stdout(captured):
                status = hia_main(["build", str(source_path), "--backend", "selfhost",
                    "--selfhost-manifest", str(self.manifest),
                    "--selfhost-manifest-sha256", self.pin, "-o", str(output)])
            self.assertEqual(status, 0, captured.getvalue())
            receipt = json.loads(captured.getvalue())
            self.assertEqual(receipt["input_sha256"], expected.input_sha256)
            self.assertEqual(receipt["core_sha256"], expected.sha256)
            self.assertEqual(receipt["nominal_lowering"]["input_schema"], source["schema"])
            self.assertFalse(receipt["nominal_lowering"]["host_semantic_fallback"])
            library_path = output.with_suffix(".so")
            subprocess.run(["cc", "-shared", str(output), "-Wl,-z,defs,-z,noexecstack", "-o", str(library_path)],
                           check=True, capture_output=True, timeout=20)
            library = ctypes.CDLL(str(library_path))
            entry = getattr(library, function)
            entry.argtypes, entry.restype = [], ctypes.c_uint32
            actual = entry()
            self.assertEqual(actual, answer["values"][0])
            _write_json(self.root / (label + ".receipt.json"), receipt)
            rows.append({"case": label, "expected": answer["values"][0], "actual": actual,
                         "object_sha256": sha256(output.read_bytes()).hexdigest()})
        selection.check_custody()
        _write_json(self.root / "native-nominal-cli.json", rows)
        self._save_nominal_evidence("native-nominal-cli")

    def test_native_nominal_missing_owners_forged_core_and_wide_results_refuse(self):
        from hepta.hia_program import HIAProgramRejected, VerifiedProgram, verify_program
        from tests import test_hia_composite_returned_loans as loans
        selection = self._nominal_selection()
        source = loans.pair_program()
        with patch.dict(os.environ, selection.reference_environment):
            expected = verify_program(source)
            from hepta.hia_agent_assembly import assemble_program
            from tools.hia_selfhost_multi_results import extended_refusals
            seven = next(row for row in extended_refusals() if row["id"] == "seven-scalar-results")
            wide = assemble_program(seven["source"].encode()).as_dict()
            wide["functions"][0]["params"] = []
            wide["functions"][0]["blocks"][0]["params"] = []
            wide["exports"] = ["f0"]
            wide = verify_program(wide)
            unsupported = {**source, "schema": "hepta.hia.composite.v5"}
        self.assertGreater(max(len(fn["returns"]) for fn in wide.as_dict()["functions"]), 6)
        failures = []
        # The authority is now one complete executable and its exact pin.
        # Retain the original semantic inputs; missing either authority must
        # refuse before any child. The previous five ctypes owner-group
        # assertions are retained separately in the frozen qualification.
        from hepta.hia_nominal_program_native import SELECTOR, PIN_SELECTOR
        for index, changes in enumerate(({SELECTOR: ""}, {PIN_SELECTOR: ""},
                                         {PIN_SELECTOR: "0" * 64})):
            output = self.root / ("missing-" + str(index) + ".o")
            with self.subTest(selection=changes), self._native_nominal_scope(selection), \
                    patch.dict(os.environ, changes), \
                    patch("subprocess.Popen", side_effect=AssertionError("refused selection executed child")):
                with self.assertRaises(native.SelfhostBuildRejected) as caught:
                    self.build(source, output=output)
            self.assertEqual(caught.exception.code, "E_HIA_SELFHOST_NOMINAL")
            self.assertFalse(output.exists())
            failures.append({"case": changes, "error": str(caught.exception), "published": False})
        forged = VerifiedProgram(expected.canonical_bytes + b" ", expected.structured_bytes)
        run_native = native._run
        def nominal_admission_only(*args, **kwargs):
            if kwargs.get("argv0") not in {"hia-admit-agent-json", "hia-verify-core-json"}:
                raise AssertionError("forged Core executed the object compiler")
            return run_native(*args, **kwargs)
        # Native admission must run to preserve the original nominal error
        # order before comparing the retained Core. The object compiler and
        # publication remain unreachable for both refusals.
        with self._native_nominal_scope(selection), \
                patch.object(native, "_run", side_effect=nominal_admission_only):
            with self.assertRaisesRegex(HIAProgramRejected, "structured input and executable core differ"):
                self.build(forged)
            with self.assertRaises(HIAProgramRejected):
                self.build(unsupported)
        self.assertFalse((self.root / "result.o").exists())
        with self._native_nominal_scope(selection):
            with self.assertRaises(native.SelfhostBuildRejected) as caught:
                self.build(wide)
        self.assertEqual(caught.exception.code, "E_HIA_SELFHOST_COMPILE")
        self.assertIsNotNone(caught.exception.capture)
        self.assertFalse((self.root / "result.o").exists())
        failures.append({"case": "seven-result-core", "error": str(caught.exception),
                         "capture": caught.exception.capture, "published": False})
        selection.check_custody()
        _write_json(self.root / "native-nominal-refusals.json", failures)
        self._save_nominal_evidence("native-nominal-refusals")

    def test_complete_nominal_diagnostics_keep_original_owner_locations(self):
        from hepta.hia_program import HIAProgramRejected, verify_program
        from tests.test_hia_program_composite import enum_owner_program, task_program
        from tests.test_hia_composite_returned_loans import pair_program
        selection = self._nominal_selection()
        cases = []
        for factory in (enum_owner_program, task_program, pair_program):
            original = factory()
            for index, definition in enumerate(original["types"]):
                for label, change in (
                    ("name", lambda item: item.update(name="00")),
                    ("reserved", lambda item: item.update(name="h2internal_bad")),
                    ("fields", lambda item: item.update(unexpected=True)),
                ):
                    value = copy.deepcopy(original)
                    change(value["types"][index])
                    cases.append((factory.__name__ + "-" + str(index) + "-" + label, value))
                if definition.get("fields"):
                    value = copy.deepcopy(original)
                    value["types"][index]["fields"][0]["unexpected"] = True
                    cases.append((factory.__name__ + "-" + str(index) + "-field-shape", value))
                if definition.get("variants"):
                    value = copy.deepcopy(original)
                    value["types"][index]["variants"][0]["unexpected"] = True
                    cases.append((factory.__name__ + "-" + str(index) + "-variant-shape", value))
            value = copy.deepcopy(original)
            value["functions"][0]["blocks"] = []
            cases.append((factory.__name__ + "-block-inventory", value))
            value = copy.deepcopy(original)
            value["functions"][0]["effects"] = ["unknown"]
            cases.append((factory.__name__ + "-effects", value))
        results = []
        for label, value in cases:
            with self.subTest(case=label):
                with patch.dict(os.environ, selection.reference_environment):
                    with self.assertRaises(HIAProgramRejected) as reference:
                        verify_program(value)
                with self._native_nominal_scope(selection):
                    with self.assertRaises(HIAProgramRejected) as actual:
                        native._verify_selfhost_input(value)
                self.assertEqual(actual.exception.code, reference.exception.code)
                self.assertEqual(str(actual.exception), str(reference.exception))
                self.assertEqual(actual.exception.capture["admission"]["returncode"], 2)
                self.assertEqual(actual.exception.capture["diagnostic"]["returncode"], 2)
                self.assertTrue(actual.exception.capture["diagnostic"]["leader_reaped"])
                results.append({"case": label, "expected": str(reference.exception),
                                "actual": str(actual.exception), "capture": actual.exception.capture})
        self.assertGreater(len(results), 20)
        _write_json(self.root / "complete-nominal-refusals.json", results)
        selection.check_custody()
        self._save_nominal_evidence("complete-nominal-refusals")

    def test_complete_nominal_changed_selection_cannot_return_verified_bytes(self):
        from hepta.hia_nominal_program_native import SELECTOR, PIN_SELECTOR
        from tests.test_hia_program_composite import enum_owner_program
        selection = self._nominal_selection()
        copied = self.root / "nominal-selection"
        copied.mkdir()
        value = json.loads(selection.manifest.read_bytes())
        executable = copied / value["executable_path"]
        executable.write_bytes((selection.manifest.parent / value["executable_path"]).read_bytes())
        executable.chmod(0o500)
        manifest = copied / "program-manifest.json"
        manifest.write_bytes(selection.manifest.read_bytes())
        pin = sha256(manifest.read_bytes()).hexdigest()
        run_native, captures = native._run, []
        def change_after_admission(*args, **kwargs):
            output, capture = run_native(*args, **kwargs)
            captures.append(capture)
            manifest.write_bytes(manifest.read_bytes() + b" ")
            return output, capture
        with self._native_nominal_scope(selection), \
                patch.dict(os.environ, {SELECTOR: str(manifest), PIN_SELECTOR: pin}), \
                patch.object(native, "_run", side_effect=change_after_admission):
            with self.assertRaises(native.SelfhostBuildRejected) as caught:
                self.build(enum_owner_program())
        self.assertEqual(caught.exception.code, "E_HIA_SELFHOST_NOMINAL")
        self.assertEqual(len(captures), 1)
        self.assertTrue(captures[0]["leader_reaped"])
        self.assertFalse((self.root / "result.o").exists())
        selection.check_custody()

    def test_installed_complete_nominal_default_uses_pinned_native_program(self):
        from hepta.hia_program import verify_program
        from tests import test_hia_program_composite as original
        from tests import test_hia_partial_record as partial
        from tests import test_hia_composite_returned_loans as loans
        from tests.hia_nominal_program_fixture import LEGACY_SELECTORS
        from hepta.hia_nominal_program_native import SELECTOR, PIN_SELECTOR
        from tests.hia_distribution_fixture import ordinary_wheel
        cases = []
        for version in (1, 2):
            value = original.scalar_task_program()
            value["schema"] = "hepta.hia.composite.v" + str(version)
            cases.append(value)
        cases.extend((partial.roundtrip_program(), loans.pair_program("read")))
        with patch.dict(os.environ, dict.fromkeys((*LEGACY_SELECTORS, SELECTOR, PIN_SELECTOR), "")):
            rows = [{"source": value, "core_sha256": verify_program(value).sha256,
                     "input_sha256": verify_program(value).input_sha256} for value in cases]
        inputs = self.root / "original-inputs.json"
        _write_json(inputs, rows)
        installed = self.root / "installed-complete"
        result = subprocess.run([sys.executable, "-m", "pip", "install", "--no-index", "--no-deps",
            "--target", str(installed), str(ordinary_wheel(ROOT, python=sys.executable))],
            cwd=self.root, capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, (result.stdout, result.stderr))
        child = r'''
import importlib.abc,json,sys
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,sys.argv[1])
class RefuseCodegen(importlib.abc.MetaPathFinder):
    def find_spec(self,name,path=None,target=None):
        if name == 'tools' or name.startswith('tools.') or name == 'tests' or name.startswith('tests.') or name in {
            'hepta.hia_program_native','hepta.hia_machine_x64','hepta.hia_machine_elf'}:
            raise AssertionError('host codegen or authoring import: '+name)
sys.meta_path.insert(0,RefuseCodegen())
from hepta import hia_program_composite as composite
from hepta import hia_program_selfhost as native
from hepta.hia_nominal_program_native import _Selection
rows=json.loads(Path(sys.argv[2]).read_text())
def forbidden(*args,**kwargs):raise AssertionError('Python nominal semantic or continuation owner')
with ExitStack() as stack:
    for name in ('_Types','elaborate_program','elaborate_program_native'):
        stack.enter_context(patch.object(composite,name,new=forbidden))
    stack.enter_context(patch.object(composite._Elaborator,'__init__',new=forbidden))
    if sys.argv[5] == 'changed':
        with patch('subprocess.Popen',side_effect=AssertionError('changed program executed')):
            try:_Selection.package()
            except native.SelfhostBuildRejected as error:
                assert 'wheel RECORD' in str(error),str(error)
                print(json.dumps({'changed_executable_refused_before_child':True}))
            else:raise AssertionError('changed installed program accepted')
    else:
        receipts=[]
        for index,row in enumerate(rows):
            report=native.build_program_selfhost(row['source'],Path(sys.argv[6]) / ('installed-'+str(index)+'.o'),
                manifest=sys.argv[3],manifest_sha256=sys.argv[4])
            assert report['core_sha256']==row['core_sha256'],report
            assert report['input_sha256']==row['input_sha256'],report
            capture=report['nominal_capture']
            assert capture['selection_origin']=='matching-source-wheel-record',capture
            assert capture['native_orchestration'] and not capture['host_semantic_fallback'],capture
            assert capture['capture']['leader_reaped'] and capture['capture']['returncode']==0,capture
            receipts.append(report)
        print(json.dumps({'receipts':receipts},sort_keys=True))
'''
        environment = {key: value for key, value in os.environ.items()
                       if not key.startswith("HEPTA_") and key != "PYTHONPATH"}
        environment["PATH"] = ""
        def invoke(mode):
            return subprocess.run([sys.executable, "-I", "-S", "-B", "-c", child,
                str(installed), str(inputs), str(self.manifest), self.pin, mode, str(self.root)],
                cwd=self.root, env=environment, capture_output=True, text=True, timeout=60)
        observed = invoke("complete")
        self.assertEqual(observed.returncode, 0, (observed.stdout, observed.stderr))
        result = json.loads(observed.stdout)
        self.assertEqual(len(result["receipts"]), 4)
        executable = installed / "bin/hia-nominal-constructor"
        raw = executable.read_bytes()
        executable.chmod(0o700)
        executable.write_bytes(raw[:-1] + bytes([raw[-1] ^ 1]))
        refused = invoke("changed")
        self.assertEqual(refused.returncode, 0, (refused.stdout, refused.stderr))
        result.update(json.loads(refused.stdout))
        destination = os.environ.get("HEPTA_HIA_SELFHOST_NOMINAL_EVIDENCE")
        if destination:
            target = Path(destination) / "installed-complete-nominal.json"
            target.parent.mkdir(parents=True, exist_ok=True)
            _write_json(target, {"inputs": rows, **result})

    def test_explicit_export_subset_and_new_path_publication(self):
        value = {**self.program, "exports": ["calculate"]}
        result = self.build(value)
        self.assertEqual(result["binary_inventory"]["defined"], ["calculate"])
        before = (self.root / "result.o").read_bytes()
        with self.assertRaises(native.SelfhostBuildRejected):
            self.build(value)
        self.assertEqual((self.root / "result.o").read_bytes(), before)

    def test_wrong_pin_modified_executable_and_symlinks_refuse_before_child(self):
        with patch("subprocess.Popen", side_effect=AssertionError("unexpected child")):
            with self.assertRaises(native.SelfhostBuildRejected):
                native.build_program_selfhost(self.program, self.root / "badpin.o",
                    manifest=self.manifest, manifest_sha256="0" * 64)
            binary = self.root / self.executable.name
            binary.write_bytes(binary.read_bytes()[:-1] + b"X")
            with self.assertRaises(native.SelfhostBuildRejected):
                self.build()
            binary.unlink()
            binary.symlink_to(self.executable)
            with self.assertRaises(OSError):
                self.build()
            binary.unlink()
            shutil.copyfile(self.executable, binary)
            alias = self.root / "manifest-alias"
            alias.symlink_to(self.manifest)
            with self.assertRaises(OSError):
                native.build_program_selfhost(self.program, self.root / "symlink.o",
                    manifest=alias, manifest_sha256=self.pin)
            directory_alias = self.root / "directory-alias"
            directory_alias.symlink_to(self.root, target_is_directory=True)
            with self.assertRaises(OSError):
                native.build_program_selfhost(self.program, self.root / "parentlink.o",
                    manifest=directory_alias / self.manifest.name, manifest_sha256=self.pin)
        self.assertFalse((self.root / "result.o").exists())

    def test_changed_installed_source_refuses_and_native_semantic_failure_has_no_fallback(self):
        copies = self.root / "sources"
        copies.mkdir()
        paths = {}
        for index, name in enumerate(native.SOURCE_FILES):
            target = copies / str(index)
            shutil.copyfile(ROOT / name, target)
            paths[name] = target
        paths[native.SOURCE_FILES[0]].write_bytes(b"changed")
        with (patch.object(native, "_source_resource_path", lambda name: paths[name]),
              patch("subprocess.Popen", side_effect=AssertionError("unexpected child"))):
            with self.assertRaises(native.SelfhostBuildRejected) as caught:
                self.build()
            self.assertEqual(caught.exception.code, "E_HIA_SELFHOST_SOURCE")
        value = copy.deepcopy(self.program)
        value["functions"][0]["blocks"][0]["ops"].insert(0,
            {"op": "call", "args": ["x"], "out": [{"name": "recursive", "type": "u32"}],
             "attrs": {"function": "calculate"}})
        # Preserve the original recursive input bytes: this profile now admits
        # them and the actual scalar-export entry enforces its private budget.
        recursive_output = self.root / "recursive-admitted.o"
        with patch("hepta.hia_program_native.emit_program_machine", side_effect=AssertionError("fallback")):
            admitted = self.build(value, output=recursive_output)
        self.assertTrue(admitted["ok"])
        recursive_library = self.root / "recursive-admitted.so"
        subprocess.run(["cc", "-shared", str(recursive_output), "-Wl,-z,defs,-z,noexecstack", "-o", str(recursive_library)],
                       check=True, capture_output=True, timeout=20)
        child = "import ctypes,sys; f=ctypes.CDLL(sys.argv[1]).calculate; f.argtypes=[ctypes.c_uint32]; f.restype=ctypes.c_uint32; f(0)"
        exhausted = subprocess.run([sys.executable, "-I", "-S", "-c", child, str(recursive_library)],
                                   capture_output=True, timeout=5)
        self.assertEqual(exhausted.returncode, -4)
        _write_json(self.root / "recursive-admitted.receipt.json", admitted)
        value = copy.deepcopy(self.program)
        # Keep the seven-result helper private so the native compiler, not
        # the scalar public ABI precheck, owns this unchanged result limit.
        value["exports"] = [function["name"] for function in value["functions"]]
        value["functions"].append({"name": "wide_returns", "params": [{"name": "x", "type": "u32"}],
            "returns": ["u32"] * 7, "effects": [], "entry": "b0", "blocks": [{"id": "b0",
                "params": [{"name": "x", "type": "u32"}], "ops": [],
                "term": {"op": "ret", "values": ["x"] * 7}}]})
        with patch("hepta.hia_program_native.emit_program_machine", side_effect=AssertionError("fallback")):
            with self.assertRaises(native.SelfhostBuildRejected) as caught:
                self.build(value)
        self.assertEqual(caught.exception.code, "E_HIA_SELFHOST_COMPILE")
        self.assertEqual(caught.exception.capture["returncode"], 2)
        self.assertFalse((self.root / "result.o").exists())

    def test_primitive_old_schema_does_not_claim_native_v8_support(self):
        # Keep the original test ID; v6/v7 now execute while v1-v5 still refuse.
        import ctypes
        from hepta.hia_program import verify_program
        for version in (6, 7):
            value = {**self.program, "schema": "hepta.hia.program.v" + str(version)}
            expected = verify_program(value)
            output = self.root / ("v" + str(version) + ".o")
            receipt = self.build(value, output=output)
            self.assertEqual(receipt["input_sha256"], expected.input_sha256)
            self.assertEqual(receipt["core_sha256"], expected.sha256)
            self.assertNotIn("nominal_lowering", receipt)
            library_path = output.with_suffix(".so")
            subprocess.run(["cc", "-shared", str(output), "-Wl,-z,defs,-z,noexecstack", "-o", str(library_path)],
                           check=True, capture_output=True, timeout=20)
            library = ctypes.CDLL(str(library_path))
            for function in ("calculate", "caller"):
                entry = getattr(library, function)
                entry.argtypes, entry.restype = [ctypes.c_uint32], ctypes.c_uint32
                for argument in (0, 1, 4294967295):
                    self.assertEqual(entry(argument), self.expected[function, argument])
        for version in (1, 2, 3, 4, 5):
            old = {**self.program, "schema": "hepta.hia.program.v" + str(version)}
            verify_program(old)
            with self.subTest(version=version), patch("subprocess.Popen", side_effect=AssertionError("unexpected child")):
                with self.assertRaises(native.SelfhostBuildRejected) as caught:
                    self.build(old)
            self.assertEqual(caught.exception.code, "E_HIA_SELFHOST_PROFILE")
            self.assertFalse((self.root / "result.o").exists())

    def test_selection_mutation_after_execution_prevents_publication(self):
        original = native._run
        def altered(*args, **kwargs):
            result = original(*args, **kwargs)
            self.manifest.write_bytes(self.manifest.read_bytes() + b" ")
            return result
        with patch.object(native, "_run", altered):
            with self.assertRaises(native.SelfhostBuildRejected):
                self.build()
        self.assertFalse((self.root / "result.o").exists())

    def test_parent_substitution_during_execution_cannot_redirect_output_effects(self):
        destination = self.root / "output"
        destination.mkdir()
        alternate = self.root / "alternate"
        alternate.mkdir()
        moved = self.root / "original-output"
        original = native._run
        def altered(*args, **kwargs):
            result = original(*args, **kwargs)
            destination.rename(moved)
            destination.symlink_to(alternate, target_is_directory=True)
            return result
        with patch.object(native, "_run", altered):
            with self.assertRaises((native.SelfhostBuildRejected, OSError)):
                self.build(output=destination / "result.o")
        self.assertEqual(list(alternate.iterdir()), [])
        self.assertEqual(list(moved.iterdir()), [])

    def test_postpublication_selection_failure_withdraws_only_our_link(self):
        original = native.publish_verified
        def altered(*args, **kwargs):
            receipt = original(*args, **kwargs)
            self.manifest.write_bytes(self.manifest.read_bytes() + b" ")
            return receipt
        with patch.object(native, "publish_verified", altered):
            with self.assertRaises(native.SelfhostBuildRejected):
                self.build()
        self.assertFalse((self.root / "result.o").exists())

    def test_actual_native_publication_uses_captured_parent_and_rolls_back_own_link(self):
        from tools.build_hia_artifact_publication import build, current_sources, SOURCES, OPERATIONS
        from tools.hia_selfhost_contract import PROFILE
        from tools.qualify_hia_selfhost import compile_stage, invoke
        from tools.generate_hia_artifact_publication import MAGIC
        publication = self.root / "publication"
        if self.cold_report:
            executable = build(publication, self.compiler, self.cold_report)
        else:
            publication.mkdir()
            images = {}
            for name in ("artifact_publication_policy", "artifact_publication_packer", "sha256_stream"):
                images[name], _ = compile_stage(publication, name, self.compiler,
                    (ROOT / "examples/hia_bootstrap" / (name + ".hepta")).read_bytes())
            policy = images["artifact_publication_policy"].read_bytes()
            digest = images["sha256_stream"].read_bytes()
            frame = struct.pack("<3Q", MAGIC, len(policy), len(digest)) + policy + digest
            result, packed = invoke(publication, "pack", images["artifact_publication_packer"], frame)
            self.assertEqual((result["status"], result["abi_status"]), ("returned", 0))
            executable = publication / "hia-artifact"
            executable.write_bytes(packed[:result["core_u32"]])
            executable.chmod(0o500)
            _write_json(publication / "build.json", {
                "schema": "hepta.hia.artifact-publication-build.v1",
                "status": "NATIVE_ARTIFACT_PUBLICATION_BUILT", "profile": PROFILE,
                "source_manifest": current_sources(), "operations": OPERATIONS,
                "executable_path": "hia-artifact", "executable_sha256": sha256(executable.read_bytes()).hexdigest(),
                "source_sha256": {name: sha256((ROOT / name).read_bytes()).hexdigest() for name in SOURCES},
                "development_only": True, "matching_source_cold_qualified": False})
        environment = {"HEPTA_HIA_ARTIFACT_PUBLICATION_MANIFEST": str(publication / "build.json")}
        with (patch.dict(os.environ, environment),
              patch("hepta.artifact_publication._read_exact", side_effect=AssertionError("host publication"))):
            receipt = self.build()
            self.assertEqual(receipt["artifact_sha256"], sha256((self.root / "result.o").read_bytes()).hexdigest())
            destination, moved, alternate = (self.root / name for name in ("output", "moved", "alternate"))
            destination.mkdir()
            alternate.mkdir()
            original = native.publish_verified
            def altered(*args, **kwargs):
                result = original(*args, **kwargs)
                destination.rename(moved)
                destination.symlink_to(alternate, target_is_directory=True)
                return result
            with patch.object(native, "publish_verified", altered):
                with self.assertRaises((native.SelfhostBuildRejected, OSError)):
                    self.build(output=destination / "result.o")
            self.assertEqual(list(alternate.iterdir()), [])
            self.assertEqual(list(moved.iterdir()), [])

    def test_actual_cli_and_installed_wheel_forbid_host_codegen_and_authoring_imports(self):
        source = self.root / "program.hepta"
        _write_json(source, self.program)
        child = r'''
import importlib.abc,json,sys
sys.path.insert(0,sys.argv[1])
class RefuseCodegen(importlib.abc.MetaPathFinder):
    def find_spec(self,name,path=None,target=None):
        if name == 'tools' or name.startswith('tools.') or name in {
            'hepta.hia_program_native','hepta.hia_machine_x64','hepta.hia_machine_elf'}:
            raise AssertionError('host codegen or authoring import: '+name)
sys.meta_path.insert(0,RefuseCodegen())
from hepta.cli import hia_main
raise SystemExit(hia_main(json.loads(sys.argv[2])))
'''
        environment = {key: value for key, value in os.environ.items()
                       if not key.startswith("HEPTA_") and key != "PYTHONPATH"}
        environment["PATH"] = ""
        def invoke(root, output):
            args = ["build", str(source), "--backend", "selfhost", "--selfhost-manifest",
                    str(self.manifest), "--selfhost-manifest-sha256", self.pin, "-o", str(output)]
            return subprocess.run([sys.executable, "-I", "-S", "-B", "-c", child,
                                   str(root), json.dumps(args)], cwd=self.root,
                                  env=environment, capture_output=True, text=True, timeout=30)
        current = invoke(ROOT, self.root / "cli.o")
        self.assertEqual(current.returncode, 0, (current.stdout, current.stderr))
        self.assertEqual(json.loads(current.stdout)["profile"], native.PROFILE)
        from hepta.hia_agent_contract import DISCOVERY_FILES, NATIVE_SOURCE_FILES, SOURCE_BUILD_FILES, COMPILER_BUILD_FILES, PUBLICATION_BUILD_FILES, BACKEND_BUILD_FILES, EMITTER_BUILD_FILES, BYTE_WRAPPER_BUILD_FILES, MACHINE_OBJECT_BUILD_FILES, EXECUTION_OBSERVATION_BUILD_FILES, CONTINUATION_BUILD_FILES
        resources = (tuple("docs/" + name for name in DISCOVERY_FILES) + NATIVE_SOURCE_FILES + SOURCE_BUILD_FILES + COMPILER_BUILD_FILES + PUBLICATION_BUILD_FILES) + BACKEND_BUILD_FILES + EMITTER_BUILD_FILES + BYTE_WRAPPER_BUILD_FILES + MACHINE_OBJECT_BUILD_FILES + EXECUTION_OBSERVATION_BUILD_FILES + CONTINUATION_BUILD_FILES
        package = self.root / "package"
        package.mkdir()
        shutil.copytree(ROOT / "hepta", package / "hepta", ignore=shutil.ignore_patterns("__pycache__"))
        for name in (*resources, "setup.py", "pyproject.toml", "MANIFEST.in"):
            target = package / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)
        wheels, installed = self.root / "wheels", self.root / "installed"
        from tests.hia_distribution_fixture import ordinary_wheel
        steps = [
            [sys.executable, "-m", "pip", "wheel", '--no-index', "--no-deps", "--no-build-isolation", "--wheel-dir", str(wheels), str(ordinary_wheel(package, python=sys.executable))],
        ]
        for command in steps:
            result = subprocess.run(command, cwd=self.root, capture_output=True, text=True, timeout=60)
            self.assertEqual(result.returncode, 0, (result.stdout, result.stderr))
        wheel, = wheels.glob("*.whl")
        result = subprocess.run([sys.executable, "-m", "pip", "install", "--no-index", "--no-deps",
            "--target", str(installed), str(wheel)], capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, (result.stdout, result.stderr))
        for name in native.SOURCE_FILES:
            self.assertEqual((installed / "hepta/_data" / name).read_bytes(), (ROOT / name).read_bytes())
        observed = invoke(installed, self.root / "installed.o")
        self.assertEqual(observed.returncode, 0, (observed.stdout, observed.stderr))
        self.assertEqual((self.root / "installed.o").read_bytes(), (self.root / "cli.o").read_bytes())
        (installed / "hepta/_data" / native.SOURCE_FILES[2]).write_bytes(b"changed installed packer")
        refused = invoke(installed, self.root / "changed-installed.o")
        self.assertEqual(refused.returncode, 2, (refused.stdout, refused.stderr))
        self.assertFalse((self.root / "changed-installed.o").exists())


if __name__ == "__main__":
    unittest.main()

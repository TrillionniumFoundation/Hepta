"""Standard CLI publication, ABI selection and selected HIA argv control."""
from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import ctypes
import importlib.util
import io
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from hepta import cli
from hepta.hia_cli_native import NativeCli, SOURCES
from hepta.hia_machine_x64 import Code
from hepta.hia_program import verify_program
from hepta.hia_verified_simd import simd_kernel_program
from tests.test_hia_agent_entry import fixture as ordinary_module
from tests.test_hia_program import arithmetic
from tests.test_hia_verified_scalar import multiply_add


ROOT = Path(__file__).resolve().parents[1]
AVAILABLE = (platform.system() == "Linux" and platform.machine().lower() in {"x86_64", "amd64"}
             and shutil.which("ld") is not None and importlib.util.find_spec("z3") is not None)


def _environment():
    result = {name: value for name, value in os.environ.items() if not name.startswith("HEPTA_")}
    result.update(COLUMNS="80", LINES="24", TERM="dumb", PYTHON_COLORS="0", NO_COLOR="", FORCE_COLOR="")
    return result


def _invoke(argv):
    output, errors = io.StringIO(), io.StringIO()
    with redirect_stdout(output), redirect_stderr(errors):
        try:
            code = cli.hia_main(list(map(str, argv)))
        except SystemExit as error:
            code = error.code
    return code, output.getvalue(), errors.getvalue()


@unittest.skipUnless(AVAILABLE, "Linux x86-64, GNU ld and pinned Z3 are required")
class VerifiedCliTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="hia-verified-cli-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        clean = patch.dict(os.environ, _environment(), clear=True)
        clean.start()
        self.addCleanup(clean.stop)

    def source(self, program, name="source"):
        path = self.root / (name + ".core.hepta")
        path.write_bytes(verify_program(program).canonical_bytes)
        return path

    def accepted(self, argv):
        code, output, errors = _invoke(argv)
        self.assertEqual((code, errors), (0, ""), output + errors)
        return json.loads(output)

    def test_default_object_keeps_original_abi_without_linker_or_solver(self):
        source = self.source(ordinary_module())
        destination = self.root / "ordinary.o"
        child = '''
import importlib.abc,json,sys
class ForbidVerification(importlib.abc.MetaPathFinder):
 def find_spec(self,fullname,path=None,target=None):
  if fullname == 'z3' or fullname.startswith('z3.') or fullname.startswith('hepta.hia_verified_'):
   raise AssertionError('ordinary object invoked kernel validation')
sys.meta_path.insert(0,ForbidVerification())
from hepta.cli import hia_main
raise SystemExit(hia_main(['build',sys.argv[1],'-o',sys.argv[2]]))
'''
        environment = _environment()
        environment["PATH"] = ""
        process = subprocess.run([sys.executable, "-B", "-c", child, str(source), str(destination)],
                                 cwd=ROOT, env=environment, capture_output=True, text=True, timeout=30)
        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        report = json.loads(process.stdout)
        self.assertEqual(report["kind"], "object")
        self.assertFalse(report["claims"]["external_linker_used"])
        self.assertFalse(report["claims"]["backend_refinement_proved"])
        self.assertEqual(destination.read_bytes()[:4], b"\x7fELF")

    def test_standard_shared_build_auto_selects_and_proves_register_scalar(self):
        source = self.source(multiply_add())
        result = self.accepted(["build", source, "-o", self.root / "scalar.so", "--kind", "shared"])
        self.assertEqual(result["selected_strategy"], "scalar")
        self.assertTrue(result["validation"]["ok"] and result["validation"]["complete"])
        self.assertEqual(result["runtime_solver_calls"], 0)
        function = ctypes.CDLL(result["output"]).multiply_add
        function.argtypes, function.restype = [ctypes.c_uint64] * 3, ctypes.c_uint64
        self.assertEqual(function(3, 5, 7), 22)
        self.assertEqual(function(2**64 - 1, 2, 3), 1)

    def test_standard_shared_build_selects_checked_arithmetic_before_proof(self):
        source = self.source(arithmetic("int.add.checked", "u64"))
        result = self.accepted(["build", source, "-o", self.root / "checked.so", "--kind", "shared"])
        self.assertEqual(result["selected_strategy"], "checked")
        self.assertTrue(result["validation"]["ok"] and result["validation"]["complete"])
        function = ctypes.CDLL(result["output"]).calculate
        function.argtypes, function.restype = [ctypes.c_uint64] * 2, ctypes.c_uint64
        self.assertEqual(function(17, 25), 42)

    def test_standard_shared_sse2_uses_direct_borrowed_u64_result(self):
        source = self.source(simd_kernel_program("sum_u8"))
        result = self.accepted(["build", source, "-o", self.root / "sum.so", "--kind", "shared",
                                "--target-isa", "sse2"])
        self.assertEqual(result["selected_strategy"], "simd")
        self.assertTrue(result["validation"]["ok"] and result["validation"]["complete"])
        function = ctypes.CDLL(result["output"]).calculate
        function.argtypes, function.restype = [ctypes.c_void_p, ctypes.c_uint64, ctypes.c_uint64], ctypes.c_uint64
        data = (ctypes.c_uint8 * 137)(*range(137))
        self.assertEqual(function(data, 137, 137), sum(range(137)))
        self.assertEqual(function(data, 137, 65), sum(range(65)))
        self.assertEqual(function(None, 0, 0), 0)

    def test_standard_shared_default_isa_is_admitted_for_the_actual_host(self):
        source = self.source(simd_kernel_program("sum_u8"))
        result = self.accepted(["build", source, "-o", self.root / "host.so", "--kind", "shared"])
        self.assertEqual(result["selected_strategy"], "simd")
        self.assertIn(result["simd_isa"], ("sse2", "avx2", "avx512"))
        self.assertTrue(result["validation"]["ok"] and result["validation"]["complete"])
        self.assertTrue(result["cpu_admission"])
        function = ctypes.CDLL(result["output"]).calculate
        function.argtypes, function.restype = [ctypes.c_void_p, ctypes.c_uint64, ctypes.c_uint64], ctypes.c_uint64
        data = (ctypes.c_uint8 * 513)(*(index % 251 for index in range(513)))
        self.assertEqual(function(data, 513, 513), sum(index % 251 for index in range(513)))
        self.assertEqual(function(data, 513, 257), sum(index % 251 for index in range(257)))

    def test_outside_profile_shared_rejects_without_unverified_fallback(self):
        source = self.source(ordinary_module())
        destination = self.root / "refused.so"
        with patch("hepta.hia_program_native.build_program_machine", side_effect=AssertionError("unverified fallback")):
            code, output, errors = _invoke(["build", source, "-o", destination, "--kind", "shared"])
        self.assertEqual((code, errors), (2, ""))
        self.assertFalse(json.loads(output)["ok"])
        self.assertFalse(destination.exists())

    def test_proof_counterexample_never_publishes_or_switches_backend(self):
        source = self.source(multiply_add())
        destination = self.root / "counterexample.so"
        with patch.object(Code, "add", Code.sub), \
                patch("hepta.hia_verified_kernel.build_safe_core", side_effect=AssertionError("fallback after failed proof")):
            code, output, errors = _invoke(["build", source, "-o", destination, "--kind", "shared"])
        self.assertEqual((code, errors), (2, ""))
        self.assertFalse(json.loads(output)["ok"])
        self.assertFalse(destination.exists())

    def test_explicit_native_shared_keeps_ordinary_module_contract(self):
        source = self.source(ordinary_module())
        with patch("hepta.hia_verified_kernel.build_verified_kernel", side_effect=AssertionError("unexpected verified ABI")):
            result = self.accepted(["build", source, "-o", self.root / "ordinary.so",
                                    "--backend", "native", "--kind", "shared"])
        self.assertEqual(result["kind"], "shared")
        self.assertFalse(result["claims"]["backend_refinement_proved"])
        function = ctypes.CDLL(result["output"]).caller
        function.argtypes, function.restype = [ctypes.c_uint32], ctypes.c_uint32
        self.assertEqual(function(9), 10)

    def test_cross_field_errors_precede_source_read_or_publication(self):
        source, output = self.root / "missing.core.hepta", self.root / "missing.so"
        tails = (["--target-isa", "native"],
                 ["--backend", "native", "--kind", "shared", "--target-isa", "avx2"],
                 ["--backend", "selfhost", "--kind", "shared", "--selfhost-manifest", "compiler.json",
                  "--selfhost-manifest-sha256", "a" * 64])
        with patch("hepta.hia_program_tools.read_bounded", side_effect=AssertionError("source read before argument refusal")):
            for tail in tails:
                with self.subTest(tail=tail):
                    code, stdout, stderr = _invoke(["build", source, "-o", output, *tail])
                    self.assertEqual((code, stdout), (2, ""))
                    self.assertIn("error:", stderr)
        self.assertFalse(output.exists())


@unittest.skipUnless(AVAILABLE, "Linux x86-64 and GNU ld are required")
class VerifiedCliNativeRoutingTests(unittest.TestCase):
    """Executed HIA controls; this fixture does not qualify a cold compiler build."""
    @classmethod
    def setUpClass(cls):
        from hepta.hia_agent_assembly import assemble_program
        from hepta.hia_program_native import build_program_machine
        cls.temporary = tempfile.TemporaryDirectory(prefix="hia-verified-cli-control-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.root = Path(cls.temporary.name)
        cls.images = []
        for name in ("control", "format"):
            program = assemble_program(SOURCES[name].read_bytes())
            first = program.as_dict()["functions"][0]["name"]
            report = build_program_machine(program, cls.root / (name + ".so"), linker="ld",
                                           foreign_buffer_exports=((first, 1 << 20),))
            library = ctypes.CDLL(report["output"])
            function = getattr(library, first)
            function.argtypes, function.restype = [ctypes.c_void_p, ctypes.c_uint64] * 3, ctypes.c_uint64
            cls.images.append(SimpleNamespace(_entry=function, library=library))
        cls.owner = NativeCli(*cls.images)

    def setUp(self):
        clean = patch.dict(os.environ, _environment(), clear=True)
        clean.start()
        self.addCleanup(clean.stop)

    def test_every_ordinary_help_width_matches_reference_with_new_isa_choices(self):
        from tests.test_hia_cli_native import parser_outcome
        for width in range(1, 161):
            with self.subTest(width=width), patch.dict(os.environ, {"COLUMNS": str(width)}):
                expected = parser_outcome(self.owner, ["build", "--help"], selected=False)
                actual = parser_outcome(self.owner, ["build", "--help"], selected=True)
                self.assertEqual(actual, expected)

    def test_native_owner_routes_default_and_explicit_isa_with_no_python_parser(self):
        from tests.test_hia_cli_native import entry_outcome
        source = self.root / "route.core.hepta"
        source.write_bytes(verify_program(multiply_add()).canonical_bytes)
        for isa in (None, "native", "sse2", "avx2", "avx512"):
            calls = []
            argv = ["build", str(source), "-o", str(self.root / "route.so"), "--kind", "shared"]
            if isa is not None:
                argv += ["--target-isa", isa]
            def record(program, output, **options):
                calls.append((program.sha256, output, options))
                return {"ok": True, "scope": "native-command-transport-control"}
            with self.subTest(isa=isa), patch("hepta.hia_verified_kernel.build_verified_kernel", side_effect=record), \
                    patch("hepta.hia_program_native.build_program_machine", side_effect=AssertionError("unverified fallback")), \
                    patch("hepta.hia_cli_native.installed_cli", return_value=self.owner):
                expected = entry_outcome(argv)
                actual = entry_outcome(argv, self.root / "transport-only-manifest.json")
            self.assertEqual(actual, expected)
            self.assertEqual(len(calls), 2)
            self.assertEqual(calls[0], calls[1])
            self.assertEqual(calls[1][2], {"strategy": "auto", "simd_isa": isa or "native"})

    def test_native_cross_field_errors_match_before_any_foreign_source_read(self):
        from tests.test_hia_cli_native import entry_outcome
        prefix = ["build", "missing.core.hepta", "-o", "never-created.so"]
        tails = (["--target-isa", "native"],
                 ["--kind", "shared", "--backend", "native", "--target-isa", "avx512"],
                 ["--backend", "selfhost", "--kind", "shared", "--selfhost-manifest", "compiler.json",
                  "--selfhost-manifest-sha256", "a" * 64],
                 ["--kind", "shared", "--target-isa", "invalid"],
                 ["--kind", "shared", "--target"],
                 ["--kind", "shared", "--tar", "native"])
        with patch("hepta.hia_cli_native.installed_cli", return_value=self.owner), \
                patch("hepta.hia_program_tools.read_bounded", side_effect=AssertionError("source read before argument refusal")):
            for tail in tails:
                with self.subTest(tail=tail):
                    expected = entry_outcome(prefix + tail)
                    actual = entry_outcome(prefix + tail, self.root / "transport-only-manifest.json")
                    self.assertEqual(actual, expected)
                    self.assertEqual(actual[0], ("exit", 2))


if __name__ == "__main__":
    unittest.main()

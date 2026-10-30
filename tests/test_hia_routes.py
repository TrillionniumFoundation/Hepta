"""Route metadata cannot widen admission or select an implicit backend."""
from __future__ import annotations
import contextlib
import io
import importlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from hepta.cli import main
from hepta.executable_core import lower_executable_core
from hepta.hia_routes import RouteRejected, admit_route, admit_captured_cpp, execute_route, route_inventory
from hepta.hia_program_runtime import HIAProgramTrap
from hepta.parser import parse
from tests.test_core_unification import OWNED, SCALAR
from tests.test_hia_core import fixture, _PROJECT
from tests.test_hia_optimization import constant_program


class RouteTests(unittest.TestCase):
    def test_independent_rust_profile_cannot_mint_default_or_native_admission(self):
        inventory = route_inventory()
        profile, = inventory["independent_execution_profiles"]
        self.assertEqual(profile["route"], "rust-byte-dag")
        self.assertEqual(profile["profile"], "raw-byte-dag-v1")
        module, name = profile["entry"].rsplit(".", 1)
        self.assertTrue(callable(getattr(importlib.import_module(module), name)))
        self.assertEqual(inventory["authority"], "hepta.hia_program.verify_program")
        for key in ("python_semantic_admission_required", "default_admission_changed",
                    "source_or_nominal_lowering", "native_execution_authorized",
                    "receipt_grants_admission"):
            self.assertIs(profile[key], False)
        # A descriptor/report is not an alternate constructor of VerifiedProgram.
        with patch("hepta.hia_routes.verify_program", side_effect=AssertionError("must refuse first")):
            with self.assertRaisesRegex(RouteRejected, "E_HIA_ROUTE_UNSUPPORTED"):
                admit_route(profile["route"], constant_program())
        profile["native_execution_authorized"] = True
        self.assertIs(route_inventory()["independent_execution_profiles"][0]
                      ["native_execution_authorized"], False)

    def test_versioned_inventory_has_all_languages_and_legacy_non_authorities(self):
        inventory = route_inventory()
        self.assertEqual({"Hepta", "C", "C++", "C++ compilation database", "Rust", "TypeScript",
                          "Python", "Go", "assembly"},
                         {row["language"] for row in inventory["source_languages"]})
        self.assertFalse(inventory["claims"]["metadata_grants_admission"])
        inventory["claims"]["metadata_grants_admission"] = True
        self.assertFalse(route_inventory()["claims"]["metadata_grants_admission"])
        for row in inventory["historical_ir"]:
            self.assertFalse(row["independent_execution"])

    def test_optimization_commands_have_explicit_distinct_contracts(self):
        profiles = {p["command"]: p for p in route_inventory()["optimization_profiles"]}
        self.assertEqual(profiles["optimize"]["verification_command"], "verify-translation")
        self.assertEqual(profiles["fold-constants"]["verification_command"], "verify-optimization")
        self.assertTrue(profiles["optimize"]["native_ndu"])
        self.assertFalse(profiles["fold-constants"]["native_ndu"])
        self.assertFalse(profiles["verify-translation"]["receipt_grants_admission"])
        self.assertFalse(profiles["verify-optimization"]["receipt_grants_admission"])
        self.assertEqual(profiles["optimize-guarded"]["verification_command"], "verify-guarded")
        self.assertEqual(profiles["build-guarded"]["verification_command"], "verify-guarded")
        self.assertFalse(profiles["optimize-guarded"]["native_ndu"])
        self.assertFalse(profiles["verify-guarded"]["receipt_grants_admission"])
        # A command never switches meaning when another mode's flags are used.
        for argv in (["hia", "optimize", "unused.json", "--policy", "policy.json"],
                     ["hia", "fold-constants", "unused.json", "--bridge", "bridge"]):
            with self.subTest(argv=argv), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as error:
                    main(argv)
                self.assertEqual(error.exception.code, 2)

    def test_cli_options_cannot_reinterpret_ranking_guarded_or_source_routes(self):
        ranking = ["hia", "optimize", "unused.json", "--function", "calculate",
                   "--bridge", "bridge", "--bridge-build-receipt", "receipt.json",
                   "--observations", "observations.json", "--objective", "objective.json"]
        invocations = [
            ranking + ["--policy", "policy.json"],
            ranking + ["--output", "candidate.json"],
            ["hia", "fold-constants", "unused.json", "--maximum", "16"],
            ["hia", "optimize-guarded", "unused.json", "--bridge", "bridge"],
            ["hia", "verify-guarded", "unused.json", "--candidate", "candidate.json",
             "--function", "calculate"],
            ["hia", "lower", "unused.hepta", "--clangxx", "clang++"],
            ["hia", "import-cpp-project", "capture.json", "--variant", "unused"],
            ["hia", "import-cpp-composed-matrix", "matrix.json", "--variant", "selected",
             "--core-schema", "hepta.hia.program.v8"],
        ]
        for argv in invocations:
            with self.subTest(argv=argv), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as error:
                    main(argv)
                self.assertEqual(error.exception.code, 2)

    def test_source_and_both_legacy_routes_execute_one_value_model(self):
        source_program, checked, scalar = fixture(SCALAR)
        old = lower_executable_core(source_program, checked)
        inputs = [admit_route("hepta-source", SCALAR),
                  admit_route("legacy-executable", old, source=SCALAR),
                  admit_route("legacy-scalar", scalar, source=SCALAR, path="hia_scalar.hepta",
                              project_sha256=_PROJECT)]
        from hepta.core import execute_core
        for core in inputs:
            with patch("hepta.parser.parse", side_effect=AssertionError("execution reparsed source")):
                self.assertEqual(execute_core(core, "sum_rows", [5])["result"], 18)

    def test_explicit_v8_source_route_keeps_returned_loans_and_cannot_override_wire_bytes(self):
        source_path = Path(__file__).resolve().parents[1] / "examples/hia_returned_loans/returned_views.hepta"
        source = source_path.read_text()
        from hepta.hia_program_source import HIAProgramSourceRejected
        # This branching helper needs explicit v8; the older projection-only
        # source profile must keep refusing it rather than choosing a schema.
        with self.assertRaises(HIAProgramSourceRejected):
            admit_route("hepta-source", source)
        legacy = admit_route("hepta-source", "pub fn identity(x:u8)->u8 effects{} { return x; }")
        current = admit_route("hepta-source", source, core_schema="hepta.hia.program.v8")
        self.assertEqual(legacy.as_dict()["schema"], "hepta.hia.program.v1")
        self.assertEqual(current.as_dict()["schema"], "hepta.hia.program.v8")
        functions = {f["name"]: f for f in current.as_dict()["functions"]}
        self.assertEqual(functions["view"]["return_loans"], [functions["view"]["params"][0]["name"]])
        self.assertEqual(functions["edit"]["return_loans"], [functions["edit"]["params"][0]["name"]])
        calls = [op["attrs"]["function"] for b in functions["probe"]["blocks"] for op in b["ops"] if op["op"] == "call"]
        self.assertEqual(calls, ["edit", "view"])
        result = execute_route("hepta-source", source, "probe", [1, 42, True],
                               context={"core_schema": "hepta.hia.program.v8"})
        self.assertEqual(result["result"], 42 ^ 90)
        self.assertEqual(result["resources"]["live_local_loans"], 0)
        for route, payload in (("standalone-hia", current), ("legacy-executable", {}),
                               ("legacy-scalar", {}), ("legacy-composite-v2", {})):
            with self.assertRaisesRegex(RouteRejected, "cannot override"):
                admit_route(route, payload, core_schema="hepta.hia.program.v1")

    def test_cli_v8_lower_and_run_use_the_same_explicit_contract(self):
        examples = Path(__file__).resolve().parents[1] / "examples/hia_returned_loans"
        with tempfile.TemporaryDirectory() as directory:
            for filename in ("returned_views.hepta", "returned_record_views.hepta"):
                with self.subTest(source=filename):
                    source = examples / filename
                    output = Path(directory) / (source.stem + ".json")
                    stream = io.StringIO()
                    with contextlib.redirect_stdout(stream):
                        self.assertEqual(main(["hia", "lower", str(source), "--core-schema",
                            "hepta.hia.program.v8", "-o", str(output)]), 0)
                    document = json.loads(output.read_text())
                    self.assertEqual(document["schema"], "hepta.hia.program.v8")
                    self.assertEqual(document["exports"], ["probe"])
                    functions = {fn["name"]: fn for fn in document["functions"]}
                    for name in ("view", "edit"):
                        self.assertEqual(functions[name]["return_loans"],
                                         [functions[name]["params"][0]["name"]])
                        self.assertNotIn("return_origins", functions[name])
                    for choose in (False, True):
                        stream = io.StringIO()
                        with contextlib.redirect_stdout(stream):
                            self.assertEqual(main(["hia", "run", str(output), "--function", "probe",
                                "--arguments", json.dumps([1, 42, choose])]), 0)
                        report = json.loads(stream.getvalue())
                        self.assertEqual(report["result"], 42 ^ 90)
                        self.assertEqual(report["resources"]["live_owners"], 0)
                        self.assertEqual(report["resources"]["live_local_loans"], 0)
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                main(["hia", "lower", str(source), "--core-schema", "hepta.hia.program.v7"])

    def test_source_and_legacy_share_resource_and_failure_semantics(self):
        old = lower_executable_core(parse(OWNED, "owned.hepta"))
        programs = [admit_route("hepta-source", OWNED),
                    admit_route("legacy-executable", old, source=OWNED)]
        from hepta.core import execute_core
        for program in programs:
            report = execute_core(program, "checksum", [10])
            self.assertEqual(report["result"], 45)
            self.assertEqual(report["resources"]["live_owners"], 0)
            self.assertEqual(report["resources"]["live_local_loans"], 0)
            with self.assertRaises(HIAProgramTrap) as trap:
                execute_core(program, "checksum", [10], allocation_fail_at=1)
            self.assertEqual(trap.exception.code, "allocation")

    def test_unknown_language_metadata_receipt_and_backend_never_fallback(self):
        for route in ("Rust", "TypeScript", "Python", "Go", "assembly", "hepta.resource-ir.v5"):
            with self.assertRaises(RouteRejected):
                admit_route(route, constant_program())
        with self.assertRaises(RouteRejected):
            admit_route("standalone-hia", constant_program(), source="override")
        with self.assertRaises(RouteRejected):
            admit_route("legacy-executable", {}, source=None)
        for backend in ("rust", "c", "direct-llvm", "auto"):
            with self.assertRaises(RouteRejected):
                execute_route("standalone-hia", constant_program(), "calculate", [0], backend=backend)

    def test_cli_routes_and_optimization_publication_refusal(self):
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            self.assertEqual(main(["hia", "routes"]), 0)
        self.assertEqual(json.loads(stream.getvalue())["schema"], "hepta.hia.routes.v1")
        from hepta.hia_optimization import DEFAULT_POLICY
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, policy, output = root / "input.json", root / "policy.json", root / "output.json"
            source.write_text(json.dumps(constant_program()))
            policy.write_text(json.dumps({**DEFAULT_POLICY, "timeout_ms": 0}))
            stream = io.StringIO()
            with contextlib.redirect_stdout(stream):
                result = main(["hia", "fold-constants", str(source), "--policy", str(policy), "-o", str(output)])
            self.assertEqual(result, 1)
            self.assertEqual(json.loads(stream.getvalue())["verification"]["status"], "timeout")
            self.assertFalse(output.exists())

    def test_captured_matrix_verifies_unselected_variant_before_admission(self):
        captured = {"variants": [{"name": "selected", "program": constant_program()},
                                  {"name": "other", "program": {"schema": "untrusted-receipt"}}]}
        with patch("hepta.cpp_composed_project.lower_composed_matrix", return_value=captured):
            with self.assertRaises(ValueError):
                admit_captured_cpp("cpp-composed-matrix", "captured.json", variant="selected")
        with self.assertRaises(RouteRejected):
            admit_route("cpp-composed-project", "captured.json", source="override")
        with self.assertRaises(RouteRejected):
            admit_captured_cpp("cpp-composed-project", "captured.json", variant="unused")

    def test_captured_routes_execute_the_same_core_and_never_trust_a_receipt(self):
        def lower(*args, **kwargs):
            return {"program": constant_program(), "declarations": []}
        with patch("hepta.cpp_composed_project.lower_composed_project", side_effect=lower):
            program, ledger = admit_captured_cpp("cpp-composed-project", "capture.json")
            report = execute_route("cpp-composed-project", "capture.json", "calculate", [7])
        self.assertEqual(ledger["program_sha256"], program.sha256)
        self.assertFalse(ledger["native_executed"])
        from hepta.core import execute_core
        self.assertEqual(report, execute_core(program, "calculate", [7]))
        with self.assertRaises(RouteRejected):
            admit_route("standalone-hia", program, clangxx="clang++")

    def test_route_context_is_rejected_before_capture_or_source_access(self):
        captured = ("cpp-project", "cpp-matrix", "cpp-composed-project", "cpp-composed-matrix")
        overrides = {"source": "untrusted", "path": "other.hepta", "project_sha256": "0" * 64,
                     "module": "other", "core_schema": "hepta.hia.program.v8"}
        with patch("hepta.hia_routes.admit_captured_cpp", side_effect=AssertionError("capture must not start")):
            for route in captured:
                for name, value in overrides.items():
                    with self.subTest(route=route, option=name):
                        with self.assertRaisesRegex(RouteRejected, "E_HIA_ROUTE_CONTEXT"):
                            admit_route(route, "missing-capture.json", **{name: value})
        for route in ("standalone-hia", "hepta-source", "legacy-executable",
                      "legacy-scalar", "legacy-composite-v2"):
            for option in ({"clangxx": "clang++"}, {"variant": "selected"}):
                with self.subTest(route=route, option=option):
                    with self.assertRaisesRegex(RouteRejected, "capture options"):
                        admit_route(route, b"invalid-before-admission", **option)

    def test_captured_route_cannot_claim_or_force_another_core_schema(self):
        from hepta.hia_schema import SCHEMA_V8
        scalar = admit_route("hepta-source", "pub fn identity(x:u8)->u8 effects{} { return x; }",
                             core_schema=SCHEMA_V8)
        with patch("hepta.cpp_composed_project.lower_composed_project",
                   return_value={"program": scalar, "declarations": []}):
            program, ledger = admit_captured_cpp("cpp-composed-project", "capture.json")
        self.assertEqual(program.as_dict()["schema"], SCHEMA_V8)
        self.assertEqual(program.sha256, scalar.sha256)
        self.assertEqual(ledger["program_sha256"], scalar.sha256)
        # The route verifies the supplied Core and preserves its version; it
        # does not grant arbitrary resource admission from capture metadata.
        self.assertEqual(execute_route("standalone-hia", program, "identity", [27])["result"], 27)


if __name__ == "__main__":
    unittest.main()

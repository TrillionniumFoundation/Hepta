"""Route metadata cannot widen admission or select an implicit backend."""
from __future__ import annotations
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from hepta.cli import main
from hepta.executable_core import lower_executable_core
from hepta.hia_routes import RouteRejected, admit_route, execute_route, route_inventory
from hepta.hia_program_runtime import HIAProgramTrap
from hepta.parser import parse
from tests.test_core_unification import OWNED, SCALAR
from tests.test_hia_core import fixture, _PROJECT
from tests.test_hia_optimization import constant_program


class RouteTests(unittest.TestCase):
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
        # A command never switches meaning when another mode's flags are used.
        for argv in (["hia", "optimize", "unused.json", "--policy", "policy.json"],
                     ["hia", "fold-constants", "unused.json", "--bridge", "bridge"]):
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


if __name__ == "__main__":
    unittest.main()

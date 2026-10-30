"""New CLI/captured routes must end at actual standalone admission."""
import contextlib
import io
import json
import unittest
from unittest.mock import patch

from hepta.cli import main
from hepta.hia_routes import admit_captured_cpp, route_inventory
from tests.test_hia_optimization import constant_program


class RoundThreeRoutes(unittest.TestCase):
    def test_new_optimization_and_capture_routes_are_explicit(self):
        inventory = route_inventory()
        self.assertTrue({"modular-narrowing", "guarded-narrowing"} <=
                        {r["route"] for r in inventory["optimizations"]})
        self.assertTrue({"cpp-unique-project", "cpp-unique-matrix"} <=
                        {r["route"] for r in inventory["inputs"]})

    def test_unique_matrix_cannot_hide_an_invalid_unselected_core(self):
        captured = {"variants": [{"name": "selected", "program": constant_program()},
                                  {"name": "other", "program": {"schema": "forged"}}]}
        with patch("hepta.cpp_unique_project.lower_unique_matrix", return_value=captured):
            with self.assertRaises(ValueError):
                admit_captured_cpp("cpp-unique-matrix", "captured.json", variant="selected")

    def test_both_unique_cli_routes_dispatch_to_checked_core(self):
        for action, function, result in (
            ("import-cpp-unique-project", "lower_unique_project", {"program": constant_program()}),
            ("import-cpp-unique-matrix", "lower_unique_matrix", {"variants": [
                {"name": "selected", "program": constant_program()}]})):
            with self.subTest(action=action):
                stream = io.StringIO()
                arguments = ["hia", action, "captured.json"]
                if "matrix" in action:
                    arguments += ["--variant", "selected"]
                with patch("hepta.cpp_unique_project." + function, return_value=result), \
                        contextlib.redirect_stdout(stream):
                    self.assertEqual(main(arguments), 0)
                self.assertEqual(json.loads(stream.getvalue())["schema"], "hepta.hia.program.v1")


if __name__ == "__main__":
    unittest.main()

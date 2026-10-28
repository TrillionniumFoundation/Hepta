"""Captured declarations must agree on resolved parameter-contract bindings."""
from copy import deepcopy
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest

from hepta.c_migrate import migrate_c_project


CLANG = os.environ.get("CLANG") or shutil.which("clang")


@unittest.skipUnless(CLANG, "Actual Clang is required for captured contract admission")
class CContractIdentityTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="hepta-c-contract-identity-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.number = 0

    def migrate(self, header, definition, contracts, *, declaration_first=False):
        self.number += 1
        directory = self.root / str(self.number)
        directory.mkdir()
        (directory / "api.h").write_text(header)
        # Put the prototype and definition in different TUs so neither
        # definition-first nor declaration-first collection can hide a drift.
        (directory / "declaration.c").write_text('#include "api.h"\n')
        (directory / "definition.c").write_text(definition)
        names = ["declaration.c", "definition.c"] if declaration_first else ["definition.c", "declaration.c"]
        database = directory / "compile_commands.json"
        database.write_text(json.dumps([
            {"directory": str(directory), "file": name,
             "arguments": [CLANG, "-std=c11", "-O0", "-c", name, "-o", name + ".o"]}
            for name in names]))
        output = directory / "translated"
        report = migrate_c_project(database, output, contracts=deepcopy(contracts), clang=CLANG)
        return report, output

    def assert_incompatible(self, report, output):
        self.assertFalse(report["ok"], report)
        self.assertEqual(report["diagnostics"][-1]["code"], "E_C_FUNCTION", report["diagnostics"])
        self.assertTrue(report["declaration_inventory_complete"])
        self.assertFalse(output.exists(), "A conflicting declaration set must not publish a bundle")

    @staticmethod
    def slice_contract():
        return {"schema": "hepta.c-contracts.v1", "functions": {
            "probe": {"slices": {"0": {"length": "n", "access": "read"}}}}}

    def test_slice_length_preserves_same_position_parameter_renaming(self):
        contract = self.slice_contract()
        report, output = self.migrate(
            "unsigned probe(const unsigned *p, unsigned n, unsigned other);\n",
            "unsigned probe(const unsigned *data, unsigned n, unsigned spare) { return data[0]+n+spare; }\n",
            contract)
        self.assertTrue(report["ok"], report["diagnostics"])
        self.assertEqual(report["contracts"], contract)
        self.assertEqual(report["functions"][0]["params"][0]["name"], "data")
        self.assertEqual(report["functions"][0]["params"][0]["length"], "n")
        self.assertTrue((output / "source.hepta").is_file())

    def test_slice_length_rejects_parameter_position_drift_in_either_unit_order(self):
        for declaration_first in (False, True):
            with self.subTest(declaration_first=declaration_first):
                report, output = self.migrate(
                    "unsigned probe(const unsigned *p, unsigned n, unsigned other);\n",
                    "unsigned probe(const unsigned *data, unsigned other, unsigned n) { return data[0]+n+other; }\n",
                    self.slice_contract(), declaration_first=declaration_first)
                self.assert_incompatible(report, output)

    def test_record_view_shape_keeps_ordinary_slice_length_binding(self):
        record = "struct State { unsigned *data; unsigned long n; };\n"
        contract = {"schema": "hepta.c-record-views.v1",
                    "records": {"State": {"buffers": {"data": {"length_field": "n", "add": 0}}}},
                    "functions": {"probe": {"records": {}, "slices": {"0": {"length": "n", "access": "read"}}}}}
        header = record + "unsigned probe(const unsigned *p, unsigned n, unsigned other);\n"
        for swapped in (False, True):
            with self.subTest(swapped=swapped):
                parameters = "unsigned other, unsigned n" if swapped else "unsigned n, unsigned other"
                report, output = self.migrate(header,
                    record + "unsigned probe(const unsigned *data, " + parameters + ") {return data[0]+n+other;}\n", contract)
                if swapped:
                    self.assert_incompatible(report, output)
                else:
                    self.assertTrue(report["ok"], report["diagnostics"])

    @staticmethod
    def initializer_contract():
        return {"schema": "hepta.c-record-views.v1",
                "records": {"State": {"buffers": {"data": {"length_field": "n", "add": 0}}}},
                "functions": {"bind": {
                    "records": {"0": {"access": "mut", "initialize": {"data": "a"}}},
                    "slices": {"1": {"length": "n", "access": "mut"},
                               "2": {"length": "n", "access": "mut"}}}}}

    def initializer(self, swapped):
        record = "struct State { unsigned *data; unsigned long n; };\n"
        header = record + "void bind(struct State *ctx, unsigned *a, unsigned *b, unsigned long n);\n"
        middle = "unsigned *b, unsigned *a" if swapped else "unsigned *a, unsigned *spare"
        definition = record + "void bind(struct State *state, " + middle + ", unsigned long n) {state->data=a;state->n=n;}\n"
        return self.migrate(header, definition, self.initializer_contract())

    def test_initializer_source_preserves_same_position_renaming(self):
        report, output = self.initializer(False)
        self.assertTrue(report["ok"], report["diagnostics"])
        self.assertEqual(report["contracts"], self.initializer_contract())
        self.assertEqual(report["functions"][0]["params"][0]["name"], "state")
        self.assertEqual(report["functions"][0]["params"][0]["initialize"], {"data": "a"})
        self.assertTrue((output / "bridge.rs").is_file())

    def test_initializer_source_rejects_parameter_position_drift(self):
        report, output = self.initializer(True)
        self.assert_incompatible(report, output)

    def test_fixed_one_is_distinct_from_parameter_ordinal_one(self):
        # A fixed extent 1 is not the scalar at argument position 1. Swapping
        # the pointer names must not collapse these into the same identity.
        contract = {"schema": "hepta.c-contracts.v1", "functions": {"probe": {"slices": {
            "a": {"length": 1, "access": "read"}, "b": {"length": "n", "access": "read"}}}}}
        report, output = self.migrate(
            "unsigned probe(const unsigned *a, unsigned n, const unsigned *b);\n",
            "unsigned probe(const unsigned *b, unsigned n, const unsigned *a) {return a[0]+b[0];}\n",
            contract)
        self.assert_incompatible(report, output)


if __name__ == "__main__":
    unittest.main()

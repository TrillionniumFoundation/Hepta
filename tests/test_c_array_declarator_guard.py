"""Clang-backed checks for C array-parameter decay before slice admission."""
import copy
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from hepta.c_migrate import MigrationRejected, migrate_c_project
from hepta.c_translation import reject_adjusted_pointer_parameter


class CArrayParameterGuardTests(unittest.TestCase):
    def setUp(self):
        self.clang = shutil.which("clang")
        if not self.clang:
            self.skipTest("Clang is mandatory for the C migration qualification")
        temp = tempfile.TemporaryDirectory(prefix="hepta-c-array-decl-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.source = self.root / "input.c"

    def parameter(self, source):
        self.source.write_text(source, encoding="utf-8")
        proc = subprocess.run(
            [self.clang, "-std=c11", "-fsyntax-only", "-Xclang", "-ast-dump=json", str(self.source)],
            check=True, capture_output=True, text=True, timeout=30,
        )
        tree = json.loads(proc.stdout)
        function = next(node for node in tree["inner"]
                        if node.get("kind") == "FunctionDecl" and node.get("name") == "probe")
        return [node for node in function["inner"] if node.get("kind") == "ParmVarDecl"][-1]

    def test_array_declarator_rejected_after_clang_type_decay(self):
        prefix = "unsigned int probe(unsigned int n, const unsigned int "
        suffix = ") { return n; }\n"
        pointer = self.parameter(prefix + "*data" + suffix)
        self.assertEqual(pointer["type"]["qualType"], "const unsigned int *")
        reject_adjusted_pointer_parameter(pointer)
        for declarator in ("data[]", "data[4]", "data[n]", "data[++n]", "data[static n]"):
            with self.subTest(declarator=declarator):
                param = self.parameter(prefix + declarator + suffix)
                self.assertEqual(param["type"]["qualType"], pointer["type"]["qualType"])
                with self.assertRaises(MigrationRejected) as error:
                    reject_adjusted_pointer_parameter(param)
                self.assertEqual(error.exception.code, "E_C_PARAMETER_DECLARATOR")

    def test_macro_expansion_and_missing_locations_refuse(self):
        macro = self.parameter(
            "#define VLA_PARAM data[++n]\n"
            "unsigned int probe(unsigned int n, const unsigned int VLA_PARAM) { return n; }\n"
        )
        with self.assertRaises(MigrationRejected) as error:
            reject_adjusted_pointer_parameter(macro)
        self.assertEqual(error.exception.code, "E_C_PARAMETER_DECLARATOR")
        direct = self.parameter("unsigned int probe(unsigned int n, const unsigned int *data) { return n; }")
        for edit in (lambda node: node.pop("loc"),
                     lambda node: node["loc"].update(offset=True),
                     lambda node: node["range"].pop("end")):
            altered = copy.deepcopy(direct)
            edit(altered)
            with self.assertRaises(MigrationRejected) as error:
                reject_adjusted_pointer_parameter(altered)
            self.assertEqual(error.exception.code, "E_C_PARAMETER_DECLARATOR")

    def test_caller_entry_side_effect_survives_warning_suppression(self):
        self.source.write_text(
            '#pragma clang diagnostic ignored "-Wvla"\n'
            'unsigned int changed(unsigned int n, const unsigned int data[++n]) { return n; }\n'
            'unsigned int plain(unsigned int n, const unsigned int *data) { return n; }\n'
            'int main(void) { unsigned int x[10] = {0}; '
            'return changed(7u, x) == 8u && plain(7u, x) == 7u ? 0 : 1; }\n',
            encoding="utf-8",
        )
        for optimization in ("-O0", "-O2"):
            with self.subTest(optimization=optimization):
                exe = self.root / ("native-" + optimization[1:])
                subprocess.run([self.clang, "-std=c11", optimization, "-Werror=vla",
                                str(self.source), "-o", str(exe)],
                               check=True, capture_output=True, text=True, timeout=30)
                subprocess.run([str(exe)], check=True, capture_output=True, timeout=30)

    def test_c_project_refuses_vla_before_publication(self):
        contracts = {"schema": "hepta.c-contracts.v1", "functions": {
            "probe": {"slices": {"data": {"length": "n", "access": "read"}}}}}
        self.source.write_text(
            '#pragma clang diagnostic ignored "-Wvla"\n'
            'unsigned int probe(unsigned int n, const unsigned int data[++n]) { return n; }\n',
            encoding="utf-8",
        )
        database = self.root / "compile_commands.json"
        database.write_text(json.dumps([{
            "directory": str(self.root), "file": "input.c",
            "arguments": [self.clang, "-std=c11", "-Werror", "-c", "input.c", "-o", "input.o"],
        }]), encoding="utf-8")
        output = self.root / "translated"
        report = migrate_c_project(database, output, contracts=contracts, clang=self.clang)
        self.assertFalse(report["ok"], report)
        self.assertFalse(output.exists())
        self.assertIn("E_C_PARAMETER_DECLARATOR", [row["code"] for row in report["diagnostics"]], report)

        # Ordinary source pointer with the same explicit slice contract remains valid.
        self.source.write_text(
            'unsigned int probe(unsigned int n, const unsigned int *data) { return n; }\n',
            encoding="utf-8",
        )
        positive = migrate_c_project(database, output, contracts=contracts, clang=self.clang)
        self.assertTrue(positive["ok"], positive)

    def test_record_view_does_not_erase_array_parameter_entry_effects(self):
        prefix = ('#pragma clang diagnostic ignored "-Wvla"\n'
                  'struct View { unsigned char *data; unsigned int length; };\n')
        changed = ('unsigned int probe(unsigned int n, const struct View value[++n]) '
                   '{ return n; }\n')
        self.source.write_text(prefix + changed)
        caller = self.root / "caller.c"
        caller.write_text(prefix +
            'unsigned int probe(unsigned int n, const struct View *value);\n'
            'int main(void) { struct View views[8] = {{0}}; '
            'return probe(7u, views) == 8u ? 0 : 1; }\n')
        for opt in ("-O0", "-O2"):
            exe = self.root / ("record-native" + opt)
            subprocess.run([self.clang, "-std=c11", opt, "-Werror=vla",
                            str(self.source), str(caller), "-o", str(exe)],
                           check=True, capture_output=True, text=True, timeout=30)
            subprocess.run([str(exe)], check=True, capture_output=True, timeout=30)
        database = self.root / "compile_commands.json"
        database.write_text(json.dumps([{"directory": str(self.root), "file": "input.c",
            "arguments": [self.clang, "-std=c11", "-Werror", "-c", "input.c"]}]))
        contracts = {"schema": "hepta.c-record-views.v1", "records": {
            "View": {"buffers": {"data": {"length_field": "length", "add": 0}}}},
            "functions": {"probe": {"slices": {}, "records": {"value": {"access": "read"}}}}}
        output = self.root / "translated"
        report = migrate_c_project(database, output, contracts=contracts, clang=self.clang)
        self.assertFalse(report["ok"], report)
        self.assertFalse(output.exists())
        self.assertIn("E_C_PARAMETER_DECLARATOR", [d["code"] for d in report["diagnostics"]])
        self.source.write_text(prefix +
            'unsigned int probe(unsigned int n, const struct View *value) { return n; }\n')
        positive = migrate_c_project(database, output, contracts=contracts, clang=self.clang)
        self.assertTrue(positive["ok"], positive)


if __name__ == "__main__":
    unittest.main()

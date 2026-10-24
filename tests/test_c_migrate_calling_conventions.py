"""Non-default calling conventions must never become default C exports."""
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from hepta.c_migrate import migrate_c


class CallingConventionMigrationTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(shutil.which("clang"), "Clang required for calling-convention checks")
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.source = self.root / "input.c"
        self.output = self.root / "output.hepta"

    def test_type_level_calling_conventions_reject_entire_input(self):
        for convention in ("ms_abi", "vectorcall", "preserve_most", "preserve_all"):
            with self.subTest(convention=convention):
                self.source.write_text(
                    "int ordinary(int value) { return value; }\n"
                    f"int __attribute__(({convention})) special(int value) {{ return value; }}\n")
                output = self.root / (convention + ".hepta")
                result = migrate_c(self.source, output)
                self.assertFalse(result["ok"], result)
                self.assertIn("E_C_ATTRIBUTE", [x["code"] for x in result["rejected"]])
                self.assertEqual(result["converted"], [])
                self.assertFalse(output.exists())

    def test_clang_exposes_ms_abi_on_type_without_attribute_child(self):
        self.source.write_text("int __attribute__((ms_abi)) special(int value) { return value; }")
        proc = subprocess.run(["clang", "-std=c11", "-Werror", "-fsyntax-only", "-Xclang",
                               "-ast-dump=json", str(self.source)], text=True, capture_output=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        fn = next(x for x in json.loads(proc.stdout)["inner"] if x.get("name") == "special")
        self.assertIn("ms_abi", fn["type"]["qualType"])
        self.assertEqual({x["kind"] for x in fn["inner"]}, {"ParmVarDecl", "CompoundStmt"})

    def test_plain_function_and_void_signature_remain_supported(self):
        self.source.write_text("int identity(int value) {return value;} int answer(void) {return 42;}")
        result = migrate_c(self.source, self.output)
        self.assertTrue(result["ok"], result)
        self.assertEqual([x["name"] for x in result["converted"]], ["identity", "answer"])


if __name__ == "__main__":
    unittest.main()

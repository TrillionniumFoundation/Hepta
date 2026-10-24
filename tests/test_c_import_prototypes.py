"""Native header probes must confirm every imported function prototype."""
from pathlib import Path
import shutil
import tempfile
import unittest

from hepta.ast import HeptaError
from hepta.c_import import import_header


@unittest.skipUnless(shutil.which("gcc"), "GCC required for native C import probes")
class NativePrototypeImportTests(unittest.TestCase):
    def import_source(self, source):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "api.h"
            path.write_text(source)
            return import_header(path)

    def test_predefined_guard_cannot_mint_absent_function_binding(self):
        with self.assertRaises(HeptaError) as error:
            self.import_source("#ifndef __STDC__\n#define __STDC__\nint hidden(int value);\n#endif\n")
        self.assertEqual(error.exception.diagnostic.code, "E_C_IMPORT_PROBE")

    def test_probe_main_does_not_supply_an_absent_header_symbol(self):
        with self.assertRaises(HeptaError) as error:
            self.import_source("#ifndef __STDC__\n#define __STDC__\nint main(void);\n#endif\n")
        self.assertEqual(error.exception.diagnostic.code, "E_C_IMPORT_PROBE")

    def test_preincluded_header_cannot_hide_a_conflicting_prototype(self):
        # stdio.h is included by the probe before the user header. On glibc,
        # this guard hides the parsed int(int) declaration, leaving the real
        # int(const char *) remove declaration visible to the compiler.
        with self.assertRaises(HeptaError) as error:
            self.import_source("#ifndef _STDIO_H\n#define _STDIO_H\nint remove(int value);\n#endif\n")
        self.assertEqual(error.exception.diagnostic.code, "E_C_IMPORT_PROBE")

    def test_preincluded_typedef_cannot_disguise_an_incompatible_abi(self):
        # Comparing the source prototype's spelling alone would compare the
        # native __gnuc_va_list with itself, while the parser maps it to int.
        # Do not call the incompatible foreign ABI to establish this failure.
        with self.assertRaises(HeptaError) as error:
            self.import_source("#ifndef _STDIO_H\n#define _STDIO_H\ntypedef int __gnuc_va_list;\nint vprintf(const char *format, __gnuc_va_list args);\n#endif\n")
        self.assertEqual(error.exception.diagnostic.code, "E_C_IMPORT_PROBE")
        self.assertIn("imported C typedef mismatch", error.exception.diagnostic.message)

    def test_inactive_typedef_cannot_mint_a_native_type_fact(self):
        with self.assertRaises(HeptaError) as error:
            self.import_source("#ifndef __STDC__\n#define __STDC__\ntypedef int Hidden;\n#endif\n")
        self.assertEqual(error.exception.diagnostic.code, "E_C_IMPORT_PROBE")

    def test_layout_only_and_empty_headers_remain_supported(self):
        for source in ["", "struct Point { int x; };"]:
            with self.subTest(source=source):
                imported = self.import_source(source)
                self.assertEqual(imported.manifest["functions"], [])

    def test_real_pointer_record_and_unnamed_prototypes_still_import(self):
        imported = self.import_source("""
            typedef struct Point { int x; } Point;
            const int *read_value(const int *);
            Point transform(Point value, Point *output);
            int empty(void);
        """)
        self.assertEqual([f["name"] for f in imported.manifest["functions"]],
                         ["read_value", "transform", "empty"])
        self.assertIn("-> raw const i32", imported.source)


if __name__ == "__main__":
    unittest.main()

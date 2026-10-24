from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from hepta.ast import HeptaError
from hepta.c_import import import_header
from hepta.c_backend import compile_c, emit_c
from hepta.checker import check
from hepta.parser import parse


@unittest.skipUnless(shutil.which("gcc"), "GCC required for native C import probes")
class CImportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="hepta-import-test-")
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.header = self.directory / "api.h"

    def test_actual_layout_types_typedefs_and_constant_macros(self):
        self.header.write_text('''#ifndef API_H
        #define API_H
        #include <stdint.h>
        #include <stddef.h>
        #define LIMIT (1u << 5)
        #define NEGATIVE (-7)
        #define SAMPLE_COUNT 3
        typedef unsigned long Counter;
        typedef struct Point { int32_t x; double y; } Point;
        typedef struct Packet { Point origin; uint16_t samples[SAMPLE_COUNT]; } Packet;
        Point transform(Point value, const uint8_t *data, size_t count);
        int add(int a, int b);
        #endif
        ''')
        result = import_header(self.header)
        facts = result.manifest
        self.assertEqual(facts["constants"]["LIMIT"]["value"], 32)
        self.assertEqual(facts["constants"]["NEGATIVE"]["value"], -7)
        self.assertEqual(facts["layouts"]["Point"]["fields"]["x"]["offset"], 0)
        self.assertEqual(facts["layouts"]["Packet"]["fields"]["samples"]["size"], 6)
        self.assertIn("Counter", facts["typedefs"])
        self.assertIn("raw const u8", result.source)
        self.assertIn("arg2: usize", result.source)
        self.assertIn("alloc", facts["functions"][0]["effects"])
        self.assertEqual(facts["functions"][0]["semantic_contract"], "conservative_unknown_foreign_effects")
        self.assertTrue(check(parse(result.source)).ok)

    def test_imported_api_links_and_executes_in_independent_backend(self):
        self.header.write_text('''#include <stdint.h>
        #include <stddef.h>
        #define LIMIT 32u
        typedef struct Point { int32_t x; double y; } Point;
        Point transform(Point value, const uint8_t *data, size_t count);
        ''')
        result = import_header(self.header, contracts={"transform": {"ffi", "unsafe"}})
        source = result.source + '''
        fn main() -> Unit effects { ffi, unsafe, panic } {
            let data: [u8; 2] = [4, 5];
            let point: Point = Point { x: 10, y: 1.5 };
            unsafe {
                let output = transform(point, ptr_read(read data), 2);
                assert(output.x == 19); assert(output.y == 3.5);
            }
            assert(cconst_LIMIT() == 32);
        }
        '''
        native = self.directory / "api.c"
        native.write_text('''#include "api.h"
        Point transform(Point p, const uint8_t *data, size_t count) {
            for (size_t i=0;i<count;i++) p.x += data[i];
            p.y += count; return p;
        }''')
        obj = self.directory / "api.o"
        subprocess.run(["gcc", "-std=c11", "-Werror", "-c", str(native), "-o", str(obj)], check=True, capture_output=True)
        program = parse(source)
        checked = check(program)
        self.assertTrue(checked.ok, [d.to_dict() for d in checked.diagnostics])
        report = compile_c(emit_c(program, checked), output=self.directory / "consumer", link_args=[str(obj)], sanitize=True)
        self.assertTrue(report["ok"], report["diagnostics"])
        self.assertEqual(subprocess.run([report["artifact"]], capture_output=True).returncode, 0)
        self.assertEqual(result.manifest["functions"][0]["semantic_contract"], "caller_supplied_assumption")

    def test_unsupported_constructs_are_never_silently_skipped(self):
        sources = [
            "typedef struct Bad { unsigned x: 3; } Bad;",
            "int printf(const char *fmt, ...);",
            "int old_style();",
            "int callback(int (*cb)(int));",
            "typedef union U { int x; float y; } U;",
            "enum Mode { A, B };",
            "#define FN(x) ((x)+1)\nint safe(void);",
            "#if UNKNOWN\nint safe(void);\n#endif",
            "#include <pthread.h>\nint safe(void);",
            "typedef _Bool Hidden;\nint safe(void);",
            "int array_param(int values[4]);",
            "typedef struct Bad { int values[]; } Bad;",
            "int inline_body(void) { return 1; }",
        ]
        for source in sources:
            with self.subTest(source=source):
                self.header.write_text(source)
                with self.assertRaises(HeptaError) as error:
                    import_header(self.header)
                self.assertTrue(error.exception.diagnostic.code.startswith("E_C_IMPORT_"))


if __name__ == "__main__":
    unittest.main()

"""Clang's actual typedef types, never familiar identifier spellings, define C types."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from hepta.c_migrate import migrate_c


class TypedefSemanticsTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(shutil.which('clang'))
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def migrate(self, header, source):
        (self.root / 'types.h').write_text(header)
        path = self.root / 'input.c'
        path.write_text('#include "types.h"\n' + source)
        output = self.root / 'output.hepta'
        result = migrate_c(path, output)
        return result, output

    def test_signed_alias_negative_branch_uses_actual_type(self):
        result, output = self.migrate('typedef signed int uint32_t;',
            'uint32_t probe(uint32_t x) {if (x < 0) {return 1;} return 0;}')
        self.assertTrue(result['ok'], result)
        self.assertEqual(result['converted'][0]['params'], {'x': 'i32'})
        self.assertEqual(result['converted'][0]['returns'], 'i32')
        self.assertIn('x: i32', output.read_text())

    def test_defined_negative_value_matches_native_c(self):
        from hepta.c_backend import emit_c
        from hepta.checker import check
        from hepta.parser import parse
        self.assertIsNotNone(shutil.which('gcc'))
        result, output = self.migrate('typedef signed int uint32_t;',
            'int probe(uint32_t x) {if (x < 0) {return 1;} return 0;}')
        self.assertTrue(result['ok'], result)
        program = parse(output.read_text())
        generated = emit_c(program, check(program), crate_type='obj')
        # Each caller sees its own real prototype. Conversion of -1 to an
        # unsigned parameter in the broken baseline is defined, not ABI UB.
        driver = '\nint main(void) {return probe(-1); }\n'
        originals = (self.root / 'input.c').read_text()
        results = []
        for name, source in [('original', originals), ('generated', generated)]:
            path = self.root / (name + '.c')
            path.write_text(source + driver)
            binary = self.root / name
            build = subprocess.run(['gcc', '-std=c11', '-O2', str(path), '-o', str(binary)],
                                   capture_output=True, text=True, timeout=30)
            self.assertEqual(build.returncode, 0, build.stderr)
            results.append(subprocess.run([str(binary)], timeout=10).returncode)
        self.assertEqual(results[0], 1)
        self.assertEqual(results[1], results[0])

    def test_return_only_alias_and_chain_use_actual_width(self):
        result, _ = self.migrate('typedef unsigned long long Base; typedef Base int32_t;',
            'int32_t probe(void) {return 4294967296ULL;}')
        self.assertTrue(result['ok'], result)
        self.assertEqual(result['converted'][0]['returns'], 'u64')

    def test_alias_to_unsupported_type_is_rejected(self):
        for target in ('double', 'short', 'int *', 'const int'):
            with self.subTest(target=target):
                (self.root / 'output.hepta').unlink(missing_ok=True)
                result, output = self.migrate('typedef ' + target + ' uint32_t;',
                    'uint32_t probe(void) {return 0;}')
                self.assertFalse(result['ok'], result)
                self.assertFalse(output.exists())


if __name__ == '__main__':
    unittest.main()

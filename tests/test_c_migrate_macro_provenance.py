"""Macro-dependent main declarations must not disappear from scalar migration."""
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from hepta import c_migrate


class MacroProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(shutil.which('clang'))
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.src = self.root / 'input.c'
        self.out = self.root / 'output.hepta'

    def rejected(self, text, code='E_C_MACRO'):
        self.src.write_text(text)
        result = c_migrate.migrate_c(self.src, self.out)
        self.assertFalse(result['ok'], result)
        self.assertIn(code, [d['code'] for d in result['rejected']], result)
        self.assertEqual(result['converted'], [])
        self.assertFalse(self.out.exists())

    def test_macro_global_after_function_and_before_trailing_function(self):
        self.rejected('int first(int x){return x;}\n#define GLOBAL int hidden=7;\n'
                      'GLOBAL\nint last(int x){return x+1;}\n')

    def test_first_node_macro_global_cannot_hide_its_source_file(self):
        self.rejected('#define GLOBAL int hidden=7;\nGLOBAL\nint f(int x){return x;}\n')

    def test_header_defined_macro_expands_in_main_file(self):
        (self.root / 'defs.h').write_text('#define GLOBAL int hidden=7;\n')
        self.rejected('#include "defs.h"\nint first(int x){return x;}\nGLOBAL\n')

    def test_first_macro_then_header_cannot_reset_inventory_origin(self):
        self.rejected('#define GLOBAL int hidden=7;\nGLOBAL\n#include <stdint.h>\n'
                      'int f(int x){return x;}\n')

    def test_line_directive_does_not_hide_physical_main_origin(self):
        self.rejected('#line 200 "pretend-header.h"\nint first(int x){return x;}\n'
                      '#define GLOBAL int hidden=7;\nGLOBAL\n')

    def test_header_presumed_filename_does_not_become_main_origin(self):
        (self.root / 'types.h').write_text('#line 1 "input.c"\ntypedef signed int uint32_t;\n')
        self.src.write_text('#include "types.h"\nuint32_t f(uint32_t x){return x;}\n')
        result = c_migrate.migrate_c(self.src, self.out)
        self.assertTrue(result['ok'], result)
        self.assertEqual(result['converted'][0]['returns'], 'i32')

    def test_nested_body_macro_is_explicitly_unsupported(self):
        self.rejected('#define INC(x) ((x)+1)\nint f(int x){if(x<0){return INC(x);}return x;}\n')

    def test_macro_generated_entire_function_is_explicitly_unsupported(self):
        self.rejected('#define FN(name) int name(int x){return x;}\nFN(f)\n')

    def test_token_paste_and_spliced_directives_cannot_hide_globals(self):
        for directive in ('#define GLOBAL(name) int name##value=7;\n',
                          '%:define GLOBAL(name) int name##value=7;\n',
                          '#\\\ndefine GLOBAL(name) int name##value=7;\n'):
            with self.subTest(directive=directive):
                self.rejected('int first(int x){return x;}\n' + directive + 'GLOBAL(hidden)\n')

    def test_header_typedef_with_internal_macro_remains_supported(self):
        (self.root / 'types.h').write_text('#define INTEGER signed int\ntypedef INTEGER uint32_t;\n')
        self.src.write_text('#include "types.h"\nuint32_t f(uint32_t x){if(x<0){return 1;}return 0;}\n')
        result = c_migrate.migrate_c(self.src, self.out)
        self.assertTrue(result['ok'], result)
        self.assertEqual(result['converted'][0]['params'], {'x': 'i32'})
        self.assertEqual(result['converted'][0]['returns'], 'i32')

    def test_stdint_internal_macros_and_unused_main_macro_remain_supported(self):
        self.src.write_text('#include <stdint.h>\n#define UNUSED 99\nuint32_t f(uint32_t x){return x;}\n')
        result = c_migrate.migrate_c(self.src, self.out)
        self.assertTrue(result['ok'], result)

    def test_missing_main_range_is_not_silently_omitted(self):
        from hepta import c_frontend
        real_frontend = c_frontend.scalar_frontend
        def missing_range(*args):
            ast, model = real_frontend(*args)
            fn = next(n for n in ast['inner'] if n.get('name') == 'last')
            fn['range'].pop('begin')
            return ast, model
        with patch.object(c_frontend, 'scalar_frontend', side_effect=missing_range):
            self.rejected('int first(int x){return x;}\nint last(int x){return x;}\n',
                          'E_C_SOURCE_LOCATION')


if __name__ == '__main__':
    unittest.main()

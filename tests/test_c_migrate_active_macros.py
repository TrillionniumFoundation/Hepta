"""Real compiler regression for macro tokens missing from the JSON AST."""
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from hepta.c_migrate import migrate_c

class ActiveMacroTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
    def run_source(self, source, name='input.c'):
        src=self.root/name;src.write_text(source);out=self.root/(name+'.hepta')
        result=migrate_c(src,out)
        return result,out
    def test_operator_tokens_are_rejected(self):
        for name in ['input.c','odd : > é.c','newline\nname.c']:
            with self.subTest(name=name):
                r,o=self.run_source('#define PLUS +\n#line 900 "fake.h"\nint f(int x,int y){return x PLUS y;}\n',name)
                self.assertFalse(r['ok'],r);self.assertIn('E_C_MACRO',[x['code'] for x in r['rejected']]);self.assertFalse(o.exists())
    def test_empty_and_nested_operator_macros(self):
        for i,s in enumerate(['#define GAP\nint f(int x){return GAP x;}\n','#define OP +\n#define PLUS OP\nint f(int x,int y){return x PLUS y;}\n']):
            with self.subTest(source=s):
                r,o=self.run_source(s,f'case{i}.c');self.assertFalse(r['ok'],r);self.assertFalse(o.exists())
    def test_header_expansion_in_main_rejected_internal_typedef_preserved(self):
        (self.root/'types.h').write_text('#define INTEGER signed int\ntypedef INTEGER uint32_t;\n#define PLUS +\n')
        r,o=self.run_source('#include "types.h"\nuint32_t f(uint32_t x){return x;}\n')
        self.assertTrue(r['ok'],r);self.assertEqual(r['converted'][0]['returns'],'i32')
        r,o=self.run_source('#include "types.h"\nint f(int x,int y){return x PLUS y;}\n','bad.c')
        self.assertFalse(r['ok'],r);self.assertFalse(o.exists())
    def test_active_condition_expansion_rejected_but_defined_reference_preserved(self):
        r,o=self.run_source('#define YES 1\n#if YES\nint f(int x){return x;}\n#endif\n')
        self.assertFalse(r['ok'],r);self.assertFalse(o.exists())
        r,o=self.run_source('#define YES 1\n#if defined(YES)\nint f(int x){return x;}\n#endif\n','defined.c')
        self.assertTrue(r['ok'],r)
    def test_missing_helper_fails_closed(self):
        with patch.dict(os.environ,{'HEPTA_C_FRONTEND':str(self.root/'missing')}):
            r,o=self.run_source('int f(int x){return x;}\n')
        self.assertFalse(r['ok'],r);self.assertIn('E_C_FRONTEND_ENV',[x['code'] for x in r['rejected']]);self.assertFalse(o.exists())

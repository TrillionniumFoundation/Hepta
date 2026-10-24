"""Project types come from the captured TU, not familiar typedef spellings."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from hepta.c_migrate import migrate_c_project
from hepta.c_backend import emit_c
from hepta.parser import parse
from hepta.checker import check


class ProjectTypedefTests(unittest.TestCase):
    def migrate(self, root, source, header=None):
        if header is not None:
            (root / 'types.h').write_text(header)
        (root / 'input.c').write_text(source)
        db = root / 'compile_commands.json'
        db.write_text(json.dumps([{'directory': str(root), 'file': 'input.c',
            'arguments': ['clang', '-std=c11', '-c', 'input.c']}]))
        result = migrate_c_project(db, root / 'out', clang=shutil.which('clang'))
        return result, root / 'out/source.hepta'

    def test_signed_local_defined_behavior_native_oracle(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source = 'typedef signed int uint32_t; int probe(void) {uint32_t x=-1; if(x<0) return 1; return 0;}'
            report, output = self.migrate(root, source)
            self.assertTrue(report['ok'], report)
            program = parse(output.read_text()); checked = check(program)
            generated = emit_c(program, checked, crate_type='obj')
            observed = []
            for name, text in [('original', source+'\nint main(void){return probe();}'),
                               ('generated', generated+'\nint main(void){return __hepta_cb_fn_c_probe();}')]:
                cfile = root / (name+'.c'); binary = root / name
                cfile.write_text(text)
                subprocess.run([shutil.which('clang'), '-std=c11', '-O2', str(cfile), '-o', str(binary)], check=True, capture_output=True, timeout=30)
                observed.append(subprocess.run([str(binary)], timeout=10).returncode)
            self.assertEqual(observed, [1, 1])

    def test_parameter_return_and_header_alias_chains(self):
        for alias, underlying, hepta, literal in [('uint32_t','int','i32','1'), ('int32_t','unsigned long long','u64','4294967296ULL')]:
            for header in [False, True]:
                with self.subTest(alias=alias, header=header), tempfile.TemporaryDirectory() as td:
                    root=Path(td); defs=f'typedef {underlying} Base; typedef Base {alias};'
                    source = ('#include "types.h"\n' if header else defs) + f'{alias} echo({alias} x){{return x;}} {alias} result(void){{return {literal};}}'
                    report, output=self.migrate(root, source, defs if header else None)
                    self.assertTrue(report['ok'],report)
                    self.assertIn(f'fn c_echo(p_x: {hepta}) -> {hepta}',output.read_text())
                    self.assertIn(f'fn c_result() -> {hepta}',output.read_text())

    def test_unsupported_aliases_fail_closed(self):
        for typ in ['volatile int', 'int *', '_Atomic(int)']:
            with self.subTest(typ=typ), tempfile.TemporaryDirectory() as td:
                root=Path(td)
                report,_=self.migrate(root, f'typedef {typ} uint32_t; uint32_t result(void){{return 0;}}')
                self.assertFalse(report['ok'],report)
                self.assertFalse((root/'out').exists())

    def test_standard_header_aliases_remain_supported(self):
        with tempfile.TemporaryDirectory() as td:
            report,output=self.migrate(Path(td),'#include <stdint.h>\n#include <stddef.h>\nuint32_t value(uint32_t x){return x;} size_t length(size_t n){return n;}')
            self.assertTrue(report['ok'],report)
            self.assertIn('p_n: usize',output.read_text())
            self.assertIn('p_x: u32',output.read_text())

    def test_translation_unit_context_and_conflicting_aliases(self):
        for same in [True, False]:
            with self.subTest(same=same), tempfile.TemporaryDirectory() as td:
                root=Path(td); entries=[]
                for name, typ in [('a','int'),('b','int' if same else 'unsigned int')]:
                    (root/(name+'.c')).write_text(f'typedef {typ} Value; Value {name}(Value x){{return x;}}')
                    entries.append({'directory':str(root),'file':name+'.c','arguments':['clang','-std=c11','-c',name+'.c']})
                db=root/'compile_commands.json'; db.write_text(json.dumps(entries))
                report=migrate_c_project(db,root/'out',clang=shutil.which('clang'))
                self.assertEqual(report['ok'],same,report)
                if not same:
                    self.assertIn('E_C_ALIAS',[d['code'] for d in report['diagnostics']])
                    self.assertFalse((root/'out').exists())

    def test_type_context_does_not_borrow_names_from_another_unit(self):
        from hepta.c_translation import CTranslator
        from hepta.c_migrate import MigrationRejected
        model={'long_bits':64,'pointer_bits':64,'char_unsigned':False}
        translator=CTranslator({'configurations':[{'model':model},{'model':model}]})
        translator.typedef_types={0:{'uint32_t':{'qualType':'int'}},1:{}}
        translator.aliases={'uint32_t':'i32'}
        self.assertEqual(translator.typ('uint32_t',unit=0),'i32')
        for name in ['uint32_t','size_t']:
            with self.assertRaises(MigrationRejected):
                translator.typ(name,unit=1)
        translator.typedef_types[1]={'Loop':{'qualType':'Loop'}}
        with self.assertRaises(MigrationRejected):
            translator.typ('Loop',unit=1)

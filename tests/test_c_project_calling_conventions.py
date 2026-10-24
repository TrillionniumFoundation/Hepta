"""Captured project migration must not erase type-level ABI conventions."""
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from hepta.c_migrate import migrate_c_project


class ProjectCallingConventionTests(unittest.TestCase):
    def migrate(self, root, source):
        (root/'input.c').write_text(source)
        database=root/'compile_commands.json'
        database.write_text(json.dumps([{'directory':str(root),'file':'input.c',
            'arguments':['clang','-std=c11','-c','input.c']}]))
        return migrate_c_project(database,root/'out',clang=shutil.which('clang'))

    def test_explicit_type_level_conventions_reject_without_bundle(self):
        for convention in ['ms_abi','vectorcall','preserve_most','preserve_all']:
            for position in ['before_type','before_name']:
                with self.subTest(convention=convention,position=position), tempfile.TemporaryDirectory() as td:
                    root=Path(td); attr=f'__attribute__(({convention}))'
                    declaration=f'{attr} int probe' if position=='before_type' else f'int {attr} probe'
                    report=self.migrate(root,declaration+'(int x){return x;}')
                    self.assertFalse(report['ok'],report)
                    self.assertIn('E_C_ATTRIBUTE',[d['code'] for d in report['diagnostics']])
                    self.assertFalse((root/'out').exists())

    def test_inherited_convention_and_typedef_return_reject(self):
        for convention in ['ms_abi','vectorcall']:
            with self.subTest(convention=convention), tempfile.TemporaryDirectory() as td:
                root=Path(td)
                source=f'typedef int Value; Value __attribute__(({convention})) probe(Value x); Value probe(Value x){{return x;}}'
                report=self.migrate(root,source)
                self.assertFalse(report['ok'],report)
                self.assertIn('E_C_ATTRIBUTE',[d['code'] for d in report['diagnostics']])
                self.assertFalse((root/'out').exists())

    def test_plain_builtin_and_typedef_signatures_remain_supported(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            report=self.migrate(root,'typedef unsigned long long Value; Value probe(Value x); Value probe(Value x){return x;} int zero(void){return 0;}')
            self.assertTrue(report['ok'],report)
            self.assertIn('fn c_probe(p_x: u64) -> u64',(root/'out/source.hepta').read_text())

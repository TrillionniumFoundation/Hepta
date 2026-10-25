"""Boundary repairs preserve the newer record-view and ABI-model interfaces."""
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from hepta.c_migrate import migrate_c_project, MigrationRejected
from hepta.c_record_views import CRecordViewTranslator


class ProjectBoundaryIntegrationTests(unittest.TestCase):
    def test_record_field_hook_uses_explicit_translation_unit(self):
        model = {'long_bits': 64, 'pointer_bits': 64, 'char_unsigned': False}
        contracts = {'schema': 'hepta.c-record-views.v1', 'records': {
            'State': {'buffers': {'data': {'length_field': 'n', 'add': 0}}}}, 'functions': {}}
        t = CRecordViewTranslator({'configurations': [{'model': model}, {'model': model}]}, contracts)
        t.typedef_types = {0: {'Element': {'qualType': 'int'}}, 1: {'Element': {'qualType': 'unsigned char'}}}
        pointer = {'name': 'data', 'type': {'qualType': 'Element *'}}
        scalar = {'name': 'count', 'type': {'qualType': 'Element'}}
        self.assertEqual(t.field_type('State', pointer, unit=1), 'view:u8')
        self.assertEqual(t.field_type('State', scalar, unit=1), 'u8')
        self.assertEqual(t.field_type('State', scalar, unit=0), 'i32')
        t.typedef_types[1] = {}
        with self.assertRaises(MigrationRejected):
            t.field_type('State', pointer, unit=1)

    def test_two_record_view_units_keep_separate_alias_context(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); entries = []; records = {}; functions = {}
            for name in ['A', 'B']:
                source = (f'#include <stddef.h>\ntypedef unsigned char {name}Byte; '
                          f'struct {name} {{ {name}Byte *data; size_t n; }}; '
                          f'{name}Byte read_{name}(struct {name} *p){{return p->data[0];}}')
                (root / (name + '.c')).write_text(source)
                entries.append({'directory': td, 'file': name + '.c', 'arguments': ['clang', '-std=c11', '-c', name + '.c']})
                records[name] = {'buffers': {'data': {'length_field': 'n', 'add': 0}}}
                functions['read_' + name] = {'records': {'p': {'access': 'read'}}, 'slices': {}}
            db = root / 'compile_commands.json'; db.write_text(json.dumps(entries))
            report = migrate_c_project(db, root / 'out', clang=shutil.which('clang'), contracts={
                'schema': 'hepta.c-record-views.v1', 'records': records, 'functions': functions})
            self.assertTrue(report['ok'], report)
            self.assertEqual(report['coverage']['status_counts']['record_converted'], 2)
            text = (root / 'out/source.hepta').read_text()
            self.assertIn('fn c_read_A', text); self.assertIn('fn c_read_B', text)

    def test_record_view_rejects_type_level_calling_convention(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / 'input.c').write_text('#include <stddef.h>\nstruct State { unsigned char *data; size_t n; }; '
                '__attribute__((ms_abi)) int read_value(struct State *p){return p->data[0];}')
            db = root / 'compile_commands.json'; db.write_text(json.dumps([{'directory': td,
                'file': 'input.c', 'arguments': ['clang', '-std=c11', '-c', 'input.c']}]))
            report = migrate_c_project(db, root / 'out', clang=shutil.which('clang'), contracts={
                'schema': 'hepta.c-record-views.v1', 'records': {'State': {'buffers': {'data': {'length_field': 'n', 'add': 0}}}},
                'functions': {'read_value': {'records': {'p': {'access': 'read'}}, 'slices': {}}}})
            self.assertFalse(report['ok'], report)
            self.assertIn('E_C_ATTRIBUTE', [d['code'] for d in report['diagnostics']])
            self.assertFalse((root / 'out').exists())

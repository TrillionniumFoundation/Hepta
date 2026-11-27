"""Whole-file predecessor and tamper controls for native cold caller wiring."""
import ast
from copy import deepcopy
from hashlib import sha256
from pathlib import Path
import unittest

from tools import hia_cold_caller_sources as subject

ROOT = Path(__file__).resolve().parents[1]


class NativeColdCallerSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = (ROOT / subject.FIXTURE).read_bytes()
        cls.relations = subject.read_relations(cls.raw)

    def test_every_current_file_restores_its_complete_pinned_predecessor(self):
        for name, item in self.relations.items():
            with self.subTest(path=name):
                raw = (ROOT / name).read_bytes()
                self.assertEqual(subject.pin(raw), item['current'])
                old = subject.restore_caller_source(name, raw, self.relations)
                self.assertEqual(subject.pin(old), item['predecessor'])
                self.assertEqual(subject.restore_caller_source(name, old, self.relations), old)

    def test_changed_complete_source_is_refused_at_three_separated_bytes(self):
        for name in self.relations:
            raw = (ROOT / name).read_bytes()
            for offset in (0, len(raw) // 2, len(raw) - 1):
                with self.subTest(path=name, offset=offset):
                    changed = bytearray(raw); changed[offset] ^= 1
                    with self.assertRaises(ValueError):
                        subject.restore_caller_source(name, bytes(changed), self.relations)

    def test_changed_authority_is_refused_at_three_separated_bytes(self):
        for offset in (0, len(self.raw) // 2, len(self.raw) - 1):
            with self.subTest(offset=offset):
                changed = bytearray(self.raw); changed[offset] ^= 1
                with self.assertRaises(ValueError):
                    subject.read_relations(bytes(changed))

    def test_inverse_coordinates_and_expected_original_cannot_be_substituted(self):
        name = 'tests/test_hia_evaluation_native.py'
        raw = (ROOT / name).read_bytes()
        for mode in ('offset', 'current', 'predecessor', 'expected'):
            with self.subTest(mode=mode):
                changed = deepcopy(self.relations)
                row = changed[name]
                if mode == 'offset':row['splices'][0]['offset'] = -1
                elif mode == 'current':row['splices'][0]['current_hex'] = 'ff'
                elif mode == 'predecessor':row['splices'][0]['predecessor_hex'] = 'ff'
                else:row['predecessor']['sha256'] = '0' * 64
                with self.assertRaises(ValueError):
                    subject.restore_caller_source(name, raw, changed)

    def test_existing_frozen_component_relations_keep_all_original_hashes(self):
        from tools.hia_frozen_component_sources import FIXTURE, reviewed_source
        import json
        rows = json.loads((ROOT / FIXTURE).read_bytes())['files']
        self.assertEqual(len(rows), 17)
        for name, relation in rows.items():
            with self.subTest(path=name):
                old = reviewed_source(ROOT, name, (ROOT / name).read_bytes())
                self.assertEqual(sha256(old).hexdigest(), relation['reviewed_sha256'])

    def test_all_test_method_ids_and_assertions_remain_original(self):
        def inventory(raw):
            result = {}
            def walk(node, prefix=''):
                for child in ast.iter_child_nodes(node):
                    if isinstance(child, ast.ClassDef):
                        walk(child, prefix + child.name + '.')
                    elif isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        if child.name.startswith('test_'):
                            assertions = [ast.dump(n) for n in ast.walk(child)
                                if isinstance(n, ast.Assert) or (isinstance(n, ast.Call)
                                    and isinstance(n.func, ast.Attribute)
                                    and n.func.attr.startswith('assert'))]
                            result[prefix + child.name] = assertions
                    else:walk(child, prefix)
            walk(ast.parse(raw));return result
        for name in self.relations:
            if not name.startswith('tests/'):continue
            with self.subTest(path=name):
                raw = (ROOT / name).read_bytes()
                old = subject.restore_caller_source(name, raw, self.relations)
                self.assertEqual(inventory(raw), inventory(old))

    def test_unlisted_source_is_not_given_a_successor_exception(self):
        raw = b'unchanged unlisted source'
        self.assertEqual(subject.restore_caller_source('unlisted.py', raw, self.relations), raw)


if __name__ == '__main__':
    unittest.main()

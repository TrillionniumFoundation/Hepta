"""Source and profile boundaries for the separately qualified bulk-word path."""
from pathlib import Path
from types import SimpleNamespace
import ast
import tempfile
import unittest

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_worker_config_json import document
from tools.generate_hia_seed_backend import program as original
from tools.generate_hia_seed_word_backend import program as word
from tools.generate_hia_seed_bulk_backend import program as bulk
from tools.generate_hia_seed_endian_backend import program as endian
from tools.generate_hia_seed_cold_backend import program as cold
from tools.generate_hia_seed_cold_bulk_word_backend import program as combined
from tools.hia_seed_word_store import add_word_store
from tools.generate_hia_cold_qualification_driver import policy_source
from tools.generate_hia_cold_toolchain_build import Stage, PROFILE_SOURCE
from tools.hia_native_cold_preseed import Builder, PROFILE_SOURCE as PRESEED_PROFILES

ROOT = Path(__file__).resolve().parents[1]


def functions(source):
    return {node.name: node for node in ast.parse(source).body}


class ColdBulkWordScopeTests(unittest.TestCase):
    def test_exact_new_source_and_all_original_profile_bytes(self):
        for name, source in [
                ('seed_word_backend', word()), ('seed_bulk_backend', bulk()),
                ('seed_div_bulk_backend', bulk(division=True)), ('seed_endian_backend', endian()),
                ('seed_cold_bulk_backend', cold('bulk')), ('seed_cold_endian_backend', cold('endian')),
                ('seed_cold_bulk_word_backend', combined())]:
            self.assertEqual(render_assembly(document(source, name)).encode(),
                             (ROOT / 'examples/hia_bootstrap' / (name + '.hepta')).read_bytes(), name)

    def test_only_resource_functions_and_entry_change(self):
        for source, old_name, new_name in [
                (original(), 'seed_backend', 'seed_word_backend'),
                (cold('bulk'), 'seed_cold_bulk_backend', 'seed_cold_bulk_word_backend')]:
            before = functions(source)
            after = functions(add_word_store(source, expected_entry=old_name, new_entry=new_name))
            after[old_name] = after.pop(new_name)
            after[old_name].name = old_name
            self.assertEqual(set(before), set(after))
            for name in before.keys() - {'resource_admit', 'resource'}:
                self.assertEqual(ast.dump(before[name]), ast.dump(after[name]), name)

    def test_changed_parent_guards_and_reapplication_refuse(self):
        source = original()
        cases = [
            source.replace('kind != 4', 'kind != 3'),
            source.replace('inputs != 3', 'inputs != 2'),
            source.replace('immediate(o, w, 11, 8)', 'immediate(o, w, 11, 7)'),
            source.replace('enc(o, w, 8, 2, 0, 0, 0, 0)', 'enc(o, w, 8, 2, 0, 1, 0, 0)'),
            source.replace('def seed_backend(', 'def missing_entry('),
            source + '\n' + ast.unparse(functions(source)['resource_admit']),
            source + '\ndef seed_word_backend()->u32:\n    return 0\n',
        ]
        for changed in cases:
            self.assertNotEqual(changed, source)
            with self.assertRaises(ValueError):
                add_word_store(changed, expected_entry='seed_backend', new_entry='seed_word_backend')
        with self.assertRaises(ValueError):
            add_word_store(word(), expected_entry='seed_word_backend', new_entry='twice_word_backend')

    def test_driver_only_put_changes_and_original_partial_trap_order_remains(self):
        before, after = functions(policy_source(word=False)), functions(policy_source())
        self.assertEqual(set(before), set(after))
        for name in before.keys() - {'put'}:
            self.assertEqual(ast.dump(before[name]), ast.dump(after[name]), name)
        fast, *fallback = after['put'].body
        self.assertEqual(ast.unparse(fast.test), 'at <= length(w) and 8 <= length(w) - at')
        self.assertEqual(ast.unparse(fast.body[0]), 'word_store(w, at, value)')
        self.assertEqual([ast.dump(node) for node in fallback],
                         [ast.dump(node) for node in before['put'].body])

    def test_closed_build_and_preseed_choose_only_the_declared_combination(self):
        cases = [('', 'v1'), ('int.div', 'div'), ('buffer.move_within', 'cold-bulk'),
                 ('int.rem buffer.move_within', 'div-bulk'),
                 ('buffer.store.u64.le', 'word'), ('buffer.load.u64.be', 'cold-endian'),
                 ('buffer.store.u64.le buffer.move_within', 'cold-bulk-word')]
        refused = ['int.div buffer.store.u64.le', 'int.rem buffer.move_within buffer.store.u64.le',
                   'buffer.load.u64.be buffer.move_within', 'buffer.store.u64.be buffer.move_within']
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / 'examples/hia_bootstrap/probe.hepta'
            path.parent.mkdir(parents=True)
            stage = object.__new__(Stage)
            stage.build = SimpleNamespace(root=root)
            preseed = object.__new__(Builder)
            preseed.source_bytes = lambda role: path.read_bytes()
            for text, expected in cases:
                path.write_text(text)
                self.assertEqual(stage.profile('probe'), expected)
                self.assertEqual(preseed.profile('probe'), expected)
            for text in refused:
                path.write_text(text)
                with self.assertRaises(ValueError):
                    stage.profile('probe')
                with self.assertRaises(AssertionError):
                    preseed.profile('probe')
        for profiles in (PROFILE_SOURCE, PRESEED_PROFILES):
            self.assertEqual(profiles['cold-bulk-word'], 'seed_cold_bulk_word_backend')


if __name__ == '__main__':
    unittest.main()

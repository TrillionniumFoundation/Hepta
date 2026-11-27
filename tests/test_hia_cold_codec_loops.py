"""Development-author scope refusals and complete checked-source closure."""
import ast
from pathlib import Path
import unittest
from unittest.mock import patch

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_cold_document import bulk_document
from tools import generate_hia_cold_master_archive as archive
from tools import generate_hia_cold_qualification_driver as driver
from tools import generate_hia_seed_bulk_backend as seed
from tools.generate_hia_worker_config_json import document as seed_document
from tools.hia_cold_codec_loops import specialize

ROOT = Path(__file__).resolve().parents[1]


def original(author, function):
    with patch.object(author, 'specialize', lambda source, **kwargs: source):
        return function()


def functions(source):
    return {node.name: node for node in ast.parse(source).body}


class ColdCodecLoopScopeTests(unittest.TestCase):
    def test_all_four_native_sources_are_reproducible(self):
        for name, source in [('cold_master_archive', archive.source()),
                             ('cold_qualification_driver', driver.policy_source())]:
            self.assertEqual(render_assembly(bulk_document(source, name)).encode(),
                             (ROOT / 'examples/hia_bootstrap' / (name + '.hepta')).read_bytes())
        for division, name in [(False, 'seed_bulk_backend'), (True, 'seed_div_bulk_backend')]:
            self.assertEqual(render_assembly(seed_document(seed.program(division=division), name)).encode(),
                             (ROOT / 'examples/hia_bootstrap' / (name + '.hepta')).read_bytes())

    def test_changed_workspace_or_decoder_domain_is_not_silently_specialized(self):
        baseline = original(driver, driver.policy_source)
        cases = [
            ('length(w) != 4194304', 'length(w) != 4194303'),
            ('length(o) != 128', 'length(o) != 129'),
            ('encoded > 65536', 'encoded > 65537'),
            ('size > 65504', 'size > 65505'),
            ('distance == 0 or distance > out', 'distance > out'),
            ('payload != encoded - 32', 'payload != encoded - 31'),
            ('distance != 0 and to >= source', 'distance >= 0 and to >= source'),
            ('3276800', '3276808'),
            ('pos + count * 8 + 8 <= size', 'pos + count * 8 <= size'),
            ('700000 + i', '700008 + i'),
        ]
        for before, after in cases:
            with self.subTest(before=before):
                self.assertIn(before, baseline)
                with self.assertRaises(ValueError):
                    specialize(baseline.replace(before, after), packing=True)

    def test_other_actor_logic_and_all_original_decoder_tests_stay_equal(self):
        for author, function, packing in [(archive, archive.source, False),
                                           (driver, driver.policy_source, True)]:
            before = functions(original(author, function))
            after = functions(function())
            self.assertEqual(set(before), set(after))
            changed = {'unpack_chunk', 'copy_forward'}
            if packing:
                changed.update(('pack_chunk_rle', 'pack_lz', 'pack_chunk', 'chunk_equal'))
            for name in before.keys() - changed:
                self.assertEqual(ast.dump(before[name]), ast.dump(after[name]), name)
            for name in ('unpack_chunk', 'copy_forward'):
                old_tests = [ast.dump(node.test) for node in ast.walk(before[name]) if isinstance(node, ast.If)]
                new_tests = [ast.dump(node.test) for node in ast.walk(after[name]) if isinstance(node, ast.If)]
                self.assertEqual(old_tests, new_tests, name)
            self.assertEqual([ast.dump(node) for node in before['copy_forward'].body[1:]],
                             [ast.dump(node) for node in after['copy_forward'].body[1:]])


if __name__ == '__main__':
    unittest.main()

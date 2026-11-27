"""Scope and refusal controls for the separate cold seed code generation."""
from pathlib import Path
import ast
import unittest

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_worker_config_json import document
from tools.generate_hia_seed_cold_backend import PARENTS, program, specialize

ROOT = Path(__file__).resolve().parents[1]


class ColdSeedScopeTests(unittest.TestCase):
    def test_exact_new_sources_and_unchanged_parents(self):
        for profile, author in PARENTS.items():
            with self.subTest(profile=profile):
                old_name = 'seed_' + profile + '_backend'
                new_name = 'seed_cold_' + profile + '_backend'
                self.assertEqual(render_assembly(document(author(), old_name)).encode(),
                                 (ROOT / 'examples/hia_bootstrap' / (old_name + '.hepta')).read_bytes())
                self.assertEqual(render_assembly(document(program(profile), new_name)).encode(),
                                 (ROOT / 'examples/hia_bootstrap' / (new_name + '.hepta')).read_bytes())

    def test_only_edge_and_entry_name_change(self):
        for profile, author in PARENTS.items():
            before = {node.name: node for node in ast.parse(author()).body}
            after = {node.name: node for node in ast.parse(program(profile)).body}
            old_name = 'seed_' + profile + '_backend'
            new_name = 'seed_cold_' + profile + '_backend'
            entry = after.pop(new_name)
            entry.name = old_name
            after[old_name] = entry
            self.assertEqual(set(before), set(after))
            for name in before.keys() - {'edge'}:
                self.assertEqual(ast.dump(before[name]), ast.dump(after[name]), (profile, name))

    def test_missing_duplicate_and_changed_edge_refuse(self):
        for profile, author in PARENTS.items():
            source = author()
            nodes = ast.parse(source)
            edge = next(n for n in nodes.body if n.name == 'edge')
            cases = [source + '\n' + ast.unparse(edge),
                     source.replace('def edge(', 'def missing_edge('),
                     source.replace('stage(s, o, w, word(s, record + 8), count)',
                                    'stage(s, o, w, word(s, record + 16), count)'),
                     source.replace('def seed_' + profile + '_backend(', 'def missing_entry(')]
            for changed in cases:
                with self.subTest(profile=profile, changed=changed[-120:]):
                    with self.assertRaises(ValueError):
                        specialize(changed, profile)
        with self.assertRaises(ValueError):
            specialize(PARENTS['bulk'](), 'v1')


if __name__ == '__main__':
    unittest.main()

"""Fixed original word semantics, including full width and partial traps."""
from __future__ import annotations

import ast
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from tools.qualify_hia_fixed_word_access import FIXTURE, ROOT, helper_comparisons


class FixedWordAccessTests(unittest.TestCase):
    def test_original_fixture_identity_and_scope(self):
        self.assertEqual(sha256(FIXTURE.read_bytes()).hexdigest(),
                         '6d8cedbd84295b8011b7a2453be68057797a45d3a20d57b1bbc2427c1cc1557a')
        fixture = json.loads(FIXTURE.read_bytes())
        self.assertEqual(fixture['origin_commit'], 'a7710b5727cca43875357f92c6b83308046deb6e')
        self.assertEqual(set(fixture['components']), {'execution-budget', 'agent-journal'})

    def test_only_local_journal_hash_get_and_put_are_expanded(self):
        from tools.generate_hia_agent_journal import hash_program, journal_hash_program
        original = ast.parse(hash_program()).body
        current = ast.parse(journal_hash_program()).body
        self.assertEqual([node.name for node in original], [node.name for node in current])
        changed = [a.name for a, b in zip(original, current) if ast.dump(a) != ast.dump(b)]
        self.assertEqual(changed, ['hash_get', 'hash_put'])
        fixture = json.loads(FIXTURE.read_bytes())['components']['agent-journal']['helpers']
        for node in original:
            if node.name in fixture:
                self.assertEqual(ast.dump(node), ast.dump(ast.parse(fixture[node.name]).body[0]))

    def test_full_width_bounds_wrap_and_partial_writes_equal_original(self):
        self.assertEqual(helper_comparisons('execution-budget'), 270)
        self.assertEqual(helper_comparisons('agent-journal'), 288)

    def test_optimized_controller_refuses_before_output_or_compilation(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'must-not-exist'
            commands = [
                [str(ROOT / 'tools/qualify_hia_fixed_word_access.py'), '--component', 'agent-journal',
                 '--development-compiler', str(output / 'unread-compiler'), '--output', str(output)],
                ['-c', 'from tools.qualify_hia_fixed_word_access import helper_comparisons; '
                       'helper_comparisons("agent-journal")'],
            ]
            for command in commands:
                result = subprocess.run([sys.executable, '-O', '-B', *command], cwd=ROOT,
                                        capture_output=True, text=True, timeout=5)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('require enabled assertions', result.stderr)
                self.assertFalse(output.exists())


if __name__ == '__main__':
    unittest.main()

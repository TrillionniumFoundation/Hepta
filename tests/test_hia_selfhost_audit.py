"""Whole-project boundaries must not disappear behind Python package counts."""
from hashlib import sha256
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from tools.audit_hia_selfhost_closure import tracked_tree_inventory


class WholeSelfhostAuditTests(unittest.TestCase):
    def test_native_research_and_external_links_keep_distinct_implementation_boundaries(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'checkout'
            root.mkdir()
            subprocess.run(['git', 'init', '-q', str(root)], check=True)
            files = {'hepta/runtime.py': 'pass\n', 'tools/observer.c': 'int observe(void);\n',
                     'rust/bridge/src/lib.rs': 'pub fn bridge() {}\n',
                     'formal/Main.lean': 'example : True := True.intro\n',
                     'experiments/old/lib.rs': 'fn historical() {}\n',
                     '.github/workflows/build.yml': 'name: build\n'}
            for name, content in files.items():
                p = root / name
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(content)
            # An absolute external target may exist but must never be consumed.
            secret = Path(tmp) / 'outside'
            secret.write_bytes(b'not part of the checkout')
            link = root / 'tools/external.h'
            link.symlink_to(secret)
            subprocess.run(['git', '-C', str(root), 'add', '.'], check=True)
            report = tracked_tree_inventory(root)
            self.assertEqual(report['tracked_paths'], 7)
            self.assertTrue(report['all_tracked_paths_accounted_for'])
            self.assertFalse(report['file_inventory_is_semantic_audit'])
            self.assertFalse(report['file_inventory_is_execution_evidence'])
            rows = {r['path']: r for r in report['file_identity_manifest']}
            self.assertEqual(rows['experiments/old/lib.rs']['role'], 'research_experiments')
            self.assertEqual(rows['rust/bridge/src/lib.rs']['role'], 'native_rust_bridges')
            self.assertEqual(rows['tools/external.h']['sha256'], sha256(os.fsencode(secret)).hexdigest())
            supported = report['live_non_python_support_sources']
            self.assertEqual({r['path'] for r in supported},
                             {'tools/observer.c', 'rust/bridge/src/lib.rs', 'formal/Main.lean'})
            self.assertFalse(any(r['rewritten_in_hia'] for r in supported))
            secret.write_bytes(b'changed outside bytes')
            self.assertEqual(report, tracked_tree_inventory(root))
            with self.assertRaises(ValueError):
                tracked_tree_inventory(root / 'rust')


if __name__ == '__main__':
    unittest.main()

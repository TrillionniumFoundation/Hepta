"""Small real-Git/source-custody controls; no product or native execution."""
from pathlib import Path
import importlib.util
import json
import os
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('context_ci_driver', HERE / 'run_context_development.py')
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)


class ContextCIDriverTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='hia-context-ci-git-')
        self.root = Path(self.temp.name)
        subprocess.run(['git', 'init', '-q', str(self.root)], check=True)
        self.path = self.root / 'sample.txt'
        self.path.write_bytes(b'original exact bytes\n')
        self.path.chmod(0o644)
        subprocess.run(['git', '-C', str(self.root), 'add', '--', 'sample.txt'], check=True)
        tree = subprocess.check_output(['git', '-C', str(self.root), 'write-tree']).decode().strip()
        self.records = subprocess.check_output(['git', '-C', str(self.root), 'ls-tree', '-r', '-z', tree])

    def tearDown(self):
        self.temp.cleanup()

    def test_real_git_snapshot_accepts_exact_bytes_and_modes(self):
        rows = driver.admit_git_snapshot(self.root, driver.files(self.root), self.records)
        self.assertEqual(set(rows), {'sample.txt'})

    def test_real_git_byte_drift_refuses(self):
        self.path.write_bytes(b'different exact bytes\n')
        with self.assertRaisesRegex(ValueError, 'bytes or mode'):
            driver.admit_git_snapshot(self.root, driver.files(self.root), self.records)

    def test_real_git_executable_mode_drift_refuses(self):
        self.path.chmod(0o755)
        with self.assertRaisesRegex(ValueError, 'bytes or mode'):
            driver.admit_git_snapshot(self.root, driver.files(self.root), self.records)

    def test_untracked_file_cannot_hide_from_complete_inventory(self):
        (self.root / 'new.txt').write_text('unexpected')
        with self.assertRaisesRegex(ValueError, 'inventories differ'):
            driver.admit_git_snapshot(self.root, driver.files(self.root), self.records)

    def test_symlink_source_is_not_admitted_as_regular_bytes(self):
        original = self.root / 'original.txt'
        self.path.rename(original)
        self.path.symlink_to(original.name)
        with self.assertRaisesRegex(ValueError, 'regular source file'):
            driver.files(self.root)

    def test_all_frozen_input_packets_have_exact_identities(self):
        for name, expected in [('context-owner.json', driver.OWNER_SHA),
                               ('retained-compiler.json', driver.COMPILER_PACKET_SHA),
                               ('original-agent-suite.json', driver.ORIGINAL_SUITE_SHA),
                               ('caller-qualifier-addendum.json', driver.QUALIFIER_SHA),
                               ('original-component-46.json', driver.ORIGINAL_COMPONENT_SHA)]:
            with self.subTest(name=name):
                self.assertEqual(driver.digest((HERE / name).read_bytes()), expected)
        owner = json.loads((HERE / 'context-owner.json').read_bytes())
        self.assertEqual(len(owner['owned_files']), 10)
        self.assertEqual(len(owner['shared_files']), 4)
        for name, row in {**owner['owned_files'], **owner['shared_files']}.items():
            raw = row['utf8'].encode()
            self.assertEqual(len(raw), row['bytes'], name)
            self.assertEqual(driver.digest(raw), row['sha256'], name)
        suite = json.loads((HERE / 'original-agent-suite.json').read_bytes())
        ids = [test for name in suite['modules']
               for test in suite['files'][name.replace('.', '/') + '.py']['expected_ids']]
        self.assertEqual(len(ids), 48)
        self.assertEqual(len(set(ids)), 48)


if __name__ == '__main__':
    unittest.main(verbosity=2)

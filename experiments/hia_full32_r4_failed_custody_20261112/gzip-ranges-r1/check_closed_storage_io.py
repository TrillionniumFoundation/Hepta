"""Actual tiny namespace and sparse-size boundary tests, no artifact or owner run."""
from pathlib import Path
from hashlib import sha256
import importlib.util
import json
import os
import sys
import tempfile
import time
import types
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location('_storage_' + name, ROOT / 'control' / (name + '.py'))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module


c, g = load('controller'), load('gzip_evidence')
c.GZIP_HELPER = g
POLICY = json.loads((ROOT / 'control/policy.json').read_bytes())


class StorageControls(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='closed-', dir=ACTUAL)
        self.base = Path(self.tmp.name)
        self.root, self.public = self.base / 'root', self.base / 'public'
        self.root.mkdir(mode=0o700); self.public.mkdir(mode=0o700)
        for name in ('control', 'guard', 'original', 'parts', 'api', 'small'):
            (self.root / name).mkdir(mode=0o700)
        (self.public / 'small').mkdir(mode=0o700)
        for part in c.expected_parts(POLICY):
            directory = self.public / ('part-%02d' % part['ordinal'])
            directory.mkdir(mode=0o700); (directory / 'controls').mkdir(mode=0o700)
        c.create(self.root / 'context.json', b'{}\n')
        c.create(self.root / 'small/INDEX.json', b'{}\n')
        c.create(self.root / 'small/O000001.original', b'original')
        c.create(self.public / 'small/INDEX.json', b'{}\n')
        c.create(self.public / 'small/O000001.original', b'original')
        c.create(self.public / 'small/SMALL-CAPTURE.json', b'{}\n')
        c.create(self.public / 'small/current--context.json', b'{}\n')
        c.create(self.public / 'part-00/controls/context.json', b'{}\n')
        c.create(self.public / 'part-00/slice.bin.gz', b'tiny synthetic payload')

    def tearDown(self):
        self.tmp.cleanup()

    def test_real_fixed_namespace_and_actual_allocations(self):
        result = c.closed_storage_observation(self.root, self.public, POLICY)
        self.assertEqual(result['logical_bytes_by_category']['payload'], len(b'tiny synthetic payload'))
        self.assertEqual(result['one_serial_upload_workspace_reserved'], 320 << 20)
        self.assertEqual(result['filesystem_overhead_reserved'], 512 << 20)
        self.assertTrue((self.public / 'small/CLOSED-STORAGE.json').is_file())

    def test_unknown_regular_rejected(self):
        c.create(self.root / 'unexpected.raw', b'x')
        with self.assertRaises(c.Refusal): c.closed_storage_observation(self.root, self.public, POLICY)

    def test_unknown_directory_rejected(self):
        (self.root / 'not-a-control').mkdir(mode=0o700)
        with self.assertRaises(c.Refusal): c.closed_storage_observation(self.root, self.public, POLICY)

    def test_symbolic_link_rejected_without_open(self):
        (self.root / 'original/forbidden-link').symlink_to('/must-not-be-opened')
        with self.assertRaises(c.Refusal): c.closed_storage_observation(self.root, self.public, POLICY)

    def test_hard_link_window_rejected(self):
        os.link(self.root / 'context.json', self.root / 'setup.json')
        with self.assertRaises(c.Refusal): c.closed_storage_observation(self.root, self.public, POLICY)

    def test_private_metadata_logical_byte_limit_rejected(self):
        path = self.root / 'setup.json'
        with path.open('xb') as file: file.truncate((64 << 20) + 1)
        path.chmod(0o400)
        self.assertLess(path.stat().st_blocks * 512, 1 << 20)
        with self.assertRaises(c.Refusal): c.closed_storage_observation(self.root, self.public, POLICY)

    def test_payload_logical_expansion_limit_rejected(self):
        path = self.root / 'original' / ('artifact-%d.zip' % POLICY['artifact']['id'])
        limit = POLICY['artifact']['bytes'] + len(POLICY['parts']) * (313 << 20)
        with path.open('xb') as file: file.truncate(limit + 1)
        path.chmod(0o400)
        self.assertLess(path.stat().st_blocks * 512, 1 << 20)
        with self.assertRaises(c.Refusal): c.closed_storage_observation(self.root, self.public, POLICY)

    def test_explicit_synthetic_insufficient_free_bytes_or_inodes_rejected(self):
        for free, inodes in ((0, 100000), (8 << 30, 0)):
            capacity = types.SimpleNamespace(f_bavail=free, f_frsize=1, f_favail=inodes)
            with patch.object(c.os, 'statvfs', return_value=capacity):
                with self.assertRaises(c.Refusal): c.closed_storage_observation(self.root, self.public, POLICY)


if __name__ == '__main__':
    ACTUAL = ROOT / 'evidence/closed-storage-io-r1'
    ACTUAL.mkdir(mode=0o700, exist_ok=False)
    before = {p.name: sha256(p.read_bytes()).hexdigest() for p in (ROOT / 'control').iterdir() if p.is_file()}
    started = time.monotonic_ns()
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(StorageControls)
    expected = [test.id() for test in suite]
    with (ACTUAL / 'unittest.log').open('x') as log:
        result = unittest.TextTestRunner(stream=log, verbosity=2).run(suite)
    after = {p.name: sha256(p.read_bytes()).hexdigest() for p in (ROOT / 'control').iterdir() if p.is_file()}
    report = {'schema': 'hia.failed-full32-gzip.closed-storage-io-controls.v1',
        'status': 'PASS' if result.wasSuccessful() and before == after else 'HOLD',
        'expected_ids': expected, 'loaded': len(expected), 'executed': result.testsRun,
        'failures': [(x.id(), e) for x, e in result.failures], 'errors': [(x.id(), e) for x, e in result.errors],
        'skips': result.skipped, 'expected_failures': [(x.id(), e) for x, e in result.expectedFailures],
        'unexpected_successes': [x.id() for x in result.unexpectedSuccesses],
        'source_before': before, 'source_after': after, 'elapsed_ns': time.monotonic_ns() - started,
        'network_owner_product_executed': False,
        'actual_original_8GiB_admission_proven': False,
        'synthetic_statvfs_used_only_for_two_negative_free_capacity_rows': True,
        'large_logical_sizes_are_sparse_test_files_no_large_payload_written': True}
    (ACTUAL / 'REPORT.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    print(json.dumps({key: report[key] for key in ('status', 'loaded', 'executed', 'elapsed_ns')}))
    raise SystemExit(0 if report['status'] == 'PASS' else 1)

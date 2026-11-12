"""Cold-evidence IO controls only; no compiler, publisher or original39 run."""
from __future__ import annotations
from hashlib import sha256
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

from tools import hia_artifact_publication_custody as custody
from tools import qualify_hia_artifact_publication_tests as qualifier


def wire(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


class PublicationColdCustodyIngressTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='hia-publication-cold-io-')
        self.root = Path(self.temporary.name)
        self.addCleanup(self.temporary.cleanup)
        self.fd_count = len(list(Path('/proc/self/fd').iterdir()))

    def tearDown(self):
        self.assertEqual(len(list(Path('/proc/self/fd').iterdir())), self.fd_count)

    def fixture(self, label='source', padding=0):
        root = self.root / label
        root.mkdir(mode=0o700)
        image = root / 'B3.image.bin'
        image.write_bytes(bytes(range(256)) * 3 + b'actual-fixture-image')
        digest = sha256(image.read_bytes()).hexdigest()
        nested = {'schema': 'hepta.hia.selfhost-qualification.v6', 'profile': 'custody-fixture-only',
                  'status': 'SELF_HOSTED_FIXED_CORE_PASS', 'source_manifest': {'fixture': 'f' * 64},
                  'generations': [{'case': label, 'produced_image': str(image),
                                   'produced_bytes': image.stat().st_size, 'produced_sha256': digest}
                                  for label in ('B1', 'B2', 'B3')],
                  'padding_for_full_evidence_copy': 'x' * padding}
        nested_path = root / 'qualification.json'
        nested_path.write_bytes(wire(nested))
        outer = {'schema': 'hepta.hia.selfhost-cold-replay.v1', 'profile': nested['profile'],
                 'status': 'COLD_SELFHOST_REPLAY_PASS', 'source_manifest': nested['source_manifest'],
                 'nested_report': str(nested_path), 'nested_report_sha256': sha256(nested_path.read_bytes()).hexdigest(),
                 'generation_sha256': [digest] * 3}
        outer_path = root / 'cold.json'
        outer_path.write_bytes(wire(outer))
        return outer_path, nested_path, image, outer, nested

    def destination(self, label='retained'):
        path = self.root / label
        path.mkdir(mode=0o700)
        return path

    def update(self, outer_path, nested_path, outer, nested):
        nested_path.write_bytes(wire(nested))
        outer['nested_report_sha256'] = sha256(nested_path.read_bytes()).hexdigest()
        outer_path.write_bytes(wire(outer))

    def test_complete_three_input_chain_and_readback(self):
        outer, nested, image, _, _ = self.fixture()
        target = self.destination()
        originals = {p: custody.identity(p.stat()) for p in (outer, nested, image)}
        rows = qualifier.copy_cold_inputs(outer, target)
        self.assertEqual(len(rows), 3)
        for row, source in zip(rows, (outer, nested, image)):
            self.assertEqual(Path(row['retained']['path']).read_bytes(), source.read_bytes())
            self.assertEqual(row['original_identity'], originals[source])
            self.assertEqual(custody.identity(source.stat()), originals[source])
            self.assertEqual(row['stream_copy']['chunk_bytes'], 1 << 20)
        binding = json.loads((target / 'cold-binding.json').read_bytes())
        self.assertEqual(binding['raw_original_bytes'], sum(p.stat().st_size for p in (outer, nested, image)))
        self.assertEqual(binding['nested_report_expected_sha256'], rows[1]['retained']['sha256'])
        self.assertFalse(binding['product_or_cold_result_reclassified'])

    def test_nested_above_old_16_mib_is_retained_completely(self):
        outer, nested, image, _, _ = self.fixture(padding=(16 << 20) + 513)
        self.assertGreater(nested.stat().st_size, 16 << 20)
        rows = qualifier.copy_cold_inputs(outer, self.destination())
        self.assertEqual(rows[1]['retained']['bytes'], nested.stat().st_size)
        self.assertEqual(Path(rows[1]['retained']['path']).read_bytes(), nested.read_bytes())
        self.assertEqual(rows[2]['retained']['sha256'], sha256(image.read_bytes()).hexdigest())

    def test_nested_digest_mismatch_preserves_full_failed_copy(self):
        outer_path, nested_path, _, outer, _ = self.fixture()
        outer['nested_report_sha256'] = '0' * 64
        outer_path.write_bytes(wire(outer))
        target = self.destination()
        with self.assertRaisesRegex(ValueError, 'SHA256 differs'):
            qualifier.copy_cold_inputs(outer_path, target)
        self.assertEqual((target / 'cold-qualification.json').read_bytes(), nested_path.read_bytes())
        self.assertFalse((target / 'cold-binding.json').exists())

    def test_b3_size_and_noninteger_counts_refused(self):
        for index, count in enumerate((True, 0, 1 << 21, 1)):
            with self.subTest(count=count):
                op, np, image, outer, nested = self.fixture('source-' + str(index))
                nested['generations'][-1]['produced_bytes'] = count
                self.update(op, np, outer, nested)
                target = self.destination('retained-' + str(index))
                with self.assertRaises(ValueError):
                    qualifier.copy_cold_inputs(op, target)
                self.assertFalse((target / 'compiler.image.bin').exists())
                self.assertFalse((target / 'cold-binding.json').exists())
                self.assertEqual(image.stat().st_size, 788)

    def test_b3_hash_mismatch_preserves_full_failed_compiler(self):
        op, np, image, outer, nested = self.fixture()
        nested['generations'][-1]['produced_sha256'] = '1' * 64
        outer['generation_sha256'][-1] = '1' * 64
        self.update(op, np, outer, nested)
        target = self.destination()
        with self.assertRaisesRegex(ValueError, 'SHA256 differs'):
            qualifier.copy_cold_inputs(op, target)
        self.assertEqual((target / 'compiler.image.bin').read_bytes(), image.read_bytes())
        self.assertFalse((target / 'cold-binding.json').exists())

    def test_exact_total_budget_and_one_byte_short(self):
        op, np, image, _, _ = self.fixture()
        total = sum(p.stat().st_size for p in (op, np, image))
        self.assertEqual(len(qualifier.copy_cold_inputs(op, self.destination('exact'), maximum_bytes=total)), 3)
        target = self.destination('short')
        with self.assertRaisesRegex(ValueError, 'within its byte budget'):
            qualifier.copy_cold_inputs(op, target, maximum_bytes=total - 1)
        self.assertEqual((target / 'cold-qualification.json').read_bytes(), np.read_bytes())
        self.assertFalse((target / 'compiler.image.bin').exists())

    def test_budget_is_evidence_only_and_rejects_bool_or_growth(self):
        op, _, _, _, _ = self.fixture()
        self.assertEqual(qualifier.COLD_INPUT_CUSTODY_BYTES, 256 << 20)
        self.assertEqual(len(qualifier.ORIGINAL_TEST_IDS), 39)
        for i, value in enumerate((True, 0, -1, (256 << 20) + 1)):
            with self.subTest(value=value), self.assertRaises(ValueError):
                qualifier.copy_cold_inputs(op, self.destination(str(i)), maximum_bytes=value)

    def test_schema_generation_and_source_linkage_refusals(self):
        def changed_schema(o, n): n['schema'] = 'hepta.hia.selfhost-qualification.v5'
        def changed_profile(o, n): n['profile'] = 'other'
        def changed_manifest(o, n): n['source_manifest'] = {'other': 'e' * 64}
        def changed_order(o, n): n['generations'].reverse()
        def changed_outer_digest(o, n): o['generation_sha256'][-1] = 'e' * 64
        for i, change in enumerate((changed_schema, changed_profile, changed_manifest, changed_order, changed_outer_digest)):
            with self.subTest(change=change.__name__):
                op, np, _, outer, nested = self.fixture('source-' + str(i))
                change(outer, nested)
                self.update(op, np, outer, nested)
                target = self.destination('retained-' + str(i))
                with self.assertRaises(ValueError):
                    qualifier.copy_cold_inputs(op, target)
                self.assertFalse((target / 'cold-binding.json').exists())

    def test_duplicate_json_refused_after_complete_raw_retention(self):
        op, np, _, outer, _ = self.fixture()
        raw = np.read_bytes()
        raw = b'{"schema":"duplicate",' + raw[1:]
        np.write_bytes(raw)
        outer['nested_report_sha256'] = sha256(raw).hexdigest()
        op.write_bytes(wire(outer))
        target = self.destination()
        with self.assertRaisesRegex(ValueError, 'duplicate cold JSON key'):
            qualifier.copy_cold_inputs(op, target)
        self.assertEqual((target / 'cold-qualification.json').read_bytes(), raw)

    def test_source_symlink_hardlink_and_fifo_refused_without_open(self):
        original = self.root / 'original'
        original.write_bytes(b'content')
        (self.root / 'symlink').symlink_to(original)
        os.link(original, self.root / 'hardlink')
        os.mkfifo(self.root / 'fifo')
        for name in ('symlink', 'hardlink', 'fifo'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                custody.copy_cold_evidence(self.root / name, self.root / ('out-' + name), 1 << 20)
            self.assertFalse((self.root / ('out-' + name)).exists())

    def test_parent_symlink_and_existing_destination_refused(self):
        directory = self.root / 'actual'
        directory.mkdir()
        source = directory / 'source'
        source.write_bytes(b'payload')
        (self.root / 'link').symlink_to(directory, target_is_directory=True)
        with self.assertRaises(OSError):
            custody.copy_cold_evidence(self.root / 'link/source', self.root / 'new', 7)
        target = self.root / 'existing'
        target.write_bytes(b'original target')
        with self.assertRaises(FileExistsError):
            custody.copy_cold_evidence(source, target, 7)
        self.assertEqual(target.read_bytes(), b'original target')
        with self.assertRaises(OSError):
            custody.copy_cold_evidence(source, self.root / 'link/new', 7)

    def changed_during_read(self, action, *, size=128):
        source = self.root / 'source.bin'
        source.write_bytes(b'a' * size)
        before = source.stat()
        actual_read = custody.os.read
        fired = False
        def changed(fd, count):
            nonlocal fired
            current = os.fstat(fd)
            if not fired and (current.st_dev, current.st_ino) == (before.st_dev, before.st_ino):
                raw = actual_read(fd, count)
                fired = True
                action(source)
                return raw
            return actual_read(fd, count)
        with patch.object(custody.os, 'read', side_effect=changed), self.assertRaises(ValueError):
            custody.copy_cold_evidence(source, self.root / 'copy.bin', size)
        self.assertTrue(fired)

    def test_tail_growth_refused_and_partial_copy_retained(self):
        def grow(path):
            with path.open('ab') as output:
                output.write(b'grown')
        self.changed_during_read(grow)
        self.assertEqual((self.root / 'copy.bin').read_bytes(), b'a' * 128)

    def test_equal_byte_path_replacement_refused(self):
        def replace(path):
            other = path.with_name('replacement')
            other.write_bytes(path.read_bytes())
            os.replace(other, path)
        self.changed_during_read(replace)

    def test_hardlink_created_during_read_refused(self):
        self.changed_during_read(lambda path: os.link(path, path.with_name('second-name')))

    def test_truncation_during_chunked_copy_refused(self):
        self.changed_during_read(lambda path: os.truncate(path, 1 << 20), size=2 << 20)

    def test_parent_replacement_refused_after_held_descriptor_read(self):
        directory = self.root / 'parent'
        directory.mkdir()
        source = directory / 'source'
        source.write_bytes(b'parent-bound')
        original_read = custody.os.read
        observed = source.stat()
        fired = False
        def replace_parent(fd, count):
            nonlocal fired
            raw = original_read(fd, count)
            if not fired and os.fstat(fd).st_ino == observed.st_ino:
                fired = True
                directory.rename(self.root / 'old-parent')
                directory.mkdir()
                (directory / 'source').write_bytes(b'parent-bound')
            return raw
        with patch.object(custody.os, 'read', side_effect=replace_parent), self.assertRaises(ValueError):
            custody.copy_cold_evidence(source, self.root / 'copy', 100)
        self.assertTrue(fired)


if __name__ == '__main__':
    unittest.main()

"""Finite tiny-file controls; no network, subprocess, owner, or product import."""
from pathlib import Path
from hashlib import sha256
import ast
import copy
import gzip
import importlib.util
import io
import json
import os
import stat
import sys
import tarfile
import tempfile
import time
import unittest
import zipfile

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location('_tiny_io_' + name, ROOT / 'control' / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


g = load('gzip_evidence')
c = load('controller')
w = load('worker')
old = load('original_receiver')
renderer = load('render_workflow')
c.GZIP_HELPER = g
POLICY = json.loads((ROOT / 'control/policy.json').read_bytes())


def fresh(directory, name):
    path = directory / name
    path.mkdir(mode=0o700)
    return path


def sealed(path, raw):
    path.write_bytes(raw)
    path.chmod(0o400)
    return c.file_record(path, max(len(raw), 1))


def fixture(directory, *, bad_hash=False, bad_metadata=False, unreadable=False):
    """Construct authenticated tiny evidence with all 48 outer and typed special rows."""
    bodies = {'RUN-INTENT.json': b'{"fixture": true}\n', 'supply/SUPPLY.json': b'{"status": "HOLD", "error": "synthetic original"}\n'}
    for phase in ('update', 'install'):
        for name in g.APT_NAMES:
            bodies['supply/evidence/apt-owned-' + phase + '/' + name] = ('exact-' + phase + '-' + name).encode()
    now = 1700000000000000000
    rows = [{'path': '.', 'kind': 'directory', 'identity': [1, 1, stat.S_IFDIR | 0o700, 1000, 1000, 2, 0, now, now]}]
    for ordinal, (name, raw) in enumerate(bodies.items(), 2):
        rows.append({'path': name, 'kind': 'regular', 'bytes': len(raw), 'sha256': sha256(raw).hexdigest(),
                     'identity': [1, ordinal, stat.S_IFREG | 0o400, 1000, 1000, 1, len(raw), now, now]})
    rows.extend([
        {'path': 'metadata-only-link', 'kind': 'symlink', 'target': '/outside/never-open',
         'identity': [1, 100, stat.S_IFLNK | 0o777, 1000, 1000, 1, 19, now, now]},
        {'path': 'metadata-only-fifo', 'kind': 'fifo',
         'identity': [1, 101, stat.S_IFIFO | 0o600, 1000, 1000, 1, 0, now, now]},
    ])
    if unreadable:
        rows.append({'path': 'supply/apt-cache/lock', 'kind': 'regular', 'bytes': 1,
            'identity': [1, 102, stat.S_IFREG | 0o000, 0, 0, 1, 1, now, now],
            'read_error': {'type': 'PermissionError', 'errno': 13}})
    rows.sort(key=lambda x: x['path'])
    if bad_hash:
        next(x for x in rows if x['path'] == 'supply/SUPPLY.json')['sha256'] = '0' * 64
    gaps = ['supply/apt-cache/lock'] if unreadable else []
    manifest = {'schema': 'hia.v87.full-retained-typed-custody.v1', 'originals': rows,
        'unreadable_regular_paths': gaps, 'unlisted_directory_paths': [],
        'all_regular_bytes_selected': not unreadable}
    manifest_raw = g.wire(manifest)
    packed = io.BytesIO()
    with gzip.GzipFile(fileobj=packed, mode='wb', filename='', mtime=0, compresslevel=1) as compressed:
        with tarfile.open(fileobj=compressed, mode='w|', format=tarfile.PAX_FORMAT) as tar:
            for row in rows:
                if row['path'] == '.' or 'read_error' in row:
                    continue
                item = tarfile.TarInfo(row['path'])
                item.mode, item.uid, item.gid = stat.S_IMODE(row['identity'][2]), 1000, 1000
                item.mtime = now // 10**9
                if bad_metadata and row['path'] == 'supply/SUPPLY.json':
                    item.uid = 1001
                if row['kind'] == 'regular':
                    raw = bodies[row['path']]
                    item.size = len(raw)
                    tar.addfile(item, io.BytesIO(raw))
                elif row['kind'] == 'symlink':
                    item.type, item.linkname = tarfile.SYMTYPE, row['target']
                    tar.addfile(item)
                else:
                    item.type = tarfile.FIFOTYPE
                    tar.addfile(item)
            item = tarfile.TarInfo(g.MANIFEST)
            item.mode, item.size = 0o400, len(manifest_raw)
            tar.addfile(item, io.BytesIO(manifest_raw))
    archive_raw = packed.getvalue()
    expected_count = len(rows) - 1 - int(unreadable) + 1
    custody = {'schema': 'hia.v87.full-retained-custody-result.v1',
        'status': 'PARTIAL_TYPED_ORIGINALS_PENDING_CUSTODY_GUARDIAN' if unreadable else 'COMPLETE_TYPED_ORIGINALS_PENDING_CUSTODY_GUARDIAN',
        'catalog': {'bytes': len(manifest_raw), 'sha256': sha256(manifest_raw).hexdigest()},
        'archive': {'bytes': len(archive_raw), 'sha256': sha256(archive_raw).hexdigest()},
        'original_members': len(rows), 'archive_members': expected_count,
        'regular_bytes': sum(map(len, bodies.values())), 'unreadable_regular_paths': gaps,
        'unlisted_directory_paths': [], 'all_regular_bytes_read_back': not unreadable}
    final = {'status': 'HOLD', 'complete_custody': not unreadable, 'whole_native_delivery_qualified': False}
    members = {g.CAT_NAME: manifest_raw, g.CUSTODY_NAME: g.wire(custody),
               g.FINAL_NAME: g.wire(final), g.TAR_NAME: archive_raw}
    for index in range(44):
        members['hia-v87-bootstrap-originals/%02d.log' % index] = ('original-' + str(index)).encode()
    path = directory / 'synthetic.original.zip'
    with zipfile.ZipFile(path, 'x', compression=zipfile.ZIP_DEFLATED) as archive:
        for name, raw in members.items():
            item = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
            item.external_attr = (stat.S_IFREG | 0o400) << 16
            item.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(item, raw)
    path.chmod(0o400)
    raw = path.read_bytes()
    return path, {'id': 123, 'run_id': 456, 'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}


class TransportControls(unittest.TestCase):
    def setUp(self):
        self.context = tempfile.TemporaryDirectory(prefix='tiny-', dir=ACTUAL)
        self.root = Path(self.context.name)

    def tearDown(self):
        self.context.cleanup()

    def encoded(self, raw, name='part-00.bin.gz'):
        value = g.encode_range(io.BytesIO(raw), self.root / name, len(raw))
        return value, {'ordinal': 0, 'offset': 0, 'bytes': len(raw), 'name': name}

    def test_policy_exact_ten_ranges_and_caps(self):
        self.assertEqual(c.fixed_policy(POLICY), w.fixed_policy(POLICY))
        self.assertEqual(c.expected_parts(POLICY), w.expected_parts(POLICY))
        parts = c.expected_parts(POLICY)
        self.assertEqual((len(parts), parts[-1]['bytes'], sum(x['bytes'] for x in parts)), (10, 66350822, 3010752230))
        for field, actual in (('controller_seconds', 900), ('cleanup_seconds', 3), ('transfer_seconds', 720),
                              ('minimum_free_bytes', 8 << 30), ('minimum_free_inodes', 100000)):
            self.assertEqual(POLICY['limits'][field], actual)

    def test_policy_rejects_bool_range_and_missing_part(self):
        changed = copy.deepcopy(POLICY)
        changed['parts'][0]['ordinal'] = False
        with self.assertRaises(c.Refusal): c.fixed_policy(changed)
        changed = copy.deepcopy(POLICY); changed['parts'].pop()
        with self.assertRaises(c.Refusal): c.fixed_policy(changed)

    def test_gzip_small_zero_and_binary_roundtrip(self):
        for index, raw in enumerate((b'', b'\0' * 8193, bytes(range(256)) * 8193)):
            value, expected = self.encoded(raw, 'part-%02d.bin.gz' % index)
            actual = g.decode_range(value['original']['path'], expected, value['original'])
            self.assertEqual(actual['sha256'], sha256(raw).hexdigest())
            self.assertEqual(actual['bytes'], len(raw))

    def test_gzip_crc_corruption_rejected(self):
        value, expected = self.encoded(b'x' * 4096)
        raw = bytearray(Path(value['original']['path']).read_bytes()); raw[-8] ^= 1
        changed = self.root / 'bad.gz'; sealed(changed, raw)
        with self.assertRaises((g.Refusal, zlib.error)):
            g.decode_range(changed, expected, g.record(changed, 100000))

    def test_gzip_truncation_rejected(self):
        value, expected = self.encoded(b'x' * 4096)
        changed = self.root / 'short.gz'; sealed(changed, Path(value['original']['path']).read_bytes()[:-1])
        with self.assertRaises(g.Refusal): g.decode_range(changed, expected, g.record(changed, 100000))

    def test_gzip_second_member_and_trailer_rejected(self):
        value, expected = self.encoded(b'x' * 4096)
        for index, tail in enumerate((b'junk', gzip.compress(b'more'))):
            changed = self.root / ('extra%d.gz' % index)
            sealed(changed, Path(value['original']['path']).read_bytes() + tail)
            with self.assertRaises(g.Refusal): g.decode_range(changed, expected, g.record(changed, 100000))

    def test_raw_expansion_bound_rejected(self):
        value, expected = self.encoded(b'x' * 4096)
        expected['bytes'] = 4095
        with self.assertRaises(g.Refusal): g.decode_range(value['original']['path'], expected, value['original'])

    def test_gzip_identity_and_nlink_rejected(self):
        value, expected = self.encoded(b'x' * 4096)
        os.link(value['original']['path'], self.root / 'alias')
        with self.assertRaises(g.Refusal): g.decode_range(value['original']['path'], expected, value['original'])

    def test_concat_exact_bytes_rejects_missing_reorder_and_bad_full_sha(self):
        raws = (b'a' * 4096, b'b' * 4096, b'c' * 187)
        records, parts, offset = [], [], 0
        for index, raw in enumerate(raws):
            value, item = self.encoded(raw, 'part-%02d.bin.gz' % index)
            item.update(ordinal=index, offset=offset)
            offset += len(raw); records.append(value['original']); parts.append(item)
        pin = {'bytes': offset, 'sha256': sha256(b''.join(raws)).hexdigest()}
        self.assertEqual(g.concat_parts(records, pin, parts)['sha256'], pin['sha256'])
        for wrong in (records[:-1], list(reversed(records))):
            with self.assertRaises(g.Refusal): g.concat_parts(wrong, pin, parts)
        with self.assertRaises(g.Refusal): g.concat_parts(records, {**pin, 'sha256': '0' * 64}, parts)

    def test_full_split_and_same_inode_relocation(self):
        parts_dir = fresh(self.root, 'parts'); output = fresh(self.root, 'public')
        raw = bytes(range(256)) * 32
        path = self.root / 'original.zip'; sealed(path, raw)
        pin = {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}
        expected = [{'ordinal': 0, 'offset': 0, 'bytes': 4096, 'name': 'part-00.bin.gz'},
                    {'ordinal': 1, 'offset': 4096, 'bytes': 4096, 'name': 'part-01.bin.gz'}]
        result = g.split_original(path, pin, expected, self.root, time.monotonic_ns() + 10**10)
        self.assertEqual(result['concatenated_sha256'], pin['sha256'])
        actual = c.file_record(parts_dir / expected[0]['name'])
        retained = c.relocate_slice(Path(actual['path']), output / 'slice.bin.gz', actual)
        self.assertEqual(retained['identity'][:2], actual['identity'][:2])
        self.assertEqual(retained['sha256'], actual['sha256'])
        self.assertFalse(Path(actual['path']).exists())

    def test_outer_and_inner_all_bytes_with_typed_no_extraction(self):
        path, pin = fixture(self.root)
        result = g.inspect_original(path, pin, self.root, time.monotonic_ns() + 10**10, old.catalog)
        self.assertEqual(result['status'], 'ALL_AVAILABLE_BODIES_VERIFIED_HISTORICAL_RESULTS_UNCHANGED')
        self.assertTrue(result['diagnostic_channel_complete'])
        self.assertEqual(result['outer_files'], 48)
        self.assertEqual(result['original_final_status'], 'HOLD')
        self.assertFalse(result['special_members_opened_or_extracted'])
        self.assertFalse((self.root / 'metadata-only-fifo').exists())
        self.assertEqual([x['path'] for x in result['critical_originals']], list(g.CRITICAL_INNER))
        self.assertIn('ORIGINAL_MISSING', {x['status'] for x in result['critical_originals']})

    def test_original_unreadable_metadata_stays_original_gap(self):
        path, pin = fixture(self.root, unreadable=True)
        result = g.inspect_original(path, pin, self.root, time.monotonic_ns() + 10**10, old.catalog)
        self.assertTrue(result['diagnostic_channel_complete'])
        self.assertEqual(result['original_unreadable_paths'], ['supply/apt-cache/lock'])
        self.assertFalse(result['original_complete_custody'])
        self.assertFalse(result['original_whole_qualification'])

    def test_wrong_inner_sha_is_hold_with_whole_small_diagnostics(self):
        path, pin = fixture(self.root, bad_hash=True)
        result = g.inspect_original(path, pin, self.root, time.monotonic_ns() + 10**10, old.catalog)
        self.assertEqual(result['status'], 'HOLD')
        self.assertFalse(result['diagnostic_channel_complete'])
        self.assertTrue((self.root / 'small/INDEX.json').is_file())
        self.assertTrue((self.root / 'small/INSPECTION-ERROR.json').is_file())

    def test_wrong_inner_metadata_is_hold(self):
        path, pin = fixture(self.root, bad_metadata=True)
        result = g.inspect_original(path, pin, self.root, time.monotonic_ns() + 10**10, old.catalog)
        self.assertEqual(result['status'], 'HOLD')

    def test_small_success_joins_every_actual_copy(self):
        path, pin = fixture(self.root)
        result = g.inspect_original(path, pin, self.root, time.monotonic_ns() + 10**10, old.catalog)
        public = fresh(self.root, 'public'); fresh(public, 'small')
        copied = c.capture_small(self.root, public, {'artifact': pin}, result)
        self.assertTrue(copied['complete'], copied)
        receipt = json.loads((public / 'small/SMALL-CAPTURE.json').read_bytes())
        for row in receipt['files']:
            self.assertEqual(row['original']['sha256'], row['copy']['sha256'])

    def test_small_missing_original_cannot_be_complete_but_others_saved(self):
        path, pin = fixture(self.root)
        result = g.inspect_original(path, pin, self.root, time.monotonic_ns() + 10**10, old.catalog)
        first = next((self.root / 'small').glob('O*.original')); first.unlink()
        public = fresh(self.root, 'public'); fresh(public, 'small')
        copied = c.capture_small(self.root, public, {'artifact': pin}, result)
        self.assertFalse(copied['complete'])
        self.assertGreater(copied['files'], 0)

    def test_small_modified_original_cannot_be_complete(self):
        path, pin = fixture(self.root)
        result = g.inspect_original(path, pin, self.root, time.monotonic_ns() + 10**10, old.catalog)
        first = next((self.root / 'small').glob('I*.original'))
        first.chmod(0o600); first.write_bytes(b'changed'); first.chmod(0o400)
        public = fresh(self.root, 'public'); fresh(public, 'small')
        copied = c.capture_small(self.root, public, {'artifact': pin}, result)
        self.assertFalse(copied['complete'])

    def test_deadline_rejected_without_network(self):
        with self.assertRaises(g.Refusal): g.encode_range(io.BytesIO(b'a'), self.root / 'expired.gz', 1, 1)

    def test_unsafe_and_duplicate_json_names_rejected(self):
        for name in ('../x', '/x', 'x\\y', 'x//y', 'x/./y', 'x:y', 'x\n'):
            with self.assertRaises(g.Refusal): g.safe_path(name)
        with self.assertRaises(g.Refusal): g.json_value(b'{"x": 1, "x": 2}')

    def test_workflow_render_is_exact_and_small_upload_first(self):
        output, parts = renderer.render((ROOT / 'control/policy.json').read_bytes(), ROOT / 'control',
            (ROOT / 'control/workflow-template.yml').read_text(), 'a' * 40)
        text = output.decode()
        self.assertEqual(len(parts), 10)
        self.assertEqual(text.count('actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02'), 11)
        self.assertLess(text.index('hia-full32-r4-small-originals-'), text.index('hia-full32-r4-original-gzip-part-00-'))
        self.assertNotIn('PLACEHOLDER', text)
        self.assertEqual(text.count('HIA_CUSTODY_GITHUB_TOKEN:'), 1)


class RecordingResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs); self.ids = []
    def startTest(self, test):
        self.ids.append(test.id()); super().startTest(test)


if __name__ == '__main__':
    import zlib
    ACTUAL = ROOT / 'evidence/tiny-io-r1'
    ACTUAL.mkdir(mode=0o700, exist_ok=False)
    before = {x.name: sha256(x.read_bytes()).hexdigest() for x in (ROOT / 'control').iterdir() if x.is_file()}
    started = time.monotonic_ns()
    with (ACTUAL / 'unittest.log').open('x') as log:
        runner = unittest.TextTestRunner(stream=log, verbosity=2, resultclass=RecordingResult)
        result = runner.run(unittest.defaultTestLoader.loadTestsFromTestCase(TransportControls))
    after = {x.name: sha256(x.read_bytes()).hexdigest() for x in (ROOT / 'control').iterdir() if x.is_file()}
    report = {'schema': 'hia.failed-full32-gzip.finite-source-io-controls.v1',
        'status': 'PASS' if result.wasSuccessful() and before == after else 'HOLD',
        'expected': 20, 'loaded': 20, 'executed': result.testsRun, 'ids': result.ids,
        'failures': [(test.id(), trace) for test, trace in result.failures],
        'errors': [(test.id(), trace) for test, trace in result.errors],
        'skipped': result.skipped, 'unexpected_successes': [x.id() for x in result.unexpectedSuccesses],
        'expected_failures': [(test.id(), trace) for test, trace in result.expectedFailures],
        'source_before': before, 'source_after': after, 'elapsed_ns': time.monotonic_ns() - started,
        'network_or_owner_or_project_or_native_execution': False,
        'fixtures_are_tiny_synthetic_transport_data_not_original_artifact_bytes': True}
    (ACTUAL / 'REPORT.json').write_bytes(g.wire(report))
    print(json.dumps({key: report[key] for key in ('status', 'expected', 'loaded', 'executed', 'elapsed_ns')}))
    raise SystemExit(0 if report['status'] == 'PASS' else 1)

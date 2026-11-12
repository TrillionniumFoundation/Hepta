"""Finite source/I/O controls of the immutable multipart draft; no network/product."""
from __future__ import annotations
import copy
from hashlib import sha256
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SOURCE = Path(os.environ['HIA_MULTIPART_SOURCE'])
ACTUAL = Path(os.environ['HIA_MULTIPART_ACTUAL'])
EVENTS = []

def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, SOURCE / filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value

controller = module('frozen_multipart_controller', 'controller.py')
worker = module('frozen_multipart_worker', 'worker.py')
renderer = module('frozen_multipart_renderer', 'render_workflow.py')
DRAFT = json.loads((SOURCE / 'policy.json').read_bytes())

def mkdir(path, mode=0o700):
    path.mkdir(mode=mode)
    return path

def write(path, data, mode=0o400):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    return path

def policy_for(size):
    value = copy.deepcopy(DRAFT)
    value['artifact']['bytes'] = size
    parts, offset = [], 0
    while offset < size:
        count = min(312 << 20, size - offset)
        parts.append({'ordinal': len(parts), 'offset': offset, 'bytes': count,
                      'name': 'part-%02d.bin' % len(parts)})
        offset += count
    value['parts'] = parts
    return value

def fake_frozen_policy(size):
    """Synthetic shape only: no official ID, source or workflow is qualified."""
    value = policy_for(size)
    value['status'] = 'FROZEN_OFFICIAL_TRANSPORT_INPUTS_UNEXECUTED'
    value['input_pins_frozen'] = True
    value['artifact'].update(id=1, run_id=1, job_id=1, run_attempt=1,
        sha256='0' * 64, checkout_commit='1' * 40, checkout_tree='2' * 40,
        event='push', workflow_terminal='failure')
    value['source'].update(head='1' * 40, tree='2' * 40, cold_source_count=1,
        contract_sha256='0' * 64, source_manifest_canonical_sha256='0' * 64,
        profile='SYNTHETIC_SOURCE_CONTROL_ONLY_NEVER_DISPATCH')
    return value

class MultipartSourceIOTests(unittest.TestCase):
    def fixture(self, suffix=''):
        label = self._testMethodName + suffix
        base = mkdir(ACTUAL / 'fixtures' / label)
        return base

    def relocation(self, suffix=''):
        base = self.fixture(suffix)
        private = mkdir(base / 'private')
        parts = mkdir(private / 'parts')
        public = mkdir(base / 'public')
        original = write(private / 'original.zip', b'original ZIP bytes remain untouched')
        source = write(parts / 'part-00.bin', bytes(range(256)) * 3)
        target = public / 'slice.bin'
        record = controller.file_record(source)
        return base, original, source, target, record

    def storage(self, suffix=''):
        base = self.fixture(suffix)
        root, public = mkdir(base / 'private'), mkdir(base / 'public')
        for name in ('control', 'guard', 'original', 'parts', 'api'):
            mkdir(root / name)
        part = mkdir(public / 'part-00')
        mkdir(part / 'controls')
        policy = policy_for(16)
        policy['artifact']['id'] = 1
        write(root / 'original/artifact-1.zip', b'O' * 16)
        write(part / 'slice.bin', b'O' * 16)
        return root, public, policy

    def capacity(self, free=9 << 30, inodes=100000):
        return patch.object(controller.os, 'statvfs', return_value=SimpleNamespace(
            f_bavail=free, f_frsize=1, f_favail=inodes))

    def test_00_draft_policy_and_renderer_refuse(self):
        self.assertFalse(DRAFT['input_pins_frozen'])
        self.assertEqual(DRAFT['parts'], [])
        for target in (controller, worker):
            with self.assertRaises(target.Refusal): target.fixed_policy(DRAFT)
        with self.assertRaises(ValueError):
            renderer.render((SOURCE / 'policy.json').read_bytes(), SOURCE,
                            (SOURCE / 'workflow-template.yml').read_text(), '3' * 40)

    def test_01_partition_edges_and_complete_ranges(self):
        for size, count in ((1, 1), (312 << 20, 1), ((312 << 20) + 1, 2), (3 << 30, 10)):
            policy = policy_for(size)
            for target in (controller, worker):
                rows = target.expected_parts(policy)
                self.assertEqual(len(rows), count)
                self.assertEqual(sum(r['bytes'] for r in rows), size)
                self.assertEqual(rows[0]['offset'], 0)
                self.assertTrue(all(r['bytes'] <= 312 << 20 for r in rows))
                self.assertEqual(rows[-1]['offset'] + rows[-1]['bytes'], size)

    def test_02_partition_tampering_rejected(self):
        original = policy_for((312 << 20) + 17)
        variants = []
        for key, change in (('offset', 1), ('bytes', 16), ('ordinal', True)):
            value = copy.deepcopy(original); value['parts'][1][key] = change; variants.append(value)
        value = copy.deepcopy(original); value['parts'].reverse(); variants.append(value)
        value = copy.deepcopy(original); value['parts'].append(copy.deepcopy(value['parts'][0])); variants.append(value)
        value = copy.deepcopy(original); value['parts'][0]['bytes'] = float(value['parts'][0]['bytes']); variants.append(value)
        for value in variants:
            for target in (controller, worker):
                with self.assertRaises(target.Refusal): target.expected_parts(value)

    def test_03_relocate_preserves_inode_bytes_and_original(self):
        _, original, source, target, record = self.relocation()
        before = controller.file_record(original)
        result = controller.relocate_slice(source, target, record)
        self.assertFalse(os.path.lexists(source))
        self.assertEqual(result['identity'][:2], record['identity'][:2])
        self.assertEqual(result['identity'][5], 1)
        self.assertEqual((result['bytes'], result['sha256']), (record['bytes'], record['sha256']))
        self.assertEqual(controller.file_record(original), before)
        EVENTS.append({'kind': 'same-inode-relocation', 'before': record, 'after': result,
                       'unchanged_original': before})

    def test_04_relocate_refuses_changed_source(self):
        _, original, source, target, record = self.relocation()
        source.chmod(0o600)
        with source.open('ab') as stream: stream.write(b'changed')
        with self.assertRaises(controller.Refusal): controller.relocate_slice(source, target, record)
        self.assertTrue(source.is_file()); self.assertFalse(os.path.lexists(target))
        self.assertEqual(original.read_bytes(), b'original ZIP bytes remain untouched')

    def test_05_relocate_refuses_existing_target(self):
        _, _, source, target, record = self.relocation()
        write(target, b'preexisting target must remain')
        with self.assertRaises(FileExistsError): controller.relocate_slice(source, target, record)
        self.assertEqual(target.read_bytes(), b'preexisting target must remain')
        self.assertEqual(controller.file_record(source), record)

    def test_06_relocate_refuses_hardlinked_source(self):
        base, _, source, target, record = self.relocation()
        alias = base / 'source-alias.bin'; os.link(source, alias)
        with self.assertRaises(controller.Refusal): controller.relocate_slice(source, target, record)
        self.assertEqual(source.stat().st_nlink, 2); self.assertFalse(os.path.lexists(target))
        EVENTS.append({'kind': 'retained-hardlink-refusal', 'paths': [str(source), str(alias)]})

    def test_07_relocate_refuses_symlink_source(self):
        base = self.fixture(); parts = mkdir(base / 'parts'); public = mkdir(base / 'public')
        victim = write(base / 'victim.bin', b'unchanged victim')
        source = parts / 'part-00.bin'; source.symlink_to(victim)
        target = public / 'slice.bin'
        with self.assertRaises(OSError): controller.relocate_slice(source, target, {'bytes': 16})
        self.assertEqual(victim.read_bytes(), b'unchanged victim')
        self.assertFalse(os.path.lexists(target))

    def test_08_relocate_refuses_nonprivate_parent(self):
        _, _, source, target, record = self.relocation()
        target.parent.chmod(0o755)
        with self.assertRaises(controller.Refusal): controller.relocate_slice(source, target, record)
        self.assertEqual(controller.file_record(source), record)
        self.assertFalse(os.path.lexists(target))

    def test_09_link_unlink_interruption_retains_two_names_as_hold(self):
        _, original, source, target, record = self.relocation()
        original_record = controller.file_record(original)
        with patch.object(controller.os, 'unlink', side_effect=OSError('SOURCE_CONTROL_ONLY unlink cut')):
            with self.assertRaises(OSError): controller.relocate_slice(source, target, record)
        self.assertEqual(source.stat().st_nlink, 2)
        self.assertEqual((source.stat().st_dev, source.stat().st_ino),
                         (target.stat().st_dev, target.stat().st_ino))
        for path in (source, target):
            with self.assertRaises(controller.Refusal): controller.file_record(path)
        self.assertEqual(controller.file_record(original), original_record)
        EVENTS.append({'kind': 'actual-link-before-unlink-cut', 'classification': 'EXPECTED_HOLD',
                       'source': controller.typed_observation(source),
                       'target': controller.typed_observation(target)})

    def test_10_post_unlink_fsync_failure_retains_original_inode(self):
        _, original, source, target, record = self.relocation()
        original_record = controller.file_record(original)
        with patch.object(controller.os, 'fsync', side_effect=OSError('SOURCE_CONTROL_ONLY sync cut')):
            with self.assertRaises(OSError): controller.relocate_slice(source, target, record)
        self.assertFalse(os.path.lexists(source))
        result = controller.file_record(target)
        self.assertEqual(result['identity'][:2], record['identity'][:2])
        self.assertEqual(result['sha256'], record['sha256'])
        self.assertEqual(controller.file_record(original), original_record)
        EVENTS.append({'kind': 'actual-post-unlink-sync-cut', 'classification': 'EXPECTED_HOLD',
                       'retained': result})

    def test_11_post_relocation_digest_mismatch_remains_failure(self):
        _, _, source, target, record = self.relocation()
        real = controller.file_record
        def changed(path, *args, **kwargs):
            row = real(path, *args, **kwargs)
            if Path(path) == target: row['sha256'] = '0' * 64
            return row
        with patch.object(controller, 'file_record', side_effect=changed):
            with self.assertRaises(controller.Refusal): controller.relocate_slice(source, target, record)
        self.assertFalse(os.path.lexists(source))
        self.assertEqual(real(target)['sha256'], record['sha256'])

    def test_12_closed_storage_accepts_two_copies_with_fixed_reserves(self):
        root, public, policy = self.storage()
        with self.capacity(): result = controller.closed_storage_observation(root, public, policy)
        self.assertEqual(result['logical_bytes_by_category']['payload'], 32)
        self.assertEqual(result['single_link_regular_files'], 2)
        self.assertFalse(result['file_bodies_read_by_this_observation'])
        self.assertEqual(result['future_final_document_bytes_reserved'], 3 << 20)
        self.assertEqual(result['one_serial_upload_workspace_reserved'], 320 << 20)
        self.assertEqual(result['filesystem_overhead_reserved'], 512 << 20)
        EVENTS.append({'kind': 'closed-storage-synthetic-capacity-control', 'observation': result})

    def test_13_closed_storage_refuses_unknown_and_special_files(self):
        for kind in ('unknown', 'symlink', 'fifo'):
            root, public, policy = self.storage('-' + kind)
            path = root / 'unknown'
            if kind == 'unknown': write(path, b'unknown')
            elif kind == 'symlink': path.symlink_to(root / 'original/artifact-1.zip')
            else: os.mkfifo(path, 0o600)
            with self.capacity(), self.assertRaises(controller.Refusal):
                controller.closed_storage_observation(root, public, policy)
            EVENTS.append({'kind': 'special-metadata-refusal', 'type': kind,
                           'observed': controller.typed_observation(path)})

    def test_14_closed_storage_refuses_hardlink(self):
        root, public, policy = self.storage()
        alias = public / 'part-00/unverified-range.bin'
        os.link(public / 'part-00/slice.bin', alias)
        with self.capacity(), self.assertRaises(controller.Refusal):
            controller.closed_storage_observation(root, public, policy)
        self.assertEqual(alias.stat().st_nlink, 2)

    def test_15_closed_storage_refuses_low_capacity_and_inodes(self):
        for free, inodes, label in ((0, 100000, '-bytes'), (9 << 30, 1, '-inodes')):
            root, public, policy = self.storage(label)
            with self.capacity(free, inodes), self.assertRaises(controller.Refusal):
                controller.closed_storage_observation(root, public, policy)

    def test_16_closed_storage_refuses_oversize_payload_and_diagnostics(self):
        root, public, policy = self.storage('-payload')
        write(root / 'parts/part-00.bin', b'extra payload')
        with self.capacity(), self.assertRaises(controller.Refusal):
            controller.closed_storage_observation(root, public, policy)
        root, public, policy = self.storage('-diagnostics')
        write(public / 'part-00/controls/context.json', b'X' * ((2 << 20) + 1))
        with self.capacity(), self.assertRaises(controller.Refusal):
            controller.closed_storage_observation(root, public, policy)

    def test_17_partial_range_copy_keeps_original_and_cannot_be_sealed(self):
        base = self.fixture(); source = write(base / 'partial.zip', b'0123456789')
        target = base / 'unverified-range.bin'; record = controller.file_record(source)
        result = controller.copy_unverified_range(source, target, record,
                                                  {'offset': 7, 'bytes': 10})
        self.assertEqual(target.read_bytes(), b'789')
        self.assertEqual(result['bytes'], 3)
        self.assertEqual(controller.file_record(source), record)
        self.assertNotIn('sealed', result)
        with self.assertRaises(controller.Refusal):
            controller.copy_unverified_range(source, base / 'absent.bin', record,
                                             {'offset': 10, 'bytes': 10})
        self.assertFalse(os.path.lexists(base / 'absent.bin'))

    def test_18_proxy_client_uses_configured_environment(self):
        marker = object(); opener = object()
        with patch.object(worker.urllib.request, 'ProxyHandler', return_value=marker) as proxy:
            with patch.object(worker.urllib.request, 'build_opener', return_value=opener) as build:
                self.assertIs(worker.new_client(), opener)
        proxy.assert_called_once_with()
        self.assertIs(build.call_args.args[0], marker)
        self.assertIsInstance(build.call_args.args[1], worker.NoRedirect)
        self.assertIsNone(build.call_args.args[1].redirect_request(None, None, 302, None, None, None))

    def test_19_api_and_storage_credentials_are_separate(self):
        base = self.fixture(); mkdir(base / 'original')
        payload = b'SOURCE_CONTROL_ONLY_ZIP_BYTES'
        url = 'https://example.invalid/source-control-only'
        api = worker.api_request('SOURCE_CONTROL_ONLY_TOKEN', '/repos/TrillionniumFoundation/Hepta/actions/artifacts/1')
        self.assertEqual(api.get_header('Authorization'), 'Bearer SOURCE_CONTROL_ONLY_TOKEN')
        observed = []
        class Response(io.BytesIO):
            status = 200
            headers = {'Content-Encoding': 'identity', 'Content-Length': str(len(payload))}
            def geturl(self): return url
        class Client:
            def open(self, request, timeout):
                observed.append(request)
                self_test.assertEqual(timeout, 30)
                return Response(payload)
        self_test = self
        report = {'GET_attempts': []}
        checkpoints = []
        helper = SimpleNamespace(checkpoint=lambda value: checkpoints.append(copy.deepcopy(value)),
                                 sync_dir=controller.sync_dir)
        pin = {'id': 1, 'bytes': len(payload), 'sha256': sha256(payload).hexdigest()}
        with patch.object(worker, 'new_client', return_value=Client()):
            result = worker.storage_download(url, pin, base, time.monotonic_ns() + 10**9, report, helper)
        self.assertEqual(result.read_bytes(), payload)
        self.assertEqual(len(observed), 1)
        self.assertFalse(observed[0].has_header('Authorization'))
        self.assertFalse(observed[0].has_header('Cookie'))
        self.assertEqual(report['GET_attempts'][0]['attempt'], 1)
        self.assertFalse(os.path.lexists(result.with_name(result.name + '.partial')))
        self.assertNotIn(url, json.dumps(report))
        self.assertNotIn('SOURCE_CONTROL_ONLY_TOKEN', json.dumps(report))
        EVENTS.append({'kind': 'mock-HTTP-real-storage-control', 'network_requested': False,
                       'report': report, 'checkpoints': checkpoints})

    def test_20_rendered_partition_is_exact_and_serial(self):
        policy = fake_frozen_policy(3 << 30)
        raw = (json.dumps(policy, sort_keys=True, indent=2) + '\n').encode()
        text, parts = renderer.render(raw, SOURCE, (SOURCE / 'workflow-template.yml').read_text(), '3' * 40)
        self.assertEqual(len(parts), 10)
        self.assertEqual(text.count(b'uses: actions/upload-artifact@'), 10)
        self.assertNotIn(b'PLACEHOLDER', text)
        self.assertNotIn(b'PENDING_ACTUAL', text)
        self.assertIn(b'permissions: {}', text)
        self.assertIn(b'actions: read', text)
        positions = [text.index(('name: hia-v88-full-original-part-%02d-' % i).encode()) for i in range(10)]
        self.assertEqual(positions, sorted(positions))
        base = self.fixture()
        write(base / 'SYNTHETIC-NEVER-INSTALL-OR-TRIGGER.yml', text)
        EVENTS.append({'kind': 'synthetic-render-only', 'bytes': len(text),
                       'sha256': sha256(text).hexdigest(), 'parts': 10, 'workflow_installed': False})

if __name__ == '__main__':
    unittest.main()

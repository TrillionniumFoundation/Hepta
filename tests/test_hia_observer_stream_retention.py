"""Source/byte controls for complete actual process-stream retention.

The execute boundary is an explicit CompletedProcess/TimeoutExpired fixture.
These controls never execute a compiler/native image and do not replace the
original 47 x 3, handoff8, REF18, FD18, CT36 or full cold qualifications.
"""
from __future__ import annotations
from contextlib import nullcontext
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import zlib

ROOT = Path(__file__).resolve().parents[1]
GATE_SHA = '8720447c115e1737dc395271ebb91bb4c8bd5a83bc89558224058b09371bc1d5'


def wire(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode() + b'\n'


class ObserverStreamRetentionSourceTests(unittest.TestCase):
    def setUp(self):
        from tools import hia_selfhost_native_observer as flat
        from tools import hia_selfhost_linked_observer as linked
        from tools import read_hia_cold_native_transport as reader
        self.flat, self.linked, self.reader = flat, linked, reader

    def files(self, root):
        image, observer = root / 'input.image.bin', root / 'observer.elf'
        image.write_bytes(b'\xc3')
        observer.write_bytes(b'explicit Source fixture; never executed')
        return image, observer

    def call(self, root, module, outcome, *, source=b'A\0\xff', output=b'\xa5' * 4,
             workspace=b'\xc7' * 1033, snapshot=None, side_effect=None):
        image, observer = self.files(root)
        with patch.object(module, 'execute', side_effect=side_effect or (lambda *a, **k: outcome)) as execute:
            if module is self.linked:
                with patch.object(module, 'output_snapshot', return_value=nullcontext(17)), \
                        patch.object(module, 'read_output_snapshot', return_value=snapshot):
                    result, actual_output = module.invoke(root, 'case', observer, image, source,
                        capacity=len(output), workspace_size=len(workspace), workspace_fill=199)
            else:
                result, actual_output = module.invoke(root, 'case', observer, image, source,
                    capacity=len(output), workspace_size=len(workspace), workspace_fill=199)
        execute.assert_called_once()
        self.assertEqual(image.read_bytes(), b'\xc3')
        self.assertEqual(observer.read_bytes(), b'explicit Source fixture; never executed')
        return result, actual_output

    def decode(self, root):
        return self.reader.decode_original_process_streams(
            (root / 'case.process-streams.json').read_bytes(),
            (root / 'case.request.json').read_bytes(),
            {name: (root / ('case.process.' + name + '.zlib')).read_bytes()
             for name in ('stdout', 'stderr')}, label='case')

    def assert_old_receipts(self, root, result):
        self.assertEqual(json.loads((root / 'case.stdout.log').read_bytes()), result)
        self.assertEqual(json.loads((root / 'case.receipt.json').read_bytes()), result)
        self.assertNotIn('process_streams', result)

    def test_01_actual_flat_return_preserves_full_frame_and_original_receipts(self):
        source, output, workspace = b'A\0\xff', b'\xa5' * 4, b'\xc7' * 1033
        actual = b'HIAOBR02' + struct.pack('<2Q', 0, 13) + source + output + workspace
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result, observed = self.call(root, self.flat,
                subprocess.CompletedProcess(['explicit-data-fixture'], 0, actual, b''))
            record, raw = self.decode(root)
            self.assertEqual((result['status'], observed), ('returned', output))
            self.assertEqual(raw, {'stdout': actual, 'stderr': b''})
            self.assertEqual(record['returncode'], 0)
            self.assertIs(record['timed_out'], False)
            self.assertEqual(result['native_elapsed_ns'], 13)
            self.assertEqual(result['workspace_header'], {
                str(at): int.from_bytes(workspace[at:at + 8], 'little')
                for at in self.flat.WORKSPACE_FIELDS if at + 8 <= len(workspace)})
            self.assertEqual((root / 'case.output.bin').read_bytes(), output)
            self.assertEqual((root / 'case.stderr.log').read_bytes(), b'')
            self.assert_old_receipts(root, result)

    def test_02_linked_return_keeps_boundary_whitespace_and_prefinalizer_bytes(self):
        source, output, workspace = b' \t\n', b'\0\xff \n', b'\x00' * 1033
        frame = b'HIAOBR03' + struct.pack('<2Q', 7, 19) + source + output + workspace
        actual = b' \t\r\n' + frame + b'\n\t '
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result, observed = self.call(root, self.linked,
                subprocess.CompletedProcess(['explicit-data-fixture'], 0, actual, b''),
                source=source, output=output, workspace=workspace, snapshot=output)
            record, raw = self.decode(root)
            self.assertEqual((result['status'], observed), ('returned', output))
            self.assertEqual(raw['stdout'], actual)
            self.assertNotEqual(raw['stdout'], frame)
            self.assertEqual(result['core_u32'], 7)
            self.assertTrue(result['prefinalizer_output_snapshot']['available'])
            self.assertEqual(result['prefinalizer_output_snapshot']['sha256'], sha256(output).hexdigest())
            self.assert_old_receipts(root, result)

    def test_03_original_failures_timeouts_and_explicit_empty_streams_are_retained(self):
        cases = (
            ('nonzero-empty', -9, b'', b'', False, 'child_failed'),
            ('nonzero-binary', 7, b'\0\xffpartial', b'\xfeerror\0', False, 'child_failed'),
            ('malformed', 0, b'invalid\0frame', b'', False, 'protocol_failed'),
            ('timeout-empty', None, b'', b'', True, 'timeout'),
            ('timeout-partial', None, b'actual\0partial', b'\xffpartial-error', True, 'timeout'),
        )
        for module in (self.flat, self.linked):
            for name, code, stdout, stderr, timed_out, status in cases:
                with self.subTest(observer=module.__name__, case=name), tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    if timed_out:
                        failure = subprocess.TimeoutExpired(['explicit-data-fixture'], 20,
                            output=stdout or None, stderr=stderr or None)
                        def outcome(*args, **kwargs):
                            raise failure
                        result, output = self.call(root, module, None, side_effect=outcome)
                    else:
                        result, output = self.call(root, module,
                            subprocess.CompletedProcess(['explicit-data-fixture'], code, stdout, stderr))
                    record, raw = self.decode(root)
                    self.assertEqual((record['returncode'], record['timed_out']), (code, timed_out))
                    self.assertEqual(raw, {'stdout': stdout, 'stderr': stderr})
                    self.assertEqual(result['status'], status)
                    self.assertEqual(output, b'')
                    self.assertEqual((root / 'case.stderr.log').read_bytes(), stderr)
                    for stream in ('stdout', 'stderr'):
                        self.assertEqual(record['streams'][stream]['raw_bytes'], len(raw[stream]))
                        self.assertGreater(record['streams'][stream]['stored_bytes'], 0)
                    self.assert_old_receipts(root, result)
        # The old linked contract keeps the already committed f0 snapshot even
        # when the actual finalizer then fails and produces unrelated stdout.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); snapshot = b'live'
            result, output = self.call(root, self.linked,
                subprocess.CompletedProcess(['explicit-data-fixture'], 7, b'finalizer\xff', b'failure'),
                output=snapshot, snapshot=snapshot)
            self.assertEqual((result['status'], output), ('child_failed', snapshot))
            self.assertEqual(self.decode(root)[1], {'stdout': b'finalizer\xff', 'stderr': b'failure'})

    def test_04_request_drift_and_failed_retention_cannot_publish_a_success_receipt(self):
        for module in (self.flat, self.linked):
            for failure_kind in ('request-drift', 'write-failure'):
                with self.subTest(observer=module.__name__, kind=failure_kind), tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary); image, observer = self.files(root)
                    original_error = OSError('actual retention write failure')
                    def execute(*args, **kwargs):
                        if failure_kind == 'request-drift':
                            path = root / 'case.request.json'; path.write_bytes(path.read_bytes() + b'\n')
                        return subprocess.CompletedProcess(['explicit-data-fixture'], 7, b'actual', b'error')
                    real_write = Path.write_bytes
                    def write(path, raw):
                        if failure_kind == 'write-failure' and path.name == 'case.process.stdout.zlib':
                            raise original_error
                        return real_write(path, raw)
                    with patch.object(module, 'execute', side_effect=execute) as actual_execute, \
                            patch.object(Path, 'write_bytes', write), \
                            patch.object(self.linked, 'output_snapshot', return_value=nullcontext(17)), \
                            patch.object(self.linked, 'read_output_snapshot', return_value=None):
                        with self.assertRaises(ValueError if failure_kind == 'request-drift' else OSError) as caught:
                            module.invoke(root, 'case', observer, image, b'', capacity=0,
                                          workspace_size=0, workspace_fill=0)
                    actual_execute.assert_called_once()
                    if failure_kind == 'write-failure': self.assertIs(caught.exception, original_error)
                    self.assertFalse((root / 'case.receipt.json').exists())
                    self.assertFalse((root / 'case.process-streams.json').exists())

    def test_05_independent_reader_rejects_changed_truncated_and_oversized_streams(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); request = {'frame_sha256': 'explicit Source-only request'}
            request_raw = (json.dumps(request, sort_keys=True) + '\n').encode()
            (root / 'case.request.json').write_bytes(request_raw)
            self.flat.retain_process_streams(root, 'case', b'HIAOBR02\0\xff', b'\xffstderr',
                request=request, returncode=0, timed_out=False)
            original_raw = (root / 'case.process-streams.json').read_bytes()
            original = json.loads(original_raw)
            streams = {name: (root / ('case.process.' + name + '.zlib')).read_bytes() for name in ('stdout', 'stderr')}
            self.assertEqual(self.reader.decode_original_process_streams(original_raw, request_raw, streams, label='case')[1],
                             {'stdout': b'HIAOBR02\0\xff', 'stderr': b'\xffstderr'})
            variants = ('extra-field', 'schema', 'request', 'return-bool', 'timeout-int', 'timeout-code',
                'limit', 'limit-bool', 'missing-stream', 'extra-stream', 'name', 'encoding', 'level', 'level-bool',
                'raw-count', 'raw-count-bool', 'raw-sha', 'stored-count', 'stored-sha', 'byte-change',
                'truncation', 'trailing', 'second-stream', 'not-zlib', 'decompression-limit')
            for name in ('stdout', 'stderr'):
                for variant in variants:
                    with self.subTest(stream=name, variant=variant):
                        record, actual = deepcopy(original), dict(streams)
                        row = record['streams'][name]
                        if variant == 'extra-field': record['extra'] = True
                        elif variant == 'schema': record['schema'] += '-changed'
                        elif variant == 'request': record['request_sha256'] = '0' * 64
                        elif variant == 'return-bool': record['returncode'] = False
                        elif variant == 'timeout-int': record['timed_out'] = 0
                        elif variant == 'timeout-code': record['timed_out'] = True
                        elif variant == 'limit': record['decoded_stream_limit_bytes'] += 1
                        elif variant == 'limit-bool': record['decoded_stream_limit_bytes'] = True
                        elif variant == 'missing-stream': del record['streams'][name]
                        elif variant == 'extra-stream': record['streams']['extra'] = deepcopy(row)
                        elif variant == 'name': row['file'] = '../' + row['file']
                        elif variant == 'encoding': row['encoding'] = 'gzip'
                        elif variant == 'level': row['compression_level'] = 9
                        elif variant == 'level-bool': row['compression_level'] = True
                        elif variant == 'raw-count': row['raw_bytes'] += 1
                        elif variant == 'raw-count-bool': row['raw_bytes'] = True
                        elif variant == 'raw-sha': row['raw_sha256'] = '0' * 64
                        elif variant == 'stored-count': row['stored_bytes'] += 1
                        elif variant == 'stored-sha': row['stored_sha256'] = '0' * 64
                        elif variant == 'byte-change': actual[name] = b'\0' + actual[name][1:]
                        else:
                            if variant == 'truncation': actual[name] = actual[name][:-1]
                            elif variant == 'trailing': actual[name] += b'\0'
                            elif variant == 'second-stream': actual[name] += zlib.compress(b'second', level=1)
                            elif variant == 'not-zlib': actual[name] = b'not a zlib stream'
                            else:
                                actual[name] = zlib.compress(b'x' * ((16 << 20) + 1), level=1)
                                row['raw_bytes'] = 16 << 20
                                row['raw_sha256'] = sha256(b'x' * (16 << 20)).hexdigest()
                            row['stored_bytes'] = len(actual[name]); row['stored_sha256'] = sha256(actual[name]).hexdigest()
                        with self.assertRaises(ValueError):
                            self.reader.decode_original_process_streams(wire(record), request_raw, actual, label='case')
            for changed in (original_raw + b' ', b'{"schema":0,' + original_raw[1:], original_raw[:-1]):
                with self.assertRaises(ValueError):
                    self.reader.decode_original_process_streams(changed, request_raw, streams, label='case')
            with self.assertRaises(ValueError):
                self.reader.decode_original_process_streams(original_raw, request_raw + b'\n', streams, label='case')

    def test_06_original_fixture_full_execute_and_selection_sources_remain_exact(self):
        from tools import hia_cold_native_transport_evidence as producer
        raw = (ROOT / 'tests/fixtures/cold_native_transport_original_gates_v3.json').read_bytes()
        self.assertEqual(sha256(raw).hexdigest(), GATE_SHA)
        fixture = json.loads(raw)
        for row in fixture['original_observers']:
            current = (ROOT / row['path']).read_bytes(); tail = row['selection_tail'].encode()
            self.assertTrue(current.endswith(tail)); body = current[:-len(tail)]
            old = producer.restore_observer_source(row['path'], body, row['before'])
            self.assertEqual(self.reader.restore_observer_source(row['path'], body, row['before']), old)
            self.assertEqual({'bytes': len(old), 'sha256': sha256(old).hexdigest()}, row['before'])
            self.assertEqual(body.count(row['execute_source'].encode()), 1)
            for changed in (body + b'\n', body[:-1], old):
                with self.assertRaises(ValueError):
                    producer.restore_observer_source(row['path'], changed, row['before'])
                with self.assertRaises(ValueError):
                    self.reader.restore_observer_source(row['path'], changed, row['before'])
        left = producer.observer_source_profile(ROOT, producer.Captures())
        right = self.reader.observer_source_profile(ROOT, self.reader.Raw())
        self.assertEqual(left, right)
        self.assertEqual(len(left[1]), 47)
        self.assertEqual(left[0]['original_method_count'], 44)
        self.assertEqual(left[0]['cold_phase_count'], 38)
        self.assertEqual(left[0]['independent_reference_count'], 17)
        self.assertEqual(left[0]['original_caps']['cold_seconds'], 180)
        self.assertEqual(left[0]['original_caps']['cleanup_seconds'], 3)


if __name__ == '__main__':
    unittest.main()

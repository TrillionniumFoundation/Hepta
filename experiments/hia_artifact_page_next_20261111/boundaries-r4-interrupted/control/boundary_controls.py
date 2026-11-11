"""Actual page+wire differential: full payload, page/budget and cursor boundaries."""
from collections import Counter
from hashlib import sha256
import json
import os
from pathlib import Path
import sqlite3
import struct
import sys
import time
import traceback
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path('/tmp/hia-e26e-artifact-page-r4')
SOURCE = ROOT / 'source'
sys.path.insert(0, str(SOURCE))
from hepta import hia_agent_service as service_module
from hepta import hia_agent_store as store_module
from hepta import hia_artifact_page_native as page

OWNER = page.installed_artifact_page(ROOT / 'page-bundle.json')
RETAINED = service_module.HIAAgentService._hia_read
WIRE = service_module.wire
OUTPUT = ROOT / 'boundary-r4'
OUTPUT.mkdir(mode=0o700)

def file_hashes():
    baseline = json.loads((ROOT / 'MATERIALIZATION.json').read_bytes())['final_members']
    return {name: sha256((SOURCE / name).read_bytes()).hexdigest() for name in baseline}

def wire_record(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}

class Database:
    def __init__(self):
        self.raw = sqlite3.connect(':memory:')
        self.raw.row_factory = sqlite3.Row
        self.raw.execute('CREATE TABLE cursors(id TEXT PRIMARY KEY,artifact_id TEXT,sha256 TEXT,offset INTEGER)')
        self.calls = []
    def execute(self, sql, args):
        self.calls.append([sql, list(args)])
        return self.raw.execute(sql, args)
    def rows(self):
        return [list(row) for row in self.raw.execute('SELECT * FROM cursors ORDER BY id')]

def service(data, initial):
    db = Database()
    if initial is not None:
        db.raw.execute('INSERT INTO cursors VALUES (?,?,?,?)', initial)
    events = []
    def get(ref):
        events.append('store.get')
        return data, {}
    return SimpleNamespace(store=SimpleNamespace(get=get, db=db), events=events)

class Session(page.PageSession):
    def __init__(self, *args):
        super().__init__(*args)
        self.codes = Counter()
        self.requests = Counter()
        self.byte_observations = []
        self.wires = []
    def step(self, packet=None):
        code = super().step(packet)
        self.codes[code] += 1
        return code
    def observe(self):
        opcode, = struct.unpack_from('<Q', self.workspace, 8)
        self.requests[opcode] += 1
        if opcode == 10:
            _, start, count = struct.unpack_from('<3Q', self.workspace, 200)
            self.byte_observations.append([start, count])
        return super().observe()
    def _wire(self, handle):
        raw = super()._wire(handle)
        self.wires.append(wire_record(raw))
        return raw

def observed(fn):
    try:
        return {'returned': fn()}
    except BaseException as error:
        return {'type': type(error).__name__, 'message': str(error), 'code': getattr(error, 'code', None)}

def result_summary(value):
    if 'returned' not in value:
        return value
    result = value['returned']
    content = result['content'].encode('utf-8')
    return {'encoding': result['encoding'], 'content_points': len(result['content']),
            'content_utf8_bytes': len(content), 'content_sha256': sha256(content).hexdigest(),
            'next_cursor': result['next_cursor']}

def case(name, data, limit, *, offset=None, cursor_mode=None):
    ref = {'id': 'a-fixture', 'sha256': sha256(data).hexdigest(), 'uri': 'hia://fixture'}
    args = {'artifact': ref, 'max_bytes': limit}
    initial = None
    if offset is not None or cursor_mode is not None:
        args['cursor'] = 'page-original'
        if cursor_mode != 'missing':
            initial = ('page-original', 'other-artifact' if cursor_mode == 'wrong-id' else ref['id'],
                       'f' * 64 if cursor_mode == 'wrong-sha' else ref['sha256'], offset or 0)
    old, new = service(data, initial), service(data, initial)
    wire_calls = []
    def reference_wire(value):
        raw = WIRE(value)
        wire_calls.append(wire_record(raw))
        return raw
    started = time.monotonic_ns()
    try:
        with patch.object(service_module, 'wire', reference_wire), patch.object(store_module, 'wire', reference_wire):
            expected = observed(lambda: RETAINED(old, args))
        reference_ns = time.monotonic_ns() - started
        session = Session(OWNER, new, args)
        native_start = time.monotonic_ns()
        with patch.object(service_module.HIAAgentService, '_hia_read', side_effect=AssertionError('retained page forbidden')), \
             patch.object(service_module, 'digest', side_effect=AssertionError('retained cursor digest forbidden')), \
             patch.object(service_module.base64, 'b64encode', side_effect=AssertionError('retained base64 forbidden')), \
             patch.object(service_module, 'wire', side_effect=AssertionError('retained page wire forbidden')):
            actual = observed(session.run)
        native_ns = time.monotonic_ns() - native_start
        assert actual == expected, (name, result_summary(actual), result_summary(expected))
        assert new.store.db.rows() == old.store.db.rows(), name
        assert new.store.db.calls == old.store.db.calls, name
        assert new.events == old.events == ['store.get']
        assert session.wires == wire_calls, (name, session.wires, wire_calls)
        if 'returned' in actual:
            result = actual['returned']
            assert result['artifact'] is ref
            wire_budget = len(WIRE(result['content'])) + len(WIRE(WIRE(result['content']).decode('utf-8')))
            assert wire_budget <= 230000
            assert sum(count for _, count in session.byte_observations) == len(data)
            assert session.byte_observations == [[i, min(65536, len(data) - i)] for i in range(0, len(data), 65536)]
            assert session.codes[2] == 1
        else:
            wire_budget = None
            assert actual['code'] == 'E_HIA_CURSOR' and session.codes[100] == 1
        return {'case': name, 'status': 'PASS', 'source_bytes': len(data), 'raw_limit': limit,
                'offset': offset, 'cursor_mode': cursor_mode, 'result': result_summary(actual),
                'cursor_rows': new.store.db.rows(), 'sql_calls': new.store.db.calls,
                'wire_calls': session.wires, 'wire_budget': wire_budget,
                'native_return_codes': dict(session.codes), 'effect_requests': dict(session.requests),
                'full_input_observation_bytes': sum(x[1] for x in session.byte_observations),
                'full_input_observation_chunks': len(session.byte_observations),
                'reference_ns': reference_ns, 'native_ns': native_ns}
    finally:
        old.store.db.raw.close()
        new.store.db.raw.close()

specifications = [
    ('empty', lambda: b'', 512, {}),
    ('public-minimum', lambda: b'A' * 4096, 512, {}),
    ('public-maximum', lambda: b'A' * 70000, 65536, {}),
    ('max-artifact-ascii', lambda: b'A' * (64 << 20), 512, {}),
    ('max-artifact-invalid-last', lambda: b'A' * ((64 << 20) - 1) + b'\xff', 512, {}),
    ('max-artifact-utf8-four', lambda: b'\xf0\x90\x80\x80' * (16 << 20), 512, {}),
    ('utf8-stream-page-two', lambda: b'A' * 65535 + b'\xc2\x80Z', 65536, {}),
    ('utf8-stream-page-three', lambda: b'A' * 65535 + b'\xe0\xa0\x80Z', 65536, {}),
    ('utf8-stream-page-four', lambda: b'A' * 65535 + b'\xf4\x8f\xbf\xbfZ', 65536, {}),
    ('page-begins-in-continuation', lambda: b'A\xe9\x9b\xaaZ', 512, {'offset': 2}),
    ('zero-private-limit', lambda: b'abc', 0, {}),
    ('one-byte-private-limit', lambda: b'\xc2\x80Z', 1, {}),
    ('nul-public-max-two-shrinks', lambda: b'\0' * 65536, 65536, {}),
    ('quote-backslash-max', lambda: b'"\\' * 32768, 65536, {}),
    ('mixed-control-max', lambda: b'\0"\\\n' * 16384, 65536, {}),
    ('binary-max', lambda: bytes(range(256)) * 256, 65536, {}),
]
for i, malformed in enumerate((b'\x80', b'\xc0\xaf', b'\xc1\xbf', b'\xc2', b'\xe0\x9f\xbf',
                               b'\xed\xa0\x80', b'\xf0\x8f\xbf\xbf', b'\xf4\x90\x80\x80',
                               b'\xf5\x80\x80\x80', b'\xfe', b'\xff', b'\xe9\x9b')):
    specifications.append(('malformed-%02d' % i, lambda m=malformed: b'A' * 510 + m + b'Z', 512, {}))
for offset in (-(1 << 63), -100, -5, -1, 0, 1, 4, 5, (1 << 63) - 1):
    specifications.append(('signed-offset-%d' % offset, lambda: b'abcde', 512, {'offset': offset}))
for kind in ('missing', 'wrong-id', 'wrong-sha'):
    specifications.append(('cursor-' + kind, lambda: b'abcde', 512, {'cursor_mode': kind}))

report = {'schema': 'hia.artifact-page.native-boundaries.v1', 'status': 'HOLD',
          'scope': 'ACTUAL_DEVELOPMENT_PAGE_AND_WIRE_NOT_GLOBAL_QUALIFICATION',
          'policy_image': OWNER.policy.image_sha256, 'wire_image': OWNER.wire.image_sha256,
          'observations': [], 'failures': [], 'whole_native_delivery_qualified': False,
          'source_before': file_hashes(), 'sqlite_scope': 'actual in-memory SQL semantics, no storage durability claim'}
start = time.monotonic_ns()
with patch.dict(os.environ, {}, clear=True):
    threshold = max(n for n in range(17680, 17700)
                    if len(WIRE('\0' * n)) + len(WIRE(WIRE('\0' * n).decode())) <= 230000)
    report['actual_retained_nul_threshold'] = threshold
    for n in (threshold, threshold + 1):
        specifications.append(('nul-budget-%d' % n, lambda n=n: b'\0' * n, 65536, {}))
    report['expected_case_count'] = len(specifications)
    for name, build, limit, options in specifications:
        try:
            result = case(name, build(), limit, **options)
            report['observations'].append(result)
            print(json.dumps({k: result[k] for k in ('case', 'status', 'source_bytes', 'native_ns', 'wire_budget')}), flush=True)
        except BaseException as error:
            report['failures'].append({'case': name, 'error_type': type(error).__name__,
                                       'message': str(error), 'traceback': traceback.format_exc()})
            print(json.dumps({'case': name, 'status': 'FAIL', 'error': str(error)}), flush=True)
        (OUTPUT / 'progress.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
report['source_after'] = file_hashes()
report['source_preserved'] = report['source_before'] == report['source_after']
report['elapsed_ns'] = time.monotonic_ns() - start
if (not report['failures'] and len(report['observations']) == report['expected_case_count'] and report['source_preserved']):
    report['status'] = 'DEVELOPMENT_BOUNDARIES_PASS'
(OUTPUT / 'report.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
print(json.dumps({'status': report['status'], 'expected_cases': report['expected_case_count'],
                  'passed': len(report['observations']), 'failures': len(report['failures']),
                  'elapsed_ns': report['elapsed_ns']}), flush=True)
raise SystemExit(0 if report['status'] == 'DEVELOPMENT_BOUNDARIES_PASS' else 1)

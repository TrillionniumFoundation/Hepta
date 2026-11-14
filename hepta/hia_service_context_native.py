"""Current Agent context/deadline policy executed by a captured HIA image.

Python transports ordinary Agent objects and invokes fixed schema, profile,
buffer, SQL, clock and budget providers. HIA chooses every policy branch and
loop, exact integer arithmetic, effect permission and terminal outcome. The
four public routes keep their current JSON/provider domain and deadlines.
Arbitrary replacement implementations of private Python helpers are not a
new supported language profile. SQLite and Python object transport are not
claimed native here.
"""
from __future__ import annotations
import ctypes
from dataclasses import dataclass
from functools import lru_cache
from hashlib import sha256
import json
import os
from pathlib import Path
import struct
import threading

from .hia_json_preflight_native import NativeHiaJsonImage, _source_resource_path
from .hia_store_lifecycle_native import _regular_bytes

SOURCE = _source_resource_path('examples/hia_bootstrap/service_context.hepta')
SCHEMA = 'hepta.hia.service-context-native.v1'
SELECTOR = 'HEPTA_HIA_SERVICE_CONTEXT_MANIFEST'
REQUEST_MAGIC = int.from_bytes(b'HCTXREQ1', 'little')
RESULT_MAGIC = int.from_bytes(b'HCTXRSP1', 'little')
MATH_MAGIC = int.from_bytes(b'HCTXINT1', 'little')
MATH_RESULT_MAGIC = int.from_bytes(b'HCTXNUM1', 'little')
STATE_BYTES = 128
OUTPUT_BYTES = 80
_INTEROP = object()
_FRAME_CUSTODY = {}
_CUSTODY_LOCK = threading.Lock()
_CUSTODY_PID = os.getpid()


class ServiceContextUnknown(RuntimeError):
    """An actual effect or acknowledgement is unconfirmed; never replay it."""


def _after_fork_child():
    global _CUSTODY_LOCK, _CUSTODY_PID
    _CUSTODY_LOCK = threading.Lock()
    _CUSTODY_PID = os.getpid()


if hasattr(os, 'register_at_fork'):
    os.register_at_fork(after_in_child=_after_fork_child)


def _custody_lock():
    if os.getpid() != _CUSTODY_PID:
        raise ServiceContextUnknown('context custody lock was not established in this process')
    return _CUSTODY_LOCK


class NativeServiceContextImage(NativeHiaJsonImage):
    def arithmetic(self, operation, left, right):
        """Representation only; the image supplies every exact-int answer."""
        if type(operation) is not int or not 1 <= operation <= 8:
            raise ServiceContextUnknown('context arithmetic operation differs')
        a_tag, b_tag = int(type(left) is int), int(type(right) is int)
        a = int.to_bytes(left, (int.bit_length(left) + 8) // 8, 'little', signed=True) if a_tag else b''
        b = int.to_bytes(right, (int.bit_length(right) + 8) // 8, 'little', signed=True) if b_tag else b''
        raw = struct.pack('<8Q', MATH_MAGIC, operation, a_tag, b_tag, len(a), len(b), 0, 0) + a + b
        width = max(len(a), len(b)) + 8
        capacity, extent = 32 + width, width * 3
        source = ctypes.create_string_buffer(raw + b'\xc9' * 16, len(raw) + 16)
        output = ctypes.create_string_buffer(capacity + 16)
        workspace = ctypes.create_string_buffer(extent + 16)
        ctypes.memmove(ctypes.addressof(output) + capacity, b'\xa5' * 16, 16)
        ctypes.memmove(ctypes.addressof(workspace) + extent, b'\xda' * 16, 16)
        code = self._entry(source, len(raw), output, capacity, workspace, extent)
        if (type(code) is not int or code != 32 or source.raw != raw + b'\xc9' * 16
                or output.raw[capacity:] != b'\xa5' * 16 or workspace.raw[extent:] != b'\xda' * 16):
            raise ServiceContextUnknown('context arithmetic has no exact guarded result')
        magic, kind, size, echoed = struct.unpack_from('<4Q', output)
        if (magic != MATH_RESULT_MAGIC or echoed != operation or size > width
                or output.raw[32 + size:capacity] != bytes(capacity - 32 - size)):
            raise ServiceContextUnknown('context arithmetic receipt differs')
        if kind == 1 and size == 0:
            return _INTEROP
        if kind == 2 and size == 1 and output.raw[32] in (0, 1):
            return bool(output.raw[32])
        if kind == 0 and size > 0:
            return int.from_bytes(output.raw[32:32 + size], 'little', signed=True)
        raise ServiceContextUnknown('context arithmetic representation differs')


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError('duplicate service-context manifest field')
        result[key] = value
    return result


@lru_cache(maxsize=3)
def _mapped_context(raw, expected):
    return NativeServiceContextImage(raw, expected)


def installed_service_context(manifest_path):
    from .hia_native_helpers import pinned_image
    selected = pinned_image(manifest_path, SOURCE, SCHEMA, NativeServiceContextImage)
    path = Path(manifest_path).resolve(strict=True)
    raw = _regular_bytes(path, 16384)
    value = json.loads(raw, object_pairs_hook=_pairs)
    if (type(value) is not dict or set(value) != {
            'schema', 'source_sha256', 'image_path', 'image_sha256', 'compiler_sha256'}
            or value['schema'] != SCHEMA
            or any(type(value[key]) is not str or len(value[key]) != 64
                   or any(char not in '0123456789abcdef' for char in value[key])
                   for key in ('source_sha256', 'image_sha256', 'compiler_sha256'))):
        raise ValueError('invalid service-context manifest')
    name = value['image_path']
    if (type(name) is not str or not name or name in ('.', '..')
            or Path(name).name != name or any(ord(char) < 32 for char in name)):
        raise ValueError('service-context image must be a sibling basename')
    source = _regular_bytes(SOURCE, 8 << 20)
    image_path = path.parent / name
    image = _regular_bytes(image_path, 1 << 20)
    if sha256(source).hexdigest() != value['source_sha256']:
        raise ValueError('service-context source identity mismatch')
    if sha256(image).hexdigest() != value['image_sha256']:
        raise ValueError('service-context image identity mismatch')
    if selected is None:
        selected = _mapped_context(image, value['image_sha256'])
    elif type(selected) is not NativeServiceContextImage or selected.image_sha256 != value['image_sha256']:
        raise ValueError('service-context selection differs from pinned worker image')
    if (_regular_bytes(path, 16384) != raw or _regular_bytes(SOURCE, 8 << 20) != source
            or _regular_bytes(image_path, 1 << 20) != image):
        raise ValueError('service-context selection changed during admission')
    return selected


@dataclass(frozen=True)
class ContextReceipt:
    port: int
    sequence: int
    phase: int
    mode: int
    index: int
    failed: int


class ContextFrame:
    def __init__(self, image, mode, service, argument, *, candidate=False, namespace=None):
        if type(image) is not NativeServiceContextImage or type(mode) is not int or mode not in (1, 2, 3, 4):
            raise ServiceContextUnknown('context image or mode differs')
        if namespace is None:
            from . import hia_agent_service
            namespace = vars(hia_agent_service)
        self.image, self.mode, self.service, self.namespace = image, mode, service, namespace
        self.data = {('args', 'ref', 'context', 'context')[mode - 1]: argument,
                     'candidate': candidate, 'result': None}
        self.identity = struct.unpack('<2Q', os.urandom(16))
        self.creator, self.thread = os.getpid(), threading.get_ident()
        self.buffer = ctypes.create_string_buffer(STATE_BYTES)
        self.receipt = None
        self.fenced = False
        self.unconfirmed = False
        self.native_failed = False
        self.error = None
        # Reserve growable process-lifetime custody before any foreign effect.
        # A failed acknowledgement cannot drop the only actual effect owner.
        with _custody_lock():
            if any(frame.unconfirmed and frame.service is service for frame in _FRAME_CUSTODY.values()):
                raise ServiceContextUnknown('service has an unconfirmed context effect')
            _FRAME_CUSTODY[id(self)] = self
        self.call(0)

    def call(self, event, observation=0):
        if self.fenced or os.getpid() != self.creator or threading.get_ident() != self.thread:
            raise ServiceContextUnknown('context frame cannot be resumed or inherited')
        try:
            sequence, port = (0, 0) if self.receipt is None else (self.receipt.sequence, self.receipt.port)
            numbers = (REQUEST_MAGIC, event, sequence, port, observation, self.mode, *self.identity, 0, 0)
            if any(type(value) is not int or not 0 <= value < 1 << 64 for value in numbers):
                raise ServiceContextUnknown('context observation is not an exact ABI integer')
            raw = struct.pack('<10Q', *numbers)
            source = ctypes.create_string_buffer(raw, len(raw))
            output = ctypes.create_string_buffer(OUTPUT_BYTES)
            code = self.image._entry(source, len(raw), output, OUTPUT_BYTES, self.buffer, STATE_BYTES)
            if type(code) is not int or code != OUTPUT_BYTES or source.raw != raw:
                raise ServiceContextUnknown('context machine return is unconfirmed')
            words = struct.unpack('<10Q', output.raw)
            state = struct.unpack('<16Q', self.buffer.raw)
            if (words[0] != RESULT_MAGIC or words[1] > 1
                    or words[2:8] != (state[3], state[4], state[5], state[2], state[8], state[9])
                    or words[8:10] != self.identity or state[6:8] != self.identity
                    or words[5] != self.mode or words[3] == 0
                    or words[4] not in (1, 2, 4, 5, 6) or words[6] > 3 or words[7] > 1):
                raise ServiceContextUnknown('context receipt differs from its issued state')
            if words[1] or words[4] == 6:
                raise ServiceContextUnknown('context native claim or observation refused')
            self.receipt = ContextReceipt(*words[2:8])
            return self.receipt
        except BaseException:
            self.fenced = self.unconfirmed = True
            raise

    def finish(self):
        returned = False
        try:
            while self.receipt.phase == 1:
                self.call(1)
                try:
                    observed = self.effect(self.receipt.port)
                except BaseException as error:
                    self.error = error
                    if self.native_failed:
                        self.unconfirmed = True
                        raise
                    self.call(3)
                    if self.receipt.phase != 5:
                        self.unconfirmed = True
                        raise ServiceContextUnknown('context exception has no native terminal')
                    # No synthetic raise or interpreter ABI changes the actual
                    # foreign exception, cause, context, notes or traceback.
                    raise
                else:
                    self.call(2, 0 if observed is None else observed)
            if self.receipt.phase != 4:
                self.unconfirmed = True
                raise ServiceContextUnknown('context continuation did not return')
            result = self.data['result']
            returned = True
            return result
        finally:
            if self.receipt is None or self.receipt.phase not in (4, 5):
                self.unconfirmed = True
            self.fenced = True
            if not self.unconfirmed:
                with _custody_lock():
                    if _FRAME_CUSTODY.get(id(self)) is self:
                        del _FRAME_CUSTODY[id(self)]
                if returned:
                    self.data.clear()
                    self.service = None
                # Real exception tracebacks retain the original service/local
                # objects. An unconfirmed handoff instead keeps process custody.
                self.error = None

    def _next(self, iterator, target):
        try:
            self.data[target] = next(self.data[iterator])
        except StopIteration:
            return 0
        return 1

    def _math(self, operation, left, right):
        self.data['math_left'], self.data['math_right'] = left, right
        try:
            value = self.image.arithmetic(operation, left, right)
        except BaseException:
            self.native_failed = True
            raise
        if value is not _INTEROP:
            self.data.pop('math_left')
            self.data.pop('math_right')
        return value

    def effect(self, port):
        d, s, api = self.data, self.service, self.namespace
        if port == 1:
            from .hia_agent_buffers import export_manifest, buffer_size, MAX_WORKLOAD_BUFFER_BYTES
            d.update(export_manifest=export_manifest, buffer_size=buffer_size,
                     MAX_WORKLOAD_BUFFER_BYTES=MAX_WORKLOAD_BUFFER_BYTES)
        elif port == 2:
            s._profile(d['args']['compiler_profile'], 'compiler')
        elif port == 3:
            s._profile(d['args']['target_profile'], 'target')
        elif port == 4:
            d['workload'], d['_'] = s.store.get_json(d['args']['workload'])
        elif port == 5:
            d['objective'], d['_'] = s.store.get_json(d['args']['objective'])
        elif port == 6:
            d['cost_policy'], d['_'] = s.store.get_json(d['args']['budget']['cost_policy'])
        elif port == 7:
            api['validate'](d['workload'], api['WORKLOAD_SCHEMA'], 'workload')
        elif port == 8:
            d['foreign_buffer_exports'] = d['export_manifest'](d['workload'])
        elif port == 9:
            d['sum'] = 0
            d['case_iterator'] = iter(d['workload']['cases'])
        elif port == 10:
            return self._next('case_iterator', 'case')
        elif port == 11:
            d['value_iterator'] = iter(d['case']['arguments'])
        elif port == 12:
            return self._next('value_iterator', 'value')
        elif port == 13:
            return int(type(d['value']) is dict)
        elif port == 14:
            d['size'] = d['buffer_size'](d['value'])
        elif port == 15:
            value = self._math(1, d.pop('sum'), d.pop('size'))
            d['sum'] = d.pop('math_left') + d.pop('math_right') if value is _INTEROP else value
        elif port == 16:
            d['snapshot_bytes'] = d.pop('sum')
            for name in ('case_iterator', 'value_iterator', 'case', 'value'):
                d.pop(name, None)
        elif port == 17:
            value = self._math(5, d['snapshot_bytes'], d['MAX_WORKLOAD_BUFFER_BYTES'])
            return int(bool(d.pop('math_left') > d.pop('math_right'))) if value is _INTEROP else int(value)
        elif port == 18:
            api['validate'](d['objective'], api['OBJECTIVE_SCHEMA'], 'objective')
        elif port == 19:
            api['validate'](d['cost_policy'], api['COST_POLICY_SCHEMA'], 'cost_policy')
        elif port == 20:
            d['name'] = ('max_candidates', 'max_model_tokens', 'max_total_wall_ms', 'max_native_wall_ms')[self.receipt.index]
            d['args']['budget'][d['name']] = int(d['args']['budget'][d['name']])
        elif port == 21:
            api['uint64'](d['cost_policy']['expected_invocations'], 'expected_invocations')
        elif port == 22:
            d['memory'] = api['uint64'](d['args']['budget']['max_memory_bytes'], 'max_memory_bytes')
        elif port == 23:
            value = self._math(6, 64 * 1024**2, d['memory'])
            return int(bool(d.pop('math_left') <= d.pop('math_right'))) if value is _INTEROP else int(value)
        elif port == 24:
            value = self._math(6, d['memory'], 4 * 1024**3)
            return int(bool(d.pop('math_left') <= d.pop('math_right'))) if value is _INTEROP else int(value)
        elif port == 25:
            value = self._math(5, d['args']['budget']['max_native_wall_ms'], d['args']['budget']['max_total_wall_ms'])
            return int(bool(d.pop('math_left') > d.pop('math_right'))) if value is _INTEROP else int(value)
        elif port == 26:
            d['name'] = ('model_wall_ns', 'discovery_wall_ns')[self.receipt.index]
        elif port == 27:
            return int(d['cost_policy']['external_costs'][d['name']] is not None)
        elif port == 28:
            api['uint64'](d['cost_policy']['external_costs'][d['name']], d['name'])
        elif port == 29:
            pass
        elif port == 30:
            d['tokens'] = d['cost_policy']['external_costs']['model_tokens']
        elif port == 31:
            return int(d['tokens'] is not None)
        elif port == 32:
            value = self._math(5, d['tokens'], d['args']['budget']['max_model_tokens'])
            return int(bool(d.pop('math_left') > d.pop('math_right'))) if value is _INTEROP else int(value)
        elif port == 33:
            return int(bool(d['cost_policy']['external_costs_complete']))
        elif port == 34:
            d['cost_iterator'] = iter(d['cost_policy']['external_costs'].values())
        elif port == 35:
            return self._next('cost_iterator', 'v')
        elif port == 36:
            return int(d['v'] is None)
        elif port == 37:
            d.pop('cost_iterator', None)
            d.pop('v', None)
            d['baseline_sha'] = None
        elif port == 38:
            return int(d['args']['baseline_program'] is not None)
        elif port == 39:
            d['baseline_sha'] = s._program(d['args']['baseline_program']).sha256
        elif port == 40:
            d['sampled'] = api['_now']()
        elif port == 41:
            d['record'] = {'schema': 'hepta.hia.agent.context.v1', 'catalog_sha256': s.catalog_sha256,
                'installation': s.identities, 'compiler_profile': d['args']['compiler_profile'],
                'target_profile': d['args']['target_profile'], 'baseline_program': d['args']['baseline_program'],
                'baseline_core_sha256': d['baseline_sha'], 'workload': d['args']['workload'],
                'objective': d['args']['objective'],
                'foreign_buffer_exports': [list(pair) for pair in d['foreign_buffer_exports']],
                'budget': d['args']['budget'], 'sampled_at': d['sampled'],
                'target_observation': {'system': api['platform'].system(), 'machine': api['platform'].machine(),
                    'cpu_count': api['os'].cpu_count(), 'observation_only': True},
                'resource_reservation_held': False, 'context_is_execution_authority': False}
        elif port == 42:
            d['manifest'] = s.store.json(d['record'], 'context')
        elif port == 43:
            d['context'] = {'id': 'ctx-' + api['uuid'].uuid4().hex, 'sha256': d['manifest']['sha256']}
        elif port == 44:
            s.store.db.execute('INSERT INTO contexts VALUES (?,?,?,?,0)',
                (d['context']['id'], d['context']['sha256'], api['wire'](d['manifest']).decode(), str(api['time'].time_ns())))
        elif port == 45:
            s.store.execution_budgets.create(d['context']['id'])
        elif port == 46:
            d['result'] = {'context': d['context'], 'manifest': d['manifest'], 'sampled_at': d['sampled'],
                'compiler_profile': d['args']['compiler_profile'], 'target_profile': d['args']['target_profile'],
                'resource_reservation_held': False, 'context_is_execution_authority': False}
        elif port == 90:
            api['reject']('E_HIA_BUFFER_BUDGET', 'frozen workload exceeds 32 MiB of external byte snapshots', 'context')
        elif port == 91:
            api['reject']('E_HIA_BUDGET', 'execution profile admits 64 MiB..4 GiB address-space budgets', 'context')
        elif port == 92:
            api['reject']('E_HIA_BUDGET', 'native wall budget exceeds total wall budget', 'context')
        elif port == 94:
            api['reject']('E_HIA_BUDGET', 'reported model tokens exceed the frozen budget', 'context')
        elif port == 95:
            d.pop('cost_iterator', None)
            d.pop('v', None)
            api['reject']('E_HIA_COST', 'complete external cost report cannot contain unknown fields', 'context')
        elif port == 101:
            api['keys'](d['ref'], ('id', 'sha256'), label='context reference')
        elif port == 102:
            d['row'] = s.store.db.execute('SELECT * FROM contexts WHERE id=?', (d['ref']['id'],)).fetchone()
        elif port == 103:
            return int(d['row'] is None)
        elif port == 104:
            return int(bool(d['row']['sha256'] != d['ref']['sha256']))
        elif port == 105:
            d['context'], d['_'] = s.store.get_json(api['decode_data'](d['row']['artifact']), kind='context')
        elif port == 106:
            return int(bool(d['context']['installation'] != s.identities))
        elif port == 107:
            return int(bool(d['context']['catalog_sha256'] != s.catalog_sha256))
        elif port == 108:
            d['name'] = ('compiler', 'target')[self.receipt.index]
        elif port == 109:
            s._profile(d['context'][d['name'] + '_profile'], d['name'])
        elif port == 110:
            d['context']['ref'] = d['ref']
        elif port == 111:
            d['result'] = d['context']
        elif port == 190:
            api['reject']('E_HIA_CONTEXT_IDENTITY', 'context is not a retained server record', 'context')
        elif port == 191:
            api['reject']('E_HIA_CONTEXT_STALE', 'context binds a different installed implementation', 'context')
        elif port == 201:
            d['row'] = s.store.db.execute('SELECT * FROM contexts WHERE id=?', (d['context']['ref']['id'],)).fetchone()
        elif port == 202:
            d['limits'] = d['context']['budget']
        elif port == 203:
            d['now'] = api['time'].time_ns()
        elif port == 204:
            d['created'] = int(d['row']['created_ns'])
        elif port == 205:
            value = self._math(2, d.pop('now'), d.pop('created'))
            d['elapsed'] = d.pop('math_left') - d.pop('math_right') if value is _INTEROP else value
        elif port == 206:
            value = self._math(3, d['limits']['max_total_wall_ms'], 1000000)
            d['wall'] = d.pop('math_left') * d.pop('math_right') if value is _INTEROP else value
        elif port == 207:
            value = self._math(5, d.pop('elapsed'), d.pop('wall'))
            return int(bool(d.pop('math_left') > d.pop('math_right'))) if value is _INTEROP else int(value)
        elif port == 208:
            return int(bool(d['candidate']))
        elif port == 209:
            s._consume_attempt(d['context'])
        elif port == 290:
            api['reject']('E_HIA_BUDGET', 'context total wall budget has expired', 'context')
        elif port == 301:
            d['row'] = s.store.db.execute('SELECT created_ns FROM contexts WHERE id=?', (d['context']['ref']['id'],)).fetchone()
        elif port == 302:
            d['created'] = int(d['row']['created_ns'])
        elif port == 303:
            value = self._math(3, d['context']['budget']['max_total_wall_ms'], 1000000)
            d['wall'] = d.pop('math_left') * d.pop('math_right') if value is _INTEROP else value
        elif port == 304:
            value = self._math(1, d.pop('created'), d.pop('wall'))
            d['deadline'] = d.pop('math_left') + d.pop('math_right') if value is _INTEROP else value
        elif port == 305:
            d['maximum'] = max
        elif port == 306:
            d['now'] = api['time'].time_ns()
        elif port == 307:
            value = self._math(2, d['deadline'], d.pop('now'))
            d['remaining'] = d.pop('math_left') - d.pop('math_right') if value is _INTEROP else value
        elif port == 308:
            value = self._math(4, d.pop('remaining'), 1000000)
            d['quotient'] = d.pop('math_left') // d.pop('math_right') if value is _INTEROP else value
        elif port == 309:
            value = self._math(8, d.pop('quotient'), 0)
            d['result'] = d.pop('maximum')(d.pop('math_right'), d.pop('math_left')) if value is _INTEROP else value
            d.pop('maximum', None)
        else:
            raise ServiceContextUnknown('context image issued an unknown fixed operation')
        return None


def unconfirmed_context_count():
    with _custody_lock():
        return sum(frame.unconfirmed for frame in _FRAME_CUSTODY.values())

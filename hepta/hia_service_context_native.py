"""Opt-in HIA context/deadline continuation owner with explicit foreign ports.

HIA chooses every branch, loop, rejection and effect order.  This module retains
real Python identities and performs only the issued fixed object/SQLite/provider
operation. Exact-integer arithmetic is HIA; foreign numeric protocols,
schema/profile validation, artifact JSON
and the existing execution-budget provider remain declared dependencies.  This
development component is not a claim that those dependencies are HIA-native.
"""
from __future__ import annotations

import ctypes
from dataclasses import dataclass
from functools import lru_cache
from hashlib import sha256
import json
import os
from pathlib import Path
import stat
import struct
import threading

from .hia_json_preflight_native import NativeHiaJsonImage, _source_resource_path
from .hia_exception_delivery import ExceptionDelivery

SOURCE = _source_resource_path('examples/hia_bootstrap/service_context.hepta')
SCHEMA = 'hepta.hia.service-context-native.v3'
SELECTOR = 'HEPTA_HIA_SERVICE_CONTEXT_MANIFEST'
REQUEST_MAGIC = int.from_bytes(b'HIACTQ01', 'little')
RESULT_MAGIC = int.from_bytes(b'HIACTR01', 'little')
MATH_MAGIC = int.from_bytes(b'HIACTM01', 'little')
MATH_RESULT_MAGIC = int.from_bytes(b'HIACTN01', 'little')
_INTEGER_INTEROP = object()
STATE_BYTES = 128
PREDICATES = frozenset((9, 11, 12, 17, 26, 27, 28, 29, 31, 34, 35, 36,
    38, 39, 42, 59, 104, 105, 109, 110, 208, 209, 212, 213))
TEMPORARIES = ('sum', 'values_iterator', 'size', 'record_fields', 'exports_list',
    'exports_iterator', 'pair', 'system', 'machine', 'cpu_count', 'context_id',
    'execute', 'insert_id', 'insert_hash', 'artifact_wire', 'created_ns', 'cursor',
    'get_json', 'artifact', 'now', 'created', 'elapsed', 'wall', 'remaining', 'quotient',
    'math_left', 'math_right')


class ContextUnknown(RuntimeError):
    """An effect or native acknowledgement is unconfirmed; never a rejection."""


class NativeContextImage(NativeHiaJsonImage):
    def __init__(self, image, expected_sha256):
        super().__init__(image, expected_sha256)
        self.delivery = ExceptionDelivery.from_hia(self)


def admitted_context(*, capture_identity=False):
    selected = os.environ.get(SELECTOR)
    if not selected:
        return None
    return installed_context(selected, capture_identity=capture_identity)


def _manifest_pairs(items):
    value = {}
    for key, item in items:
        if key in value:
            raise ValueError('duplicate service-context manifest field')
        value[key] = item
    return value


def _regular_bytes(path, limit):
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= limit:
            raise ValueError('service-context input must be a bounded ordinary file')
        raw = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
    fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
    if (len(raw) != before.st_size
            or any(getattr(before, name) != getattr(after, name) for name in fields)):
        raise ValueError('service-context input changed while being read')
    return raw


@lru_cache(maxsize=3)
def _mapped_context(image, image_sha256):
    return NativeContextImage(image, image_sha256)


def installed_context(manifest_path, *, capture_identity=False):
    """Fresh complete manifest/source/image reads before each new selection.

    The returned service owner keeps the selected immutable image. A later
    selector or disk change cannot replace that held image. A new selection
    still checks every actual byte, including when the immutable map is cached.
    An active explicit worker bundle remains the authority; no ambient fallback
    is introduced for a component not yet registered in that bundle family.
    """
    from .hia_native_helpers import pinned_image
    selected = pinned_image(manifest_path, SOURCE, SCHEMA, NativeContextImage)
    path = Path(manifest_path).resolve(strict=True)
    raw = _regular_bytes(path, 16384)
    value = json.loads(raw, object_pairs_hook=_manifest_pairs)
    if (type(value) is not dict or set(value) != {
            'schema', 'source_sha256', 'image_path', 'image_sha256', 'compiler_sha256'}
            or value['schema'] != SCHEMA
            or any(type(value[name]) is not str or len(value[name]) != 64
                   or any(char not in '0123456789abcdef' for char in value[name])
                   for name in ('source_sha256', 'image_sha256', 'compiler_sha256'))):
        raise ValueError('invalid service-context manifest')
    name = value['image_path']
    if (type(name) is not str or not name or name in ('.', '..')
            or any(ord(char) < 32 for char in name) or Path(name).name != name):
        raise ValueError('service-context image must be a sibling basename')
    source_raw = _regular_bytes(SOURCE, 8 << 20)
    if sha256(source_raw).hexdigest() != value['source_sha256']:
        raise ValueError('service-context source identity mismatch')
    image_path = path.parent / name
    image_raw = _regular_bytes(image_path, 1 << 20)
    if sha256(image_raw).hexdigest() != value['image_sha256']:
        raise ValueError('service-context image identity mismatch')
    if selected is None:
        selected = _mapped_context(image_raw, value['image_sha256'])
    elif type(selected) is not NativeContextImage or selected.image_sha256 != value['image_sha256']:
        raise ValueError('service-context selection differs from its pinned worker image')
    if (_regular_bytes(path, 16384) != raw or _regular_bytes(SOURCE, 8 << 20) != source_raw
            or _regular_bytes(image_path, 1 << 20) != image_raw):
        raise ValueError('service-context selection changed during admission')
    if capture_identity:
        from .hia_checker_identity import hold_native_owner
        return hold_native_owner(SELECTOR, selected, raw, source_raw)
    return selected


@dataclass(frozen=True)
class ContextReceipt:
    words: tuple[int, ...]
    raw: bytes

    @property
    def action(self):
        return self.words[3]

    @property
    def sequence(self):
        return self.words[4]

    @property
    def stage(self):
        return self.words[5]


class ContextState:
    """The state exists and is owned before the first HIA entry or callback.

    The HIA stage, not ``fenced`` or any Python delivery flag, consumes each
    invocation.  Losing the claim/result/receipt assignment cannot restore it.
    """
    def __init__(self, owner, mode, data):
        self.owner, self.mode, self.data = owner, mode, data
        self.creator, self.thread = os.getpid(), threading.get_ident()
        self.identity = struct.unpack('<2Q', os.urandom(16))
        self.buffer = ctypes.create_string_buffer(STATE_BYTES)
        self.receipt = None
        self.fenced = False
        self.closed = False
        self.error = None

    def check(self):
        if (self.closed or self.fenced or self.owner.closed or self.creator != os.getpid()
                or self.thread != threading.get_ident()
                or self.owner.active.get(self.identity) is not self):
            raise ContextUnknown('context continuation is not live in its original owner, process and thread')

    def call(self, event, observation=0):
        self.check()
        if (type(event) is not int or type(observation) is not int
                or not 0 <= event <= 4 or not 0 <= observation <= 1):
            raise ContextUnknown('context packet does not have exact integer fields')
        sequence = 0 if self.receipt is None else self.receipt.sequence
        raw = struct.pack('<8Q', REQUEST_MAGIC, event, sequence, *self.identity,
                          observation, self.mode, 0)
        source = ctypes.create_string_buffer(raw, len(raw))
        output = ctypes.create_string_buffer(144)
        try:
            size = self.owner.image._entry(source, len(raw), output, len(output), self.buffer, len(self.buffer))
            self.check()
            if type(size) is not int or size != 144 or source.raw != raw:
                raise ContextUnknown('context native ABI refused or changed its request')
            returned = output.raw
            if struct.unpack('<2Q', returned[:16]) != (RESULT_MAGIC, 0):
                raise ContextUnknown('context native receipt is not a successful exact result')
            owned = self.buffer.raw
            if returned[16:] != owned:
                raise ContextUnknown('context native receipt differs from its retained state')
            words = struct.unpack('<16Q', owned)
            if (words[1] != 3 or words[2] != self.mode or words[6:8] != self.identity
                    or words[9] >= (1 << len(TEMPORARIES)) or words[10] not in (0, 1)
                    or any(words[12:])):
                raise ContextUnknown('context native receipt belongs to a different operation')
            receipt = ContextReceipt(words, owned)
            self.receipt = receipt
            return receipt
        except ContextUnknown:
            self.fenced = True
            raise
        except Exception as error:
            self.fenced = True
            raise ContextUnknown('context native call or receipt handoff is unconfirmed') from error
        except BaseException:
            self.fenced = True
            raise

    def invoke(self, receipt):
        self.check()
        if (receipt is not self.receipt or type(receipt) is not ContextReceipt
                or type(receipt.words) is not tuple or len(receipt.words) != 16
                or any(type(word) is not int for word in receipt.words)
                or receipt.raw != struct.pack('<16Q', *receipt.words)
                or receipt.raw != self.buffer.raw or receipt.stage != 1):
            raise ContextUnknown('foreign operation is not the current exact HIA result')
        action, sequence = receipt.action, receipt.sequence
        claimed = self.call(1)
        if claimed.stage != 2 or claimed.action != action or claimed.sequence != sequence:
            raise ContextUnknown('context effect preclaim was not confirmed')
        captured = error = None
        try:
            captured = self._capture_effect(action)
            if not captured[0]:
                error = captured[1]
                # The catcher has returned: temporary retirement must observe
                # the original outer handled exception, not this returned one.
                if self.receipt.words[10]:
                    raise ContextUnknown('context error retirement outcome is unconfirmed') from error
                self.error = error
                if isinstance(error, ContextUnknown) or not isinstance(error, Exception):
                    self.owner.delivery.deliver(error)
                self.call(3)
                self._finish_error()
                raise ContextUnknown('context original error delivery returned unexpectedly')
            observed = captured[1]
            if action in PREDICATES:
                if type(observed) is not bool:
                    raise ContextUnknown('context foreign predicate did not return an exact bool')
                observation = int(observed)
            else:
                if observed is not None:
                    raise ContextUnknown('context foreign void operation returned a value')
                observation = 0
            return self.call(2, observation)
        finally:
            captured = error = None

    def _capture_effect(self, action):
        try:
            return True, self._effect(action)
        except BaseException as error:
            return False, error

    def _finish_error(self):
        error = self.error
        try:
            while self.receipt.stage == 1:
                if not 600 <= self.receipt.action < 600 + len(TEMPORARIES):
                    raise ContextUnknown('context error cleanup issued a business operation')
                self.invoke(self.receipt)
            if self.receipt.stage != 4 or self.receipt.words[10] != 1:
                raise ContextUnknown('context error cleanup did not finish')
            delivered = self.call(4)
            if delivered.stage != 7 or delivered.words[9]:
                raise ContextUnknown('context original error lacks consumed delivery permission')
            self.owner.delivery.deliver(error)
        finally:
            # The original exception remains rooted on the state until the
            # public run handler observes that exact delivered instance. Loss
            # between native grant and physical delivery cannot become a
            # successful terminal error merely because stage 7 was reached.
            error = None

    def _next(self, iterator, target):
        # Only StopIteration raised by this exact next operation is consumed.
        # A returned object is assigned with the original for-target lifetime.
        try:
            self.data[target] = next(self.data[iterator])
        except StopIteration:
            del self.data[iterator]
            return False
        return True

    def _math_prepare(self, action, left, right):
        # The native action preclaimed these two operand slots. This helper
        # only borrows them for exact-type observation and physical boxing;
        # it has returned before any foreign numeric protocol is invoked.
        self.data['math_left'], self.data['math_right'] = left, right
        return self.owner.numeric(action, left, right)

    def _math_value(self, value):
        # A native numeric answer is possible only for two exact Python ints.
        # Their retirement cannot run a user numeric object's destructor.
        self.data.pop('math_left')
        self.data.pop('math_right')
        return value

    def _effect(self, action):
        # Imports supply the same existing objects that the original service
        # uses.  They are explicit physical/provider ports, never policy fallback.
        from . import hia_agent_service as api
        d, s = self.data, self.owner.service
        if 600 <= action < 600 + len(TEMPORARIES):
            d.pop(TEMPORARIES[action - 600], None)
            return None
        if action == 1:
            s._profile(d['args']['compiler_profile'], 'compiler')
        elif action == 2:
            s._profile(d['args']['target_profile'], 'target')
        elif action == 3:
            d['workload'], d['_'] = s.store.get_json(d['args']['workload'])
        elif action == 4:
            d['objective'], d['_'] = s.store.get_json(d['args']['objective'])
        elif action == 5:
            d['cost_policy'], d['_'] = s.store.get_json(d['args']['budget']['cost_policy'])
        elif action == 6:
            api.validate(d['workload'], api.WORKLOAD_SCHEMA, 'workload')
        elif action == 7:
            d['foreign_buffer_exports'] = d['export_manifest'](d['workload'])
        elif action == 8:
            d['sum'] = 0
            d['cases_iterator'] = iter(d['workload']['cases'])
        elif action == 9:
            return self._next('cases_iterator', 'case')
        elif action == 10:
            d['values_iterator'] = iter(d['case']['arguments'])
        elif action == 11:
            return self._next('values_iterator', 'value')
        elif action == 12:
            return type(d['value']) is dict
        elif action == 13:
            d['size'] = d['buffer_size'](d['value'])
        elif action == 14:
            numeric = self._math_prepare(action, d.pop('sum'), d.pop('size'))
            d['sum'] = (d.pop('math_left') + d.pop('math_right') if numeric is _INTEGER_INTEROP
                        else self._math_value(numeric))
        elif action == 16:
            d.pop('case', None)
            d.pop('value', None)
            d['snapshot_bytes'] = d.pop('sum')
        elif action == 17:
            numeric = self._math_prepare(action, d['snapshot_bytes'], d['MAX_WORKLOAD_BUFFER_BYTES'])
            if numeric is not _INTEGER_INTEROP:
                return self._math_value(numeric)
            if d.pop('math_left') > d.pop('math_right'):
                return True
            return False
        elif action == 18:
            api.validate(d['objective'], api.OBJECTIVE_SCHEMA, 'objective')
        elif action == 19:
            api.validate(d['cost_policy'], api.COST_POLICY_SCHEMA, 'cost_policy')
        elif action in (20, 21, 22, 23):
            d['name'] = ('max_candidates', 'max_model_tokens', 'max_total_wall_ms', 'max_native_wall_ms')[action - 20]
            d['args']['budget'][d['name']] = int(d['args']['budget'][d['name']])
        elif action == 24:
            api.uint64(d['cost_policy']['expected_invocations'], 'expected_invocations')
        elif action == 25:
            d['memory'] = api.uint64(d['args']['budget']['max_memory_bytes'], 'max_memory_bytes')
        elif action == 26:
            numeric = self._math_prepare(action, 64 * 1024**2, d['memory'])
            if numeric is not _INTEGER_INTEROP:
                return self._math_value(numeric)
            if d.pop('math_left') <= d.pop('math_right'):
                return True
            return False
        elif action == 27:
            numeric = self._math_prepare(action, d['memory'], 4 * 1024**3)
            if numeric is not _INTEGER_INTEROP:
                return self._math_value(numeric)
            if d.pop('math_left') <= d.pop('math_right'):
                return True
            return False
        elif action == 28:
            numeric = self._math_prepare(action, d['args']['budget']['max_native_wall_ms'],
                                         d['args']['budget']['max_total_wall_ms'])
            if numeric is not _INTEGER_INTEROP:
                return self._math_value(numeric)
            if d.pop('math_left') > d.pop('math_right'):
                return True
            return False
        elif action in (29, 31):
            d['name'] = ('model_wall_ns', 'discovery_wall_ns')[(action - 29) // 2]
            return d['cost_policy']['external_costs'][d['name']] is not None
        elif action in (30, 32):
            api.uint64(d['cost_policy']['external_costs'][d['name']], d['name'])
        elif action == 33:
            d['tokens'] = d['cost_policy']['external_costs']['model_tokens']
        elif action == 34:
            return d['tokens'] is not None
        elif action == 35:
            numeric = self._math_prepare(action, d['tokens'], d['args']['budget']['max_model_tokens'])
            if numeric is not _INTEGER_INTEROP:
                return self._math_value(numeric)
            if d.pop('math_left') > d.pop('math_right'):
                return True
            return False
        elif action == 36:
            if d['cost_policy']['external_costs_complete']:
                return True
            return False
        elif action == 37:
            d['costs_iterator'] = iter(d['cost_policy']['external_costs'].values())
        elif action == 38:
            return self._next('costs_iterator', 'v')
        elif action == 39:
            return d['v'] is None
        elif action == 40:
            d.pop('v', None)
        elif action == 41:
            d['baseline_sha'] = None
        elif action == 42:
            return d['args']['baseline_program'] is not None
        elif action == 43:
            d['baseline_sha'] = s._program(d['args']['baseline_program']).sha256
        elif action == 44:
            d['sampled'] = api._now()
        elif action == 50:
            # The original BUILD_CONST_KEY_MAP follows all fifteen value
            # expressions. A temporary list preserves their stack order and
            # reverse release on a later expression's error; an incremental
            # dict would instead release them in insertion order.
            d['record_fields'] = ['hepta.hia.agent.context.v1', s.catalog_sha256]
        elif action == 51:
            d['record_fields'].append(s.identities)
        elif action in (52, 53, 54, 56, 57):
            field = {52: 'compiler_profile', 53: 'target_profile', 54: 'baseline_program',
                     56: 'workload', 57: 'objective'}[action]
            d['record_fields'].append(d['args'][field])
        elif action == 55:
            d['record_fields'].append(d['baseline_sha'])
        elif action == 58:
            d['exports_list'] = []
            d['exports_iterator'] = iter(d['foreign_buffer_exports'])
        elif action == 59:
            if self._next('exports_iterator', 'pair'):
                return True
            d.pop('pair', None)
            d['record_fields'].append(d.pop('exports_list'))
            return False
        elif action == 60:
            d['exports_list'].append(list(d['pair']))
        elif action == 61:
            d['record_fields'].append(d['args']['budget'])
        elif action == 62:
            d['record_fields'].append(d['sampled'])
        elif action == 63:
            d['system'] = api.platform.system()
        elif action == 64:
            d['machine'] = api.platform.machine()
        elif action == 65:
            d['cpu_count'] = api.os.cpu_count()
        elif action == 66:
            d['record'] = dict(zip(('schema', 'catalog_sha256', 'installation', 'compiler_profile',
                'target_profile', 'baseline_program', 'baseline_core_sha256', 'workload', 'objective',
                'foreign_buffer_exports', 'budget', 'sampled_at', 'target_observation',
                'resource_reservation_held', 'context_is_execution_authority'),
                d.pop('record_fields') + [{'system': d.pop('system'), 'machine': d.pop('machine'),
                'cpu_count': d.pop('cpu_count'), 'observation_only': True}, False, False]))
        elif action == 67:
            d['manifest'] = s.store.json(d['record'], 'context')
        elif action == 68:
            d['context_id'] = 'ctx-' + api.uuid.uuid4().hex
        elif action == 69:
            d['context'] = {'id': d.pop('context_id'), 'sha256': d['manifest']['sha256']}
        elif action == 70:
            d['execute'] = s.store.db.execute
        elif action == 71:
            d['insert_id'], d['insert_hash'] = d['context']['id'], d['context']['sha256']
        elif action == 72:
            d['artifact_wire'] = api.wire(d['manifest']).decode()
        elif action == 73:
            d['created_ns'] = str(api.time.time_ns())
        elif action == 74:
            d.pop('execute')('INSERT INTO contexts VALUES (?,?,?,?,0)',
                (d.pop('insert_id'), d.pop('insert_hash'), d.pop('artifact_wire'), d.pop('created_ns')))
        elif action == 75:
            s.store.execution_budgets.create(d['context']['id'])
        elif action == 76:
            d['result'] = {'context': d['context'], 'manifest': d['manifest'], 'sampled_at': d['sampled'],
                'compiler_profile': d['args']['compiler_profile'], 'target_profile': d['args']['target_profile'],
                'resource_reservation_held': False, 'context_is_execution_authority': False}
        elif action == 90:
            api.reject('E_HIA_BUFFER_BUDGET', 'frozen workload exceeds 32 MiB of external byte snapshots', 'context')
        elif action == 91:
            api.reject('E_HIA_BUDGET', 'execution profile admits 64 MiB..4 GiB address-space budgets', 'context')
        elif action == 92:
            api.reject('E_HIA_BUDGET', 'native wall budget exceeds total wall budget', 'context')
        elif action == 93:
            api.reject('E_HIA_BUDGET', 'reported model tokens exceed the frozen budget', 'context')
        elif action == 94:
            # any() closes its temporary generator before reject is invoked.
            d.pop('costs_iterator', None)
            d.pop('v', None)
            api.reject('E_HIA_COST', 'complete external cost report cannot contain unknown fields', 'context')
        elif action == 101:
            api.keys(d['ref'], ('id', 'sha256'), label='context reference')
        elif action == 102:
            d['cursor'] = (s.store.db if d['connection'] is None else d['connection']).execute(
                'SELECT * FROM contexts WHERE id=?', (d['ref']['id'],))
        elif action == 103:
            d['row'] = d.pop('cursor').fetchone()
        elif action == 104:
            return d['row'] is None
        elif action == 105:
            if d['row']['sha256'] != d['ref']['sha256']:
                return True
            return False
        elif action == 106:
            d['get_json'] = s.store.get_json
        elif action == 107:
            d['artifact'] = api.decode_data(d['row']['artifact'])
        elif action == 108:
            d['context'], d['_'] = d.pop('get_json')(d.pop('artifact'), kind='context',
                **api._connection_arguments(d['connection']))
        elif action == 109:
            if d['context']['installation'] != s.identities:
                return True
            return False
        elif action == 110:
            if d['context']['catalog_sha256'] != s.catalog_sha256:
                return True
            return False
        elif action in (111, 112):
            d['name'] = 'compiler' if action == 111 else 'target'
            s._profile(d['context'][d['name'] + '_profile'], d['name'],
                **api._connection_arguments(d['connection']))
        elif action == 113:
            d['context']['ref'] = d['ref']
        elif action == 190:
            api.reject('E_HIA_CONTEXT_IDENTITY', 'context is not a retained server record', 'context')
        elif action == 191:
            api.reject('E_HIA_CONTEXT_STALE', 'context binds a different installed implementation', 'context')
        elif action == 201:
            d['cursor'] = s.store.db.execute('SELECT * FROM contexts WHERE id=?', (d['context']['ref']['id'],))
        elif action == 202:
            d['row'] = d.pop('cursor').fetchone()
        elif action == 203:
            d['limits'] = d['context']['budget']
        elif action == 204:
            d['now'] = api.time.time_ns()
        elif action == 205:
            d['created'] = int(d['row']['created_ns'])
        elif action == 206:
            numeric = self._math_prepare(action, d.pop('now'), d.pop('created'))
            d['elapsed'] = (d.pop('math_left') - d.pop('math_right') if numeric is _INTEGER_INTEROP
                            else self._math_value(numeric))
        elif action == 207:
            numeric = self._math_prepare(action, d['limits']['max_total_wall_ms'], 1_000_000)
            d['wall'] = (d.pop('math_left') * d.pop('math_right') if numeric is _INTEGER_INTEROP
                         else self._math_value(numeric))
        elif action == 208:
            numeric = self._math_prepare(action, d.pop('elapsed'), d.pop('wall'))
            if numeric is not _INTEGER_INTEROP:
                return self._math_value(numeric)
            if d.pop('math_left') > d.pop('math_right'):
                return True
            return False
        elif action == 209:
            if d['candidate']:
                return True
            return False
        elif action == 213:
            return getattr(s, '_candidate_budget', None) is not None
        elif action == 214:
            # HIA selected this one operation after the original wall check.
            # The candidate owner owns its own SQL/commit/ACK protocol; do not
            # also execute the context owner's old UPDATE path.
            s._candidate_budget.consume(d['context']['ref']['id'],
                                        d['context']['budget']['max_candidates'])
        elif action == 210:
            d['cursor'] = s.store.db.execute('UPDATE contexts SET attempts=attempts+1 WHERE id=? AND attempts<?',
                (d['context']['ref']['id'], d['limits']['max_candidates']))
        elif action == 211:
            d['changed'] = d.pop('cursor').rowcount
        elif action == 212:
            numeric = self._math_prepare(action, d['changed'], 1)
            if numeric is not _INTEGER_INTEROP:
                return self._math_value(numeric)
            if d.pop('math_left') != d.pop('math_right'):
                return True
            return False
        elif action == 290:
            api.reject('E_HIA_BUDGET', 'context total wall budget has expired', 'context')
        elif action == 291:
            api.reject('E_HIA_BUDGET', 'candidate attempt budget exhausted', 'context')
        elif action == 301:
            d['cursor'] = s.store.db.execute('SELECT created_ns FROM contexts WHERE id=?', (d['context']['ref']['id'],))
        elif action in (302, 402):
            d['row'] = d.pop('cursor').fetchone()
        elif action in (303, 403):
            d['created'] = int(d['row']['created_ns'])
        elif action in (304, 404):
            numeric = self._math_prepare(action, d['context']['budget']['max_total_wall_ms'], 1_000_000)
            d['wall'] = (d.pop('math_left') * d.pop('math_right') if numeric is _INTEGER_INTEROP
                         else self._math_value(numeric))
        elif action in (305, 405):
            numeric = self._math_prepare(action, d.pop('created'), d.pop('wall'))
            d['deadline'] = (d.pop('math_left') + d.pop('math_right') if numeric is _INTEGER_INTEROP
                             else self._math_value(numeric))
        elif action in (306, 501):
            d['now'] = api.time.time_ns()
        elif action in (307, 502):
            numeric = self._math_prepare(action, d['deadline'], d.pop('now'))
            d['remaining'] = (d.pop('math_left') - d.pop('math_right') if numeric is _INTEGER_INTEROP
                              else self._math_value(numeric))
        elif action in (308, 503):
            numeric = self._math_prepare(action, d.pop('remaining'), 1_000_000)
            d['quotient'] = (d.pop('math_left') // d.pop('math_right') if numeric is _INTEGER_INTEROP
                             else self._math_value(numeric))
        elif action in (309, 504):
            numeric = self._math_prepare(action, d.pop('quotient'), 0)
            d['result'] = (max(d.pop('math_right'), d.pop('math_left')) if numeric is _INTEGER_INTEROP
                           else self._math_value(numeric))
        elif action == 401:
            d['cursor'] = s.store.db.execute('SELECT created_ns FROM contexts WHERE id=?', (d['args']['context']['id'],))
        else:
            raise ContextUnknown('HIA requested an unknown context foreign primitive')
        return None


class NativeContextService:
    """One pinned image; independent states permit original concurrent calls.

    Unknown operations retain their real buffers and object custody. They have
    no retry/forget API. A new explicit invocation is not an implicit replay;
    durable request-key authority continues to belong to the request journal.
    """
    def __init__(self, service, image, *, checker_custody=None):
        self.service, self.image = service, image
        if checker_custody is not None and checker_custody.image is not image:
            raise ValueError('context checker custody belongs to a different held image')
        self._checker_custody = checker_custody
        self.delivery = getattr(image, 'delivery', None)
        if self.delivery is None:
            self.delivery = ExceptionDelivery.from_hia(image)
        self.creator = os.getpid()
        self.active = {}
        self.unknown = {}
        self.last = None
        self.closed = False

    def checker_owner(self):
        """The exact image this service executes, independent of later paths."""
        if self._checker_custody is None or self._checker_custody.image is not self.image:
            raise ValueError('context service lacks its admitted checker image custody')
        return self._checker_custody

    def numeric(self, action, left, right):
        """Box/unbox a HIA-chosen numeric operation, with explicit interop.

        CPython int byte conversion is a representation port. No arithmetic
        answer, comparison, sign decision or quotient is computed in Python.
        The packet and output extents derive from the actual operand bytes.
        """
        if type(action) is not int:
            raise ContextUnknown('context numeric action must be an exact integer')
        left_tag, right_tag = int(type(left) is int), int(type(right) is int)
        a = int.to_bytes(left, (int.bit_length(left) + 8) // 8, 'little', signed=True) if left_tag else b''
        b = int.to_bytes(right, (int.bit_length(right) + 8) // 8, 'little', signed=True) if right_tag else b''
        raw = struct.pack('<8Q', MATH_MAGIC, action, left_tag, right_tag, len(a), len(b), 0, 0) + a + b
        limbs = (len(a) + len(b)) // 4 + 4
        capacity, extent = 33 + limbs * 4, 4 * (24 + limbs * 8)
        source = ctypes.create_string_buffer(raw + b'\xc9' * 16, len(raw) + 16)
        output = ctypes.create_string_buffer(b'\xa5' * (capacity + 16), capacity + 16)
        workspace = ctypes.create_string_buffer(b'\xb7' * extent + b'\xda' * 16, extent + 16)
        count = self.image._entry(source, len(raw), output, capacity, workspace, extent)
        if (type(count) is not int or count != 32 or source.raw != raw + b'\xc9' * 16
                or output.raw[capacity:] != b'\xa5' * 16 or workspace.raw[extent:] != b'\xda' * 16):
            raise ContextUnknown('context native arithmetic has no exact guarded outcome')
        magic, kind, size, echoed = struct.unpack('<4Q', output.raw[:32])
        if (magic != MATH_RESULT_MAGIC or echoed != action or size > capacity - 32
                or output.raw[32 + size:capacity] != b'\xa5' * (capacity - 32 - size)):
            raise ContextUnknown('context arithmetic receipt differs from its issued action or extent')
        if kind == 1 and size == 0:
            return _INTEGER_INTEROP
        if kind == 2 and size == 1 and output.raw[32] in (0, 1):
            return bool(output.raw[32])
        if kind == 0 and size > 0:
            return int.from_bytes(output.raw[32:32 + size], 'little', signed=True)
        raise ContextUnknown('context arithmetic returned an unknown representation')

    def run(self, mode, **data):
        if self.closed or self.creator != os.getpid():
            raise ContextUnknown('context owner is closed or belongs to a different process')
        state = ContextState(self, mode, data)
        self.active[state.identity] = state
        try:
            state.call(0)
            while state.receipt.stage == 1:
                state.invoke(state.receipt)
            if state.receipt.stage != 3:
                raise ContextUnknown('context operation did not reach its native completion')
            delivered = state.call(4)
            if delivered.stage != 5:
                raise ContextUnknown('context return permission was not consumed')
            # Returning the already-built object needs no new policy effect.
            # Clearing completed local custody can still run original object
            # destructors; it is not claimed to be callback-free.
            if mode == 2:
                result = data.pop('context')
            elif mode == 3:
                result = None
            elif mode == 5:
                result = (data.pop('row'), data.pop('deadline'))
            else:
                result = data.pop('result')
            self.last = delivered
            self.active.pop(state.identity)
            state.closed = True
            data.clear()
            return result
        except BaseException as error:
            if (state.receipt is not None and state.receipt.stage == 7 and not state.fenced
                    and error is state.error):
                # Retain original locals only through the actually returned
                # exception's traceback, as the original Python frame does.
                self.last = state.receipt
                self.active.pop(state.identity, None)
                state.closed = True
                state.error = None
            else:
                self.unknown[state.identity] = state
                state.fenced = True
            raise

    def freeze(self, args):
        from .hia_agent_buffers import export_manifest, buffer_size, MAX_WORKLOAD_BUFFER_BYTES
        return self.run(1, args=args, export_manifest=export_manifest, buffer_size=buffer_size,
                        MAX_WORKLOAD_BUFFER_BYTES=MAX_WORKLOAD_BUFFER_BYTES)

    def context(self, ref, *, connection=None):
        return self.run(2, ref=ref, connection=connection)

    def budget(self, context, *, candidate=False):
        return self.run(3, context=context, candidate=candidate)

    def remaining_ms(self, context):
        return self.run(4, context=context)

    def capture_deadline(self, args, context):
        return self.run(5, args=args, context=context)

    def remaining_captured(self, deadline):
        return self.run(6, deadline=deadline)

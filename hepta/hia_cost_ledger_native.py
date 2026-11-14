"""HIA cost-ledger control with explicit read-only foreign object ports.

SQLite query/fetch, JSON decoding, row access, int/str conversion and object
allocation retain their CPython semantics. HIA owns every ledger loop/branch,
row attribution comparison, truncation, signed unbounded sum and termination.
No port writes persistent state; an unconfirmed native continuation is fenced
and is never replayed or replaced by the retained Python method.
"""
from __future__ import annotations
import ctypes
from functools import lru_cache
from hashlib import sha256
import json
import os
from pathlib import Path
import stat
import struct
import threading
from .hia_json_preflight_native import NativeHiaJsonImage, _source_resource_path, _unique_manifest_pairs

SOURCE = _source_resource_path('examples/hia_bootstrap/cost_ledger.hepta')
SCHEMA = 'hepta.hia.cost-ledger-native.v1'
SELECTOR = 'HEPTA_HIA_COST_LEDGER_MANIFEST'
REQUEST_MAGIC = int.from_bytes(b'HIACLRQ1', 'little')
RESULT_MAGIC = int.from_bytes(b'HIACLRS1', 'little')
STATE_BYTES = 128
OUTPUT_BYTES = 80
QUERY = 'SELECT * FROM costs WHERE context_id=? OR context_id IS NULL ORDER BY sequence LIMIT 10001'


class CostLedgerUnknown(RuntimeError):
    """The current read-only frame has an unconfirmed native observation."""


def integer_bytes(value):
    # Object representation only. int() is called separately at precisely the
    # original selected-row point; no arithmetic is performed on its value.
    return value.to_bytes(max(1, (value.bit_length() + 8) // 8), 'little', signed=True)


def identity_bytes(value):
    # SQLite's TEXT-affinity context column returns None, str or BLOB bytes.
    # Numeric query arguments are represented separately and cannot equal a
    # returned TEXT string merely because SQLite coerced the WHERE argument.
    if value is None:
        return b'\0'
    if type(value) is str:
        return b'\1' + value.encode('utf-8', 'surrogatepass')
    if type(value) is bytes:
        return b'\2' + value
    if type(value) in (bool, int):
        return b'\3' + integer_bytes(int(value))
    if type(value) is float:
        return b'\4' + struct.pack('<d', value)
    raise TypeError('cost-ledger context identity is not a SQLite scalar')


def binary_packet(mode, left, right):
    return struct.pack('<4Q', REQUEST_MAGIC, mode, len(left), len(right)) + left + right


class NativeCostLedger(NativeHiaJsonImage):
    def binary(self, mode, left, right):
        raw = binary_packet(mode, left, right)
        capacity = max(len(left), len(right)) + 17 if mode == 10 else 16
        source = ctypes.create_string_buffer(raw, len(raw))
        initial = b'\xa5' * capacity
        output = ctypes.create_string_buffer(initial, capacity)
        unused = ctypes.create_string_buffer(1)
        code = self._entry(source, len(raw), output, capacity, unused, 0)
        if code != 16 or source.raw != raw or unused.raw != b'\0':
            raise CostLedgerUnknown('cost-ledger binary return or immutable input differs')
        magic, value = struct.unpack_from('<2Q', output.raw)
        if magic != RESULT_MAGIC:
            raise CostLedgerUnknown('cost-ledger binary output identity differs')
        if mode == 10:
            if not 1 <= value <= capacity - 16:
                raise CostLedgerUnknown('cost-ledger sum extent differs')
            return output.raw[16:16+value]
        if value not in (0, 1):
            raise CostLedgerUnknown('cost-ledger equality result differs')
        return value

    def add(self, left, right):
        return self.binary(10, left, right)

    def equal(self, left, right):
        return self.binary(11, identity_bytes(left), identity_bytes(right))


def _regular_bytes(path, limit):
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb', buffering=8192) as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= limit:
            raise ValueError('cost-ledger input must be a bounded ordinary file')
        raw = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
    fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
    if len(raw) != before.st_size or any(getattr(before, key) != getattr(after, key) for key in fields):
        raise ValueError('cost-ledger input changed while being read')
    return raw


@lru_cache(maxsize=3)
def _mapped_ledger(raw, digest, source_digest):
    image = NativeCostLedger(raw, digest)
    image.admitted_source_sha256 = source_digest
    return image


def installed_cost_ledger(manifest_path):
    if not manifest_path:
        raise ValueError('cost-ledger selector must not be empty')
    from .hia_native_helpers import pinned_image
    selected = pinned_image(manifest_path, SOURCE, SCHEMA, NativeCostLedger)
    path = Path(manifest_path).resolve(strict=True)
    raw = _regular_bytes(path, 16384)
    value = json.loads(raw, object_pairs_hook=_unique_manifest_pairs)
    if (type(value) is not dict or set(value) != {
            'schema', 'source_sha256', 'image_path', 'image_sha256', 'compiler_sha256'}
            or value['schema'] != SCHEMA
            or any(type(value[key]) is not str or len(value[key]) != 64
                   or any(char not in '0123456789abcdef' for char in value[key])
                   for key in ('source_sha256', 'image_sha256', 'compiler_sha256'))):
        raise ValueError('invalid cost-ledger manifest')
    name = value['image_path']
    if (type(name) is not str or not name or name in ('.', '..')
            or Path(name).name != name or any(ord(char) < 32 for char in name)):
        raise ValueError('cost-ledger image must be a sibling basename')
    source = _regular_bytes(SOURCE, 8 << 20)
    image_path = path.parent / name
    image = _regular_bytes(image_path, 1 << 20)
    if sha256(source).hexdigest() != value['source_sha256']:
        raise ValueError('cost-ledger source identity mismatch')
    if sha256(image).hexdigest() != value['image_sha256']:
        raise ValueError('cost-ledger image identity mismatch')
    if selected is None:
        selected = _mapped_ledger(image, value['image_sha256'], value['source_sha256'])
    elif type(selected) is not NativeCostLedger or selected.image_sha256 != value['image_sha256']:
        raise ValueError('cost-ledger selection differs from pinned worker image')
    if (_regular_bytes(path, 16384) != raw or _regular_bytes(SOURCE, 8 << 20) != source
            or _regular_bytes(image_path, 1 << 20) != image):
        raise ValueError('cost-ledger selection changed during admission')
    return selected


class CostLedgerFrame:
    def __init__(self, image, service, context, evaluation_wall_ns, native_wall_ns):
        if type(image) is not NativeCostLedger:
            raise TypeError('cost ledger requires an admitted native image')
        self.image, self.service, self.context = image, service, context
        self.evaluation_wall_ns, self.native_wall_ns = evaluation_wall_ns, native_wall_ns
        self.identity = struct.unpack('<2Q', os.urandom(16))
        self.creator, self.thread = os.getpid(), threading.get_ident()
        self.buffer = ctypes.create_string_buffer(STATE_BYTES)
        self.receipt, self.fenced, self.finished = None, False, False
        self.call(0)

    def call(self, event, observation=0):
        if self.fenced or self.finished or os.getpid() != self.creator or threading.get_ident() != self.thread:
            raise CostLedgerUnknown('cost-ledger frame cannot be resumed or inherited')
        try:
            port, sequence = (0, 0) if self.receipt is None else self.receipt[:2]
            values = (REQUEST_MAGIC, event, sequence, port, observation, 0, *self.identity, 0, 0)
            raw = struct.pack('<10Q', *values)
            source = ctypes.create_string_buffer(raw, len(raw))
            output = ctypes.create_string_buffer(OUTPUT_BYTES)
            code = self.image._entry(source, len(raw), output, OUTPUT_BYTES, self.buffer, STATE_BYTES)
            if code != OUTPUT_BYTES or source.raw != raw:
                raise CostLedgerUnknown('cost-ledger continuation return is unconfirmed')
            words, state = struct.unpack('<10Q', output.raw), struct.unpack('<16Q', self.buffer.raw)
            if (words[0] != RESULT_MAGIC or words[1] != 0
                    or words[2:8] != (state[3], state[4], state[5], state[8], state[9], state[13])
                    or words[8:10] != self.identity or state[6:8] != self.identity
                    or words[4] not in (1, 2, 4, 5) or words[6] > 1 or words[7] > 1):
                raise CostLedgerUnknown('cost-ledger receipt differs from issued state')
            self.receipt = words[2:8]
            self.retained_rows = state[12]
            return self.receipt
        except BaseException:
            self.fenced = True
            raise

    def finish(self):
        while not self.finished:
            if self.receipt[2] != 1:
                self.fenced = True
                raise CostLedgerUnknown('cost-ledger effect is not newly issued')
            self.call(1)
            try:
                observed = self.effect(self.receipt[0])
            except BaseException:
                self.call(3)
                if self.receipt[2] != 5:
                    raise CostLedgerUnknown('cost-ledger exception was not propagated')
                self.finished = True
                raise
            self.call(2, observed)
            if self.receipt[2] == 4:
                self.finished = True
                return self.result
        raise CostLedgerUnknown('cost-ledger frame already completed')

    def effect(self, port):
        """One fixed foreign operation; HIA supplies loop index and sum bank."""
        index, bank = self.receipt[3:5]
        if port == 1:
            self.rows = self.service.store.db.execute(QUERY, (self.context['ref']['id'],)).fetchall()
            return len(self.rows)
        elif port == 2:
            self.rows = self.rows[:self.retained_rows]
            self.entries = []
        elif port == 3:
            from .hia_agent_service import decode_data
            row = self.rows[index]
            self.entries.append({'sequence': row['sequence'], 'tool': row['tool'], 'request_id': row['request_id'],
                'context_id': row['context_id'], 'wall_ns': row['wall_ns'], 'status': row['status'],
                'details': decode_data(row['details'])})
        elif port == 4:
            self.policy, self.policy_metadata = self.service.store.get_json(self.context['budget']['cost_policy'])
        elif port == 5:
            self.external = dict(self.policy['external_costs'])
        elif port == 6:
            return int(bool(self.policy['external_costs_complete']))
        elif port == 7:
            self.unknown = {}
            self.keys = iter(self.external)
            return len(self.external)
        elif port == 8:
            self.unknown[next(self.keys)] = None
        elif port == 9:
            self.external = self.unknown
        elif port == 10:
            self.totals = [b'\0', b'\0']
        elif port == 11:
            return self.image.equal(self.rows[index]['context_id'], self.context['ref']['id'])
        elif port == 12:
            self.number = int(self.rows[index]['wall_ns'])
        elif port == 13:
            self.totals[bank] = self.image.add(self.totals[bank], integer_bytes(self.number))
        elif port == 14:
            return self.image.equal(self.rows[index]['context_id'], None)
        elif port == 15:
            self.result = {'schema': 'hepta.hia.agent.cost-ledger.v1', 'context': self.context['ref'],
                'entries': self.entries, 'entries_truncated': bool(self.receipt[5]),
                'context_tool_wall_ns_before_evaluation': str(int.from_bytes(self.totals[0], 'little', signed=True)),
                'unattributed_discovery_artifact_read_wall_ns': str(int.from_bytes(self.totals[1], 'little', signed=True)),
                'evaluation_wall_ns_through_report': str(self.evaluation_wall_ns),
                'native_child_wall_ns': str(self.native_wall_ns),
                'external_costs': self.external, 'external_cost_source': 'caller-supplied report, independently unmeasured',
                'external_costs_complete': self.policy['external_costs_complete'],
                'adoption_wall_ns': None, 'future_execution_count': self.policy['expected_invocations'],
                'failed_attempts_retained': True, 'full_search_cost_complete': False,
                'net_optimization_benefit_proved': False,
                'scope': 'observed request prefix; unscoped calls cannot be uniquely attributed and adoption/future/model cost may be unknown'}
        else:
            raise CostLedgerUnknown('cost-ledger issued an unknown foreign port')
        return 0

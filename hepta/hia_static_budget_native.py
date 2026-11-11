"""Fixed foreign-object bridge for the HIA structural resource controller.

Graph traversal, profile membership, numeric comparisons, limits, error choice
and every receipt field are in the selected HIA image. The bridge executes
only its issued, once-only physical/object continuations. Complete Python
objects are opaque identities; their semantic contents are never preplanned.
"""
from __future__ import annotations

import ctypes
from dataclasses import dataclass
from hashlib import sha256
import json
import mmap
import os
import struct
import sys

from .hia_instruction_policy_native import transport
from .hia_json_preflight_native import NativeHiaJsonImage, _installed_json_image, _source_resource_path
from .hia_native_value_graph import NativeObjectPool, decode_bound_native_graph

SOURCE = _source_resource_path('examples/hia_bootstrap/static_budget.hiaasm')
SCHEMA = 'hepta.hia.static-budget-native.v1'
SELECTOR = 'HEPTA_HIA_STATIC_BUDGET_MANIFEST'
MAGIC = int.from_bytes(b'HIABUD01', 'little')
ABI = 0xfffffff1
BASE = 8192
MASK = (1 << 64) - 1
QUERIES = frozenset((7, 11, 12, 13, 15))
REQUESTS = frozenset((*range(1, 18), 100, 101))
EMPTY = transport(None)
POLICY_KEYS = ('max_allocator_interactions', 'max_vm_ticks', 'max_call_depth',
               'max_live_heap_bytes')


def rejected(detail):
    from .hia_static_budget import HIAStaticBudgetRejected
    raise HIAStaticBudgetRejected('E_HIA_BUDGET_NATIVE', 'native structural transport: ' + detail)


def _pointer(value):
    return ctypes.addressof(ctypes.c_char.from_buffer(value)) if len(value) else 0


def _metadata(value):
    typ = type(value)
    if value is None:
        return [0, 0, 0, 0]
    if typ is bool:
        return [1, 0, 0, int(value)]
    if typ is int:
        return [2, int(value < 0), value.bit_length(), value & MASK]
    if typ is str:
        return [4, 0, 0, 0]
    if typ is list:
        return [5, 0, 0, 0]
    if typ is dict:
        return [6, 0, 0, 0]
    return [7, 0, 0, 0]


def _binary_integer(value):
    if type(value) is not int:
        rejected('binary object is not an exact integer')
    negative = value < 0
    magnitude = -value if negative else value
    raw = magnitude.to_bytes((magnitude.bit_length() + 7) // 8, 'little')
    return struct.pack('<2Q', 12, 1 + len(raw)) + bytes((int(negative),)) + raw


@dataclass(frozen=True)
class BudgetFrame:
    sequence: int
    request: int
    words: tuple[int, int, int, int]
    status: int
    value: object


class BudgetContext:
    """Per-invocation opaque custody and non-replayable foreign permissions."""
    def __init__(self, mode, program=None, limits=(None, None, None, None), *,
                 policy=None, document=None, schema=None, allow_chain=False):
        self.closed = False
        self.workspace = self.output = None
        self._created_arena = self._previous_arena = None
        self._created_output = self._previous_output = None
        self.pool = NativeObjectPool()
        self.input = self.source_wire = None
        self.pending = self.terminal = self.binding = None
        self.fields = None
        self.sequence = self.executed = self.completed = 0
        self.accepted = False
        self.cleanup_error = None
        try:
            none_id = self.pool.add(None)
            program_id = self.pool.add(program)
            limit_ids = [self.pool.add(value) for value in limits]
            policy_id = self.pool.add(policy)
            expected = {'max_allocator_interactions', 'max_vm_ticks', 'max_call_depth',
                        'max_live_heap_bytes'}
            expected_id = self.pool.add(expected)
            literal_ids = [self.pool.add(key) for key in POLICY_KEYS]
            raw = transport([mode, program_id, limit_ids, policy_id, expected_id,
                             none_id, schema, int(allow_chain), document, literal_ids])
            self.workspace = mmap.mmap(-1, max(1 << 20, (BASE + len(raw) + 4095) & ~4095))
            self.output = mmap.mmap(-1, 1 << 16)
            self.input = bytearray(raw)
            self.source_wire = raw
        except BaseException:
            self._close_preserving_error()
            raise

    def close(self, *, release_objects=True):
        self.closed = True
        self.pending = self.terminal = self.binding = self.fields = None
        self.input = self.source_wire = None
        first = None
        for name in ('_created_arena', '_previous_arena', 'workspace',
                     '_created_output', '_previous_output', 'output'):
            arena = getattr(self, name)
            if arena is not None:
                try:
                    arena.close()
                    setattr(self, name, None)
                except BaseException as exc:
                    if first is None:
                        first = exc
        if release_objects:
            try:
                self.pool.clear()
            except BaseException as exc:
                if first is None:
                    first = exc
        self.cleanup_error = first
        if first is not None:
            raise first

    def _close_preserving_error(self):
        try:
            # Original Python locals remain alive in a retained exception
            # traceback. Keep still-live foreign identities with this context;
            # only explicitly completed temporaries were already released.
            # Owned arenas and all execution permissions close immediately.
            self.close(release_objects=False)
        except BaseException:
            pass

    def _grow(self, needed, *, output=False):
        name = 'output' if output else 'workspace'
        created = '_created_output' if output else '_created_arena'
        previous = '_previous_output' if output else '_previous_arena'
        current = getattr(self, name)
        if type(needed) is not int or needed <= len(current):
            rejected('growth request does not increase an arena')
        size = (max(needed, len(current) * 2) + 4095) & ~4095
        setattr(self, created, mmap.mmap(-1, size))
        ctypes.memmove(_pointer(getattr(self, created)), _pointer(current), len(current))
        setattr(self, previous, current)
        setattr(self, name, getattr(self, created))
        setattr(self, created, None)
        getattr(self, previous).close()
        setattr(self, previous, None)

    @staticmethod
    def _fields(frame):
        if (type(frame) is not BudgetFrame or type(frame.sequence) is not int
                or type(frame.request) is not int or type(frame.status) is not int
                or type(frame.words) is not tuple or len(frame.words) != 4
                or any(type(value) is not int for value in frame.words)):
            rejected('issued frame has a changed exact representation')
        return (frame.sequence, frame.request, frame.words, frame.status)

    def _check(self, frame, *, terminal):
        if (self.closed or frame is not (self.terminal if terminal else self.pending)
                or self._fields(frame) != self.fields):
            rejected('frame is not the current exact issued result')
        if self.binding is not None:
            try:
                self.binding.validate(frame.value)
            except (ValueError, TypeError) as exc:
                rejected('issued graph changed: ' + str(exc))
        elif frame.value is not None:
            rejected('empty continuation payload changed')

    def service(self, frame):
        try:
            self._check(frame, terminal=False)
            if frame.sequence != self.sequence or self.executed == self.sequence:
                rejected('foreign permission has already been consumed')
            self.executed = self.sequence
            self.pending = None
            raw = self._invoke(frame)
            if raw is not None:
                used = struct.unpack_from('<Q', self.workspace, 64)[0]
                needed = (used + len(raw) + 7) & ~7
                if needed > len(self.workspace):
                    self._grow(needed)
                self.input = bytearray(raw)
                self.source_wire = raw
            struct.pack_into('<Q', self.workspace, 88, frame.sequence)
            self.completed = frame.sequence
            self.binding = self.fields = None
        except BaseException:
            self._close_preserving_error()
            raise

    def _invoke(self, frame):
        request = frame.request
        a, b, _c, _d = frame.words
        pool = self.pool
        value = frame.value
        if request == 100:
            self._grow(a)
            return None
        if request == 101:
            self._grow(a, output=True)
            return None
        if request == 1:
            result = _metadata(pool.get(a))
        elif request == 2:
            from .hia_program import verify_program
            checked = verify_program(pool.get(a))
            result = [pool.add(checked), checked.as_dict(), checked.structured_bytes is not None if b else False]
        elif request == 3:
            result = pool.add(pool.get(a).copy())
        elif request == 4:
            result = pool.add(set(pool.get(a)))
        elif request == 5:
            result = pool.get(a) != pool.get(b)
        elif request == 6:
            result = pool.add(iter(pool.get(a).values()))
        elif request == 7:
            result = pool.add(pool.get(a)[value])
        elif request == 8:
            return _binary_integer(pool.get(a))
        elif request == 9:
            checked = pool.get(a)
            result = [checked.sha256, checked.input_sha256 if b else None]
        elif request == 10:
            from .hia_heap_bound import analyze_constant_live_heap
            result = pool.add(analyze_constant_live_heap(pool.get(a)))
        elif request == 11:
            from .hia_heap_bound import qualify_entry_live_heap_budget
            result = pool.add(qualify_entry_live_heap_budget(pool.get(a), value,
                                                           max_live_heap_bytes=pool.get(b)))
        elif request == 12:
            ident = pool.add(value)
            raw = json.dumps(value, sort_keys=True, separators=(',', ':'),
                             ensure_ascii=False, allow_nan=False).encode('utf-8')
            result = [ident, sha256(raw).hexdigest()]
        elif request == 13:
            pool.get(a)[value[0]] = value[1]
            result = None
        elif request == 14:
            try:
                item = next(pool.get(a))
            except StopIteration:
                result = [True, 0]
            else:
                result = [False, pool.add(item)]
        elif request == 15:
            result = pool.add(value)
        elif request == 16:
            result = pool.add(iter(pool.get(a)))
        elif request == 17:
            pool.release(a)
            result = None
        else:
            rejected('unrecognized foreign request')
        return transport(result)

    def accept(self, frame):
        try:
            self._check(frame, terminal=True)
            if self.accepted or frame.request:
                rejected('terminal permission has already been consumed')
            self.accepted = True
            if frame.status == 2:
                if (type(frame.value) is not list or len(frame.value) != 2
                        or any(type(value) is not str for value in frame.value)):
                    rejected('semantic refusal has an invalid representation')
                from .hia_static_budget import HIAStaticBudgetRejected
                raise HIAStaticBudgetRejected(*frame.value)
            return frame.value
        except BaseException:
            self._close_preserving_error()
            raise


class NativeStaticBudget(NativeHiaJsonImage):
    def step(self, context):
        try:
            if (context.closed or context.pending is not None or context.terminal is not None
                    or context.completed != context.sequence):
                rejected('closed or incomplete context cannot enter the image')
            returned = self._entry(_pointer(context.input), len(context.input),
                _pointer(context.output), len(context.output),
                _pointer(context.workspace), len(context.workspace))
            if bytes(context.input) != context.source_wire:
                rejected('immutable foreign reply/source bytes changed')
            if returned == ABI:
                rejected('HIA ABI refused its private representation')
            words = struct.unpack_from('<16Q', context.workspace)
            magic, _phase, sequence, request, a, b, c, d = words[:8]
            status, length = words[12:14]
            if (magic != MAGIC or sequence != context.sequence + 1 or returned != request
                    or request not in REQUESTS | {0} or status not in (0, 1, 2)
                    or bool(request) == bool(status) or length > len(context.output)
                    or request and request not in QUERIES and length):
                rejected('native result header differs')
            if request and (c or d or (request in (2, 9) and b not in (0, 1))
                    or (request not in (2, 5, 9, 11) and b)):
                rejected('foreign request words are not canonical')
            value = binding = None
            if length:
                value, binding = decode_bound_native_graph(bytes(context.output[:length]), EMPTY,
                    binary_integers=True, objects=context.pool, extent_bounds=True)
            elif status or request in QUERIES:
                rejected('native result omitted its complete graph')
            frame = BudgetFrame(sequence, request, (a, b, c, d), status, value)
            context.sequence = sequence
            context.fields = context._fields(frame)
            context.binding = binding
            if request:
                context.pending = frame
            else:
                context.terminal = frame
            return frame
        except BaseException:
            context._close_preserving_error()
            raise

    def _run(self, *args, **kwargs):
        context = BudgetContext(*args, **kwargs)
        try:
            while True:
                frame = self.step(context)
                if frame.request:
                    context.service(frame)
                else:
                    return context.accept(frame)
        finally:
            if sys.exc_info()[0] is None:
                context.close()
            else:
                context._close_preserving_error()

    def qualify_vm_call_depth(self, program, *, max_call_depth):
        return self._run(1, program, (None, None, max_call_depth, None))

    def analyze_static_budget(self, program, *, max_allocator_interactions=None,
                              max_vm_ticks=None, max_call_depth=None, max_live_heap_bytes=None):
        return self._run(2, program, (max_allocator_interactions, max_vm_ticks,
                                     max_call_depth, max_live_heap_bytes))

    def qualify_bounded_resources(self, program, *, limits):
        return self._run(3, program, policy=limits)

    def audit_resource_profile(self, document, *, schema, allow_chain):
        return self._run(4, document=document, schema=schema, allow_chain=allow_chain)


def installed_static_budget(path):
    return _installed_json_image(path, SOURCE, SCHEMA, NativeStaticBudget)


def selected_static_budget():
    path = os.environ.get(SELECTOR)
    if not path:
        return None
    try:
        return installed_static_budget(path)
    except (ValueError, OSError, UnicodeError, RuntimeError) as exc:
        from .hia_static_budget import HIAStaticBudgetRejected
        raise HIAStaticBudgetRejected('E_HIA_BUDGET_NATIVE',
                                     'selected native structural image refused: ' + str(exc)) from exc

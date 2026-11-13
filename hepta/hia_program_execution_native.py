"""Pinned HIA interpreter with representation-only storage continuations.

The HIA image interprets admitted Core as data. Python preserves byte storage,
performs its requested zeroed allocation/free/window operations, and materializes
the image's complete result. It never resolves an opcode, a block, a call,
a loan origin, an allocation policy, or a VM stop condition.
"""
from __future__ import annotations

import ctypes
from dataclasses import dataclass
import mmap
import os
import struct
import sys

from .hia_instruction_policy_native import transport
from .hia_json_preflight_native import NativeHiaJsonImage, _installed_json_image, _source_resource_path

SOURCE = _source_resource_path('examples/hia_bootstrap/program_execution.hepta')
SCHEMA = 'hepta.hia.program-execution-native.v1'
SELECTOR = 'HEPTA_HIA_PROGRAM_EXECUTION_MANIFEST'
MAGIC = int.from_bytes(b'HIAVM001', 'little')
ABI = 0xfffffff1
BASE = 8192
MASK = (1 << 64) - 1
TYPES = ('', 'i8', 'i16', 'i32', 'i64', 'u8', 'u16', 'u32', 'u64',
         'isize', 'usize', 'bool', 'unit', 'buffer', 'readbuf', 'mutbuf', 'chain')
WIDTHS = (0, 8, 16, 32, 64, 8, 16, 32, 64, 64, 64)
RESOURCE_FIELDS = ('allocations', 'frees', 'allocation_attempts', 'owners_created',
                   'owners_dropped', 'live_owners', 'live_bytes', 'peak_bytes',
                   'loans_started', 'loans_ended')
CHAIN_FIELDS = ('chains_created', 'chains_consumed', 'live_chains',
                'chain_nodes_created', 'chain_nodes_dropped')
ERRORS = {
    2: ('division_by_zero', 'integer divisor is zero'),
    3: ('overflow', 'signed minimum divided by minus one'),
    4: ('overflow', 'shift count is outside the word width'),
    5: ('allocation', 'allocation exceeds the 64-bit object-size model'),
    6: ('allocation', 'allocator returned failure'),
    7: ('bounds', 'head borrow of an empty chain'),
    8: ('bounds', 'byte load outside the borrowed buffer'),
    9: ('bounds', 'byte store outside the borrowed buffer'),
    10: ('bounds', 'bulk copy exceeds an owner extent'),
    11: ('bounds', 'in-place byte range exceeds owned extent'),
    12: ('bounds', 'cross-owner range copy exceeds byte extent'),
    13: ('bounds', 'fill range exceeds owned extent'),
    14: ('bounds', 'swap byte offset outside owner extent'),
    15: ('user', 'explicit core trap'),
    16: ('overflow', 'explicit core trap'),
    17: ('division_by_zero', 'explicit core trap'),
    18: ('bounds', 'explicit core trap'),
    19: ('allocation', 'explicit core trap'),
    20: ('steps', 'finite step limit reached'),
    21: ('heap', 'finite live-byte limit reached'),
    22: ('calls', 'finite call-depth limit reached'),
}
INPUT_ERRORS = {
    40: 'unknown entry/wrong argument count',
    41: 'public evaluator boundary cannot carry capabilities',
    42: 'entry arguments are not exactly typed machine values',
}
INVARIANTS = {
    230: 'expired runtime chain', 231: 'expired runtime owner',
    232: 'expired/cyclic runtime view', 233: 'duplicate runtime drop',
    234: 'end of non-view', 235: 'write through non-mutable view',
    236: 'fill without a mutable view',
    237: 'copy requires checked mutable and shared loans',
    238: 'copy alias escaped static owner verification',
    239: 'in-place move needs a unique mutable loan',
    240: 'range fill requires unique mutable loan',
    241: 'range copy violates checked distinct-owner loans',
    242: 'swap needs one live mutable borrow',
    243: 'returned view permission invariant', 244: 'returned view origin invariant',
    246: 'successful scalar entry leaked a verified resource',
    247: 'successful borrowed entry leaked or consumed a resource',
    248: 'invalid external runtime roots', 249: 'invalid external runtime views',
    250: 'invalid native execution transport', 251: 'invalid return origin binding',
    252: 'runtime result arity mismatch', 253: 'invalid live runtime SSA binding',
    254: 'E_HIA_EXECUTION_CONTRACT: native execution ledger differs',
    255: 'unhandled verified opcode',
}


def rejected(message):
    from .hia_program import HIAProgramRejected
    raise HIAProgramRejected('native execution transport: ' + message, 'E_HIA_RUNTIME_INVARIANT')


@dataclass(frozen=True)
class ExternalBuffer:
    """Already admitted, separately owned Agent snapshot; never a wire capability."""
    data: bytearray
    mutable: bool


@dataclass(frozen=True)
class ExecutionFrame:
    sequence: int
    request: int
    words: tuple[int, int, int, int]
    status: int
    error: int
    typ: int
    steps: int
    resources: tuple[int, ...]
    with_chains: bool
    chains: tuple[int, ...]
    values: tuple[tuple[int, int], ...]


def _pointer(value):
    # No exported ctypes array survives this expression. The context retains
    # the exact fixed-size byte storage for the synchronous foreign entry.
    return ctypes.addressof(ctypes.c_char.from_buffer(value)) if len(value) else 0


def _scalar_row(value):
    """Lossless immutable scalar representation, without a declared type."""
    typ = type(value)
    if value is None:
        return [0, 0, 0, 0]
    if typ is bool:
        return [1, int(value), 0, 0]
    if typ is int:
        return [2, int(value < 0), value.bit_length(), value & MASK]
    return [7, 0, 0, 0]


def _materialize_scalar(typ, word):
    # Fixed bit-pattern decoding. Admissibility and arithmetic are in HIA.
    if typ == 12:
        if word != 0:
            rejected('unit result has a noncanonical word')
        return None
    if typ == 11:
        if word > 1:
            rejected('boolean result has a noncanonical word')
        return bool(word)
    if 1 <= typ <= 10:
        width = WIDTHS[typ]
        if word >= 1 << width:
            rejected('integer result has noncanonical high bits')
        if (typ <= 4 or typ == 9) and word >= 1 << (width - 1):
            return word - (1 << width)
        return word
    rejected('terminal contains a capability or unknown scalar representation')


class ExecutionContext:
    """One native invocation; each exact issued storage request is consumed once."""
    def __init__(self, program, function, arguments, limits, *, borrowed=False):
        self.program, self.function, self.arguments = program, function, arguments
        self.borrowed = borrowed
        self.closed = False
        self.workspace = self._created_arena = self._previous_arena = None
        self._created_storage = None
        self.pool = {}
        self.next_handle = 1
        self.pending = None
        self.sequence = self.executed = self.completed = 0
        self.terminal = None
        self.accepted = False
        self.cleanup_error = None
        self.input = self.output = None
        self.source_wire = None
        self._frame_binding = None
        failure = limits[2]
        represented_failure = [0, 0] if failure is None else [failure.bit_length(), failure & MASK]
        self.wire = transport([program.as_dict(), function, len(arguments),
            [limits[0], limits[1], limits[3], represented_failure], int(borrowed), 0])
        try:
            self.workspace = mmap.mmap(-1, max(1 << 20, (BASE + len(self.wire) + 4095) & ~4095))
            self.input = bytearray(self.wire)
            self.output = bytearray()
            self.source_wire = self.wire
        except BaseException:
            self._close_preserving_error()
            raise

    def close(self):
        # Revocation is permanent; release is retryable if an external exported
        # buffer or an interrupted close temporarily prevents physical release.
        self.closed = True
        self.pending = self.terminal = self._frame_binding = None
        self.input = self.output = self.source_wire = None
        self.wire = b''
        first_error = None
        try:
            for handle, (data, external) in tuple(self.pool.items()):
                try:
                    if not external:
                        data.clear()
                    del self.pool[handle]
                except BaseException as exc:
                    if first_error is None:
                        first_error = exc
        except BaseException as exc:
            first_error = exc
        if self._created_storage is not None:
            try:
                self._created_storage.clear()
                self._created_storage = None
            except BaseException as exc:
                if first_error is None:
                    first_error = exc
        for name in ('_created_arena', '_previous_arena', 'workspace'):
            arena = getattr(self, name)
            if arena is not None:
                try:
                    arena.close()
                    setattr(self, name, None)
                except BaseException as exc:
                    if first_error is None:
                        first_error = exc
        self.cleanup_error = first_error
        if first_error is not None:
            raise first_error

    def _close_preserving_error(self):
        try:
            self.close()
        except BaseException:
            # Keep unreleased objects in this permanently revoked context.
            # Do not replace the original callback/foreign failure with cleanup.
            pass

    def _binding(self, frame):
        # Only fixed immutable built-in words/tuples are exposed by the decoder.
        # Preserve exact kinds, so bool/int equality cannot forge a frame word.
        def atom(value):
            if type(value) is tuple:
                return (tuple, tuple(atom(item) for item in value))
            if type(value) is int or type(value) is bool:
                return (type(value), value)
            rejected('frame has an invalid representation')
        return tuple(atom(getattr(frame, name)) for name in ExecutionFrame.__dataclass_fields__)

    def _check(self, frame, *, terminal):
        if (self.closed or frame is not (self.terminal if terminal else self.pending)
                or self._binding(frame) != self._frame_binding):
            rejected('result is not the current immutable issued frame')

    def service(self, frame):
        try:
            self._check(frame, terminal=False)
            if frame.sequence != self.sequence or self.executed == self.sequence:
                rejected('storage permission was already consumed')
            self.executed = self.sequence
            self.pending = None
            self._service(frame)
            self.completed = self.sequence
        except BaseException:
            self._close_preserving_error()
            raise

    def _service(self, frame):
        request, (a, b, c, d) = frame.request, frame.words
        reply = 0
        if request == 1:
            if a != len(self.arguments) or b or c or d:
                rejected('argument snapshot framing differs')
            rows, external = [], []
            for value in self.arguments:
                if type(value) is ExternalBuffer:
                    if type(value.data) is not bytearray or type(value.mutable) is not bool:
                        rejected('external storage is not an exact snapshot')
                    handle = self.next_handle
                    self.next_handle += 1
                    self.pool[handle] = (value.data, True)
                    rows.append([8, len(external), 0, 0])
                    external.append([handle, len(value.data), int(value.mutable)])
                else:
                    rows.append(_scalar_row(value))
            self.wire = transport([rows, external])
            self.input = bytearray(self.wire)
            self.output = bytearray()
            self.source_wire = self.wire
            reply = len(self.wire)
        elif request == 2:
            if a <= len(self.workspace) or b or c or d:
                rejected('arena request is not a strict extent increase')
            self._created_arena = mmap.mmap(-1, a)
            ctypes.memmove(_pointer(self._created_arena), _pointer(self.workspace), len(self.workspace))
            self._previous_arena = self.workspace
            self.workspace = self._created_arena
            self._created_arena = None
            self._previous_arena.close()
            self._previous_arena = None
            reply = a
        elif request == 3:
            if a == 0 or b or c or d:
                rejected('raw allocation request framing differs')
            try:
                self._created_storage = bytearray(a)
            except (MemoryError, OverflowError):
                reply = 0
            else:
                handle = self.next_handle
                self.next_handle += 1
                self.pool[handle] = (self._created_storage, False)
                self._created_storage = None
                reply = handle
            self.input = self.output = bytearray()
            self.source_wire = None
        elif request == 4:
            if a not in self.pool or self.pool[a][1] or b or c or d:
                rejected('release does not name held internal storage')
            # Discard window references before shrinking the released bytearray.
            self.input = self.output = bytearray()
            self.source_wire = None
            self.pool[a][0].clear()
            del self.pool[a]
            reply = 1
        elif request == 5:
            if a == 0:
                if c:
                    rejected('nonempty source has no storage handle')
                self.input = bytearray()
            elif a not in self.pool or len(self.pool[a][0]) != c:
                rejected('source window does not match held storage')
            else:
                self.input = self.pool[a][0]
            if b == 0:
                if d:
                    rejected('nonempty destination has no storage handle')
                self.output = bytearray()
            elif b not in self.pool or len(self.pool[b][0]) != d:
                rejected('destination window does not match held storage')
            else:
                self.output = self.pool[b][0]
            self.source_wire = None
        else:
            rejected('unknown raw storage continuation')
        struct.pack_into('<3Q', self.workspace, 64, frame.sequence, reply, 0)

    def accept(self, frame):
        try:
            return self._accept(frame)
        except BaseException:
            self._close_preserving_error()
            raise

    def _accept(self, frame):
        self._check(frame, terminal=True)
        if self.accepted or frame.request:
            rejected('terminal permission was already consumed')
        self.accepted = True
        from .hia_program import HIAProgramRejected
        from .hia_program_runtime import HIAProgramBudgetExceeded, HIAProgramTrap
        if frame.status == 4:
            raise HIAProgramRejected(INPUT_ERRORS[frame.error], 'E_HIA_INPUT')
        if frame.status == 5:
            raise HIAProgramRejected(INVARIANTS[frame.error], 'E_HIA_RUNTIME_INVARIANT')
        error = None
        if frame.status in (2, 3):
            code, message = (('overflow', 'result is outside ' + TYPES[frame.typ])
                             if frame.error == 1 else ERRORS[frame.error])
            error = (HIAProgramTrap if frame.status == 2 else HIAProgramBudgetExceeded)(code, message)
        resources = dict(zip(RESOURCE_FIELDS, frame.resources))
        resources['live_local_loans'] = resources['loans_started'] - resources['loans_ended']
        if frame.with_chains:
            resources.update(zip(CHAIN_FIELDS, frame.chains))
            resources['live_chain_nodes'] = resources['chain_nodes_created'] - resources['chain_nodes_dropped']
        status = ('', 'returned', 'trapped', 'budget_exceeded')[frame.status]
        report = {'schema': 'hepta.hia.program-execution.v1', 'status': status,
            'program_sha256': self.program.sha256, 'function': self.function,
            'input_sha256': self.program.input_sha256, 'steps': frame.steps,
            'resources': resources, 'word_bits': 64, 'source_used': False,
            'claims': {'finite_core_execution': True, 'whole_language_soundness_proved': False,
                       'backend_refinement_proved': False}}
        if frame.status == 1:
            values = [_materialize_scalar(typ, word) for typ, word in frame.values]
            report['values'] = values
            report['result'] = values[0] if len(values) == 1 else values
        if error is not None:
            report['error'] = {'code': error.code, 'message': str(error)}
            error.report = report
            raise error
        return report


class NativeProgramExecution(NativeHiaJsonImage):
    def step(self, context):
        try:
            if context.closed or context.pending is not None or context.terminal is not None:
                rejected('closed or outstanding execution context cannot resume')
            if context.completed != context.sequence:
                rejected('storage continuation has not completed')
            result = self._entry(_pointer(context.input), len(context.input),
                _pointer(context.output), len(context.output), _pointer(context.workspace), len(context.workspace))
            if context.source_wire is not None and bytes(context.input) != context.source_wire:
                rejected('immutable source transport changed')
            if result == ABI:
                rejected('native ABI refusal')
            header = struct.unpack_from('<14Q', context.workspace)
            magic, _phase, sequence, request, a, b, c, d, _ack, _ra, _rb, status, error, typ = header
            if (magic != MAGIC or request not in range(6) or result != request
                    or sequence != context.sequence + 1 or status not in range(6)
                    or bool(status) == bool(request) or request and (error or typ)
                    or status == 1 and (error or typ)) :
                rejected('native result/sequence framing differs')
            values = ()
            if status == 1:
                at, count = struct.unpack_from('<2Q', context.workspace, 544)
                if at > len(context.workspace) or count > (len(context.workspace) - at) // 16:
                    rejected('terminal value extent differs')
                values = tuple(struct.iter_unpack('<2Q', context.workspace[at:at + count * 16]))
                for kind, word in values:
                    _materialize_scalar(kind, word)
            if status == 4 and error not in INPUT_ERRORS or status == 5 and error not in INVARIANTS:
                rejected('unknown input/invariant result code')
            if status == 2 and error not in {*range(1, 20)} or status == 3 and error not in {20, 21, 22}:
                rejected('unknown trap/budget result code')
            if status == 2 and error == 1 and not 1 <= typ <= 10:
                rejected('overflow type representation differs')
            with_chains = struct.unpack_from('<Q', context.workspace, 384)[0]
            if with_chains not in (0, 1):
                rejected('chain profile flag is not canonical')
            frame = ExecutionFrame(sequence, request, (a, b, c, d), status, error, typ,
                struct.unpack_from('<Q', context.workspace, 256)[0],
                struct.unpack_from('<10Q', context.workspace, 264),
                bool(with_chains),
                struct.unpack_from('<5Q', context.workspace, 344), values)
            context.sequence = sequence
            context._frame_binding = context._binding(frame)
            if request:
                context.pending = frame
            else:
                context.terminal = frame
            return frame
        except BaseException:
            context._close_preserving_error()
            raise

    def execute(self, program, function, arguments, *, max_steps=1_000_000,
                max_heap_bytes=16 << 20, allocation_fail_at=None, max_call_depth=256,
                borrowed=False):
        context = ExecutionContext(program, function, arguments,
            (max_steps, max_heap_bytes, allocation_fail_at, max_call_depth), borrowed=borrowed)
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


def installed_program_execution(path):
    return _installed_json_image(path, SOURCE, SCHEMA, NativeProgramExecution)


def selected_program_execution():
    path = os.environ.get(SELECTOR)
    if not path:
        return None
    try:
        return installed_program_execution(path)
    except (ValueError, OSError, UnicodeError, RuntimeError) as exc:
        from .hia_program import HIAProgramRejected
        raise HIAProgramRejected('selected native execution refused: ' + str(exc),
                                 'E_HIA_RUNTIME_INVARIANT') from exc


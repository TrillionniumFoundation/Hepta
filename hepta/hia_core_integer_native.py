"""Mechanical exact-int windows for the independently selected HIA owner.

HIA owns ADD/SUB/NEG/INVERT, all carry/borrow/sign decisions, requested windows,
and signed result normalization. Exact Python integer representation, bytes
allocation, result materialization and the Core object registry remain hosted.
This module does not load an image, select itself, or change the ordinary Core.
"""
from __future__ import annotations

import _operator
import ctypes
import struct
from types import BuiltinFunctionType

MAGIC = int.from_bytes(b'HIAINT01', 'little')
REFUSAL = 0xfffffffd
FRAME = struct.Struct('<16Q')
INPUT_BYTES = 256
OUTPUT_BYTES = 256
WORKSPACE_BYTES = 640
WINDOW_LIMBS = 32
MAX_REPRESENTABLE_WORDS = 4611686018427387902

_TYPE, _INT, _BYTES = type, int, bytes
_BIT_LENGTH, _TO_BYTES, _FROM_BYTES = int.bit_length, int.to_bytes, int.from_bytes
_RSHIFT, _ABS = int.__rshift__, int.__abs__
_BINARY_TARGETS = (_operator.add, _operator.sub)
_UNARY_TARGETS = (_operator.neg, _operator.invert)
_BINARY_BINDINGS = tuple(
    _TYPE(target) is BuiltinFunctionType and target.__module__ == '_operator'
    and target.__name__ == name
    for target, name in zip(_BINARY_TARGETS, ('add', 'sub')))
_UNARY_BINDINGS = tuple(
    _TYPE(target) is BuiltinFunctionType and target.__module__ == '_operator'
    and target.__name__ == name
    for target, name in zip(_UNARY_TARGETS, ('neg', 'invert')))


def eligible_binary(operation, target, left, right):
    """Inspect already-bound values; preserve all inplace/foreign dispatch."""
    return (_TYPE(operation) is _INT and operation in (1, 2)
            and _BINARY_BINDINGS[operation - 1]
            and target is _BINARY_TARGETS[operation - 1]
            and _TYPE(left) is _INT and _TYPE(right) is _INT)


def eligible_unary(operation, target, value):
    """Core unary IDs 2/3 only; bool and unary positive keep the old call.

    In particular, bool.__invert__ in the pinned 3.12/3.14 sources first warns
    and may raise from the warning filter. Exact type admission excludes bool;
    this module never fabricates the warning or a silent integer replacement.
    """
    return (_TYPE(operation) is _INT and operation in (2, 3)
            and _UNARY_BINDINGS[operation - 2]
            and target is _UNARY_TARGETS[operation - 2]
            and _TYPE(value) is _INT)


def summary(value):
    if _TYPE(value) is not _INT:
        raise TypeError('exact builtin integer operand required')
    bits = _BIT_LENGTH(value)
    sign = _TO_BYTES(_RSHIFT(value, bits), 1, 'little', signed=True)[0] >> 7
    words = (bits + 31) // 32
    top = ((bits - 1) & 31) + 1 if bits else 0
    if words > MAX_REPRESENTABLE_WORDS:
        raise OverflowError('integer byte extent is not representable in the u64 ABI')
    return 2, words, (sign << 6) | top


class IntegerSession:
    """One-use exact-int operation with bounded windows and an unbounded value.

    The input magnitude cache and output accumulator are Python allocations.
    There is no policy size cap. The fixed native buffers do not imply that
    the complete Python representation is constant-memory or already native.
    """

    def __init__(self, image, operation, left, right=None):
        self._closed = False
        self._epoch = 0
        self.finished = True
        self.pending = self.finish_pending = self.busy = False
        self.next_packet = self.request = None
        if _TYPE(operation) is not _INT or operation not in (1, 2, 3, 4):
            raise TypeError('exact integer operation required')
        if _TYPE(left) is not _INT:
            raise TypeError('exact builtin integer operand required')
        if operation <= 2:
            if _TYPE(right) is not _INT:
                raise TypeError('exact builtin integer operand required')
        else:
            if right is not None:
                raise TypeError('unary integer operation has no second operand')
            right = 0
        self.image, self.operation = image, operation
        self.values = (left, right)
        self.summaries = (summary(left), summary(right))
        self.magnitudes = [None, None]
        self.total_words = max(self.summaries[0][1], self.summaries[1][1]) + 1
        self.state = ctypes.create_string_buffer(WORKSPACE_BYTES)
        self.output = ctypes.create_string_buffer(OUTPUT_BYTES)
        self.input = ctypes.create_string_buffer(INPUT_BYTES)
        self.sequence = 0
        self._written_words = 0
        self._result_bytes = bytearray()
        self.actual_steps = []
        self.actual_reads = []
        self.actual_writes = []
        header = (MAGIC, 0, 0, operation, *self.summaries[0], *self.summaries[1], *([0] * 6))
        self.next_packet = FRAME.pack(*header) + bytes(128)
        self.finished = False

    def _seal(self):
        # A normal DONE has a one-use result permission. A sealed operation
        # never does. Invalidate the ticket without allocating in error cleanup.
        self._closed = True
        self._epoch = None
        self._clear_permissions()

    def _clear_permissions(self):
        self.finished = True
        self.pending = self.finish_pending = False
        self.next_packet = self.request = None

    def _checkpoint(self, ticket):
        if self._closed or self._epoch != ticket:
            raise RuntimeError('integer operation was permanently closed during a leaf call')

    def _limbs(self, side, start, count):
        ticket = self._epoch
        self._checkpoint(ticket)
        if side not in (0, 1):
            raise RuntimeError('integer input side differs')
        _, words, _ = self.summaries[side]
        if not 1 <= count <= WINDOW_LIMBS or not 0 <= start < words or count > words - start:
            raise RuntimeError('integer input window is outside the operand')
        raw = self.magnitudes[side]
        if raw is None:
            # Representation transport is lazy. No Python addition, subtraction,
            # negation or inversion computes the operation's result here.
            self._checkpoint(ticket)
            magnitude = _ABS(self.values[side])
            self._checkpoint(ticket)
            raw = _TO_BYTES(magnitude, words * 4, 'little')
            self._checkpoint(ticket)
            self.magnitudes[side] = raw
        returned = raw[start * 4:(start + count) * 4]
        self._checkpoint(ticket)
        return returned

    def step(self, packet):
        try:
            if (self._closed or self.finished or self.busy or self.pending or self.next_packet is None
                    or packet is not self.next_packet or _TYPE(packet) is not _BYTES
                    or len(packet) != INPUT_BYTES):
                raise RuntimeError('integer operation has no entry permission')
            self.next_packet = None
            self.busy = True
            self._epoch += 1
            ticket = self._epoch
            move = ctypes.memmove
            self._checkpoint(ticket)
            move(self.input, packet, INPUT_BYTES)
            self._checkpoint(ticket)
            entry = self.image._entry
            self._checkpoint(ticket)
            status = entry(self.input, INPUT_BYTES, self.output, OUTPUT_BYTES,
                           self.state, WORKSPACE_BYTES)
            self._checkpoint(ticket)
            # This is a real entry return, not an attempted call counter.
            record_step = self.actual_steps.append
            self._checkpoint(ticket)
            record_step((self.sequence, status))
            self._checkpoint(ticket)
            if _TYPE(status) is not _INT or status not in (0, 1, 2):
                raise RuntimeError('integer image refused its ABI')
            raw_output = self.output.raw
            self._checkpoint(ticket)
            unpack = FRAME.unpack_from
            self._checkpoint(ticket)
            header = unpack(raw_output)
            self._checkpoint(ticket)
            if header[0] != MAGIC:
                raise RuntimeError('integer reply identity differs')
            if status == 0:
                _, sequence, kind, operation, extent, words, negative, byte_count, *reserved = header
                if (sequence != self.sequence or kind != 0 or operation != self.operation
                        or words != self.total_words or words != self._written_words
                        or byte_count != words * 4 or len(self._result_bytes) != byte_count
                        or not 1 <= extent <= byte_count or negative not in (0, 1)
                        or any(reserved) or any(raw_output[128:])):
                    raise RuntimeError('integer terminal framing differs')
                self.result_extent, self.result_negative = extent, negative
                self._checkpoint(ticket)
                self.finished = self.finish_pending = True
                self.pending = False
                self.request = None
                return 0
            if header[1] != self.sequence + 1 or header[2] != status:
                raise RuntimeError('integer reply sequence or kind differs')
            if status == 1:
                _, _, _, side, start, count, *reserved = header
                if (side not in (0, 1) or not 1 <= count <= WINDOW_LIMBS
                        or any(reserved) or any(raw_output[128:])):
                    raise RuntimeError('integer read request framing differs')
                _, words, _ = self.summaries[side]
                if start >= words or count > words - start:
                    raise RuntimeError('integer requested input outside the operand')
                self.request = (1, side, start, count, None)
            else:
                _, _, _, start, count, *reserved = header
                if (start != self._written_words or not 1 <= count <= WINDOW_LIMBS
                        or start >= self.total_words or count > self.total_words - start
                        or any(reserved) or any(raw_output[128 + count * 4:])):
                    raise RuntimeError('integer write request framing differs')
                self.request = (2, 0, start, count, raw_output[128:128 + count * 4])
            self._checkpoint(ticket)
            self.sequence = header[1]
            self.pending = True
            return status
        except BaseException:
            self._seal()
            raise
        finally:
            self.busy = False
            if self._closed:
                self._clear_permissions()

    def observe(self):
        try:
            if self._closed or self.finished or self.busy or not self.pending or self.request is None:
                raise RuntimeError('integer operation has no observation permission')
            self.pending = False
            self.busy = True
            self._epoch += 1
            ticket = self._epoch
            kind, side, start, count, payload = self.request
            self.request = None
            if kind == 1:
                read = self._limbs
                self._checkpoint(ticket)
                raw = read(side, start, count)
                self._checkpoint(ticket)
                if _TYPE(raw) is not _BYTES or len(raw) != count * 4:
                    raise RuntimeError('integer magnitude representation differs')
                record_read = self.actual_reads.append
                self._checkpoint(ticket)
                record_read((self.sequence, side, start, count))
                self._checkpoint(ticket)
                pack = FRAME.pack
                self._checkpoint(ticket)
                header = pack(MAGIC, 1, self.sequence, side, start, count, *([0] * 10))
                self._checkpoint(ticket)
                next_packet = header + raw + bytes(128 - len(raw))
            elif kind == 2:
                if (start != self._written_words or len(self._result_bytes) != start * 4
                        or _TYPE(payload) is not _BYTES or len(payload) != count * 4):
                    raise RuntimeError('integer output observation identity differs')
                write = self._result_bytes.extend
                self._checkpoint(ticket)
                write(payload)
                self._checkpoint(ticket)
                self._written_words += count
                record_write = self.actual_writes.append
                self._checkpoint(ticket)
                record_write((self.sequence, start, count))
                self._checkpoint(ticket)
                pack = FRAME.pack
                self._checkpoint(ticket)
                header = pack(MAGIC, 2, self.sequence, start, count, *([0] * 11))
                self._checkpoint(ticket)
                next_packet = header + bytes(128)
                self._checkpoint(ticket)
            else:
                raise RuntimeError('integer observation kind differs')
            self._checkpoint(ticket)
            self.next_packet = next_packet
            return next_packet
        except BaseException:
            self._seal()
            raise
        finally:
            self.busy = False
            if self._closed:
                self._clear_permissions()

    def finish(self):
        try:
            if self._closed or self.busy or not self.finished or not self.finish_pending:
                raise RuntimeError('integer operation has no result permission')
            # Result allocation is itself one-use. A failure must not retry it.
            self.finish_pending = False
            self.busy = True
            self._epoch += 1
            ticket = self._epoch
            self._checkpoint(ticket)
            full = _BYTES(self._result_bytes)
            self._checkpoint(ticket)
            raw = full[:self.result_extent]
            sign = self.result_negative
            if (not raw or raw[-1] >> 7 != sign
                    or any(value != (255 if sign else 0) for value in full[len(raw):])):
                raise RuntimeError('integer signed result extent differs')
            if len(raw) > 1 and ((raw[-1] == 0 and raw[-2] < 128)
                                 or (raw[-1] == 255 and raw[-2] >= 128)):
                raise RuntimeError('integer signed result is not minimal')
            # HIA already supplied the complete signed representation. The
            # bridge does not apply Python arithmetic to determine the result.
            self._checkpoint(ticket)
            returned = _FROM_BYTES(raw, 'little', signed=True)
            self._checkpoint(ticket)
            if _TYPE(returned) is not _INT:
                raise RuntimeError('integer result materialization type differs')
            self.returned = returned
            self._seal()
            return returned
        except BaseException:
            self._seal()
            raise
        finally:
            self.busy = False
            if self._closed:
                self._clear_permissions()

    def run(self):
        packet = self.next_packet
        while self.step(packet) != 0:
            packet = self.observe()
        return self.finish()


class NativeInteger:
    """A value owner constructed only after independent image admission.

    Image loading/source/compiler/ABI admission is deliberately not supplied
    by this source draft. A future selector must bind all of those originals.
    """

    def __init__(self, image):
        self.image = image

    def binary(self, operation, left, right):
        if _TYPE(operation) is not _INT or operation not in (1, 2):
            raise TypeError('unsupported exact binary integer operation')
        return IntegerSession(self.image, operation, left, right).run()

    def unary(self, operation, value):
        if _TYPE(operation) is not _INT or operation not in (2, 3):
            raise TypeError('unsupported exact unary integer operation')
        return IntegerSession(self.image, operation + 1, value).run()

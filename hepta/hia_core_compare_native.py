"""Mechanical exact-number transport for the explicitly selected HIA owner.

HIA owns the four-way numeric relation and all six predicate decisions. This
bridge retains exact builtin type admission, integer/IEEE representation,
buffer transport and Python allocation. Its lazy magnitude cache has no value
size policy cap; only a requested 32-limb window enters the fixed native ABI.
It does not close the CPython object, allocation or floating representation VM.
"""
from __future__ import annotations

import _operator
import ctypes
import struct
import sys
from types import BuiltinFunctionType

MAGIC = int.from_bytes(b'HIACMP01', 'little')
REFUSAL = 0xfffffffd
FRAME = struct.Struct('<16Q')
INPUT_BYTES = 256
OUTPUT_BYTES = 128
WORKSPACE_BYTES = 512
WINDOW_LIMBS = 32

_TYPE, _INT, _BOOL, _FLOAT = type, int, bool, float
_BIT_LENGTH, _TO_BYTES = int.bit_length, int.to_bytes
_RSHIFT, _ABS = int.__rshift__, int.__abs__
_FLOAT_BYTES, _FLOAT_WORD = struct.Struct('<d'), struct.Struct('<Q')
_OPERATORS = (_operator.eq, _operator.ne, _operator.lt,
              _operator.le, _operator.gt, _operator.ge)
_OPERATOR_NAMES = ('eq', 'ne', 'lt', 'le', 'gt', 'ge')
_BUILTIN_BINDINGS = tuple(
    _TYPE(function) is BuiltinFunctionType
    and function.__module__ == '_operator' and function.__name__ == name
    for function, name in zip(_OPERATORS, _OPERATOR_NAMES))


def _exact_number(value):
    actual = _TYPE(value)
    return actual is _INT or actual is _BOOL or actual is _FLOAT


def eligible(operation, target, left, right):
    """Check the already-bound target, after the two original operand reads.

    No registry is consulted again. Python subclasses and replacement targets
    retain their original rich-comparison/contains dispatch, even when their
    eventual result happens to be a builtin numeric value.
    """
    return (_TYPE(operation) is _INT and 1 <= operation <= 6
            and _BUILTIN_BINDINGS[operation - 1]
            and target is _OPERATORS[operation - 1]
            and _exact_number(left) and _exact_number(right))


def summary(value):
    actual = _TYPE(value)
    if actual is _BOOL:
        return 1, 0, 1 if value is True else 0
    if actual is _INT:
        bits = _BIT_LENGTH(value)
        # An arithmetic shift by the magnitude bit length yields the single
        # sign-extension byte (00 or ff). This is representation transport;
        # it neither compares two operands nor converts an integer to float.
        sign = _TO_BYTES(_RSHIFT(value, bits), 1, 'little', signed=True)[0] >> 7
        words = (bits + 31) // 32
        top = ((bits - 1) & 31) + 1 if bits else 0
        return 2, words, (sign << 6) | top
    if actual is _FLOAT:
        return 3, 0, _FLOAT_WORD.unpack(_FLOAT_BYTES.pack(value))[0]
    raise TypeError('exact builtin numeric comparison operands required')


class NumericCompareSession:
    """One owned comparison. The outer Core effect remains one observation.

    Native requests determine window order/extent; observe consumes permission
    before materialization. A failed entry, ledger write, packet check or
    representation operation permanently closes this private continuation.
    """

    def __init__(self, image, operation, left, right):
        self._closed, self._epoch = True, 0
        self.finished = True
        self.pending = self.finish_pending = self.busy = False
        self.next_packet = self.request = self.returned = None
        if _TYPE(operation) is not _INT or not 1 <= operation <= 6:
            raise TypeError('exact numeric comparison predicate required')
        if not _exact_number(left) or not _exact_number(right):
            raise TypeError('exact builtin numeric comparison operands required')
        self.image, self.operation = image, operation
        self.values = (left, right)
        self.summaries = (summary(left), summary(right))
        self.magnitudes = [None, None]
        self.state = ctypes.create_string_buffer(WORKSPACE_BYTES)
        self.input = ctypes.create_string_buffer(INPUT_BYTES)
        self.output = ctypes.create_string_buffer(OUTPUT_BYTES)
        self.sequence = 0
        self.actual_steps = []
        self.actual_windows = []
        header = (MAGIC, 0, 0, operation, *self.summaries[0], *self.summaries[1], *([0] * 6))
        self.next_packet = FRAME.pack(*header) + bytes(128)
        self.finished = False
        self._closed = False

    def _seal(self):
        # A caught invalid reentry must not be undone by the active call's
        # later DONE reply, bookkeeping, or packet materialization.
        self._closed = True
        self._epoch = None
        self.finished = True
        self.pending = self.finish_pending = False
        self.next_packet = self.request = None

    def _checkpoint(self, epoch):
        if self._closed or self._epoch != epoch:
            raise RuntimeError('numeric comparison continuation was permanently closed')

    def _leave(self):
        if self._closed:
            self.finished = True
            self.pending = self.finish_pending = False
            self.next_packet = self.request = None
        self.busy = False

    def _limbs(self, side, start, count):
        epoch = self._epoch
        self._checkpoint(epoch)
        kind, words, _ = self.summaries[side]
        if kind != 2 or not 1 <= count <= WINDOW_LIMBS or not 0 <= start < words or count > words - start:
            raise RuntimeError('numeric comparison requested an invalid integer window')
        raw = self.magnitudes[side]
        if raw is None:
            # This matches the existing GraphObserver representation leaf.
            # There is no 8 MiB integer limit and no whole-value native copy.
            # CPython bytes allocation / MemoryError remain hosted boundaries.
            magnitude = _ABS(self.values[side])
            self._checkpoint(epoch)
            raw = _TO_BYTES(magnitude, words * 4, 'little')
            self._checkpoint(epoch)
            self.magnitudes[side] = raw
        result = raw[start * 4:(start + count) * 4]
        self._checkpoint(epoch)
        return result

    def step(self, packet):
        try:
            if (self._closed or self.finished or self.busy or self.pending or self.next_packet is None
                    or packet is not self.next_packet or _TYPE(packet) is not bytes
                    or len(packet) != INPUT_BYTES):
                raise RuntimeError('numeric comparison has no entry permission')
            self.next_packet = None
            self.busy = True
            epoch = self._epoch
            ctypes.memmove(self.input, packet, INPUT_BYTES)
            self._checkpoint(epoch)
            entry = self.image._entry
            self._checkpoint(epoch)
            status = entry(self.input, INPUT_BYTES, self.output, OUTPUT_BYTES,
                           self.state, WORKSPACE_BYTES)
            self._checkpoint(epoch)
            # Accounting follows a real image return. A failure here also
            # seals the invocation, so a completed effect cannot be replayed.
            self.actual_steps.append((self.sequence, status))
            self._checkpoint(epoch)
            if _TYPE(status) is not _INT or status not in (0, 1):
                raise RuntimeError('numeric comparison image refused its ABI')
            header = FRAME.unpack(self.output.raw)
            self._checkpoint(epoch)
            if header[0] != MAGIC:
                raise RuntimeError('numeric comparison reply identity differs')
            if status == 0:
                if (header[1] != self.sequence or header[2] > 3 or header[3] > 1
                        or any(header[4:])):
                    raise RuntimeError('numeric comparison terminal reply differs')
                self.relation = header[2]
                self.returned = (False, True)[header[3]]
                self.finished = self.finish_pending = True
                self.pending = False
                self.request = None
                self._checkpoint(epoch)
                return 0
            if (header[1] != self.sequence + 1 or header[2] != 1
                    or header[3] > 1 or not 1 <= header[5] <= WINDOW_LIMBS
                    or any(header[6:])):
                raise RuntimeError('numeric comparison window request differs')
            side, start, count = header[3:6]
            kind, words, _ = self.summaries[side]
            if kind != 2 or start >= words or count > words - start:
                raise RuntimeError('numeric comparison window is outside the operand')
            self.sequence = header[1]
            self.request = (side, start, count)
            self.pending = True
            self._checkpoint(epoch)
            return 1
        except BaseException:
            self._seal()
            raise
        finally:
            self._leave()

    def observe(self):
        try:
            if self._closed or self.finished or self.busy or not self.pending or self.request is None:
                raise RuntimeError('numeric comparison has no observation permission')
            self.pending = False
            self.busy = True
            epoch = self._epoch
            side, start, count = self.request
            self.request = None
            raw = self._limbs(side, start, count)
            self._checkpoint(epoch)
            if _TYPE(raw) is not bytes or len(raw) != count * 4:
                raise RuntimeError('numeric comparison limb representation differs')
            self.actual_windows.append((self.sequence, side, start, count))
            self._checkpoint(epoch)
            header = FRAME.pack(MAGIC, 1, self.sequence, side, start, count, *([0] * 10))
            self._checkpoint(epoch)
            self.next_packet = header + raw + bytes(128 - len(raw))
            self._checkpoint(epoch)
            return self.next_packet
        except BaseException:
            self._seal()
            raise
        finally:
            self._leave()

    def finish(self):
        try:
            if self._closed or self.busy or not self.finished or not self.finish_pending:
                raise RuntimeError('numeric comparison has no result permission')
            epoch = self._epoch
            self.busy = True
            self.finish_pending = False
            result = self.returned
            self._checkpoint(epoch)
            self._seal()
            return result
        except BaseException:
            self._seal()
            raise
        finally:
            self._leave()

    def run(self):
        packet = self.next_packet
        while self.step(packet) == 1:
            packet = self.observe()
        return self.finish()


class NativeNumericCompare:
    """An explicitly admitted numeric image; no Python relation implementation."""

    def __init__(self, image):
        if (sys.float_info.radix != 2 or sys.float_info.mant_dig != 53
                or sys.float_info.min_exp != -1021 or sys.float_info.max_exp != 1024
                or struct.calcsize('d') != 8):
            raise ValueError('numeric comparison requires actual binary64 float representation')
        self.image = image

    def compare(self, operation, left, right):
        return NumericCompareSession(self.image, operation, left, right).run()

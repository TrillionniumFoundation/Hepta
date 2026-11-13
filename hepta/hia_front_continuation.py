"""Owner-local fixed continuation transport for public-front HIA.

Extracted from the exact R5 frame transport. No retained Plan/Core policy body,
public machine-plan wrapper, source selector, or backend installation route is
present. The front owner supplies its own GLOBAL/CALL/closure/import primitives.
The inherited diagnostic strings are preserved for the retained mechanics.
"""
from __future__ import annotations

from collections import Counter
import ctypes
from dataclasses import dataclass
import itertools
import operator
import struct
import sys

from .hia_exception_delivery import ExceptionDelivery, ExceptionDeliveryUnavailable
from .hia_json_preflight_native import NativeHiaJsonImage
from .hia_machine_transport import _private_zeroed_buffer

MAGIC = int.from_bytes(b'HIAPLN02', 'little')
EMIT_MAGIC = int.from_bytes(b'HIAPLT02', 'little')
_NONCES = itertools.count(1)
_UNCONFIRMED_RETIREMENTS = {}
_EMPTY = object()
_BINARY = (None, operator.add, operator.sub, operator.mul, operator.floordiv,
           operator.truediv, operator.mod, operator.pow, operator.lshift,
           operator.rshift, operator.or_, operator.xor, operator.and_)
_INPLACE = (None, operator.iadd, operator.isub, operator.imul, operator.ifloordiv,
            operator.itruediv, operator.imod, operator.ipow, operator.ilshift,
            operator.irshift, operator.ior, operator.ixor, operator.iand)
_UNARY = (None, operator.pos, operator.neg, operator.invert, operator.not_)
_COMPARE = (None, operator.eq, operator.ne, operator.lt, operator.le, operator.gt,
            operator.ge, lambda a, b: a in b, lambda a, b: a not in b,
            operator.is_, operator.is_not)


class _Cell:
    __slots__ = ('value',)

    def __init__(self, value=_EMPTY):
        self.value = value


@dataclass(frozen=True)
class Issued:
    raw: bytes


def _read_word(data, at):
    return struct.unpack_from('<Q', data, at)[0]


def _capture(frame):
    """Return outside the handler before HIA permits operand retirement."""
    try:
        return True, frame._effect()
    except BaseException as error:
        return False, error


def _capture_with_handler(frame):
    if frame.handled is None:
        return _capture(frame)
    try:
        frame.image._delivery.deliver(frame.handled)
    except BaseException as delivered:
        if delivered is not frame.handled:
            raise
        return _capture(frame)


def _runtime_profile():
    """Observe only explicitly reviewed interpreter frame ABIs.

    Public unselected Python paths keep their existing package support. This
    native continuation requires the same CPython 3.12+ exception mechanism;
    unreviewed interpreter families and future versions cannot silently borrow
    the 3.14 frame ABI. HIA, rather than this transport, chooses retirement order.
    """
    version = sys.version_info[:2]
    if sys.implementation.name != 'cpython' or version not in ((3, 12), (3, 13), (3, 14)):
        raise ExceptionDeliveryUnavailable('native frame transport requires a reviewed CPython 3.12, 3.13 or 3.14 ABI')
    return version[0] * 100 + version[1]


class ContinuationFrame:
    def __init__(self, image, mode, arguments, captures=(), *, witness=None):
        self.closed = False
        self._runtime_profile = image.runtime_profile
        self.state = self.output = None
        self.pending = self.frame_bytes = None
        self.executed = self.completed = False
        self.error = self.handled = None
        self.reply = None
        self.values = []
        self.cells = set()
        self.mode = mode
        self.image = image
        self.witness = witness
        self._terminal_taken = False
        self._yield_taken = False
        self._started = False
        self._retiring = self._retired = self._uncertain = False
        self.nonce = next(_NONCES)
        if self.nonce >= 1 << 64:
            raise OverflowError('native machine-plan continuation nonce exhausted')
        try:
            entry, slots, info, metadata = image.function(mode)
            self.parameter_count = info & 65535
            self.generator = bool((info >> 16) & 1)
            capture_count = info >> 32
            if len(arguments) != self.parameter_count or len(captures) != capture_count:
                raise TypeError('native machine-plan private argument arity differs')
            self.values = [_EMPTY] * slots
            for index in range(slots):
                if image.table[metadata + index] & 2:
                    self.cells.add(index)
                    self.values[index] = _Cell()
            for index, value in enumerate(arguments):
                self._set(index, value)
            for index, cell in enumerate(captures):
                destination = struct.unpack_from('<H', image.table, metadata + slots + 2 * index)[0]
                if type(cell) is not _Cell or destination >= slots:
                    raise RuntimeError('native machine-plan closure representation differs')
                self.cells.add(destination)
                self.values[destination] = cell
            self.state = _private_zeroed_buffer(image.workspace_bytes)
            self.output = _private_zeroed_buffer(2048)
        except BaseException:
            self.close(release=False)
            # No policy instruction has run. These two arenas belong only to
            # this partial constructor, even if its traceback retains self.
            # Argument/closure slots keep their original traceback ownership.
            self.state = self.output = None
            raise

    def _get(self, slot):
        if type(slot) is not int or not 0 <= slot < len(self.values):
            raise RuntimeError('native machine-plan object slot is outside the frame')
        value = self.values[slot]
        if slot in self.cells:
            value = value.value
        if value is _EMPTY:
            raise RuntimeError('native machine-plan read an unbound object slot')
        return value

    def _set(self, slot, value):
        if type(slot) is not int or not 0 <= slot < len(self.values):
            raise RuntimeError('native machine-plan destination is outside the frame')
        if slot in self.cells:
            self.values[slot].value = value
        else:
            self.values[slot] = value

    def _clear(self, slot):
        self._set(slot, _EMPTY)

    def close(self, *, release=True):
        self.closed = True
        self.pending = self.frame_bytes = self.reply = None
        # The delivered exception already owns the original traceback. Keeping
        # it on its own frame would create an additional frame/error cycle.
        self.error = self.handled = None
        if release:
            self._retire()

    def _retire(self):
        """Retire stack temporaries, then locals, in the HIA-issued order.

        An error traceback owns its original locals until the frame itself
        dies. Generator cancellation also reaches this boundary after Python
        has restored the outer handled-exception context.
        """
        if self._retired:
            return
        if self._uncertain:
            _UNCONFIRMED_RETIREMENTS[self.nonce] = self
            return
        self.closed = True
        if self._started and self.state is not None:
            self._retiring = True
            try:
                self._accept_result(self._invoke(4))
                while self._status == 1:
                    self.service(self.pending)
                    self.step()
                if self._status != 5:
                    raise RuntimeError('native machine-plan frame retirement did not finish')
            except BaseException:
                self._uncertain = True
                _UNCONFIRMED_RETIREMENTS[self.nonce] = self
                raise
            finally:
                self._retiring = False
        else:
            # A partial constructor has not executed a policy instruction.
            # Its argument slots have only physical frame ownership. No HIA
            # instruction or foreign policy operation has been permitted.
            indices = range(len(self.values))
            if self._runtime_profile == 314:
                indices = reversed(indices)
            for index in indices:
                self.values[index] = _EMPTY
        self.values.clear()
        self.cells.clear()
        self.pending = self.frame_bytes = self.reply = None
        self.state = self.output = None
        self._retired = True

    def __del__(self):
        if hasattr(self, '_retired') and not self._retired:
            try:
                self._retire()
            except BaseException:
                # A lost cleanup acknowledgement is retained as unknown. It
                # cannot grant a replay or silently release unconfirmed data.
                _UNCONFIRMED_RETIREMENTS[self.nonce] = self

    def _invoke(self, command, flag=0, error=0, op=0):
        if self.closed and not self._retiring:
            raise RuntimeError('native machine-plan frame is closed')
        sequence = 0 if not self._started else _read_word(self.state, 144)
        value = self.mode if command == 0 else op if command == 2 else flag
        struct.pack_into('<6Q', self.state, 0, command, self.nonce, sequence, value, error,
                         self._runtime_profile)
        self.image.entries += 1
        return self.image._entry(self.image._table_buffer, len(self.image.table),
                                 self.output, len(self.output), self.state, len(self.state))

    def step(self):
        if self.closed and not self._retiring:
            raise RuntimeError('native machine-plan frame is closed')
        if self.pending is not None and not self.completed:
            raise RuntimeError('native machine-plan observation lacks its actual acknowledgement')
        try:
            if not self._started:
                result = self._invoke(0)
                self._started = True
            elif self._status == 2:
                if not self._yield_taken:
                    raise RuntimeError('native machine-plan yielded value was not consumed')
                self._yield_taken = False
                result = self._invoke(3)
            else:
                if self.reply is None or self.pending is None:
                    raise RuntimeError('native machine-plan continuation has no issued result')
                result = self._invoke(1, *self.reply)
            self._accept_result(result)
            return result
        except BaseException:
            self._uncertain = True
            self.close(release=False)
            raise

    def _accept_result(self, result):
        self.pending = self.frame_bytes = self.reply = None
        self.executed = self.completed = False
        self._status = result
        if type(result) is not int or result not in ((1, 5) if self._retiring else (0, 1, 2, 3)):
            raise RuntimeError('native machine-plan continuation returned an invalid status')
        if result == 1:
            head = struct.unpack_from('<10Q', self.output)
            requests = (5, 6) if self._retiring else (1, 2, 3)
            if (head[0] != MAGIC or head[1] != self.nonce or head[2] == 0 or
                    head[2] != _read_word(self.state, 144) or
                    not 1 <= head[4] <= 28 or head[9] not in requests):
                raise RuntimeError('native machine-plan issued a malformed observation')
            size = 128 + 8 * sum(head[5:9])
            if size > len(self.output):
                raise RuntimeError('native machine-plan observation extent differs')
            self.frame_bytes = bytes(self.output[:size])
            self.pending = Issued(self.frame_bytes)
            self.image.observations[head[4]] += 1
        else:
            head = struct.unpack_from('<4Q', self.output)
            if head[:3] != (MAGIC, self.nonce, _read_word(self.state, 144)):
                raise RuntimeError('native machine-plan terminal identity differs')
            if result in (0, 2) and head[3] >= len(self.values):
                raise RuntimeError('native machine-plan terminal value is outside the frame')
            if result in (3, 5) and head[3] != 0:
                raise RuntimeError('native machine-plan terminal has a noncanonical payload')
            self.frame_bytes = bytes(self.output[:32])

    def service(self, issued):
        if (self.closed and not self._retiring) or issued is not self.pending or type(issued) is not Issued:
            raise RuntimeError('native machine-plan observation is not the issued permission')
        if type(issued.raw) is not bytes or issued.raw != self.frame_bytes or self.executed:
            raise RuntimeError('native machine-plan observation changed or was already consumed')
        self.executed = True
        try:
            if self._invoke(2, op=_read_word(issued.raw, 32)) != 4:
                raise RuntimeError('native machine-plan observation claim refused')
            observed = _capture_with_handler(self)
            if observed[0]:
                self.reply = (observed[1], 0)
            else:
                self.error = observed[1]
                self.reply = (0, 1)
            observed = None
            self.completed = True
        except BaseException:
            self._uncertain = True
            self.close(release=False)
            raise

    def _parts(self):
        head = struct.unpack_from('<10Q', self.frame_bytes)
        nd, na, nr, nv = head[5:9]
        values = struct.unpack_from('<' + 'Q' * (nd + na + nr + nv), self.frame_bytes, 128)
        return (head[4], values[:nd], values[nd:nd + na],
                values[nd + na:nd + na + nr], values[nd + na + nr:])

    def _global(self, name):
        raise NotImplementedError('public-front owner must supply its fixed primitive')

    def _move_call_operand(self, slot):
        """Transfer a claimed temporary into CPython's operand stack.

        The HIA CALL has consumed its one-shot permission before this primitive.
        Its later ACK retires the logical births; empty physical slots cannot
        retain the callee or its arguments beyond the original Python call.
        """
        value = self._get(slot)
        self._clear(slot)
        return value

    def _call(self, args, raw):
        raise NotImplementedError('public-front owner must supply its fixed primitive')

    def _function(self, args, raw, vector):
        raise NotImplementedError('public-front owner must supply its fixed primitive')

    def _effect(self):
        op, destinations, args, raw, vector = self._parts()
        flag = 0
        result = _EMPTY
        if op == 1:
            result = self.image.literal(raw[0])
        elif op == 2:
            result = self._global(self.image.literal(raw[0]))
        elif op == 3:
            result = getattr(self._get(args[0]), self.image.literal(raw[0]))
        elif op == 4:
            result = self._get(args[0])[self._get(args[1])]
        elif op == 5:
            if raw[0] >= 128:
                result = _INPLACE[raw[0] - 128](self._get(args[0]), self._get(args[1]))
            else:
                result = _BINARY[raw[0]](self._get(args[0]), self._get(args[1]))
        elif op == 6:
            result = _COMPARE[raw[0]](self._get(args[0]), self._get(args[1]))
        elif op == 7:
            result = _UNARY[raw[0]](self._get(args[0]))
        elif op == 8:
            flag = int(bool(self._get(args[0])))
        elif op == 9:
            result = self._call(args, raw)
        elif op == 10:
            if raw[0] == 1:
                result = [self._get(slot) for slot in vector]
            elif raw[0] == 2:
                result = tuple(self._get(slot) for slot in vector)
            elif raw[0] == 3:
                result = {self._get(slot) for slot in vector}
            elif raw[0] == 4:
                result = dict(zip([self._get(slot) for slot in vector[::2]],
                                  [self._get(slot) for slot in vector[1::2]]))
            else:
                raise RuntimeError('native machine-plan pack kind differs')
        elif op == 11:
            result = iter(self._get(args[0]))
        elif op == 12:
            try:
                result = next(self._get(args[0]))
                flag = 1
            except StopIteration:
                result = None
                flag = 0
        elif op == 13:
            if raw[0] == 1:
                left, = self._get(args[0])
                result = (left,)
                left = None
            elif raw[0] == 2:
                left, right = self._get(args[0])
                result = (left, right)
                left = right = None
            elif raw[0] == 3:
                left, middle, right = self._get(args[0])
                result = (left, middle, right)
                left = middle = right = None
            else:
                raise RuntimeError('native machine-plan unpack arity differs')
        elif op == 14:
            self._get(args[0])[self._get(args[1])] = self._get(args[2])
        elif op == 15:
            result = self._get(args[0])
        elif op == 16:
            for slot in vector:
                self._clear(slot)
        elif op == 17:
            result = slice(self._get(args[0]), self._get(args[1]), self._get(args[2]))
        elif op == 18:
            result = self._function(args, raw, vector)
        elif op == 19:
            raise NotImplementedError('public-front owner must supply its fixed import primitive')
        elif op == 20:
            if raw[0]:
                raise self._get(args[0]) from self._get(args[1])
            raise self._get(args[0])
        elif op == 21:
            flag = int(isinstance(self.error, self._get(args[0])))
        elif op == 22:
            result = self.error
        elif op == 23:
            self._get(args[0]).append(self._get(args[1]))
        elif op == 24:
            self._get(args[0]).extend(self._get(args[1]))
        elif op == 25:
            self._get(args[0]).add(self._get(args[1]))
        elif op == 26:
            self.handled = self.error
        elif op == 27:
            self.handled = None
        elif op == 28:
            for slot in vector:
                # Frame retirement drops a cell reference; it must not clear
                # the cell owned by a separately retained native generator.
                self.values[slot] = _EMPTY
        else:
            raise RuntimeError('unknown native machine-plan object primitive')
        if op == 13:
            for index, destination in enumerate(destinations):
                self._set(destination, result[index])
        elif destinations:
            if len(destinations) != 1 or result is _EMPTY:
                raise RuntimeError('native machine-plan primitive result arity differs')
            self._set(destinations[0], result)
        result = None
        return flag

    def drive(self):
        status = self.step()
        while status == 1:
            self.service(self.pending)
            status = self.step()
        if status == 3:
            if self.error is None:
                raise RuntimeError('native machine-plan failed without an actual exception')
            self._terminal_taken = True
            error, self.error = self.error, None
            self.handled = None
            try:
                self.image._delivery.deliver(error)
                raise RuntimeError('native machine-plan exception delivery returned')
            finally:
                error = None
        return status

    def take(self, *, yielded=False):
        if self.closed or self._status != (2 if yielded else 0):
            raise RuntimeError('native machine-plan value is not at the selected terminal')
        if self._yield_taken if yielded else self._terminal_taken:
            raise RuntimeError('native machine-plan value permission was already consumed')
        if yielded:
            self._yield_taken = True
        else:
            self._terminal_taken = True
        return self._get(_read_word(self.frame_bytes, 24))


class NativeContinuationImage(NativeHiaJsonImage):
    def __init__(self, image, expected_sha256):
        super().__init__(image, expected_sha256)
        self._initialize_control()

    def _initialize_control(self):
        self.runtime_profile = _runtime_profile()
        self.entries = 0
        self.observations = Counter()
        self._delivery = ExceptionDelivery.from_hia(self)
        source = ctypes.create_string_buffer(struct.pack('<8Q', EMIT_MAGIC, *([0] * 7)))
        output = _private_zeroed_buffer(1 << 20)
        workspace = _private_zeroed_buffer(96)
        size = self._entry(source, 64, output, len(output), workspace, len(workspace))
        if type(size) is not int or not 64 <= size <= len(output):
            raise RuntimeError('native machine-plan policy emission refused')
        self.table = bytes(output[:size])
        if struct.unpack_from('<2Q', self.table) != (MAGIC, len(self.table)):
            raise RuntimeError('native machine-plan policy table identity differs')
        functions, instructions, base, offsets, literals, count = struct.unpack_from('<6Q', self.table, 16)
        if (functions < 1 or base != 64 or base + functions * 32 > len(self.table)
                or offsets + instructions * 4 > len(self.table)
                or literals + count * 4 > len(self.table)):
            raise RuntimeError('native machine-plan policy table extents differ')
        self.function_count = functions
        self._literal_offsets, self._literal_count = literals, count
        self._literals = {}
        self.workspace_bytes = 1024 + 8 * max(self.function(mode)[1]
                                             for mode in range(1, functions + 1))
        self._table_buffer = ctypes.create_string_buffer(self.table, len(self.table))

    def function(self, mode):
        if type(mode) is not int or not 1 <= mode <= self.function_count:
            raise RuntimeError('native machine-plan entry identity differs')
        entry, slots, info, metadata = struct.unpack_from('<4Q', self.table, 64 + (mode - 1) * 32)
        if metadata + slots + 2 * (info >> 32) > len(self.table):
            raise RuntimeError('native machine-plan closure extent differs')
        return entry, slots, info, metadata

    def literal(self, index):
        if type(index) is not int or not 0 <= index < self._literal_count:
            raise RuntimeError('native machine-plan literal identity differs')
        if index not in self._literals:
            at = struct.unpack_from('<I', self.table, self._literal_offsets + index * 4)[0]
            kind, size = struct.unpack_from('<BQ', self.table, at)
            if at + 9 + size > len(self.table):
                raise RuntimeError('native machine-plan literal extent differs')
            raw = self.table[at + 9:at + 9 + size]
            if kind == 0 and size == 0:
                value = None
            elif kind == 1 and raw in (b'\0', b'\1'):
                value = raw == b'\1'
            elif kind == 2:
                value = int(raw)
            elif kind == 3:
                value = raw.decode('utf-8')
            elif kind == 4:
                # The HIA-emitted literal tag requests the same identifier
                # interning as the retained Python code's constant table.
                value = sys.intern(raw.decode('utf-8'))
            else:
                raise RuntimeError('native machine-plan literal kind differs')
            self._literals[index] = value
        return self._literals[index]

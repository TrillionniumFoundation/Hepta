"""HIA-owned Code state admission, labels, registers and final fixup ordering.

The bridge performs requested primitive Python object operations and preserves
the actual public mutable objects. It holds no duplicate native labels/fixups
map. Instruction admission outside these six operations remains a separate
owner; emitted rel32 bytes are supplied by the selected HIA byte encoder.
"""
from __future__ import annotations

from collections import Counter
import ctypes
from functools import lru_cache
import struct
import sys

from .hia_json_preflight_native import NativeHiaJsonImage, _installed_json_image, _source_resource_path
from .hia_json_wire_native import _private_zeroed_buffer

SOURCE = _source_resource_path('examples/hia_bootstrap/machine_state.hiaasm')
SCHEMA = 'hepta.hia.machine-state-native.v1'
SELECTOR = 'HEPTA_HIA_MACHINE_STATE_MANIFEST'
MAGIC = int.from_bytes(b'HIACST01', 'little')
MASK = (1 << 64) - 1
MODES = ('initialize', 'emit', 'label', 'finalize', 'offset', 'register')


class MachineStateSession:
    """One immutable entry request, private continuation and one-shot effects."""
    def __init__(self, image, receiver, mode, *arguments):
        if type(mode) is not int or not 1 <= mode <= 6 or len(arguments) > 3:
            raise ValueError('invalid native Code state operation')
        self.image, self.receiver, self.mode = image, receiver, mode
        self.values = [None]
        self.identities = {}
        self.workspace = _private_zeroed_buffer(2048)
        self.output = ctypes.create_string_buffer(b'\xa5' * 8, 8)
        args = arguments + (None,) * (3 - len(arguments))
        self.none = self.register(None)
        self.packet = struct.pack('<10Q', MAGIC, 0, 0, mode, self.register(receiver),
                                  *(self.register(v) for v in args), self.none, 0)
        self.finished = False
        self.pending = False
        self.prepared = True

    def register(self, value):
        identity = id(value)
        handle = self.identities.get(identity)
        if handle is None:
            handle = len(self.values)
            self.values.append(value)
            self.identities[identity] = handle
        else:
            assert self.values[handle] is value
        return handle

    def value(self, handle):
        if not 0 < handle < len(self.values):
            raise RuntimeError('native Code state requested an unknown object handle')
        return self.values[handle]

    def _literal(self, offset, count):
        if offset != 1024 or not 0 < count <= 192:
            raise RuntimeError('native Code state literal span differs')
        text = bytes(self.workspace[offset:offset + count]).decode('utf-8')
        # CPython's original identifier constants/attribute names are interned.
        # Keep those literal objects canonical for foreign equality observers.
        return sys.intern(text) if text.isidentifier() else text

    def step(self, packet=None):
        if self.finished:
            raise RuntimeError('native Code state continuation is terminal')
        if packet is None and not self.prepared:
            raise RuntimeError('native Code state observation has not been acknowledged')
        raw = self.packet if packet is None else packet
        if type(raw) is not bytes:
            self.finished = True
            raise TypeError('native Code state packet must be exact bytes')
        self.pending = False
        self.prepared = False
        try:
            status = self.image._entry(raw, len(raw), self.output, len(self.output),
                                       self.workspace, len(self.workspace))
            self.image.transitions[self.mode] += 1
            if status == 1:
                self.pending = True
            else:
                self.finished = True
            return status
        except BaseException:
            # A native transition may already have happened. Diagnostic
            # bookkeeping must not leave a resumable or repeatable session.
            self.finished = True
            self.pending = False
            self.prepared = False
            raise

    def observe(self):
        if self.finished or not self.pending:
            raise RuntimeError('native Code state has no unconsumed observation')
        self.pending = False
        try:
            self.packet = self._observe()
        except BaseException:
            self.finished = True
            raise
        self.prepared = True
        return self.packet

    def _observe(self):
        from .hia_machine_x64 import MachineEncodingError
        opcode, sequence = struct.unpack_from('<2Q', self.workspace, 8)
        a, b, c, d = struct.unpack_from('<4Q', self.workspace, 512)
        value, reg = self.value, self.register
        x = y = z = t = 0
        self.image.observations[opcode] += 1
        if opcode == 1:
            kind = type(value(a))
            # This is an exact primitive type tag, not operand admission.
            kinds = (type(None), bool, int, str, bytes, bytearray, dict, list, tuple)
            x = next((i for i, builtin in enumerate(kinds) if kind is builtin), 9)
            y = reg(kind)
        elif opcode == 2:
            size = len(value(a))
            x, y = reg(size), size
        elif opcode == 3:
            x = reg(getattr(value(a), self._literal(b, c)))
        elif opcode == 4:
            setattr(value(a), self._literal(c, d), value(b))
        elif opcode == 5:
            x = reg(self._literal(a, b))
        elif opcode == 6:
            x = reg({})
        elif opcode == 7:
            x = reg([])
        elif opcode == 8:
            x = reg(bytearray())
        elif opcode == 9:
            x = reg(bytes(value(a)))
        elif opcode == 10:
            x = reg(dict(value(a)))
        elif opcode == 11:
            x = reg(set(value(a)))
        elif opcode == 12:
            x = reg({value(a), value(b)})
        elif opcode == 13:
            x = int(bool(value(a) != value(b)))
        elif opcode == 14:
            x = reg(iter(value(a)))
        elif opcode == 15:
            try:
                item = next(value(a))
            except StopIteration:
                x, y = self.none, 0
            else:
                x, y = reg(item), 1
        elif opcode == 16:
            first, second = value(a)
            x, y = reg(first), reg(second)
        elif opcode == 17:
            x = int(value(b) in value(a))
        elif opcode == 18:
            x = reg(value(a)[value(b)])
        elif opcode == 19:
            value(a)[value(b)] = value(c)
        elif opcode == 20:
            x = reg(value(a) + value(b))
        elif opcode == 21:
            x = reg(value(a) - value(b))
        elif opcode == 22:
            value(a)[value(b):value(c)] = value(d)
        elif opcode == 23:
            x = reg(value(a)())
        elif opcode == 24:
            x = reg(value(a)(value(b)))
        elif opcode == 25:
            x = reg(value(a)(value(b), value(c)))
        elif opcode == 26:
            value(a).append(value(b))
        elif opcode == 27:
            x = reg(a)
        elif opcode == 28:
            # HIA has already admitted the exact integer and signed width.
            # The existing byte bridge invokes the HIA rel32 command.
            x = reg(self.receiver._bytes('rel32', value=value(a)))
        elif opcode == 29:
            raise MachineEncodingError(value(a))
        elif opcode == 30:
            text = value(a)
            if type(text) is not str:
                raise RuntimeError('native Code state string observation type differs')
            x = len(text)
            points = tuple(ord(ch) for ch in text[:3]) + (0, 0, 0)
            y, z, t = points[:3]
        elif opcode == 31:
            number = value(a)
            if type(number) is not int:
                raise RuntimeError('native Code state integer observation type differs')
            x, y, z = number & MASK, int(number < 0), number.bit_length()
        elif opcode == 32:
            x = reg((value(a), value(b)))
        elif opcode == 33:
            x = reg({value(a): value(b), value(c): value(d)})
        elif opcode == 34:
            x = reg(bytearray(value(a)))
        elif opcode == 35:
            if b not in (4, 5):
                raise RuntimeError('native Code state requested an unknown type literal')
            candidate = bytes if b == 4 else bytearray
            observed = value(a)
            # Tuple membership compares the candidate first and includes the
            # foreign metaclass's reflected equality and truth observation.
            x = int(candidate is observed or bool(candidate == observed))
        else:
            raise RuntimeError('unknown native Code state observation opcode')
        return struct.pack('<10Q', MAGIC, opcode, sequence, 0, x, y, z, t, 0, 0)


class NativeMachineState(NativeHiaJsonImage):
    def __init__(self, image, expected_sha256):
        super().__init__(image, expected_sha256)
        self.calls = Counter()
        self.transitions = Counter()
        self.observations = Counter()

    def run(self, receiver, mode, *arguments):
        session = MachineStateSession(self, receiver, mode, *arguments)
        self.calls[MODES[mode - 1]] += 1
        status = session.step()
        while status == 1:
            session.observe()
            status = session.step()
        if status != 0:
            raise RuntimeError('native Code state continuation refused: ' + hex(status))
        handle, = struct.unpack('<Q', session.output)
        return session.value(handle)


@lru_cache(maxsize=3)
def selected_state_code_class(encoding, state):
    from .hia_machine_encoding_native import NativeEncodedCode

    class SelectedStateCode(NativeEncodedCode):
        def __init__(self, *, scratch_registers=None,
                     move_immediate='movabs', alu_immediate='imm32'):
            state.run(self, 1, scratch_registers, move_immediate, alu_immediate)
            self.encoding = encoding

        def emit(self, value):
            return state.run(self, 2, value)

        def label(self, name):
            return state.run(self, 3, name)

        def finalize(self):
            return state.run(self, 4)

        @property
        def offset(self):
            return state.run(self, 5)

        def _reg(self, value):
            return state.run(self, 6, value)

    return SelectedStateCode


def installed_machine_state(manifest_path):
    return _installed_json_image(manifest_path, SOURCE, SCHEMA, NativeMachineState)

"""Primitive observation bridge for HIA Function and Emitter lowering (v2 draft).

This development module contains no Function lowering decisions. HIA chooses
each primitive, operand handle, continuation and branch. Authoring policy and IR
modules are never imported here. Source-bound bundle admission and the ordinary
entry selector are implemented in hia_core_lowering_selection.
"""
from __future__ import annotations

import builtins
import ctypes
import operator
import struct
from types import FunctionType

from .hia_core_compare_native import eligible as _numeric_comparison_eligible
from .hia_core_integer_native import eligible_binary as _integer_binary_eligible
from .hia_core_integer_native import eligible_unary as _integer_unary_eligible

MAGIC = int.from_bytes(b'HIALOW02', 'little')
POOL_MAGIC = int.from_bytes(b'HIALIT01', 'little')
ABI = 0xfffffffd
FRAME = struct.Struct('<16Q')

_BINARY = {
    1: operator.add, 2: operator.sub, 3: operator.mul, 4: operator.floordiv,
    5: operator.truediv, 6: operator.mod, 7: operator.pow, 8: operator.lshift,
    9: operator.rshift, 10: operator.or_, 11: operator.xor, 12: operator.and_,
    129: operator.iadd, 130: operator.isub, 131: operator.imul,
    132: operator.ifloordiv, 133: operator.itruediv, 134: operator.imod,
    135: operator.ipow, 136: operator.ilshift, 137: operator.irshift,
    138: operator.ior, 139: operator.ixor, 140: operator.iand,
}
_COMPARE = {
    1: operator.eq, 2: operator.ne, 3: operator.lt, 4: operator.le,
    5: operator.gt, 6: operator.ge,
}
_UNARY = {1: operator.pos, 2: operator.neg, 3: operator.invert}


def _in(left, right):
    return left in right


def _not_in(left, right):
    return left not in right


_COMPARE.update({7: _in, 8: _not_in})


def _host_unpack(observed, count):
    """Retained opcode-14 value policy, independent of the HIA companion."""
    if count == 1:
        a, = observed
        results = (a,)
    elif count == 2:
        a, b = observed
        results = (a, b)
    elif count == 3:
        a, b, c = observed
        results = (a, b, c)
    elif count == 4:
        a, b, c, d = observed
        results = (a, b, c, d)
    else:
        raise RuntimeError('native lowering unpack arity differs')
    return 0, results


def _decode_pool(raw, expected_count):
    if type(raw) is not bytes or len(raw) < 16:
        raise RuntimeError('native lowering literal packet is missing')
    magic, count = struct.unpack_from('<QQ', raw)
    if magic != POOL_MAGIC or count != expected_count:
        raise RuntimeError('native lowering literal identity differs')
    values, offset = [], 16
    for _ in range(count):
        if offset + 16 > len(raw):
            raise RuntimeError('native lowering literal header is truncated')
        kind, word = struct.unpack_from('<QQ', raw, offset)
        offset += 16
        if kind == 0:
            if word != 0:
                raise RuntimeError('native lowering None literal differs')
            value = None
        elif kind == 1:
            if word > 1:
                raise RuntimeError('native lowering Boolean literal differs')
            value = bool(word)
        elif kind == 2:
            value = word
        elif kind == 3:
            padded = (word + 7) & -8
            if padded > len(raw) - offset:
                raise RuntimeError('native lowering text literal is truncated')
            value = raw[offset:offset + word].decode('utf-8')
            if any(raw[offset + word:offset + padded]):
                raise RuntimeError('native lowering text padding differs')
            offset += padded
        else:
            raise RuntimeError('native lowering literal kind differs')
        values.append(value)
    if offset != len(raw) or len(values) < 3 or values[:3] != [None, False, True]:
        raise RuntimeError('native lowering literal extent differs')
    if type(values[1]) is not bool or type(values[2]) is not bool:
        raise RuntimeError('native lowering Boolean identities differ')
    # Handle identity is essential for HIA's IS primitive. Repeated pool values
    # are invalid; the authoring pool already deduplicates by exact type/value.
    identities = {id(value) for value in values}
    if len(identities) != len(values):
        raise RuntimeError('native lowering literal handles are not distinct')
    return tuple(values)


class LoweringSession:
    """One private, single-use HIA continuation; handles keep objects alive."""

    def __init__(self, owner, mode, arguments):
        if type(mode) is not int or type(arguments) is not tuple or len(arguments) > 6:
            raise TypeError('exact native lowering invocation frame required')
        self.owner = owner
        self.values = [None, *owner.literals]
        self.handles = {id(value): index for index, value in enumerate(self.values) if index}
        self.state = ctypes.create_string_buffer(owner.workspace_bytes)
        self.output = ctypes.create_string_buffer(owner.output_bytes)
        self.input = ctypes.create_string_buffer(128)
        self.unit = 0
        self.status = None
        self.pending = False
        self.finished = False
        self.request = None
        args = tuple(self.register(value) for value in arguments)
        words = (MAGIC, 0, 0, mode, len(args), *args)
        self.initial = FRAME.pack(*words, *([0] * (16 - len(words))))

    def register(self, value):
        identity = id(value)
        previous = self.handles.get(identity)
        if previous is not None:
            if self.values[previous] is not value:
                raise RuntimeError('native lowering handle identity was reused')
            return previous
        handle = len(self.values)
        if handle >= 1 << 64:
            raise OverflowError('native lowering foreign handle extent exceeded')
        self.values.append(value)
        self.handles[identity] = handle
        return handle

    def value(self, handle):
        if type(handle) is not int or not 0 < handle < len(self.values):
            raise RuntimeError('native lowering requested an unknown object')
        return self.values[handle]

    def _close(self):
        self.finished, self.pending, self.request = True, False, None

    def step(self, packet):
        if self.finished:
            raise RuntimeError('native lowering session is closed')
        if type(packet) is not bytes or len(packet) != 128:
            self._close()
            raise TypeError('exact 128-byte native lowering packet required')
        # Successful one-shot observations consume their permission before they
        # return a packet. Raw ABI controls may submit packets directly; HIA is
        # still responsible for rejecting wrong phases, sequences and counts.
        self.pending = False
        try:
            ctypes.memmove(self.input, packet, 128)
            result = self.owner.images[self.unit]._entry(
                self.input, 128, self.output, len(self.output), self.state, len(self.state))
            if result not in (0, 1, 2, 3):
                raise RuntimeError('native lowering protocol refusal: ' + hex(result))
            header = struct.unpack_from('<16Q', self.output)
            if header[0] != MAGIC:
                raise RuntimeError('native lowering output identity differs')
            if result == 0:
                if header[2] != 0:
                    raise RuntimeError('native lowering return framing differs')
                returned = self.value(header[3])
                self.status, self.returned = 0, returned
                self._close()
                return 0
            if result == 3:
                if header[2] != 20:
                    raise RuntimeError('native lowering yield framing differs')
                self.yielded = self.value(header[3])
                self.request = header
            elif result == 2:
                if header[2] != 21 or header[3] >= len(self.owner.images):
                    raise RuntimeError('native lowering handoff framing differs')
                self.request = header
            else:
                opcode, count, vector_count, results = header[2:6]
                if not 1 <= opcode <= 19 or count > 8 or results > 4:
                    raise RuntimeError('native lowering primitive framing differs')
                if 128 + vector_count * 8 > len(self.output):
                    raise RuntimeError('native lowering vector exceeds private output')
                vector = struct.unpack_from('<' + 'Q' * vector_count, self.output, 128)
                self.request = (header, vector)
            self.status, self.pending = result, True
            return result
        except BaseException:
            self._close()
            raise

    def handoff(self):
        if self.finished or not self.pending or self.status != 2:
            self._close()
            raise RuntimeError('native lowering handoff is not pending')
        self.pending = False
        try:
            header = self.request
            self.unit = header[3]
            return FRAME.pack(MAGIC, 2, header[1], self.unit, *([0] * 12))
        except BaseException:
            self._close()
            raise

    def resume(self):
        if self.finished or not self.pending or self.status != 3:
            self._close()
            raise RuntimeError('native lowering generator resume is not pending')
        self.pending = False
        try:
            header = self.request
            return FRAME.pack(MAGIC, 3, header[1], self.unit, *([0] * 12))
        except BaseException:
            self._close()
            raise

    def observe(self):
        if self.finished or not self.pending or self.status != 1:
            self._close()
            raise RuntimeError('native lowering observation is not pending')
        # Consume before attribute access/calls. A failing foreign observation
        # cannot be replayed, including KeyboardInterrupt/SystemExit/MemoryError.
        self.pending = False
        try:
            header, vector = self.request
            opcode, count, nvector, nresults = header[2:6]
            args = header[8:8 + count]
            if opcode != 7 and vector:
                raise RuntimeError('native lowering unexpected primitive vector')
            flag, results = self._primitive(opcode, args, vector)
            if len(results) != nresults or flag not in (0, 1):
                raise RuntimeError('native lowering primitive result shape differs')
            handles = tuple(self.register(value) for value in results)
            words = (MAGIC, 1, header[1], len(handles), flag, *handles)
            return FRAME.pack(*words, *([0] * (16 - len(words))))
        except BaseException:
            self._close()
            raise

    def _primitive(self, opcode, args, vector):
        get = self.value
        if opcode == 1:  # global name selected by HIA
            name, = args
            return 0, (self.owner.global_value(get(name)),)
        if opcode == 2:
            value, name = args
            return 0, (getattr(get(value), get(name)),)
        if opcode == 3:
            value, name, assigned = args
            setattr(get(value), get(name), get(assigned))
            return 0, ()
        if opcode == 4:
            value, key = args
            return 0, (get(value)[get(key)],)
        if opcode == 5:
            value, key, assigned = args
            get(value)[get(key)] = get(assigned)
            return 0, ()
        if opcode == 6:
            callee, argc, a, b, c, d, key, value = args
            if argc > 4:
                raise RuntimeError('native lowering call arity differs')
            target = get(callee)
            positional = tuple(get(v) for v in (a, b, c, d)[:argc])
            if key == 0:
                # A HIA-selected CALL_EX observation. Do not inspect or copy
                # the mapping before CPython applies its own keyword protocol.
                result = target(*positional, **get(value))
            else:
                keyword = get(key)
                if keyword is None:
                    result = target(*positional)
                else:
                    result = target(*positional, **{keyword: get(value)})
            return 0, (result,)
        if opcode == 7:
            kind, count = args
            if count != len(vector):
                raise RuntimeError('native lowering collection extent differs')
            values = tuple(get(value) for value in vector)
            if kind == 1:
                result = list(values)
            elif kind == 2:
                result = values
            elif kind == 3:
                result = set(values)
            elif kind == 4:
                if count % 2:
                    raise RuntimeError('native lowering dictionary extent differs')
                result = {}
                for i in range(0, count, 2):
                    result[values[i]] = values[i + 1]
            else:
                raise RuntimeError('native lowering collection kind differs')
            return 0, (result,)
        if vector:
            raise RuntimeError('native lowering unexpected vector')
        if opcode == 8:
            value, = args
            return 0, (iter(get(value)),)
        if opcode == 9:
            value, = args
            try:
                result = next(get(value))
            except StopIteration:
                return 0, (None,)
            return 1, (result,)
        if opcode == 10:
            value, = args
            return int(bool(get(value))), ()
        if opcode == 11:
            operation, left, right = args
            if self.owner.integer is not None:
                # Match original callable lookup, left read, right read order.
                # The eligibility guard never re-reads operands or the registry.
                target = _BINARY[operation]
                observed_left = get(left)
                observed_right = get(right)
                if _integer_binary_eligible(operation, target, observed_left, observed_right):
                    return 0, (self.owner.integer.binary(operation, observed_left, observed_right),)
                return 0, (target(observed_left, observed_right),)
            return 0, (_BINARY[operation](get(left), get(right)),)
        if opcode == 12:
            operation, value = args
            if self.owner.integer is not None:
                target = _UNARY[operation]
                observed = get(value)
                if _integer_unary_eligible(operation, target, observed):
                    return 0, (self.owner.integer.unary(operation, observed),)
                return 0, (target(observed),)
            return 0, (_UNARY[operation](get(value)),)
        if opcode == 13:
            operation, left, right = args
            if self.owner.numeric_compare is not None:
                # The target lookup precedes both original operand reads.
                # A callback changing the registry during get cannot replace
                # that already-bound callable. Each get still occurs once.
                target = _COMPARE[operation]
                observed_left = get(left)
                observed_right = get(right)
                if _numeric_comparison_eligible(operation, target, observed_left, observed_right):
                    return 0, (self.owner.numeric_compare.compare(
                        operation, observed_left, observed_right),)
                return 0, (target(observed_left, observed_right),)
            return 0, (_COMPARE[operation](get(left), get(right)),)
        if opcode == 14:
            value, count = args
            observed = get(value)
            if self.owner.unpack is not None:
                return 0, self.owner.unpack.unpack(observed, count)
            return _host_unpack(observed, count)
        if opcode == 15:
            low, high, step = args
            return 0, (slice(get(low), get(high), get(step)),)
        if opcode == 16:
            value, item = args
            list.append(get(value), get(item))
            return 0, ()
        if opcode == 17:
            kind, = args
            if kind == 1:
                from .hia_machine_plan import VALUE_REGISTERS
                result = VALUE_REGISTERS
            elif kind == 2:
                from .hia_machine_plan import code_options
                result = code_options
            elif kind == 3:
                from .hia_native_byte_abi import emit_wrapper
                result = emit_wrapper
            else:
                raise RuntimeError('native lowering import framing differs')
            return 0, (result,)
        if opcode == 18:
            value, = args
            raise get(value)
        if opcode == 19:
            name, iterator = args
            return 0, (self.owner.generator(get(name), get(iterator)),)
        raise RuntimeError('native lowering unknown primitive')

    def advance(self, packet):
        while True:
            status = self.step(packet)
            if status in (0, 3):
                return status
            packet = self.handoff() if status == 2 else self.observe()

    def run(self):
        status = self.advance(self.initial)
        if status != 0:
            self._close()
            raise RuntimeError('ordinary lowering method unexpectedly yielded')
        return self.returned


class NativeCoreLowering:
    """Composition of admitted images and explicitly hosted object primitives."""

    def __init__(self, images, pool, abi, namespace, *, unpack=None, numeric_compare=None, integer=None):
        if type(abi) is not dict or abi.get('schema') != 'hepta.hia.core-lowering-abi.v2':
            raise ValueError('native lowering ABI metadata differs')
        if abi.get('protocol_magic') != MAGIC or abi.get('pool_magic') != POOL_MAGIC or abi.get('packet_bytes') != 128:
            raise ValueError('native lowering protocol identity differs')
        self.images = tuple(images)
        if not self.images or len(self.images) != len(abi['units']):
            raise ValueError('native lowering image inventory differs')
        self.workspace_bytes, self.output_bytes = abi['workspace_bytes'], abi['output_bytes']
        if (type(self.workspace_bytes) is not int or type(self.output_bytes) is not int
                or self.workspace_bytes < 1024 or self.output_bytes < 128):
            raise ValueError('native lowering private extents differ')
        self.modes = abi['modes']
        self.generator_modes = tuple(abi['generator_modes'])
        self.namespace = namespace
        self.unpack = unpack
        self.numeric_compare = numeric_compare
        self.integer = integer
        output = ctypes.create_string_buffer(abi['pool_bytes'])
        empty = ctypes.create_string_buffer(1)
        count = pool._entry(empty, 0, output, len(output), empty, 0)
        if count != abi['pool_bytes']:
            raise RuntimeError('native lowering literal image refused')
        self.literals = _decode_pool(ctypes.string_at(output, count), abi['literal_count'])
        self._classes = {}
        self._emitter_classes = {}
        # These wrappers bind the original helper signatures; every body is
        # another HIA invocation, never the retained helper implementation.
        def reject(message, code='E_HIA_PROGRAM_NATIVE'):
            return self.invoke('_reject', (message, code))
        def words(typ):
            return self.invoke('_words', (typ,))
        def bounds(typ):
            return self.invoke('_bounds', (typ,))
        def normalize(code, reg, typ):
            return self.invoke('_normalize', (code, reg, typ))
        def prologue(code, frame):
            return self.invoke('_prologue', (code, frame))
        self._helpers = {'_reject': reject, '_words': words, '_bounds': bounds,
                         '_normalize': normalize, '_prologue': prologue}
        for name, helper in self._helpers.items():
            helper.__qualname__ = name

    def global_value(self, name):
        # Private helper replacement is not a runtime fallback. Remaining module
        # globals are observed at the HIA-selected original lookup point.
        if name in self._helpers:
            return self._helpers[name]
        if name in self.namespace:
            return self.namespace[name]
        try:
            return getattr(builtins, name)
        except AttributeError:
            raise NameError("name '" + name + "' is not defined") from None

    def invoke(self, name, arguments):
        mode = self.modes[name]
        if len(arguments) != mode['arity']:
            raise RuntimeError('native lowering bound argument count differs')
        return LoweringSession(self, mode['number'], arguments).run()

    def generator(self, name, iterator):
        if name not in self.generator_modes or self.modes[name]['arity'] != 1:
            raise RuntimeError('native lowering generator mode differs')
        session = LoweringSession(self, self.modes[name]['number'], (iterator,))

        def suspended():
            # This Python object implements generator suspension/throw/close
            # only. All NEXT, body lookups, yields and termination are selected
            # by HIA. In particular a body StopIteration crosses this real
            # generator frame and therefore follows CPython's PEP479 behavior.
            packet = session.initial
            try:
                while True:
                    status = session.advance(packet)
                    if status == 0:
                        if session.returned is not None:
                            raise RuntimeError('native generator returned a foreign terminal value')
                        return
                    yield session.yielded
                    packet = session.resume()
            finally:
                session._close()

        return suspended()

    def function_class(self, base):
        previous = self._classes.get(base)
        if previous is not None:
            return previous
        owner = self

        class Function(base):
            def __init__(self, parent, fn, index):
                owner.invoke('_Function.__init__', (self, parent, fn, index))

            def allocate(self, words):
                return owner.invoke('_Function.allocate', (self, words))

            def label(self, suffix):
                return owner.invoke('_Function.label', (self, suffix))

            def block_label(self, name):
                return owner.invoke('_Function.block_label', (self, name))

            def load(self, name, reg='rax', word=0):
                return owner.invoke('_Function.load', (self, name, reg, word))

            def store(self, name, reg='rax', word=0):
                return owner.invoke('_Function.store', (self, name, reg, word))

            def immediate(self, name, value, word=0):
                return owner.invoke('_Function.immediate', (self, name, value, word))

            def copy(self, source, destination):
                return owner.invoke('_Function.copy', (self, source, destination))

            def fail_if(self, condition):
                return owner.invoke('_Function.fail_if', (self, condition))

            def compare_imm(self, register, value):
                return owner.invoke('_Function.compare_imm', (self, register, value))

            def range_check(self, register, typ, source=None):
                return owner.invoke('_Function.range_check', (self, register, typ, source))

            def narrow_result(self, typ, checked=False):
                return owner.invoke('_Function.narrow_result', (self, typ, checked))

            def condition_value(self, condition):
                return owner.invoke('_Function.condition_value', (self, condition))

            def edge(self, target, arguments):
                return owner.invoke('_Function.edge', (self, target, arguments))

            def operation(self, ins):
                return owner.invoke('_Function.operation', (self, ins))

            def allocate_buffer(self, size, out, trapping):
                return owner.invoke('_Function.allocate_buffer', (self, size, out, trapping))

            def range_guard(self, buffer, offset, size):
                return owner.invoke('_Function.range_guard', (self, buffer, offset, size))

            def bulk(self, op, args):
                return owner.invoke('_Function.bulk', (self, op, args))

            def push_chain(self, args, out):
                return owner.invoke('_Function.push_chain', (self, args, out))

            def pop_chain(self, arg, out):
                return owner.invoke('_Function.pop_chain', (self, arg, out))

            def drop_chain(self, arg):
                return owner.invoke('_Function.drop_chain', (self, arg))

            def render(self):
                return owner.invoke('_Function.render', (self,))

        # Keep CPython's original binding-error names without entering any
        # original method. All successfully bound bodies still invoke HIA.
        for name, method in vars(Function).items():
            if type(method) is FunctionType:
                method.__qualname__ = '_Function.' + name
        self._classes[base] = Function
        return Function

    def emitter_class(self, base):
        previous = self._emitter_classes.get(base)
        if previous is not None:
            return previous
        owner = self

        class Emitter(base):
            def __init__(self, document, allowed_exports, block_order=None,
                         foreign_buffer_exports=(), machine_plan=None):
                owner.invoke('_Emitter.__init__', (self, document, allowed_exports,
                    block_order, foreign_buffer_exports, machine_plan))

            def ordered_blocks(self, fn):
                return owner.invoke('_Emitter.ordered_blocks', (self, fn))

            def label(self, suffix):
                return owner.invoke('_Emitter.label', (self, suffix))

            def function_symbol(self, name):
                return owner.invoke('_Emitter.function_symbol', (self, name))

            def wrapper(self, fn):
                return owner.invoke('_Emitter.wrapper', (self, fn))

            def render(self):
                return owner.invoke('_Emitter.render', (self,))

        for name, method in vars(Emitter).items():
            if type(method) is FunctionType:
                method.__qualname__ = '_Emitter.' + name
        self._emitter_classes[base] = Emitter
        return Emitter

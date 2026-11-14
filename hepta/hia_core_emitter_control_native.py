"""Fixed object ports for all six HIA-owned Core emitter methods.

The HIA image owns the full method control table, effect permission, temporary
and named-local retirement, and generator suspension. These ports perform the
selected foreign operation; none calls an original emitter policy body.
"""
from __future__ import annotations

import dis
import sys
from types import FunctionType

from .hia_core_lowering_control_native import LoweringSession, NativeCoreLowering
from .hia_machine_plan_control_native import _Cell
from .hia_json_preflight_native import _source_resource_path

SOURCE = _source_resource_path('examples/hia_bootstrap/core_emitter.hepta')
SCHEMA = 'hepta.hia.core-emitter-control-native.v1'
SELECTOR = 'HEPTA_HIA_CORE_EMITTER_CONTROL_MANIFEST'

_ARITIES = {
    '_Emitter.__init__': 6,
    '_Emitter.ordered_blocks': 2,
    '_Emitter.label': 2,
    '_Emitter.function_symbol': 2,
    '_Emitter.wrapper': 2,
    '_Emitter.render': 1,
    '_native_globals': 0,
}


def _mapping_template(frame, callee_slot, mapping_slot):
    return frame._get(callee_slot)(**frame._get(mapping_slot))


def _mapping_merge_primitive():
    """Expose exactly CPython's DICT_MERGE as a fixed representation port.

    The compiler-generated primitive supplies the real callable used by the
    interpreter's duplicate-key and non-mapping diagnostics. Its suffix only
    pops the three call-stack scaffolding values and returns the exact dict.
    No business source is compiled or interpreted. Only three reviewed CPython
    ABIs and this one straight-line template are admitted.

    Named parameters contain the frame and slot numbers, never a borrowed
    callable or mapping. An error traceback therefore cannot add a hidden
    reference to a policy temporary. HIA retires the mapping after this effect
    and separately authorizes transfer of the prepared dict into the call.
    """
    if sys.implementation.name != 'cpython' or sys.version_info[:2] not in ((3, 12), (3, 13), (3, 14)):
        raise RuntimeError('native Core emitter keyword port requires a reviewed CPython ABI')
    code = _mapping_template.__code__
    instructions = tuple(dis.get_instructions(code, show_caches=True, adaptive=False))
    meaningful = tuple(item for item in instructions if item.opname != 'CACHE')
    merges = tuple(item for item in meaningful if item.opname == 'DICT_MERGE')
    calls = tuple(item for item in meaningful if item.opname == 'CALL_FUNCTION_EX')
    nulls = tuple(item for item in meaningful if item.opname == 'PUSH_NULL')
    allowed = {'RESUME', 'PUSH_NULL', 'LOAD_FAST', 'LOAD_FAST_BORROW',
               'LOAD_FAST_BORROW_LOAD_FAST_BORROW', 'LOAD_ATTR', 'LOAD_CONST',
               'CALL', 'BUILD_MAP', 'DICT_MERGE', 'CALL_FUNCTION_EX', 'RETURN_VALUE'}
    if (code.co_exceptiontable or len(merges) != 1 or len(calls) != 1 or len(nulls) != 1
            or merges[0].arg != 1 or code.co_consts != (None, ())
            or tuple(item.opname for item in meaningful[-3:]) !=
               ('DICT_MERGE', 'CALL_FUNCTION_EX', 'RETURN_VALUE')
            or any(item.opname not in allowed for item in meaningful)):
        raise RuntimeError('native Core emitter keyword opcode template differs')
    raw = bytearray(code.co_code[:calls[0].offset])
    # None has the same inert stack position as NULL, while permitting the
    # balanced POP_TOP suffix on every reviewed interpreter profile.
    raw[nulls[0].offset:nulls[0].offset + 2] = bytes((dis.opmap['LOAD_CONST'], 0))
    raw.extend(bytes((dis.opmap['SWAP'], 2, dis.opmap['POP_TOP'], 0)) * 3)
    raw.extend(bytes((dis.opmap['RETURN_VALUE'], 0)))
    primitive = FunctionType(code.replace(co_code=bytes(raw),
        co_name='_merge_mapping', co_qualname='_merge_mapping'), globals())
    if any(item.opname == 'CALL_FUNCTION_EX' for item in dis.get_instructions(primitive)):
        raise RuntimeError('native Core emitter keyword preparation still invokes a callable')
    return primitive


_MAPPING_NOT_LOADED = object()
_MAPPING_MODULE_NAMESPACE = globals()
_merge_mapping = _MAPPING_NOT_LOADED


def _load_mapping_primitive():
    """Admit the fixed ABI only for an explicit native factory.

    Preserve a caller replacement, None, or deletion of the original
    mutable global. The already-claimed CALL still reads that global.
    """
    global _merge_mapping
    if _MAPPING_MODULE_NAMESPACE.get("_merge_mapping") is _MAPPING_NOT_LOADED:
        _merge_mapping = _mapping_merge_primitive()


class EmitterFrame(LoweringSession):
    def _move_call_operand(self, slot):
        # This fixed move is part of an already claimed HIA CALL permission.
        # The CPython operand stack now owns the value; the later native ACK
        # retires an empty slot and cannot replay the foreign operation.
        value = self._get(slot)
        self._clear(slot)
        return value

    def _call(self, args, raw):
        if raw == (0, 254):
            if len(args) != 2:
                raise RuntimeError('native Core emitter mapping-prepare representation differs')
            return _merge_mapping(self, args[0], args[1])
        if raw == (0, 255):
            if len(args) != 2:
                raise RuntimeError('native Core emitter mapping-call representation differs')
            if type(self._get(args[1])) is not dict:
                raise RuntimeError('native Core emitter mapping call lacks its prepared exact dict')
            return self._move_call_operand(args[0])(**self._move_call_operand(args[1]))
        count, keywords = raw[:2]
        if len(args) != 1 + count + keywords or len(raw) != 2 + keywords:
            raise RuntimeError('native Core emitter call operand inventory differs')
        # These are the temporary call operands named by the already claimed
        # HIA instruction. Transfer them to CPython instead of adding a second
        # reference through the complete call. In particular, 3.14 can retire
        # a Python method's name argument before its temporary receiver.
        if keywords == 0:
            if count == 0:
                return self._move_call_operand(args[0])()
            if count == 1:
                return self._move_call_operand(args[0])(self._move_call_operand(args[1]))
            if count == 2:
                return self._move_call_operand(args[0])(self._move_call_operand(args[1]), self._move_call_operand(args[2]))
            if count == 3:
                return self._move_call_operand(args[0])(self._move_call_operand(args[1]), self._move_call_operand(args[2]), self._move_call_operand(args[3]))
            if count == 4:
                return self._move_call_operand(args[0])(self._move_call_operand(args[1]), self._move_call_operand(args[2]), self._move_call_operand(args[3]), self._move_call_operand(args[4]))
        return self._move_call_operand(args[0])(
            *(self._move_call_operand(args[index + 1]) for index in range(count)),
            **{self.image.literal(raw[2 + index]): self._move_call_operand(args[1 + count + index])
               for index in range(keywords)})

    def _effect(self):
        op, destinations, args, raw, vector = self._parts()
        if op == 19:
            if len(raw) != 1 or args or vector or len(destinations) != 1:
                raise RuntimeError('native Core emitter import representation differs')
            name = self.image.literal(raw[0])
            if name == 'code_options':
                from .hia_machine_plan import code_options
                self._set(destinations[0], code_options)
            elif name == 'emit_wrapper':
                from .hia_native_byte_abi import emit_wrapper
                self._set(destinations[0], emit_wrapper)
            else:
                raise RuntimeError('native Core emitter import is outside its fixed inventory')
            return 0
        return super()._effect()

    def _function(self, args, raw, vector):
        mode, generator = raw
        captures = tuple(self.values[slot] for slot in vector)
        if any(type(cell) is not _Cell for cell in captures):
            raise RuntimeError('native Core emitter captured a non-cell')
        if generator:
            frame = EmitterFrame(self.image, mode, (self._get(args[0]),), captures,
                                 witness=self.witness)
            def native_generator():
                value = None
                try:
                    while True:
                        value = None
                        status = frame.drive()
                        if status == 0:
                            return
                        value = frame.take(yielded=True)
                        yield value
                finally:
                    value = None
            return native_generator()
        image, witness = self.image, self.witness
        def native_function(*arguments):
            frame = EmitterFrame(image, mode, arguments, captures, witness=witness)
            arguments = None
            return image.finish(frame)
        return native_function


class NativeCoreEmitter(NativeCoreLowering):
    def _bind_namespace(self, namespace):
        _load_mapping_primitive()
        if namespace is None:
            from . import hia_program_native
            namespace = vars(hia_program_native)
        if type(namespace) is not dict:
            raise TypeError('native Core emitter requires an actual module namespace')
        self.namespace = namespace
        self.modes = {name: {'number': index, 'arity': arity}
                      for index, (name, arity) in enumerate(_ARITIES.items(), 1)}
        if self.function_count < len(self.modes):
            raise RuntimeError('native Core emitter complete entry inventory differs')
        for spec in self.modes.values():
            if self.function(spec['number'])[2] != spec['arity']:
                raise RuntimeError('native Core emitter entry arity differs')
        self._helpers, self._classes = {}, {}

    def prepare(self, name, arguments):
        mode = self.modes[name]
        if type(arguments) is not tuple or len(arguments) != mode['arity']:
            raise TypeError('native Core emitter bound argument count differs')
        return EmitterFrame(self, mode['number'], arguments)

    def run(self, mode, *arguments, _captures=(), _witness=None):
        frame = EmitterFrame(self, mode, arguments, _captures, witness=_witness)
        arguments = _captures = None
        return self.finish(frame)

    def emitter_class(self, base):
        previous = self._classes.get(base)
        if previous is not None:
            return previous
        owner = self

        class Emitter(base):
            def __init__(self, document, allowed_exports, block_order=None,
                         foreign_buffer_exports=(), machine_plan=None):
                frame = owner.prepare('_Emitter.__init__',
                    (self, document, allowed_exports, block_order, foreign_buffer_exports, machine_plan))
                self = document = allowed_exports = block_order = foreign_buffer_exports = machine_plan = None
                owner.finish(frame)

            def ordered_blocks(self, fn):
                frame = owner.prepare('_Emitter.ordered_blocks', (self, fn))
                self = fn = None
                return owner.finish(frame)

            def label(self, suffix):
                frame = owner.prepare('_Emitter.label', (self, suffix))
                self = suffix = None
                return owner.finish(frame)

            def function_symbol(self, name):
                frame = owner.prepare('_Emitter.function_symbol', (self, name))
                self = name = None
                return owner.finish(frame)

            def wrapper(self, fn):
                frame = owner.prepare('_Emitter.wrapper', (self, fn))
                self = fn = None
                return owner.finish(frame)

            def render(self):
                frame = owner.prepare('_Emitter.render', (self,))
                self = None
                return owner.finish(frame)

        Emitter.__name__, Emitter.__qualname__, Emitter.__module__ = base.__name__, base.__qualname__, base.__module__
        for name, method in vars(Emitter).items():
            if hasattr(method, '__code__'):
                method.__qualname__, method.__module__ = base.__qualname__ + '.' + name, base.__module__
        self._classes[base] = Emitter
        return Emitter

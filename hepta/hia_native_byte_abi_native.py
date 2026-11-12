"""Fixed object ports for the complete HIA borrowed-byte ABI controller.

HIA owns the two original functions, their load closure, the three closed
lowering helpers, short-circuit decisions and operand/frame retirement. Python
performs individual object/Code operations using the shared issued/claim/ACK
protocol. No authoring module or retained byte-ABI body is a runtime dependency.
"""
from __future__ import annotations

import builtins
import sys

from .hia_json_preflight_native import _source_resource_path
from .hia_machine_plan_control_native import PlanFrame, NativeMachinePlanControl, _Cell
from . import hia_native_byte_abi_foreign as foreign

SOURCE = _source_resource_path('examples/hia_bootstrap/native_byte_abi.hiaasm')
SCHEMA = 'hepta.hia.native-byte-abi-native.v1'
SELECTOR = 'HEPTA_HIA_NATIVE_BYTE_ABI_MANIFEST'
ARITIES = {'normalize_exports': 2, 'emit_wrapper': 3,
           '_reject': 2, '_normalize': 3, '_prologue': 2}
_IMPORTS = {
    'hia_program': frozenset(('SCALARS',)),
    'hia_program_native': frozenset(('IMPORTS', '_LOADER_HOOKS', '_reject',
                                   'MAX_FRAME_BYTES', '_ARG_REGS', '_normalize', '_prologue')),
}


class ByteABIFrame(PlanFrame):
    def _move_call_operand(self, slot):
        # HIA has already claimed this exact CALL. Its table marks every call
        # operand as a unique consumed temporary. Transfer that owned reference
        # onto the actual CPython stack; the later ACK retires an empty slot.
        # Holding a second reference through the call would delay 3.14 Python
        # parameter/receiver retirement and change observable finalizer order.
        value = self._get(slot)
        self._clear(slot)
        return value

    def _call(self, args, raw):
        if len(raw) != 2 or raw[1] != 0 or not 0 <= raw[0] <= 4 or len(args) != raw[0] + 1:
            raise RuntimeError('native byte ABI fixed call operand inventory differs')
        count = raw[0]
        if count == 0:
            return self._move_call_operand(args[0])()
        if count == 1:
            return self._move_call_operand(args[0])(self._move_call_operand(args[1]))
        if count == 2:
            return self._move_call_operand(args[0])(self._move_call_operand(args[1]), self._move_call_operand(args[2]))
        if count == 3:
            return self._move_call_operand(args[0])(self._move_call_operand(args[1]), self._move_call_operand(args[2]), self._move_call_operand(args[3]))
        return self._move_call_operand(args[0])(self._move_call_operand(args[1]), self._move_call_operand(args[2]), self._move_call_operand(args[3]), self._move_call_operand(args[4]))

    def _global(self, name):
        namespace = self.image.backend_namespace if self.mode in (3, 4, 5) else self.image.namespace
        if name in namespace:
            if (namespace is self.image.backend_namespace and name in self.image._helpers
                    and namespace[name] is self.image.public_entries[name]):
                return self.image._helpers[name]
            return namespace[name]
        if name in vars(builtins):
            return vars(builtins)[name]
        raise NameError("name '" + name + "' is not defined", name=name)

    def _function(self, args, raw, vector):
        mode, generator = raw
        captures = tuple(self.values[slot] for slot in vector)
        if any(type(cell) is not _Cell for cell in captures):
            raise RuntimeError('native byte ABI closure captured a non-cell')
        if generator:
            frame = ByteABIFrame(self.image, mode, (self._get(args[0]),), captures)
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
        image = self.image
        def native_function(*arguments):
            frame = ByteABIFrame(image, mode, arguments, captures)
            arguments = None
            return image.finish(frame)
        return native_function

    def _effect(self):
        op, destinations, args, raw, vector = self._parts()
        if op == 19:
            if len(raw) < 2 or vector or len(destinations) != 1:
                raise RuntimeError('native byte ABI import representation differs')
            if raw[0] == 0 and not args:
                module = self.image.literal(raw[1])
                names = tuple(self.image.literal(index) for index in raw[2:])
                if module not in _IMPORTS or any(name not in _IMPORTS[module] for name in names):
                    raise RuntimeError('native byte ABI import is outside its fixed foreign ports')
                port = self.image._import_names.get((module, names))
                if port is None:
                    raise RuntimeError('native byte ABI import group differs')
                self._set(destinations[0], port())
            elif raw[0] == 1 and len(raw) == 2 and len(args) == 1:
                name = self.image.literal(raw[1])
                port = self.image._import_from.get(name)
                if port is None:
                    raise RuntimeError('native byte ABI imported name differs')
                value = port(self._get(args[0]))
                if name in self.image._helpers and value is self.image.public_entries[name]:
                    value = self.image._helpers[name]
                self._set(destinations[0], value)
                value = None
            else:
                raise RuntimeError('native byte ABI import phase differs')
            return 0
        return super()._effect()


class NativeByteABI(NativeMachinePlanControl):
    def __init__(self, image, expected_sha256, namespace=None):
        super().__init__(image, expected_sha256)
        self._bind_namespace(namespace)

    def _bind_namespace(self, namespace=None):
        from . import hia_native_byte_abi, hia_program_native
        if namespace is None:
            namespace = vars(hia_native_byte_abi)
        if type(namespace) is not dict:
            raise TypeError('native byte ABI requires its actual module namespace')
        self.namespace, self.backend_namespace = namespace, vars(hia_program_native)
        self.public_entries = vars(hia_program_native)['_NATIVE_CORE_PUBLIC_ENTRIES']
        self._import_names, self._import_from = foreign.import_ports(namespace)
        self.modes = {name: (number, arity)
                      for number, (name, arity) in enumerate(ARITIES.items(), 1)}
        for number, arity in self.modes.values():
            if self.function(number)[2] != arity:
                raise RuntimeError('native byte ABI entry arity differs')
        def reject(message, code='E_HIA_PROGRAM_NATIVE'):
            frame = self.prepare('_reject', (message, code))
            message = code = None
            return self.finish(frame)
        def normalize(code, reg, typ):
            frame = self.prepare('_normalize', (code, reg, typ))
            code = reg = typ = None
            return self.finish(frame)
        def prologue(code, frame):
            invocation = self.prepare('_prologue', (code, frame))
            code = frame = None
            return self.finish(invocation)
        self._helpers = {'_reject': reject, '_normalize': normalize, '_prologue': prologue}
        for name, function in self._helpers.items():
            function.__name__ = function.__qualname__ = name
            function.__module__ = self.public_entries[name].__module__

    def prepare(self, name, arguments, captures=(), *, witness=None):
        if type(name) is str:
            mode, arity = self.modes[name]
            if type(arguments) is not tuple or len(arguments) != arity:
                raise TypeError('native byte ABI argument arity differs')
        else:
            mode = name
        return ByteABIFrame(self, mode, arguments, captures, witness=witness)

    def finish(self, frame):
        completed = False
        try:
            if frame.drive() != 0:
                raise RuntimeError('native byte ABI public entry yielded')
            completed = True
            return frame.take()
        except BaseException:
            completed = False
            raise
        finally:
            frame.close(release=completed)

    def run(self, mode, *arguments, _captures=(), _witness=None):
        frame = self.prepare(mode, arguments, _captures, witness=_witness)
        arguments = _captures = None
        return self.finish(frame)

    def normalize_exports(self, exports, program):
        frame = self.prepare('normalize_exports', (exports, program))
        exports = program = None
        return self.finish(frame)

    def emit_wrapper(self, emitter, fn, extent):
        frame = self.prepare('emit_wrapper', (emitter, fn, extent))
        emitter = fn = extent = None
        return self.finish(frame)


def installed_native_byte_abi(manifest_path):
    from .hia_native_byte_abi_selection import installed_native_byte_abi as admitted
    return admitted(manifest_path)

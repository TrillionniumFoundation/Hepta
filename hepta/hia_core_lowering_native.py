"""Fixed object ports for the complete native Core `_Function` controller.

The same HIA continuation protocol used by machine-plan control owns every
branch, generator suspension, temporary lifetime and callback permission.
This module adds only attribute assignment, the original register import and
bound entry-point representation. No retained lowering body is called.
"""
from __future__ import annotations

import builtins
import sys

from .hia_machine_plan_control_native import (
    PlanFrame, NativeMachinePlanControl, _Cell, _EMPTY)
from .hia_json_preflight_native import _source_resource_path

SOURCE = _source_resource_path('examples/hia_bootstrap/core_lowering.hiaasm')
SCHEMA = 'hepta.hia.core-lowering-native.v2'
SELECTOR = 'HEPTA_HIA_CORE_LOWERING_MANIFEST'


_ARITIES = {
    '_reject': 2, '_words': 1, '_bounds': 1, '_normalize': 3, '_prologue': 2,
    '_Function.__init__': 4, '_Function.allocate': 2, '_Function.label': 2,
    '_Function.block_label': 2, '_Function.load': 4, '_Function.store': 4,
    '_Function.immediate': 4, '_Function.copy': 3, '_Function.fail_if': 2,
    '_Function.compare_imm': 3, '_Function.range_check': 4, '_Function.narrow_result': 3,
    '_Function.condition_value': 2, '_Function.edge': 3, '_Function.operation': 2,
    '_Function.allocate_buffer': 4, '_Function.range_guard': 4, '_Function.bulk': 3,
    '_Function.push_chain': 3, '_Function.pop_chain': 3, '_Function.drop_chain': 2,
    '_Function.render': 1, '_native_globals': 0,
}


class LoweringSession(PlanFrame):
    """Private Core frame; all permission and retirement rules are shared."""

    def _global(self, name):
        if name in self.image._helpers:
            return self.image._helpers[name]
        namespace = self.image.namespace
        if name in namespace:
            return namespace[name]
        try:
            return vars(builtins)[name]
        except KeyError:
            raise NameError("name '" + name + "' is not defined") from None

    def _function(self, args, raw, vector):
        mode, generator = raw
        captures = tuple(self.values[slot] for slot in vector)
        if any(type(cell) is not _Cell for cell in captures):
            raise RuntimeError('native Core lowering captured a non-cell')
        if generator:
            frame = LoweringSession(self.image, mode, (self._get(args[0]),), captures,
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
            frame = LoweringSession(image, mode, arguments, captures, witness=witness)
            arguments = None
            return image.finish(frame)
        return native_function

    def _effect(self):
        op, destinations, args, raw, vector = self._parts()
        if op == 14 and raw:
            if len(raw) != 2 or raw[0] != 1 or len(args) != 2 or destinations or vector:
                raise RuntimeError('native Core attribute-store representation differs')
            setattr(self._get(args[0]), self.image.literal(raw[1]), self._get(args[1]))
            return 0
        if op == 19:
            if len(raw) != 1 or args or vector or len(destinations) != 1 or self.image.literal(raw[0]) != 'VALUE_REGISTERS':
                raise RuntimeError('native Core register-import representation differs')
            from .hia_machine_plan import VALUE_REGISTERS
            self._set(destinations[0], VALUE_REGISTERS)
            return 0
        return super()._effect()


class NativeCoreLowering(NativeMachinePlanControl):
    def __init__(self, image, expected_sha256, namespace=None):
        super().__init__(image, expected_sha256)
        self._bind_namespace(namespace)

    def _bind_namespace(self, namespace):
        if namespace is None:
            from . import hia_program_native
            namespace = vars(hia_program_native)
        if type(namespace) is not dict:
            raise TypeError('native Core lowering requires an actual module namespace')
        self.namespace = namespace
        self.modes = {name: {'number': index, 'arity': arity}
                      for index, (name, arity) in enumerate(_ARITIES.items(), 1)}
        if self.function_count < len(self.modes):
            raise RuntimeError('native Core complete entry inventory differs')
        for spec in self.modes.values():
            if self.function(spec['number'])[2] != spec['arity']:
                raise RuntimeError('native Core complete entry arity differs')
        self._classes = {}
        def reject(message, code='E_HIA_PROGRAM_NATIVE'):
            _invocation = self.prepare('_reject', (message, code))
            message = code = None
            return self.finish(_invocation)
        def words(typ):
            _invocation = self.prepare('_words', (typ,))
            typ = None
            return self.finish(_invocation)
        def bounds(typ):
            _invocation = self.prepare('_bounds', (typ,))
            typ = None
            return self.finish(_invocation)
        def normalize(code, reg, typ):
            _invocation = self.prepare('_normalize', (code, reg, typ))
            code = reg = typ = None
            return self.finish(_invocation)
        def prologue(code, frame):
            _invocation = self.prepare('_prologue', (code, frame))
            code = frame = None
            return self.finish(_invocation)
        self._helpers = {'_reject': reject, '_words': words, '_bounds': bounds,
                         '_normalize': normalize, '_prologue': prologue}
        for name, function in self._helpers.items():
            function.__name__ = function.__qualname__ = name
            function.__module__ = namespace.get('__name__', __name__)

    def finish(self, frame):
        """Drive only after the caller transferred its parameter references."""
        completed = False
        try:
            if frame.drive() != 0:
                raise RuntimeError('native Core lowering public entry yielded')
            completed = True
            return frame.take()
        except BaseException:
            completed = False
            raise
        finally:
            frame.close(release=completed)

    def run(self, mode, *arguments, _captures=(), _witness=None):
        frame = LoweringSession(self, mode, arguments, _captures, witness=_witness)
        arguments = _captures = None
        return self.finish(frame)

    def prepare(self, name, arguments):
        mode = self.modes[name]
        if type(arguments) is not tuple or len(arguments) != mode['arity']:
            raise TypeError('native Core lowering bound argument count differs')
        return LoweringSession(self, mode['number'], arguments)

    def invoke(self, name, arguments):
        frame = self.prepare(name, arguments)
        arguments = None
        return self.finish(frame)

    def function_class(self, base):
        previous = self._classes.get(base)
        if previous is not None:
            return previous
        owner = self

        class Function(base):
            def __init__(self, parent, fn, index):
                _invocation = owner.prepare('_Function.__init__', (self, parent, fn, index))
                self = parent = fn = index = None
                owner.finish(_invocation)

            def allocate(self, words):
                _invocation = owner.prepare('_Function.allocate', (self, words))
                self = words = None
                return owner.finish(_invocation)

            def label(self, suffix):
                _invocation = owner.prepare('_Function.label', (self, suffix))
                self = suffix = None
                return owner.finish(_invocation)

            def block_label(self, name):
                _invocation = owner.prepare('_Function.block_label', (self, name))
                self = name = None
                return owner.finish(_invocation)

            def load(self, name, reg='rax', word=0):
                _invocation = owner.prepare('_Function.load', (self, name, reg, word))
                self = name = reg = word = None
                return owner.finish(_invocation)

            def store(self, name, reg='rax', word=0):
                _invocation = owner.prepare('_Function.store', (self, name, reg, word))
                self = name = reg = word = None
                return owner.finish(_invocation)

            def immediate(self, name, value, word=0):
                _invocation = owner.prepare('_Function.immediate', (self, name, value, word))
                self = name = value = word = None
                return owner.finish(_invocation)

            def copy(self, source, destination):
                _invocation = owner.prepare('_Function.copy', (self, source, destination))
                self = source = destination = None
                return owner.finish(_invocation)

            def fail_if(self, condition):
                _invocation = owner.prepare('_Function.fail_if', (self, condition))
                self = condition = None
                return owner.finish(_invocation)

            def compare_imm(self, register, value):
                _invocation = owner.prepare('_Function.compare_imm', (self, register, value))
                self = register = value = None
                return owner.finish(_invocation)

            def range_check(self, register, typ, source=None):
                _invocation = owner.prepare('_Function.range_check', (self, register, typ, source))
                self = register = typ = source = None
                return owner.finish(_invocation)

            def narrow_result(self, typ, checked=False):
                _invocation = owner.prepare('_Function.narrow_result', (self, typ, checked))
                self = typ = checked = None
                return owner.finish(_invocation)

            def condition_value(self, condition):
                _invocation = owner.prepare('_Function.condition_value', (self, condition))
                self = condition = None
                return owner.finish(_invocation)

            def edge(self, target, arguments):
                _invocation = owner.prepare('_Function.edge', (self, target, arguments))
                self = target = arguments = None
                return owner.finish(_invocation)

            def operation(self, ins):
                _invocation = owner.prepare('_Function.operation', (self, ins))
                self = ins = None
                return owner.finish(_invocation)

            def allocate_buffer(self, size, out, trapping):
                _invocation = owner.prepare('_Function.allocate_buffer', (self, size, out, trapping))
                self = size = out = trapping = None
                return owner.finish(_invocation)

            def range_guard(self, buffer, offset, size):
                _invocation = owner.prepare('_Function.range_guard', (self, buffer, offset, size))
                self = buffer = offset = size = None
                return owner.finish(_invocation)

            def bulk(self, op, args):
                _invocation = owner.prepare('_Function.bulk', (self, op, args))
                self = op = args = None
                return owner.finish(_invocation)

            def push_chain(self, args, out):
                _invocation = owner.prepare('_Function.push_chain', (self, args, out))
                self = args = out = None
                return owner.finish(_invocation)

            def pop_chain(self, arg, out):
                _invocation = owner.prepare('_Function.pop_chain', (self, arg, out))
                self = arg = out = None
                return owner.finish(_invocation)

            def drop_chain(self, arg):
                _invocation = owner.prepare('_Function.drop_chain', (self, arg))
                self = arg = None
                return owner.finish(_invocation)

            def render(self):
                _invocation = owner.prepare('_Function.render', (self,))
                self = None
                return owner.finish(_invocation)

        Function.__name__ = base.__name__
        Function.__qualname__ = base.__qualname__
        Function.__module__ = base.__module__
        for name, method in vars(Function).items():
            if hasattr(method, '__code__'):
                method.__qualname__ = base.__qualname__ + '.' + name
                method.__module__ = base.__module__
        self._classes[base] = Function
        return Function

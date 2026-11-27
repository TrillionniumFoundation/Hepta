"""Hosted mechanical object transport for HIA-owned ELF writer policy.

Sorting, regex, Python objects and iterator frames are still hosted runtime
mechanisms. This is not a pure native runtime or legacy retirement claim.
"""
from __future__ import annotations

import builtins

from .hia_core_lowering_native import NativeCoreLowering


def _call_arguments(target, arguments):
    return target(*arguments)


def _unpack_eight(value):
    a, b, c, d, e, f, g, h = value
    return a, b, c, d, e, f, g, h


class NativeMachineObject(NativeCoreLowering):
    ABI_SCHEMA = 'hepta.hia.machine-object-abi.v1'

    def global_value(self, name):
        if name == '_hia_object_literal_bytes':
            return bytes.fromhex
        if name == '_hia_object_call_arguments':
            return _call_arguments
        if name == '_hia_object_unpack_eight':
            return _unpack_eight
        if name == '_hia_object_callback':
            def callback(mode):
                def invoke(argument):
                    return self.invoke(mode, (argument,))
                return invoke
            return callback
        if name == '_hia_object_generator':
            def generator(mode, iterator):
                def iterate():
                    while True:
                        try:
                            item = next(iterator)
                        except StopIteration:
                            return
                        include, result = self.invoke(mode, (item,))
                        if include:
                            yield result
                return iterate()
            return generator
        if name in ('_name', '_exact_int'):
            def helper(*arguments):
                return self.invoke(name, arguments)
            return helper
        if name in self.namespace:
            return self.namespace[name]
        try:
            return getattr(builtins, name)
        except AttributeError:
            raise NameError("name '" + name + "' is not defined") from None

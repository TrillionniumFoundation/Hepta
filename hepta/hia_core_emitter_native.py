"""Hosted object ABI for HIA-owned Emitter control; not a pure native runtime."""
from __future__ import annotations

import builtins
from .hia_host_import import member_importer

from .hia_core_lowering_native import NativeCoreLowering


def _call_keywords(target, mapping):
    return target(**mapping)


def _unpack_four(value):
    a, b, c, d = value
    return a, b, c, d


def _project_items(iterable, key):
    return (item[key] for item in iterable)


class NativeCoreEmitter(NativeCoreLowering):
    ABI_SCHEMA = 'hepta.hia.core-emitter-abi.v1'

    def global_value(self, name):
        if name == '_hia_emitter_call_keywords':
            return _call_keywords
        if name == '_hia_emitter_unpack_four':
            return _unpack_four
        if name == '_hia_emitter_import_member':
            def import_member(module, member):
                return member_importer(self.namespace, module, member)()
            return import_member
        if name == '_hia_emitter_project_items':
            return _project_items
        # Existing module helper entries capture the independently selected
        # Core-lowering scope; this bundle contains no copy of their policy.
        if name in self.namespace:
            return self.namespace[name]
        if name in vars(builtins):
            return vars(builtins)[name]
        raise NameError("name '" + name + "' is not defined", name=name)

    def emitter_class(self, base):
        previous = self._classes.get(base)
        if previous is not None:
            return previous
        owner = self

        class Emitter(base):
            def __init__(self, document, allowed_exports, block_order=None,
                         foreign_buffer_exports=(), machine_plan=None):
                packed = (document, allowed_exports, block_order,
                          foreign_buffer_exports, machine_plan)
                owner.invoke('_Emitter.__init__', (self, packed))

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

        Emitter.__name__ = 'HIAEmitter'
        Emitter.__qualname__ = 'NativeCoreEmitter.emitter_class.<locals>.HIAEmitter'
        self._classes[base] = Emitter
        return Emitter

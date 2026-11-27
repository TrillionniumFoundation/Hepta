"""Explicitly hosted object primitives for HIA byte-wrapper policy control."""
from __future__ import annotations

import builtins

from .hia_core_lowering_native import NativeCoreLowering
from .hia_host_import import member_importer, members_importer


class NativeByteWrapper(NativeCoreLowering):
    ABI_SCHEMA = 'hepta.hia.byte-wrapper-abi.v1'

    def global_value(self, name):
        if name == '_hia_byte_import_members':
            def imported(module, members):
                if len(members) == 1:
                    return (member_importer(self.namespace, module, members[0])(),)
                return members_importer(self.namespace, module, members)()
            return imported
        if name == '_hia_byte_closure':
            def close(mode, captures):
                if type(captures) is not tuple:
                    raise TypeError('native closure captures require an exact tuple')
                def invoke(*arguments):
                    return self.invoke(mode, (*captures, *arguments))
                return invoke
            return close
        if name in self.namespace:
            return self.namespace[name]
        try:
            return getattr(builtins, name)
        except AttributeError:
            raise NameError("name '" + name + "' is not defined") from None

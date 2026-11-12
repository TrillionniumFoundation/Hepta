"""Mechanical CPython import opcode adapter, explicitly still hosted.

The fixed template executes IMPORT_NAME / IMPORT_FROM with the caller's actual
module globals. It preserves the builtin import hook and IMPORT_FROM fallback
and ImportError semantics. There is no product policy or source-text compiler.
"""
from __future__ import annotations

from types import FunctionType


def _one_member_template():
    from ._module import _member
    return _member


def member_importer(namespace, module, member):
    template = _one_member_template.__code__
    if (template.co_names != ('_module', '_member')
            or template.co_varnames != ('_member',)
            or template.co_consts.count(('_member',)) != 1
            or not any(type(value) is int and value == 1 for value in template.co_consts)
            or any(value is not None and value != ('_member',)
                   and not (type(value) is int and value == 1)
                   for value in template.co_consts)):
        raise RuntimeError('host import opcode template requires explicit review')
    code = template.replace(co_names=(module, member), co_varnames=(member,),
                            co_consts=tuple((member,) if value == ('_member',) else value
                                            for value in template.co_consts))
    return FunctionType(code, namespace)

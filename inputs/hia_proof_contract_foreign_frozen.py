"""Fixed interpreter primitives for HIA-owned proof-contract operations.

These ports have no proof decision or old proof-function callback. They expose
ordinary fixed CALL shapes, dictionary update, and original import operations.
"""
from __future__ import annotations

import dis
import sys
from types import FunctionType

IMPORT_NAMES = ('ARTIFACT_PROFILE', 'ARTIFACT_PROPERTY', 'ARTIFACT_OBLIGATIONS',
    'SCHEMA', 'CLAIMS', 'ASSUMPTIONS', 'LIMITS', 'UNPROVED_OBLIGATIONS',
    '_checker_source_identity', '_solver_identity')


def _profile():
    if sys.implementation.name != 'cpython' or sys.version_info[:2] not in ((3, 12), (3, 13), (3, 14)):
        raise RuntimeError('proof-contract ports require a reviewed CPython ABI')


def _update_template(frame, destination_slot, mapping_slot):
    return {**frame._get(destination_slot), **frame._get(mapping_slot)}


def _update_port():
    _profile()
    code = _update_template.__code__
    meaningful = tuple(i for i in dis.get_instructions(code, show_caches=True, adaptive=False)
                       if i.opname != 'CACHE')
    maps = tuple(i for i in meaningful if i.opname == 'BUILD_MAP')
    updates = tuple(i for i in meaningful if i.opname == 'DICT_UPDATE')
    allowed = {'RESUME', 'LOAD_FAST', 'LOAD_FAST_BORROW',
               'LOAD_FAST_BORROW_LOAD_FAST_BORROW', 'LOAD_ATTR', 'LOAD_CONST',
               'CALL', 'BUILD_MAP', 'DICT_UPDATE', 'RETURN_VALUE'}
    if (code.co_exceptiontable or code.co_consts != (None,)
            or len(maps) != 1 or maps[0].arg != 0 or len(updates) != 2
            or any(i.arg != 1 for i in updates)
            or tuple(i.opname for i in meaningful[-2:]) != ('DICT_UPDATE', 'RETURN_VALUE')
            or any(i.opname not in allowed for i in meaningful)):
        raise RuntimeError('proof-contract DICT_UPDATE opcode template differs')
    raw = bytearray(code.co_code)
    for item in (maps[0], updates[0]):
        raw[item.offset:item.offset + 2] = bytes((dis.opmap['NOP'], 0))
    return FunctionType(code.replace(co_code=bytes(raw), co_name='_proof_dict_update',
                                    co_qualname='_proof_dict_update'), globals())


def _import_all_template():
    from .hia_safe_core import (ARTIFACT_PROFILE, ARTIFACT_PROPERTY, ARTIFACT_OBLIGATIONS,
        SCHEMA, CLAIMS, ASSUMPTIONS, LIMITS, UNPROVED_OBLIGATIONS,
        _checker_source_identity, _solver_identity)


def _import_assumptions_template():
    from .hia_safe_core import ASSUMPTIONS


def _import_importlib_template():
    import importlib


def _import_name_port(template, namespace, module, fromlist, level):
    _profile()
    code = template.__code__
    meaningful = tuple(i for i in dis.get_instructions(code, show_caches=True, adaptive=False)
                       if i.opname != 'CACHE')
    imports = tuple(i for i in meaningful if i.opname == 'IMPORT_NAME')
    if code.co_exceptiontable or len(imports) != 1 or imports[0].argval != module:
        raise RuntimeError('proof-contract IMPORT_NAME template differs')
    prefix = tuple(i for i in meaningful if i.offset <= imports[0].offset)
    if (tuple(i.opname for i in prefix) not in (
            ('RESUME', 'LOAD_CONST', 'LOAD_CONST', 'IMPORT_NAME'),
            ('RESUME', 'LOAD_SMALL_INT', 'LOAD_CONST', 'IMPORT_NAME'))
            or prefix[1].argval != level or prefix[2].argval != fromlist):
        raise RuntimeError('proof-contract original import operands differ')
    raw = code.co_code[:imports[0].offset + 2] + bytes((dis.opmap['RETURN_VALUE'], 0))
    return FunctionType(code.replace(co_code=raw, co_name='_proof_import_name',
                                    co_qualname='_proof_import_name'), namespace)


def _from_template(module):
    return module.ARTIFACT_PROFILE


def _import_from_port(name, namespace):
    _profile()
    if name not in IMPORT_NAMES:
        raise RuntimeError('proof-contract imported name is outside the fixed inventory')
    # Actual IMPORT_FROM includes CPython's original circular-import fallback
    # and error formatting. A generic getattr would not implement that port.
    raw = bytes((dis.opmap['RESUME'], 0, dis.opmap['LOAD_FAST'], 0,
                 dis.opmap['IMPORT_FROM'], 0, dis.opmap['SWAP'], 2,
                 dis.opmap['POP_TOP'], 0, dis.opmap['RETURN_VALUE'], 0))
    code = _from_template.__code__.replace(co_code=raw, co_names=(name,),
        co_stacksize=2, co_name='_proof_import_from', co_qualname='_proof_import_from')
    function = FunctionType(code, namespace)
    if tuple(i.opname for i in dis.get_instructions(function)) != (
            'RESUME', 'LOAD_FAST', 'IMPORT_FROM', 'SWAP', 'POP_TOP', 'RETURN_VALUE'):
        raise RuntimeError('proof-contract IMPORT_FROM primitive differs')
    return function


def import_ports(namespace):
    return (
        (_import_name_port(_import_all_template, namespace, 'hia_safe_core', IMPORT_NAMES, 1),
         _import_name_port(_import_assumptions_template, namespace, 'hia_safe_core', ('ASSUMPTIONS',), 1)),
        _import_name_port(_import_importlib_template, namespace, 'importlib', None, 0),
        {name: _import_from_port(name, namespace) for name in IMPORT_NAMES},
    )


update_dict = _update_port()


def format_plain(frame, slot):
    return f'{frame._move(slot)}'


def format_02d(frame, slot):
    return f'{frame._move(slot):02d}'


def _string_template(frame, slots):
    return f'{frame._move(slots[0])}{frame._move(slots[1])}{frame._move(slots[2])}{frame._move(slots[3])}'


def _string_port():
    _profile()
    code = _string_template.__code__
    meaningful = tuple(i for i in dis.get_instructions(code, show_caches=True, adaptive=False)
                       if i.opname != 'CACHE')
    formats = tuple(i for i in meaningful if i.opname in ('FORMAT_VALUE', 'FORMAT_SIMPLE'))
    joins = tuple(i for i in meaningful if i.opname == 'BUILD_STRING')
    if (code.co_exceptiontable or len(formats) != 4 or len(joins) != 1
            or joins[0].arg != 4
            or any(i.opname == 'FORMAT_VALUE' and i.arg != 0 for i in formats)
            or tuple(i.opname for i in meaningful[-2:]) != ('BUILD_STRING', 'RETURN_VALUE')):
        raise RuntimeError('proof-contract BUILD_STRING opcode template differs')
    raw = bytearray(code.co_code)
    for item in formats:
        raw[item.offset:item.offset + 2] = bytes((dis.opmap['NOP'], 0))
    result = FunctionType(code.replace(co_code=bytes(raw), co_name='_proof_build_string',
                                      co_qualname='_proof_build_string'), globals())
    if any(i.opname in ('FORMAT_VALUE', 'FORMAT_SIMPLE') for i in dis.get_instructions(result)):
        raise RuntimeError('proof-contract string assembly still formats a value')
    return result


build_string = _string_port()


def call_0(frame, slots):
    return frame._move(slots[0])()


def call_held(frame, slots):
    return frame._move(slots[0])(held_owners=frame._move(slots[1]))


def call_1(frame, slots):
    return frame._move(slots[0])(frame._move(slots[1]))


def call_2(frame, slots):
    return frame._move(slots[0])(frame._move(slots[1]), frame._move(slots[2]))


def call_3(frame, slots):
    return frame._move(slots[0])(frame._move(slots[1]), frame._move(slots[2]), frame._move(slots[3]))


def call_4(frame, slots):
    return frame._move(slots[0])(frame._move(slots[1]), frame._move(slots[2]), frame._move(slots[3]), frame._move(slots[4]))


CALLS = {(0, ()): call_0, (0, ('held_owners',)): call_held,
         (1, ()): call_1, (2, ()): call_2, (3, ()): call_3, (4, ()): call_4}

"""Generated fixed CPython operands for public-front HIA-issued effects.

No business-policy body, runtime AST, exec, or dynamic source compiler.
"""
from __future__ import annotations
import dis
import sys
from types import FunctionType

TABLE_SHA256 = 'd2cbcb213587302660e8fbd218c57a8cb3f405b78b9d51c349d72056af2f39fe'
ROOT_NAMES = ('_reject', 'verify_program')
FUNCTION_COUNT = 2
IMPORT_NAMES = ('elaborate_program', 'selected_core_structure')

def _profile():
    if sys.implementation.name != 'cpython' or sys.version_info[:2] not in ((3,12),(3,13),(3,14)):
        raise RuntimeError('public-front ports require a reviewed CPython ABI')

def format_value(frame, slot):
    return f'{frame._move(slot)}'

def _build_string_port(template, count):
    _profile()
    code = template.__code__
    instructions = tuple(dis.get_instructions(code, show_caches=True, adaptive=False))
    meaningful = tuple(i for i in instructions if i.opname != 'CACHE')
    format_name = 'FORMAT_SIMPLE' if sys.version_info[:2] == (3,14) else 'FORMAT_VALUE'
    formats = tuple(i for i in meaningful if i.opname == format_name)
    builds = tuple(i for i in meaningful if i.opname == 'BUILD_STRING')
    allowed = {'RESUME','LOAD_FAST','LOAD_FAST_BORROW','LOAD_FAST_BORROW_LOAD_FAST_BORROW',
               'LOAD_ATTR','LOAD_METHOD','LOAD_CONST','LOAD_SMALL_INT','BINARY_SUBSCR',
               'CALL','FORMAT_VALUE','FORMAT_SIMPLE','BUILD_STRING','RETURN_VALUE','PUSH_NULL','BINARY_OP'}
    if (code.co_exceptiontable or len(formats) != count or len(builds) != 1
            or builds[0].arg != count or tuple(i.opname for i in meaningful[-2:]) != ('BUILD_STRING','RETURN_VALUE')
            or any(i.opname not in allowed for i in meaningful)
            or any(i.opname == 'BINARY_OP' and i.argrepr != '[]' for i in meaningful)
            or any(i.opname == 'CACHE' and any(f.offset+2 == i.offset for f in formats) for i in instructions)
            or any(code.co_code[i.offset+1] != 0 for i in formats)
            or any(v is not None and (type(v) is not int or not 0 <= v < count) for v in code.co_consts)):
        raise RuntimeError('public-front BUILD_STRING fixed template differs')
    raw = bytearray(code.co_code)
    for instruction in formats:
        raw[instruction.offset:instruction.offset+2] = bytes((dis.opmap['NOP'],0))
    function = FunctionType(code.replace(co_code=bytes(raw),co_name='_public_front_build_string',
        co_qualname='_public_front_build_string'),globals())
    if any(i.opname in ('FORMAT_SIMPLE','FORMAT_VALUE') for i in dis.get_instructions(function)):
        raise RuntimeError('public-front BUILD_STRING still formats its completed operands')
    return function

def _import_name_port(template, namespace, module, names):
    _profile()
    code = template.__code__
    meaningful = tuple(i for i in dis.get_instructions(code,show_caches=True,adaptive=False) if i.opname != 'CACHE')
    imports = tuple(i for i in meaningful if i.opname == 'IMPORT_NAME')
    if code.co_exceptiontable or len(imports) != 1 or imports[0].argval != module:
        raise RuntimeError('public-front IMPORT_NAME template differs')
    prefix = tuple(i for i in meaningful if i.offset <= imports[0].offset)
    if (tuple(i.opname for i in prefix) not in (
            ('RESUME','LOAD_CONST','LOAD_CONST','IMPORT_NAME'),
            ('RESUME','LOAD_SMALL_INT','LOAD_CONST','IMPORT_NAME'))
            or prefix[1].argval != 1 or prefix[2].argval != names):
        raise RuntimeError('public-front import operands differ')
    raw = code.co_code[:imports[0].offset+2]+bytes((dis.opmap['RETURN_VALUE'],0))
    return FunctionType(code.replace(co_code=raw,co_name='_public_front_import_name',
                        co_qualname='_public_front_import_name'),namespace)

def _from_template(module):
    return module.elaborate_program

def _import_from_port(name, namespace):
    _profile()
    if name not in IMPORT_NAMES:
        raise RuntimeError('public-front import field differs')
    raw = bytes((dis.opmap['RESUME'],0,dis.opmap['LOAD_FAST'],0,dis.opmap['IMPORT_FROM'],0,
                 dis.opmap['SWAP'],2,dis.opmap['POP_TOP'],0,dis.opmap['RETURN_VALUE'],0))
    function = FunctionType(_from_template.__code__.replace(co_code=raw,co_names=(name,),
        co_stacksize=2,co_name='_public_front_import_from',co_qualname='_public_front_import_from'),namespace)
    if tuple(i.opname for i in dis.get_instructions(function)) != (
            'RESUME','LOAD_FAST','IMPORT_FROM','SWAP','POP_TOP','RETURN_VALUE'):
        raise RuntimeError('public-front IMPORT_FROM primitive differs')
    return function

def _unbound_template():
    value: object
    return value

def _empty_free_template():
    if False:
        value = None
    return lambda: value

_EMPTY_FREE = _empty_free_template()
_UNBOUND_PORTS = {}
def unbound(name, free):
    _profile()
    if type(name) is not str or type(free) is not int or free not in (0,1):
        raise RuntimeError('public-front unbound-name representation differs')
    key = (name,free)
    if key not in _UNBOUND_PORTS:
        if free:
            function = FunctionType(_EMPTY_FREE.__code__.replace(co_freevars=(name,)),
                                    globals(),closure=_EMPTY_FREE.__closure__)
            expected = 'LOAD_DEREF'
        else:
            function = FunctionType(_unbound_template.__code__.replace(co_varnames=(name,)),globals())
            expected = 'LOAD_FAST_CHECK'
        if not any(i.opname == expected and i.argval == name for i in dis.get_instructions(function,adaptive=False)):
            raise RuntimeError('public-front unbound opcode differs')
        _UNBOUND_PORTS[key] = function
    return _UNBOUND_PORTS[key]()

def _call_0(frame, slots):
    return frame._move(slots[0])()

def _call_1(frame, slots):
    return frame._move(slots[0])(frame._move(slots[1]))

def _call_2(frame, slots):
    return frame._move(slots[0])(frame._move(slots[1]), frame._move(slots[2]))

def _call_3(frame, slots):
    return frame._move(slots[0])(frame._move(slots[1]), frame._move(slots[2]), frame._move(slots[3]), frame._move(slots[4]))

CALLS = {
    (0, ()): _call_0,
    (1, ()): _call_1,
    (2, ()): _call_2,
    (4, ()): _call_3,
}

BUILD_STRINGS = {
}

def _import_template_0():
    from .hia_core_admission_native import selected_core_structure

def _import_template_1():
    from .hia_program_composite import elaborate_program

def import_ports(namespace):
    return ({
        ('hia_core_admission_native', ('selected_core_structure',)): _import_name_port(_import_template_0, namespace, 'hia_core_admission_native', ('selected_core_structure',)),
        ('hia_program_composite', ('elaborate_program',)): _import_name_port(_import_template_1, namespace, 'hia_program_composite', ('elaborate_program',)),
    }, {name: _import_from_port(name,namespace) for name in IMPORT_NAMES})

"""Generated fixed CPython operands for public-front HIA-issued effects.

No business-policy body, runtime AST, exec, or dynamic source compiler.
"""
from __future__ import annotations
import dis
import sys
from types import FunctionType

TABLE_SHA256 = '91cc76c109c62ad651691942901ef3d08d84587b4fd0178e1a6890a77c04ec84'
ROOT_NAMES = ('_reject', '_source', '_items', '_names', '_parameters', '_attrs', '_parse_assembly_document', 'assemble_program', '_render_parameters', '_render_assembly_document', 'render_assembly', 'diagnose_assembly')
FUNCTION_COUNT = 16
IMPORT_NAMES = ()

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
    return frame._move(slots[0])(accepted=frame._move(slots[1]), core_sha256=frame._move(slots[2]), core_schema=frame._move(slots[3]), diagnostic=frame._move(slots[4]))

def _call_2(frame, slots):
    return frame._move(slots[0])(source_sha256=frame._move(slots[1]), source_bytes=frame._move(slots[2]))

def _call_3(frame, slots):
    return frame._move(slots[0])(frame._move(slots[1]))

def _call_4(frame, slots):
    return frame._move(slots[0])(frame._move(slots[1]), limit=frame._move(slots[2]))

def _call_5(frame, slots):
    return frame._move(slots[0])(frame._move(slots[1]), line=frame._move(slots[2]))

def _call_6(frame, slots):
    return frame._move(slots[0])(frame._move(slots[1]), line=frame._move(slots[2]), limit=frame._move(slots[3]))

def _call_7(frame, slots):
    return frame._move(slots[0])(frame._move(slots[1]), max_nodes=frame._move(slots[2]), max_depth=frame._move(slots[3]))

def _call_8(frame, slots):
    return frame._move(slots[0])(frame._move(slots[1]), separators=frame._move(slots[2]))

def _call_9(frame, slots):
    return frame._move(slots[0])(frame._move(slots[1]), sort_keys=frame._move(slots[2]), separators=frame._move(slots[3]), ensure_ascii=frame._move(slots[4]), allow_nan=frame._move(slots[5]))

def _call_10(frame, slots):
    return frame._move(slots[0])(frame._move(slots[1]), frame._move(slots[2]))

def _call_11(frame, slots):
    return frame._move(slots[0])(frame._move(slots[1]), frame._move(slots[2]), line=frame._move(slots[3]))

def _call_12(frame, slots):
    return frame._move(slots[0])(frame._move(slots[1]), frame._move(slots[2]), phase=frame._move(slots[3]))

def _call_13(frame, slots):
    return frame._move(slots[0])(frame._move(slots[1]), frame._move(slots[2]), frame._move(slots[3]))

CALLS = {
    (0, ()): _call_0,
    (0, ('accepted', 'core_sha256', 'core_schema', 'diagnostic')): _call_1,
    (0, ('source_sha256', 'source_bytes')): _call_2,
    (1, ()): _call_3,
    (1, ('limit',)): _call_4,
    (1, ('line',)): _call_5,
    (1, ('line', 'limit')): _call_6,
    (1, ('max_nodes', 'max_depth')): _call_7,
    (1, ('separators',)): _call_8,
    (1, ('sort_keys', 'separators', 'ensure_ascii', 'allow_nan')): _call_9,
    (2, ()): _call_10,
    (2, ('line',)): _call_11,
    (2, ('phase',)): _call_12,
    (3, ()): _call_13,
}

def _string_5(frame, slots):
    return f'{frame._move(slots[0])}{frame._move(slots[1])}{frame._move(slots[2])}{frame._move(slots[3])}{frame._move(slots[4])}'

def _string_7(frame, slots):
    return f'{frame._move(slots[0])}{frame._move(slots[1])}{frame._move(slots[2])}{frame._move(slots[3])}{frame._move(slots[4])}{frame._move(slots[5])}{frame._move(slots[6])}'

def _string_11(frame, slots):
    return f'{frame._move(slots[0])}{frame._move(slots[1])}{frame._move(slots[2])}{frame._move(slots[3])}{frame._move(slots[4])}{frame._move(slots[5])}{frame._move(slots[6])}{frame._move(slots[7])}{frame._move(slots[8])}{frame._move(slots[9])}{frame._move(slots[10])}'

BUILD_STRINGS = {
    5: _build_string_port(_string_5,5),
    7: _build_string_port(_string_7,7),
    11: _build_string_port(_string_11,11),
}

def import_ports(namespace):
    return ({
    }, {name: _import_from_port(name,namespace) for name in IMPORT_NAMES})

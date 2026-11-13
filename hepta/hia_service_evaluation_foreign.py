"""Fixed CPython call/mapping primitives for HIA-issued evaluation ports.

This module performs no proof or service branch. HIA alone chooses each port,
its operands and one-use lifetime permission. The mapping templates expose
actual DICT_MERGE (duplicate refusal) and DICT_UPDATE (duplicate replacement)
separately; they do not execute a retained policy function.
"""
from __future__ import annotations
import dis
import sys
from types import FunctionType


def _merge_empty_template(frame, callee_slot, positional_slot, mapping_slot):
    return frame._get(callee_slot)(*frame._get(positional_slot), **frame._get(mapping_slot))


def _merge_kind_template(frame, callee_slot, positional_slot, kind_slot, mapping_slot):
    return frame._get(callee_slot)(*frame._get(positional_slot), kind=frame._get(kind_slot), **frame._get(mapping_slot))


def _update_template(frame, destination_slot, mapping_slot):
    return {**frame._get(destination_slot), **frame._get(mapping_slot)}


def _profile():
    if sys.implementation.name != 'cpython' or sys.version_info[:2] not in ((3, 12), (3, 13), (3, 14)):
        raise RuntimeError('evaluation mapping ports require a reviewed CPython ABI')


def _merge_port(template, constants):
    _profile()
    code = template.__code__
    instructions = tuple(dis.get_instructions(code, show_caches=True, adaptive=False))
    meaningful = tuple(i for i in instructions if i.opname != 'CACHE')
    merges = tuple(i for i in meaningful if i.opname == 'DICT_MERGE')
    calls = tuple(i for i in meaningful if i.opname == 'CALL_FUNCTION_EX')
    nulls = tuple(i for i in meaningful if i.opname == 'PUSH_NULL')
    allowed = {'RESUME', 'PUSH_NULL', 'LOAD_FAST', 'LOAD_FAST_BORROW',
               'LOAD_FAST_BORROW_LOAD_FAST_BORROW', 'LOAD_ATTR', 'LOAD_CONST',
               'CALL', 'BUILD_MAP', 'DICT_MERGE', 'CALL_FUNCTION_EX', 'RETURN_VALUE'}
    # CPython 3.14 removed this instruction's flags operand. Keep the
    # reviewed raw no-argument encoding separate from 3.12/3.13 flag 1.
    call_argument = None if sys.version_info[:2] == (3, 14) else 1
    call_raw_argument = 0 if sys.version_info[:2] == (3, 14) else 1
    if (code.co_exceptiontable or code.co_consts != constants
            or len(merges) != 1 or len(calls) != 1 or len(nulls) != 1
            or merges[0].arg != 1 or calls[0].arg != call_argument
            or code.co_code[calls[0].offset + 1] != call_raw_argument
            or tuple(i.opname for i in meaningful[-3:]) != ('DICT_MERGE', 'CALL_FUNCTION_EX', 'RETURN_VALUE')
            or any(i.opname not in allowed for i in meaningful)):
        raise RuntimeError('evaluation DICT_MERGE opcode template differs')
    # 3.14 can omit the unused implicit None from the original constants.
    # Preserve all original literal indexes; append a real None only for
    # the fixed, safely poppable replacement of the interpreter NULL.
    port_constants = constants if None in constants else constants + (None,)
    none_index = port_constants.index(None)
    raw = bytearray(code.co_code[:calls[0].offset])
    raw[nulls[0].offset:nulls[0].offset+2] = bytes((dis.opmap['LOAD_CONST'], none_index))
    raw.extend(bytes((dis.opmap['SWAP'], 2, dis.opmap['POP_TOP'], 0)) * 3)
    raw.extend(bytes((dis.opmap['RETURN_VALUE'], 0)))
    result = FunctionType(code.replace(co_code=bytes(raw), co_consts=port_constants, co_name='_evaluation_dict_merge',
                          co_qualname='_evaluation_dict_merge'), globals())
    if any(i.opname == 'CALL_FUNCTION_EX' for i in dis.get_instructions(result)):
        raise RuntimeError('evaluation mapping preparation still calls a provider')
    return result


def _update_port():
    _profile()
    code = _update_template.__code__
    instructions = tuple(dis.get_instructions(code, show_caches=True, adaptive=False))
    meaningful = tuple(i for i in instructions if i.opname != 'CACHE')
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
        raise RuntimeError('evaluation DICT_UPDATE opcode template differs')
    raw = bytearray(code.co_code)
    # Omit the unused new dict and the copy of the actual destination. The
    # remaining fixed DICT_UPDATE mutates that exact HIA-owned dict, so an
    # overwritten foreign value is not kept alive by a shadow dictionary.
    for item in (maps[0], updates[0]):
        raw[item.offset:item.offset+2] = bytes((dis.opmap['NOP'], 0))
    return FunctionType(code.replace(co_code=bytes(raw), co_name='_evaluation_dict_update',
                        co_qualname='_evaluation_dict_update'), globals())


merge_empty = _merge_port(_merge_empty_template, (None,))
merge_kind = _merge_port(_merge_kind_template,
                         ('kind',) if sys.version_info[:2] == (3, 14) else (None, 'kind'))
update_dict = _update_port()


def mapping_call(frame, callee_slot, positional_slot, keywords_slot):
    if type(frame._get(positional_slot)) is not tuple or type(frame._get(keywords_slot)) is not dict:
        raise RuntimeError('evaluation mapping call lacks exact prepared containers')
    return frame._move(callee_slot)(*frame._move(positional_slot), **frame._move(keywords_slot))


FUNCTION_LAYOUT = ((1, 'function', 90, 4, 0), (2, 'function', 206, 5, 0), (3, 'function', 17, 5, 0), (4, 'function', 114, 4, 0), (5, 'function', 696, 2, 0), (6, 'function', 210, 3, 0), (7, 'function', 167, 4, 0), (8, 'function', 8, 1, 0), (9, 'function', 18, 1, 0), (10, 'generator', 15, 1, 1), (11, 'generator', 14, 1, 1), (12, 'generator', 10, 1, 0), (13, 'function', 19, 0, 2), (14, 'generator', 7, 1, 0), (15, 'lambda', 11, 1, 0), (16, 'function', 35, 3, 6), (17, 'generator', 13, 1, 0))
IMPORT_NAMES = ('run_native_batch', 'run_reference_batch', 'validate_arguments', 'validate_cases')
def _import_name_port(template, namespace, module, fromlist, level):
    _profile()
    code = template.__code__
    meaningful = tuple(i for i in dis.get_instructions(code, show_caches=True, adaptive=False)
                       if i.opname != 'CACHE')
    imports = tuple(i for i in meaningful if i.opname == 'IMPORT_NAME')
    if code.co_exceptiontable or len(imports) != 1 or imports[0].argval != module:
        raise RuntimeError('service-evaluation IMPORT_NAME template differs')
    prefix = tuple(i for i in meaningful if i.offset <= imports[0].offset)
    if (tuple(i.opname for i in prefix) not in (
            ('RESUME', 'LOAD_CONST', 'LOAD_CONST', 'IMPORT_NAME'),
            ('RESUME', 'LOAD_SMALL_INT', 'LOAD_CONST', 'IMPORT_NAME'))
            or prefix[1].argval != level or prefix[2].argval != fromlist):
        raise RuntimeError('service-evaluation original import operands differ')
    raw = code.co_code[:imports[0].offset + 2] + bytes((dis.opmap['RETURN_VALUE'], 0))
    return FunctionType(code.replace(co_code=raw, co_name='_service_evaluation_import_name',
                                    co_qualname='_service_evaluation_import_name'), namespace)

def _from_template(module):
    return module.ARTIFACT_PROFILE

def _import_from_port(name, namespace):
    _profile()
    if name not in IMPORT_NAMES:
        raise RuntimeError('service-evaluation imported name is outside the fixed inventory')
    # Actual IMPORT_FROM includes CPython's original circular-import fallback
    # and error formatting. A generic getattr would not implement that port.
    # Move the argument onto the interpreter stack before the import. A held
    # ImportError must not retain an extra module parameter in this port's
    # traceback after the HIA controller has retired its module temporary.
    constants = _from_template.__code__.co_consts
    if None not in constants:
        constants += (None,)
    raw = bytes((dis.opmap['RESUME'], 0, dis.opmap['LOAD_FAST'], 0,
                 dis.opmap['LOAD_CONST'], constants.index(None), dis.opmap['STORE_FAST'], 0,
                 dis.opmap['IMPORT_FROM'], 0, dis.opmap['SWAP'], 2,
                 dis.opmap['POP_TOP'], 0, dis.opmap['RETURN_VALUE'], 0))
    code = _from_template.__code__.replace(co_code=raw, co_names=(name,), co_consts=constants,
        co_stacksize=2, co_name='_service_evaluation_import_from', co_qualname='_service_evaluation_import_from')
    function = FunctionType(code, namespace)
    if tuple(i.opname for i in dis.get_instructions(function)) != (
            'RESUME', 'LOAD_FAST', 'LOAD_CONST', 'STORE_FAST',
            'IMPORT_FROM', 'SWAP', 'POP_TOP', 'RETURN_VALUE'):
        raise RuntimeError('service-evaluation IMPORT_FROM primitive differs')
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
    if type(name) is not str or type(free) is not int or free not in (0, 1):
        raise RuntimeError('service-evaluation unbound-name representation differs')
    key = (name, free)
    if key not in _UNBOUND_PORTS:
        if free:
            code = _EMPTY_FREE.__code__.replace(co_freevars=(name,))
            function = FunctionType(code, globals(), closure=_EMPTY_FREE.__closure__)
            expected = 'LOAD_DEREF'
        else:
            code = _unbound_template.__code__.replace(co_varnames=(name,))
            function = FunctionType(code, globals())
            expected = 'LOAD_FAST_CHECK'
        instructions = tuple(dis.get_instructions(function, adaptive=False))
        if not any(item.opname == expected and item.argval == name for item in instructions):
            raise RuntimeError('service-evaluation unbound interpreter opcode differs')
        _UNBOUND_PORTS[key] = function
    return _UNBOUND_PORTS[key]()
def _import_template_0():
    from .hia_agent_buffers import validate_arguments

def _import_template_1():
    from .hia_agent_buffers import validate_cases

def _import_template_2():
    from .hia_agent_runner import run_native_batch

def _import_template_3():
    from .hia_agent_runner import run_native_batch, run_reference_batch

def import_ports(namespace):
    return ({
        ('hia_agent_buffers', ('validate_arguments',)): _import_name_port(_import_template_0, namespace, 'hia_agent_buffers', ('validate_arguments',), 1),
        ('hia_agent_buffers', ('validate_cases',)): _import_name_port(_import_template_1, namespace, 'hia_agent_buffers', ('validate_cases',), 1),
        ('hia_agent_runner', ('run_native_batch',)): _import_name_port(_import_template_2, namespace, 'hia_agent_runner', ('run_native_batch',), 1),
        ('hia_agent_runner', ('run_native_batch', 'run_reference_batch')): _import_name_port(_import_template_3, namespace, 'hia_agent_runner', ('run_native_batch', 'run_reference_batch'), 1),
    }, {name: _import_from_port(name, namespace) for name in IMPORT_NAMES})

def _call_0(frame, slots):
    return frame._move(slots[0])()

def _call_1(frame, slots):
    return frame._move(slots[0])(frame._move(slots[1]))

def _call_2(frame, slots):
    return frame._move(slots[0])(frame._move(slots[1]), frame._move(slots[2]))

def _call_3(frame, slots):
    return frame._move(slots[0])(frame._move(slots[1]), frame._move(slots[2]), slot=frame._move(slots[3]), context=frame._move(slots[4]), expected=frame._move(slots[5]), candidate=frame._move(slots[6]), baseline=frame._move(slots[7]), abi=frame._move(slots[8]), connection=frame._move(slots[9]))

def _call_4(frame, slots):
    return frame._move(slots[0])(frame._move(slots[1]), frame._move(slots[2]), timeout_ms=frame._move(slots[3]), memory_bytes=frame._move(slots[4]), foreign_buffer_exports=frame._move(slots[5]))

def _call_5(frame, slots):
    return frame._move(slots[0])(frame._move(slots[1]), frame._move(slots[2]), frame._move(slots[3]))

def _call_6(frame, slots):
    return frame._move(slots[0])(frame._move(slots[1]), frame._move(slots[2]), frame._move(slots[3]), timeout_ms=frame._move(slots[4]), memory_bytes=frame._move(slots[5]), capture_buffers=frame._move(slots[6]))

def _call_7(frame, slots):
    return frame._move(slots[0])(frame._move(slots[1]), frame._move(slots[2]), frame._move(slots[3]), frame._move(slots[4]))

def _call_8(frame, slots):
    return frame._move(slots[0])(frame._move(slots[1]), frame._move(slots[2]), frame._move(slots[3]), frame._move(slots[4]), now=frame._move(slots[5]), total_ms=frame._move(slots[6]), warmup=frame._move(slots[7]), repetitions=frame._move(slots[8]), memory_bytes=frame._move(slots[9]))

CALLS = {
    (0, ()): _call_0,
    (1, ()): _call_1,
    (2, ()): _call_2,
    (2, ('slot', 'context', 'expected', 'candidate', 'baseline', 'abi', 'connection')): _call_3,
    (2, ('timeout_ms', 'memory_bytes', 'foreign_buffer_exports')): _call_4,
    (3, ()): _call_5,
    (3, ('timeout_ms', 'memory_bytes', 'capture_buffers')): _call_6,
    (4, ()): _call_7,
    (4, ('now', 'total_ms', 'warmup', 'repetitions', 'memory_bytes')): _call_8,
}

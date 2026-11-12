"""Fixed CPython call/mapping primitives for HIA-issued native-build ports.

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


def _update_template(frame, destination_slot, mapping_slot):
    return {**frame._get(destination_slot), **frame._get(mapping_slot)}


def _profile():
    if sys.implementation.name != 'cpython' or sys.version_info[:2] not in ((3, 12), (3, 13), (3, 14)):
        raise RuntimeError('native-build mapping ports require a reviewed CPython ABI')


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
    if (code.co_exceptiontable or code.co_consts != constants
            or len(merges) != 1 or len(calls) != 1 or len(nulls) != 1
            or merges[0].arg != 1
            or (calls[0].arg is not None or code.co_code[calls[0].offset+1] != 0
                if sys.version_info[:2] == (3, 14)
                else calls[0].arg != 1 or code.co_code[calls[0].offset+1] != 1)
            or tuple(i.opname for i in meaningful[-3:]) != ('DICT_MERGE', 'CALL_FUNCTION_EX', 'RETURN_VALUE')
            or any(i.opname not in allowed for i in meaningful)):
        raise RuntimeError('native-build DICT_MERGE opcode template differs')
    raw = bytearray(code.co_code[:calls[0].offset])
    raw[nulls[0].offset:nulls[0].offset+2] = bytes((dis.opmap['LOAD_CONST'], 0))
    raw.extend(bytes((dis.opmap['SWAP'], 2, dis.opmap['POP_TOP'], 0)) * 3)
    raw.extend(bytes((dis.opmap['RETURN_VALUE'], 0)))
    result = FunctionType(code.replace(co_code=bytes(raw), co_name='_native_build_dict_merge',
                          co_qualname='_native_build_dict_merge'), globals())
    if any(i.opname == 'CALL_FUNCTION_EX' for i in dis.get_instructions(result)):
        raise RuntimeError('native-build mapping preparation still calls a provider')
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
        raise RuntimeError('native-build DICT_UPDATE opcode template differs')
    raw = bytearray(code.co_code)
    # Omit the unused new dict and the copy of the actual destination. The
    # remaining fixed DICT_UPDATE mutates that exact HIA-owned dict, so an
    # overwritten foreign value is not kept alive by a shadow dictionary.
    for item in (maps[0], updates[0]):
        raw[item.offset:item.offset+2] = bytes((dis.opmap['NOP'], 0))
    return FunctionType(code.replace(co_code=bytes(raw), co_name='_native_build_dict_update',
                        co_qualname='_native_build_dict_update'), globals())


merge_empty = _merge_port(_merge_empty_template, (None,))
update_dict = _update_port()


def mapping_call(frame, callee_slot, positional_slot, keywords_slot):
    if type(frame._get(positional_slot)) is not tuple or type(frame._get(keywords_slot)) is not dict:
        raise RuntimeError('native-build mapping call lacks exact prepared containers')
    return frame._move(callee_slot)(*frame._move(positional_slot), **frame._move(keywords_slot))


IMPORT_NAMES = ('MachinePlanRejected', 'PROFILE', 'VerifiedProgram', 'checker_digest', 'native_byte_abi_scope', 'native_core_emitter_scope', 'native_core_lowering_scope', 'native_elf_scope', 'native_encoding_scope', 'native_implementation_identity', 'native_machine_plan_scope', 'normalize_exports', 'qualify_bounded_resources', 'validate_plan', 'verify_program')
def _import_name_port(template, namespace, module, fromlist, level):
    _profile()
    code = template.__code__
    meaningful = tuple(i for i in dis.get_instructions(code, show_caches=True, adaptive=False)
                       if i.opname != 'CACHE')
    imports = tuple(i for i in meaningful if i.opname == 'IMPORT_NAME')
    if code.co_exceptiontable or len(imports) != 1 or imports[0].argval != module:
        raise RuntimeError('native-build IMPORT_NAME template differs')
    prefix = tuple(i for i in meaningful if i.offset <= imports[0].offset)
    if (tuple(i.opname for i in prefix) not in (
            ('RESUME', 'LOAD_CONST', 'LOAD_CONST', 'IMPORT_NAME'),
            ('RESUME', 'LOAD_SMALL_INT', 'LOAD_CONST', 'IMPORT_NAME'))
            or prefix[1].argval != level or prefix[2].argval != fromlist):
        raise RuntimeError('native-build original import operands differ')
    raw = code.co_code[:imports[0].offset + 2] + bytes((dis.opmap['RETURN_VALUE'], 0))
    return FunctionType(code.replace(co_code=raw, co_name='_native_build_import_name',
                                    co_qualname='_native_build_import_name'), namespace)

def _from_template(module):
    return module.ARTIFACT_PROFILE

def _import_from_port(name, namespace):
    _profile()
    if name not in IMPORT_NAMES:
        raise RuntimeError('native-build imported name is outside the fixed inventory')
    # Actual IMPORT_FROM includes CPython's original circular-import fallback
    # and error formatting. A generic getattr would not implement that port.
    raw = bytes((dis.opmap['RESUME'], 0, dis.opmap['LOAD_FAST'], 0,
                 dis.opmap['IMPORT_FROM'], 0, dis.opmap['SWAP'], 2,
                 dis.opmap['POP_TOP'], 0, dis.opmap['RETURN_VALUE'], 0))
    code = _from_template.__code__.replace(co_code=raw, co_names=(name,),
        co_stacksize=2, co_name='_native_build_import_from', co_qualname='_native_build_import_from')
    function = FunctionType(code, namespace)
    if tuple(i.opname for i in dis.get_instructions(function)) != (
            'RESUME', 'LOAD_FAST', 'IMPORT_FROM', 'SWAP', 'POP_TOP', 'RETURN_VALUE'):
        raise RuntimeError('native-build IMPORT_FROM primitive differs')
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
        raise RuntimeError('native-build unbound-name representation differs')
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
            raise RuntimeError('native-build unbound interpreter opcode differs')
        _UNBOUND_PORTS[key] = function
    return _UNBOUND_PORTS[key]()
def _import_template_0():
    from .hia_checker_identity import checker_digest

def _import_template_1():
    from .hia_core_emitter_selection import native_core_emitter_scope

def _import_template_2():
    from .hia_core_emitter_selection import native_implementation_identity

def _import_template_3():
    from .hia_core_lowering_selection import native_core_lowering_scope

def _import_template_4():
    from .hia_core_lowering_selection import native_implementation_identity

def _import_template_5():
    from .hia_machine_elf import native_elf_scope

def _import_template_6():
    from .hia_machine_elf import native_implementation_identity

def _import_template_7():
    from .hia_machine_plan import MachinePlanRejected, validate_plan

def _import_template_8():
    from .hia_machine_plan import native_implementation_identity

def _import_template_9():
    from .hia_machine_plan_native import native_machine_plan_scope

def _import_template_10():
    from .hia_machine_x64 import native_encoding_scope

def _import_template_11():
    from .hia_machine_x64 import native_implementation_identity

def _import_template_12():
    from .hia_native_build_selection import native_implementation_identity

def _import_template_13():
    from .hia_native_byte_abi import normalize_exports, PROFILE

def _import_template_14():
    from .hia_native_byte_abi_selection import native_byte_abi_scope

def _import_template_15():
    from .hia_native_byte_abi_selection import native_implementation_identity

def _import_template_16():
    from .hia_program import VerifiedProgram, verify_program

def _import_template_17():
    from .hia_program import verify_program

def _import_template_18():
    from .hia_static_budget import qualify_bounded_resources

def import_ports(namespace):
    return ({
        ('hia_checker_identity', ('checker_digest',)): _import_name_port(_import_template_0, namespace, 'hia_checker_identity', ('checker_digest',), 1),
        ('hia_core_emitter_selection', ('native_core_emitter_scope',)): _import_name_port(_import_template_1, namespace, 'hia_core_emitter_selection', ('native_core_emitter_scope',), 1),
        ('hia_core_emitter_selection', ('native_implementation_identity',)): _import_name_port(_import_template_2, namespace, 'hia_core_emitter_selection', ('native_implementation_identity',), 1),
        ('hia_core_lowering_selection', ('native_core_lowering_scope',)): _import_name_port(_import_template_3, namespace, 'hia_core_lowering_selection', ('native_core_lowering_scope',), 1),
        ('hia_core_lowering_selection', ('native_implementation_identity',)): _import_name_port(_import_template_4, namespace, 'hia_core_lowering_selection', ('native_implementation_identity',), 1),
        ('hia_machine_elf', ('native_elf_scope',)): _import_name_port(_import_template_5, namespace, 'hia_machine_elf', ('native_elf_scope',), 1),
        ('hia_machine_elf', ('native_implementation_identity',)): _import_name_port(_import_template_6, namespace, 'hia_machine_elf', ('native_implementation_identity',), 1),
        ('hia_machine_plan', ('MachinePlanRejected', 'validate_plan')): _import_name_port(_import_template_7, namespace, 'hia_machine_plan', ('MachinePlanRejected', 'validate_plan'), 1),
        ('hia_machine_plan', ('native_implementation_identity',)): _import_name_port(_import_template_8, namespace, 'hia_machine_plan', ('native_implementation_identity',), 1),
        ('hia_machine_plan_native', ('native_machine_plan_scope',)): _import_name_port(_import_template_9, namespace, 'hia_machine_plan_native', ('native_machine_plan_scope',), 1),
        ('hia_machine_x64', ('native_encoding_scope',)): _import_name_port(_import_template_10, namespace, 'hia_machine_x64', ('native_encoding_scope',), 1),
        ('hia_machine_x64', ('native_implementation_identity',)): _import_name_port(_import_template_11, namespace, 'hia_machine_x64', ('native_implementation_identity',), 1),
        ('hia_native_build_selection', ('native_implementation_identity',)): _import_name_port(_import_template_12, namespace, 'hia_native_build_selection', ('native_implementation_identity',), 1),
        ('hia_native_byte_abi', ('normalize_exports', 'PROFILE')): _import_name_port(_import_template_13, namespace, 'hia_native_byte_abi', ('normalize_exports', 'PROFILE'), 1),
        ('hia_native_byte_abi_selection', ('native_byte_abi_scope',)): _import_name_port(_import_template_14, namespace, 'hia_native_byte_abi_selection', ('native_byte_abi_scope',), 1),
        ('hia_native_byte_abi_selection', ('native_implementation_identity',)): _import_name_port(_import_template_15, namespace, 'hia_native_byte_abi_selection', ('native_implementation_identity',), 1),
        ('hia_program', ('VerifiedProgram', 'verify_program')): _import_name_port(_import_template_16, namespace, 'hia_program', ('VerifiedProgram', 'verify_program'), 1),
        ('hia_program', ('verify_program',)): _import_name_port(_import_template_17, namespace, 'hia_program', ('verify_program',), 1),
        ('hia_static_budget', ('qualify_bounded_resources',)): _import_name_port(_import_template_18, namespace, 'hia_static_budget', ('qualify_bounded_resources',), 1),
    }, {name: _import_from_port(name, namespace) for name in IMPORT_NAMES})

def _call_0(frame, slots):
    return frame._move(slots[0])()

def _call_1(frame, slots):
    return frame._move(slots[0])(prefix=frame._move(slots[1]), dir=frame._move(slots[2]))

def _call_2(frame, slots):
    return frame._move(slots[0])(status=frame._move(slots[1]), error=frame._move(slots[2]))

def _call_3(frame, slots):
    return frame._move(slots[0])(status=frame._move(slots[1]), returncode=frame._move(slots[2]))

def _call_4(frame, slots):
    return frame._move(slots[0])(frame._move(slots[1]))

def _call_5(frame, slots):
    return frame._move(slots[0])(frame._move(slots[1]), command_log=frame._move(slots[2]), parent_death_guard=frame._move(slots[3]), timeout=frame._move(slots[4]), stdout_limit=frame._move(slots[5]), stderr_limit=frame._move(slots[6]))

def _call_6(frame, slots):
    return frame._move(slots[0])(frame._move(slots[1]), limits=frame._move(slots[2]))

def _call_7(frame, slots):
    return frame._move(slots[0])(frame._move(slots[1]), program=frame._move(slots[2]), output=frame._move(slots[3]), kind=frame._move(slots[4]), linker=frame._move(slots[5]), command_log=frame._move(slots[6]))

def _call_8(frame, slots):
    return frame._move(slots[0])(frame._move(slots[1]), sort_keys=frame._move(slots[2]), separators=frame._move(slots[3]), ensure_ascii=frame._move(slots[4]))

def _call_9(frame, slots):
    return frame._move(slots[0])(frame._move(slots[1]), target=frame._move(slots[2]), foreign_buffer_exports=frame._move(slots[3]))

def _call_10(frame, slots):
    return frame._move(slots[0])(frame._move(slots[1]), target=frame._move(slots[2]), machine_plan=frame._move(slots[3]), foreign_buffer_exports=frame._move(slots[4]))

def _call_11(frame, slots):
    return frame._move(slots[0])(frame._move(slots[1]), frame._move(slots[2]))

def _call_12(frame, slots):
    return frame._move(slots[0])(frame._move(slots[1]), frame._move(slots[2]), frame._move(slots[3]))

def _call_13(frame, slots):
    return frame._move(slots[0])(frame._move(slots[1]), frame._move(slots[2]), frame._move(slots[3]), frame._move(slots[4]), frame._move(slots[5]))

def _call_14(frame, slots):
    return frame._move(slots[0])(frame._move(slots[1]), frame._move(slots[2]), frame._move(slots[3]), frame._move(slots[4]), frame._move(slots[5]), frame._move(slots[6]), frame._move(slots[7]), frame._move(slots[8]), frame._move(slots[9]), frame._move(slots[10]), frame._move(slots[11]), frame._move(slots[12]))

CALLS = {
    (0, ()): _call_0,
    (0, ('prefix', 'dir')): _call_1,
    (0, ('status', 'error')): _call_2,
    (0, ('status', 'returncode')): _call_3,
    (1, ()): _call_4,
    (1, ('command_log', 'parent_death_guard', 'timeout', 'stdout_limit', 'stderr_limit')): _call_5,
    (1, ('limits',)): _call_6,
    (1, ('program', 'output', 'kind', 'linker', 'command_log')): _call_7,
    (1, ('sort_keys', 'separators', 'ensure_ascii')): _call_8,
    (1, ('target', 'foreign_buffer_exports')): _call_9,
    (1, ('target', 'machine_plan', 'foreign_buffer_exports')): _call_10,
    (2, ()): _call_11,
    (3, ()): _call_12,
    (5, ()): _call_13,
    (12, ()): _call_14,
}

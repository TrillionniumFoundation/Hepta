"""Fixed CPython call/mapping primitives for HIA-issued requests ports.

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
        raise RuntimeError('requests mapping ports require a reviewed CPython ABI')


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
        raise RuntimeError('requests DICT_MERGE opcode template differs')
    # 3.14 can omit the unused implicit None from the original constants.
    # Preserve all original literal indexes; append a real None only for
    # the fixed, safely poppable replacement of the interpreter NULL.
    port_constants = constants if None in constants else constants + (None,)
    none_index = port_constants.index(None)
    raw = bytearray(code.co_code[:calls[0].offset])
    raw[nulls[0].offset:nulls[0].offset+2] = bytes((dis.opmap['LOAD_CONST'], none_index))
    raw.extend(bytes((dis.opmap['SWAP'], 2, dis.opmap['POP_TOP'], 0)) * 3)
    raw.extend(bytes((dis.opmap['RETURN_VALUE'], 0)))
    result = FunctionType(code.replace(co_code=bytes(raw), co_consts=port_constants, co_name='_requests_dict_merge',
                          co_qualname='_requests_dict_merge'), globals())
    if any(i.opname == 'CALL_FUNCTION_EX' for i in dis.get_instructions(result)):
        raise RuntimeError('requests mapping preparation still calls a provider')
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
        raise RuntimeError('requests DICT_UPDATE opcode template differs')
    raw = bytearray(code.co_code)
    # Omit the unused new dict and the copy of the actual destination. The
    # remaining fixed DICT_UPDATE mutates that exact HIA-owned dict, so an
    # overwritten foreign value is not kept alive by a shadow dictionary.
    for item in (maps[0], updates[0]):
        raw[item.offset:item.offset+2] = bytes((dis.opmap['NOP'], 0))
    return FunctionType(code.replace(co_code=bytes(raw), co_name='_requests_dict_update',
                        co_qualname='_requests_dict_update'), globals())


merge_empty = _merge_port(_merge_empty_template, (None,))
merge_kind = _merge_port(_merge_kind_template,
                         ('kind',) if sys.version_info[:2] == (3, 14) else (None, 'kind'))
update_dict = _update_port()


def mapping_call(frame, callee_slot, positional_slot, keywords_slot):
    if type(frame._get(positional_slot)) is not tuple or type(frame._get(keywords_slot)) is not dict:
        raise RuntimeError('requests mapping call lacks exact prepared containers')
    return frame._move(callee_slot)(*frame._move(positional_slot), **frame._move(keywords_slot))


TABLE_SHA256 = '9350b930c558e71b4d159c515e192f0b320d6aded4e39d9b8d42d378fe513675'

FUNCTION_LAYOUT = ((1, 'function', 34, 1, 0), (2, 'function', 132, 0, 0), (3, 'function', 81, 3, 0), (4, 'function', 179, 2, 0), (5, 'function', 76, 2, 0), (6, 'function', 210, 2, 0), (7, 'function', 234, 2, 0), (8, 'function', 184, 2, 0), (9, 'with_region', 501, 0, 19), (10, 'generator', 9, 1, 1))
IMPORT_NAMES = ('ARTIFACT_PROFILE', 'CORE_SCHEMAS', 'IMPORTS', 'LIMITS', 'PROFILE', 'SUPPORTED_OPCODES', 'TARGET', 'apply_candidate_patch', 'apply_program_patch', 'assemble_program', 'emit_program_machine', 'inspect_program', 'macro_policy_guidance', 'opcode_catalog', 'prepare_edit', 'proof_contract_scope', 'render_assembly', 'schema_registry')
def _import_name_port(template, namespace, module, fromlist, level):
    _profile()
    code = template.__code__
    meaningful = tuple(i for i in dis.get_instructions(code, show_caches=True, adaptive=False)
                       if i.opname != 'CACHE')
    imports = tuple(i for i in meaningful if i.opname == 'IMPORT_NAME')
    if code.co_exceptiontable or len(imports) != 1 or imports[0].argval != module:
        raise RuntimeError('service-requests IMPORT_NAME template differs')
    prefix = tuple(i for i in meaningful if i.offset <= imports[0].offset)
    if (tuple(i.opname for i in prefix) not in (
            ('RESUME', 'LOAD_CONST', 'LOAD_CONST', 'IMPORT_NAME'),
            ('RESUME', 'LOAD_SMALL_INT', 'LOAD_CONST', 'IMPORT_NAME'))
            or prefix[1].argval != level or prefix[2].argval != fromlist):
        raise RuntimeError('service-requests original import operands differ')
    raw = code.co_code[:imports[0].offset + 2] + bytes((dis.opmap['RETURN_VALUE'], 0))
    return FunctionType(code.replace(co_code=raw, co_name='_service_requests_import_name',
                                    co_qualname='_service_requests_import_name'), namespace)

def _from_template(module):
    return module.ARTIFACT_PROFILE

def _import_from_port(name, namespace):
    _profile()
    if name not in IMPORT_NAMES:
        raise RuntimeError('service-requests imported name is outside the fixed inventory')
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
        co_stacksize=2, co_name='_service_requests_import_from', co_qualname='_service_requests_import_from')
    function = FunctionType(code, namespace)
    if tuple(i.opname for i in dis.get_instructions(function)) != (
            'RESUME', 'LOAD_FAST', 'LOAD_CONST', 'STORE_FAST',
            'IMPORT_FROM', 'SWAP', 'POP_TOP', 'RETURN_VALUE'):
        raise RuntimeError('service-requests IMPORT_FROM primitive differs')
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
        raise RuntimeError('service-requests unbound-name representation differs')
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
            raise RuntimeError('service-requests unbound interpreter opcode differs')
        _UNBOUND_PORTS[key] = function
    return _UNBOUND_PORTS[key]()
def _import_template_0():
    from .hia_agent_assembly import assemble_program

def _import_template_1():
    from .hia_agent_assembly import assemble_program, render_assembly

def _import_template_2():
    from .hia_agent_candidate_native import apply_candidate_patch

def _import_template_3():
    from .hia_agent_macro_discovery import macro_policy_guidance

def _import_template_4():
    from .hia_edit_query import prepare_edit

def _import_template_5():
    from .hia_opcodes import opcode_catalog

def _import_template_6():
    from .hia_program_native import TARGET, PROFILE, SUPPORTED_OPCODES, CORE_SCHEMAS, IMPORTS

def _import_template_7():
    from .hia_program_native import emit_program_machine

def _import_template_8():
    from .hia_program_tools import apply_program_patch

def _import_template_9():
    from .hia_program_tools import inspect_program

def _import_template_10():
    from .hia_proof_contract_selection import proof_contract_scope

def _import_template_11():
    from .hia_safe_core import ARTIFACT_PROFILE, LIMITS

def _import_template_12():
    from .hia_schema import schema_registry

def import_ports(namespace):
    return ({
        ('hia_agent_assembly', ('assemble_program',)): _import_name_port(_import_template_0, namespace, 'hia_agent_assembly', ('assemble_program',), 1),
        ('hia_agent_assembly', ('assemble_program', 'render_assembly')): _import_name_port(_import_template_1, namespace, 'hia_agent_assembly', ('assemble_program', 'render_assembly'), 1),
        ('hia_agent_candidate_native', ('apply_candidate_patch',)): _import_name_port(_import_template_2, namespace, 'hia_agent_candidate_native', ('apply_candidate_patch',), 1),
        ('hia_agent_macro_discovery', ('macro_policy_guidance',)): _import_name_port(_import_template_3, namespace, 'hia_agent_macro_discovery', ('macro_policy_guidance',), 1),
        ('hia_edit_query', ('prepare_edit',)): _import_name_port(_import_template_4, namespace, 'hia_edit_query', ('prepare_edit',), 1),
        ('hia_opcodes', ('opcode_catalog',)): _import_name_port(_import_template_5, namespace, 'hia_opcodes', ('opcode_catalog',), 1),
        ('hia_program_native', ('TARGET', 'PROFILE', 'SUPPORTED_OPCODES', 'CORE_SCHEMAS', 'IMPORTS')): _import_name_port(_import_template_6, namespace, 'hia_program_native', ('TARGET', 'PROFILE', 'SUPPORTED_OPCODES', 'CORE_SCHEMAS', 'IMPORTS'), 1),
        ('hia_program_native', ('emit_program_machine',)): _import_name_port(_import_template_7, namespace, 'hia_program_native', ('emit_program_machine',), 1),
        ('hia_program_tools', ('apply_program_patch',)): _import_name_port(_import_template_8, namespace, 'hia_program_tools', ('apply_program_patch',), 1),
        ('hia_program_tools', ('inspect_program',)): _import_name_port(_import_template_9, namespace, 'hia_program_tools', ('inspect_program',), 1),
        ('hia_proof_contract_selection', ('proof_contract_scope',)): _import_name_port(_import_template_10, namespace, 'hia_proof_contract_selection', ('proof_contract_scope',), 1),
        ('hia_safe_core', ('ARTIFACT_PROFILE', 'LIMITS')): _import_name_port(_import_template_11, namespace, 'hia_safe_core', ('ARTIFACT_PROFILE', 'LIMITS'), 1),
        ('hia_schema', ('schema_registry',)): _import_name_port(_import_template_12, namespace, 'hia_schema', ('schema_registry',), 1),
    }, {name: _import_from_port(name, namespace) for name in IMPORT_NAMES})

def _call_0(frame, slots):
    return frame._move(slots[0])()

def _call_1(frame, slots):
    return frame._move(slots[0])(frame._move(slots[1]))

def _call_2(frame, slots):
    return frame._move(slots[0])(frame._move(slots[1]), foreign_buffer_exports=frame._move(slots[2]))

def _call_3(frame, slots):
    return frame._move(slots[0])(frame._move(slots[1]), function=frame._move(slots[2]), block=frame._move(slots[3]), output=frame._move(slots[4]), fields=frame._move(slots[5]))

def _call_4(frame, slots):
    return frame._move(slots[0])(frame._move(slots[1]), frame._move(slots[2]))

def _call_5(frame, slots):
    return frame._move(slots[0])(frame._move(slots[1]), frame._move(slots[2]), frame._move(slots[3]))

def _call_6(frame, slots):
    return frame._move(slots[0])(frame._move(slots[1]), frame._move(slots[2]), frame._move(slots[3]), frame._move(slots[4]))

CALLS = {
    (0, ()): _call_0,
    (1, ()): _call_1,
    (1, ('foreign_buffer_exports',)): _call_2,
    (1, ('function', 'block', 'output', 'fields')): _call_3,
    (2, ()): _call_4,
    (3, ()): _call_5,
    (4, ()): _call_6,
}

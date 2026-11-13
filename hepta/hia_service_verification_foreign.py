"""Fixed CPython call/mapping primitives for HIA-issued verification ports.

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
        raise RuntimeError('verification mapping ports require a reviewed CPython ABI')


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
        raise RuntimeError('verification DICT_MERGE opcode template differs')
    # 3.14 can omit the unused implicit None from the original constants.
    # Preserve all original literal indexes; append a real None only for
    # the fixed, safely poppable replacement of the interpreter NULL.
    port_constants = constants if None in constants else constants + (None,)
    none_index = port_constants.index(None)
    raw = bytearray(code.co_code[:calls[0].offset])
    raw[nulls[0].offset:nulls[0].offset+2] = bytes((dis.opmap['LOAD_CONST'], none_index))
    raw.extend(bytes((dis.opmap['SWAP'], 2, dis.opmap['POP_TOP'], 0)) * 3)
    raw.extend(bytes((dis.opmap['RETURN_VALUE'], 0)))
    result = FunctionType(code.replace(co_code=bytes(raw), co_consts=port_constants, co_name='_verification_dict_merge',
                          co_qualname='_verification_dict_merge'), globals())
    if any(i.opname == 'CALL_FUNCTION_EX' for i in dis.get_instructions(result)):
        raise RuntimeError('verification mapping preparation still calls a provider')
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
        raise RuntimeError('verification DICT_UPDATE opcode template differs')
    raw = bytearray(code.co_code)
    # Omit the unused new dict and the copy of the actual destination. The
    # remaining fixed DICT_UPDATE mutates that exact HIA-owned dict, so an
    # overwritten foreign value is not kept alive by a shadow dictionary.
    for item in (maps[0], updates[0]):
        raw[item.offset:item.offset+2] = bytes((dis.opmap['NOP'], 0))
    return FunctionType(code.replace(co_code=bytes(raw), co_name='_verification_dict_update',
                        co_qualname='_verification_dict_update'), globals())


merge_empty = _merge_port(_merge_empty_template, (None,))
merge_kind = _merge_port(_merge_kind_template,
                         ('kind',) if sys.version_info[:2] == (3, 14) else (None, 'kind'))
update_dict = _update_port()


def mapping_call(frame, callee_slot, positional_slot, keywords_slot):
    if type(frame._get(positional_slot)) is not tuple or type(frame._get(keywords_slot)) is not dict:
        raise RuntimeError('verification mapping call lacks exact prepared containers')
    return frame._move(callee_slot)(*frame._move(positional_slot), **frame._move(keywords_slot))

def _call_0(frame, slots):
    return frame._move(slots[0])()

def _call_1(frame, slots):
    return frame._move(slots[0])(claim=frame._move(slots[1]), status=frame._move(slots[2]), domain=frame._move(slots[3]), subject=frame._move(slots[4]), profile=frame._move(slots[5]), installation=frame._move(slots[6]), evidence=frame._move(slots[7]), held_native_owners=frame._move(slots[8]))

def _call_2(frame, slots):
    return frame._move(slots[0])(held_owners=frame._move(slots[1]))

def _call_3(frame, slots):
    return frame._move(slots[0])(outcome=frame._move(slots[1]), deadline_met=frame._move(slots[2]), reason=frame._move(slots[3]))

def _call_4(frame, slots):
    return frame._move(slots[0])(frame._move(slots[1]))

def _call_5(frame, slots):
    return frame._move(slots[0])(frame._move(slots[1]), foreign_buffer_exports=frame._move(slots[2]))

def _call_6(frame, slots):
    return frame._move(slots[0])(frame._move(slots[1]), kind=frame._move(slots[2]))

def _call_7(frame, slots):
    return frame._move(slots[0])(frame._move(slots[1]), machine_plan=frame._move(slots[2]), foreign_buffer_exports=frame._move(slots[3]))

def _call_8(frame, slots):
    return frame._move(slots[0])(frame._move(slots[1]), frame._move(slots[2]))

def _call_9(frame, slots):
    return frame._move(slots[0])(frame._move(slots[1]), frame._move(slots[2]), frame._move(slots[3]))

def _call_10(frame, slots):
    return frame._move(slots[0])(frame._move(slots[1]), frame._move(slots[2]), frame._move(slots[3]), frame._move(slots[4]), frame._move(slots[5]))

CALLS = {
    (0, ()): _call_0,
    (0, ('claim', 'status', 'domain', 'subject', 'profile', 'installation', 'evidence', 'held_native_owners')): _call_1,
    (0, ('held_owners',)): _call_2,
    (0, ('outcome', 'deadline_met', 'reason')): _call_3,
    (1, ()): _call_4,
    (1, ('foreign_buffer_exports',)): _call_5,
    (1, ('kind',)): _call_6,
    (1, ('machine_plan', 'foreign_buffer_exports')): _call_7,
    (2, ()): _call_8,
    (3, ()): _call_9,
    (5, ()): _call_10,
}

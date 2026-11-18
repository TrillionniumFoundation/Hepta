"""Author the complete nominal constructor, with typed native continuations.

The retained constructor is the development oracle. No Python branch below is
part of runtime admission; the installed bridge only moves issued state.
"""
from __future__ import annotations

import ast
from pathlib import Path
from pprint import pformat

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_core_json_frontend import packed
from tools.generate_hia_composite_functions import COMMON, RENDER, CONSTANTS as GENERIC
from tools.generate_hia_composite_function_admission import BODY as ADMISSION
from tools.generate_hia_instruction_policy import SOURCE as TRANSPORT
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions

KEYS = ('schema', 'module', 'types', 'functions', 'name', 'params', 'returns',
        'effects', 'entry', 'blocks', 'return_loans', 'kind')
CONSTANTS = {**GENERIC,
    'MAGIC': int.from_bytes(b'HIACTK01', 'little'),
    'STATE_MAGIC': int.from_bytes(b'HIACTS01', 'little'),
    'CTOR_MAGIC': int.from_bytes(b'HIACTR01', 'little'),
    'RESPONSE_MAGIC': int.from_bytes(b'HIACTP01', 'little'),
    'COMMAND_REQUEST': int.from_bytes(b'HIACCQ01', 'little'),
    'COMMAND_REPLY': int.from_bytes(b'HIACCP01', 'little'),
    'HANDOFF_REQUEST': int.from_bytes(b'HIACIQ01', 'little'),
    'HANDOFF_REPLY': int.from_bytes(b'HIACIP01', 'little'),
    'COMMAND_CAPACITY': (32 << 20) + 64,
    'COMMAND_CURSOR': 4096 + 384,
    'COMMAND_LIMIT': 4096 + 392,
    'COMMAND_FAILED': 4096 + 400,
    'TYPE_MAGIC': int.from_bytes(b'HIATYS01', 'little'),
    'TYPE_BYTES': 128 << 20, 'TS': 96 << 20, 'TYPES': (96 << 20) + 65536,
    **{'K_' + value: 1 << i for i, value in enumerate(KEYS)},
}
ERRORS = {
    1: ('E_HIA_FORMAT', 'nominal program: expected exactly functions, module, schema, types'),
    2: ('E_HIA_SCHEMA', 'unsupported nominal program schema'),
    3: ('E_HIA_SCHEMA', 'legacy nominal adapter only targets composite v1'),
    4: ('E_HIA_NAME', 'module: invalid/reserved ASCII identifier'),
    5: ('E_HIA_NAME', 'module: identifier uses the elaborator namespace'),
    6: ('E_HIA_FORMAT', 'invalid nominal function inventory'),
    7: ('E_HIA_FORMAT', 'function: expected exactly blocks, effects, entry, name, params, returns'),
    8: ('E_HIA_FORMAT', 'function: expected exactly blocks, effects, entry, name, params, return_loans, returns'),
    9: ('E_HIA_NAME', 'function: invalid/reserved ASCII identifier'),
    10: ('E_HIA_NAME', 'function: identifier uses the elaborator namespace'),
    11: ('E_HIA_NAME', 'duplicate nominal function'),
    12: ('E_HIA_TYPE', 'function returns must be a list'),
    13: ('E_HIA_LOAN', 'stored loans may not escape a function'),
    14: ('E_HIA_EFFECT', 'unknown/duplicate nominal function effect'),
}

# The generic state prefix is unchanged. Constructor words start at S+128.
# stage 0: no owner attributes; 1: document/counters/profile; 2: types/loan flag;
# stage 3: the five inventories exist. Prefix commits are never rolled back.
BODY = r'''
def constructor(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) < W_BYTES:
        return ABI
    if length(o) < 64 or get(w, S + 96) != 0:
        return fatal(w)
    if length(s) == 24 and word(s, 0) == COMMAND_REQUEST:
        return pack_command(s, o, w)
    if length(s) == 16 and word(s, 0) == HANDOFF_REQUEST:
        return pack_handoff(s, o, w)
    if length(s) >= 64 and word(s, 0) == RESPONSE_MAGIC:
        if get(w, S) != STATE_MAGIC or get(w, S + 128) == 0 or get(w, S + 48) != 1:
            return fatal(w)
        return response(s, o, w)
    if length(s) == TYPE_BYTES:
        if get(w, S) != STATE_MAGIC or word(s, TS) != TYPE_MAGIC or word(s, TS + 48) != 1:
            return fatal(w)
        if get(w, S + 128) != 0 or get(w, S + 112) != 0 or get(w, S + 120) >= 2000:
            return fatal(w)
        return ctor_frame(o, w, ctor_run(s, w))
    if get(w, S) != 0 or length(s) > I_BYTES or validate_packet(s, w) == 0:
        return fatal(w)
    i = 0
    while i < 384:
        put(w, S + i, 0)
        i = i + 8
    i = 0
    while i < length(s):
        store(w, SOURCE_BASE + i, byte(s, i))
        i = i + 1
    put(w, S, STATE_MAGIC)
    put(w, S + 8, ARENA)
    put(w, S + 16, length(s))
    put(w, S + 24, SOURCE_BASE)
    if g_kind(w, SOURCE_BASE) != 5 or g_count(w, SOURCE_BASE) != 2:
        return fatal(w)
    legacy = g_at(w, SOURCE_BASE, 1)
    if g_kind(w, legacy) != 1:
        return fatal(w)
    put(w, S + 144, g_at(w, SOURCE_BASE, 0))
    put(w, S + 152, byte(w, legacy + 16))
    return ctor_frame(o, w, begin_constructor(w))
def pack_command(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    sequence = word(s, 8)
    service = word(s, 16)
    if get(w, S) != STATE_MAGIC or get(w, S + 48) != 0:
        return ABI
    if sequence == 0 or sequence != get(w, S + 88) or service != get(w, S + 128):
        return ABI
    if service < 1 or service > 5:
        return ABI
    limit = length(o)
    if limit > COMMAND_CAPACITY:
        limit = COMMAND_CAPACITY
    put(w, COMMAND_CURSOR, 64)
    put(w, COMMAND_LIMIT, limit)
    put(w, COMMAND_FAILED, 0)
    command = get(w, S + 32)
    if service == 1:
        pack_init(o, w, command)
    elif service == 2:
        pack_unary(o, w, command, service)
    elif service == 3:
        pack_unary(o, w, command, service)
    elif service == 4:
        pack_origins(o, w, command)
    else:
        pack_task(o, w, command)
    if get(w, COMMAND_FAILED) != 0:
        return ABI
    extent = get(w, COMMAND_CURSOR)
    put(o, 0, COMMAND_REPLY)
    put(o, 8, sequence)
    put(o, 16, service)
    put(o, 24, extent - 64)
    put(o, 32, 0)
    put(o, 40, 0)
    put(o, 48, 0)
    put(o, 56, 0)
    # A packed request completes the same one-shot emission as the existing
    # token stream. Resolving an earlier or already emitted request is invalid.
    put(w, S + 48, 1)
    return extent

def pack_reserve(w:mutbuf, length:u64) -> u64:
    at = get(w, COMMAND_CURSOR)
    if length > get(w, COMMAND_LIMIT) - at:
        put(w, COMMAND_FAILED, 1)
        return N
    put(w, COMMAND_CURSOR, at + length)
    return at

def pack_open(o:mutbuf, w:mutbuf, kind:u64, count:u64) -> u64:
    at = pack_reserve(w, 24)
    if at != N:
        put(o, at, kind)
        put(o, at + 8, 0)
        put(o, at + 16, count)
    return at

def pack_close(o:mutbuf, w:mutbuf, at:u64) -> u64:
    if at != N:
        put(o, at + 8, get(w, COMMAND_CURSOR) - at - 16)
    return 0

def pack_text(o:mutbuf, w:mutbuf, size:u64, a:u64, b:u64, c:u64) -> u64:
    at = pack_reserve(w, size + 16)
    if at == N:
        return 0
    put(o, at, 4)
    put(o, at + 8, size)
    index = 0
    while index < size:
        word = a
        shift = index * 8
        if index >= 16:
            word = c
            shift = (index - 16) * 8
        elif index >= 8:
            word = b
            shift = (index - 8) * 8
        store(o, at + 16 + index, (word >> shift) & 255)
        index = index + 1
    return 0

def pack_original(o:mutbuf, w:mutbuf, address:u64) -> u64:
    first = get(w, S + 24)
    stop = first + get(w, S + 16)
    if address < first or address > stop or stop - address < 16:
        put(w, COMMAND_FAILED, 1)
        return 0
    last = g_end(w, address)
    if last < address + 16 or last > stop:
        put(w, COMMAND_FAILED, 1)
        return 0
    size = last - address
    at = pack_reserve(w, size)
    if at == N:
        return 0
    index = 0
    while index < size:
        store(o, at + index, byte(w, address + index))
        index = index + 1
    return 0

def pack_reference(o:mutbuf, w:mutbuf, node:u64) -> u64:
    return pack_original(o, w, SOURCE_BASE + get(w, node + 8))

def pack_boolean(o:mutbuf, w:mutbuf, node:u64) -> u64:
    return pack_flag(o, w, get(w, node + 8))

def pack_flag(o:mutbuf, w:mutbuf, flag:u64) -> u64:
    at = pack_reserve(w, 17)
    if at != N:
        put(o, at, 1)
        put(o, at + 8, 1)
        store(o, at + 16, flag)
    return 0

def pack_identifier(o:mutbuf, w:mutbuf, node:u64) -> u64:
    value = get(w, node + 8)
    if value == 0 or value > 144:
        put(w, COMMAND_FAILED, 1)
        return 0
    return pack_small_number(o, w, value)

def pack_small_number(o:mutbuf, w:mutbuf, value:u64) -> u64:
    if value > 512:
        put(w, COMMAND_FAILED, 1)
        return 0
    digits = 1
    if value >= 10:
        digits = 2
    if value >= 100:
        digits = 3
    at = pack_reserve(w, 16 + digits)
    if at == N:
        return 0
    put(o, at, 2)
    put(o, at + 8, digits)
    cursor = at + 16
    if digits == 3:
        hundreds = 0
        while value >= 100:
            value = value - 100
            hundreds = hundreds + 1
        store(o, cursor, 48 + hundreds)
        cursor = cursor + 1
    if digits >= 2:
        tens = 0
        while value >= 10:
            value = value - 10
            tens = tens + 1
        store(o, cursor, 48 + tens)
        cursor = cursor + 1
    store(o, cursor, 48 + value)
    return 0

def ir_item(w:mutbuf, list:u64, index:u64) -> u64:
    # Constructor command/signature lists contain only appended item segments.
    segment = get(w, list + 8)
    while index != 0:
        segment = get(w, segment)
        index = index - 1
    return get(w, segment + 16)

def pack_init(o:mutbuf, w:mutbuf, command:u64) -> u64:
    root = pack_open(o, w, 6, 4)
    pack_text(o, w, T_op)
    pack_text(o, w, T_init)
    pack_text(o, w, T_definitions)
    pack_reference(o, w, ir_item(w, command, 1))
    pack_text(o, w, T_recursive_chain)
    pack_boolean(o, w, ir_item(w, command, 2))
    pack_text(o, w, T_partial_records)
    pack_boolean(o, w, ir_item(w, command, 3))
    return pack_close(o, w, root)

def pack_unary(o:mutbuf, w:mutbuf, command:u64, service:u64) -> u64:
    root = pack_open(o, w, 6, 2)
    pack_text(o, w, T_op)
    if service == 2:
        pack_text(o, w, T_parameters)
        pack_text(o, w, T_params)
    else:
        pack_text(o, w, T_resolve)
        pack_text(o, w, T_ref)
    pack_reference(o, w, ir_item(w, command, 1))
    return pack_close(o, w, root)

def pack_parameters(o:mutbuf, w:mutbuf, list:u64, include_names:bool) -> u64:
    root = pack_open(o, w, 5, get(w, list + 24))
    segment = get(w, list + 8)
    while segment != 0:
        item = get(w, segment + 16)
        if include_names:
            pair = pack_open(o, w, 5, 2)
            pack_reference(o, w, ir_item(w, item, 0))
            pack_identifier(o, w, ir_item(w, item, 1))
            pack_close(o, w, pair)
        else:
            pack_identifier(o, w, ir_item(w, item, 1))
        segment = get(w, segment)
    return pack_close(o, w, root)

def pack_returns(o:mutbuf, w:mutbuf, list:u64) -> u64:
    root = pack_open(o, w, 5, get(w, list + 24))
    segment = get(w, list + 8)
    while segment != 0:
        pack_identifier(o, w, get(w, segment + 16))
        segment = get(w, segment)
    return pack_close(o, w, root)

def pack_origins(o:mutbuf, w:mutbuf, command:u64) -> u64:
    function = SOURCE_BASE + get(w, ir_item(w, command, 1) + 8)
    annotation = g_field(w, function, K_return_loans)
    root = pack_open(o, w, 6, choose(annotation == N, 3, 4))
    pack_text(o, w, T_op)
    pack_text(o, w, T_origins)
    pack_text(o, w, T_params)
    pack_parameters(o, w, ir_item(w, command, 2), True)
    pack_text(o, w, T_returns)
    pack_returns(o, w, ir_item(w, command, 3))
    if annotation != N:
        pack_text(o, w, T_return_loans)
        pack_original(o, w, annotation)
    return pack_close(o, w, root)

def pack_task(o:mutbuf, w:mutbuf, command:u64) -> u64:
    root = pack_open(o, w, 6, 3)
    pack_text(o, w, T_op)
    pack_text(o, w, T_task_protocol)
    pack_text(o, w, T_task)
    pack_identifier(o, w, ir_item(w, command, 1))
    pack_text(o, w, T_functions)
    pack_signatures(o, w, ir_item(w, command, 2), False)
    return pack_close(o, w, root)

def pack_signatures(o:mutbuf, w:mutbuf, registry:u64, include_names:bool) -> u64:
    functions = pack_open(o, w, 5, get(w, registry + 24))
    segment = get(w, registry + 8)
    while segment != 0:
        item = get(w, segment + 16)
        row = pack_open(o, w, 5, 3)
        pack_reference(o, w, ir_item(w, item, 0))
        pack_parameters(o, w, ir_item(w, item, 1), include_names)
        pack_returns(o, w, ir_item(w, item, 2))
        pack_close(o, w, row)
        segment = get(w, segment)
    return pack_close(o, w, functions)

def pack_handoff(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if get(w, S) != STATE_MAGIC or get(w, S + 112) != 0:
        return ABI
    if get(w, S + 120) != 2000 or get(w, S + 128) != 0 or get(w, S + 136) != 3:
        return ABI
    role = word(s, 8)
    if role != 1 and role != 2:
        return ABI
    limit = length(o)
    if limit > COMMAND_CAPACITY:
        limit = COMMAND_CAPACITY
    put(w, COMMAND_CURSOR, 64)
    put(w, COMMAND_LIMIT, limit)
    put(w, COMMAND_FAILED, 0)
    root = pack_open(o, w, 5, choose(role == 1, 7, 6))
    pack_original(o, w, get(w, S + 144))
    pack_signatures(o, w, get(w, S + 208), True)
    if role == 1:
        pack_loan_inventory(o, w, get(w, S + 216))
    # Constructor commits precede all generated-name and output-slot claims.
    pack_small_number(o, w, 0)
    pack_small_number(o, w, 0)
    if role == 1:
        pack_flag(o, w, get(w, S + 152))
        pack_small_number(o, w, 0)
    else:
        pack_close(o, w, pack_open(o, w, 5, 0))
        pack_close(o, w, pack_open(o, w, 5, 0))
    pack_close(o, w, root)
    if get(w, COMMAND_FAILED) != 0:
        return ABI
    extent = get(w, COMMAND_CURSOR)
    put(o, 0, HANDOFF_REPLY)
    put(o, 8, role)
    put(o, 16, extent - 64)
    put(o, 24, get(w, S + 160))
    put(o, 32, get(w, S + 88))
    put(o, 40, 0)
    put(o, 48, 0)
    put(o, 56, 0)
    return extent

def pack_loan_inventory(o:mutbuf, w:mutbuf, list:u64) -> u64:
    root = pack_open(o, w, 5, get(w, list + 24))
    segment = get(w, list + 8)
    while segment != 0:
        item = get(w, segment + 16)
        row = pack_open(o, w, 5, 2)
        pack_reference(o, w, ir_item(w, item, 0))
        pack_loan_slots(o, w, ir_item(w, item, 1))
        pack_close(o, w, row)
        segment = get(w, segment)
    return pack_close(o, w, root)

def pack_loan_slots(o:mutbuf, w:mutbuf, list:u64) -> u64:
    root = pack_open(o, w, 5, get(w, list + 24))
    segment = get(w, list + 8)
    while segment != 0:
        slot = get(w, segment + 16)
        if get(w, slot) == 4:
            at = pack_reserve(w, 16)
            if at != N:
                put(o, at, 0)
                put(o, at + 8, 0)
        else:
            row = pack_open(o, w, 5, 2)
            pack_generated_text(o, w, ir_item(w, slot, 0))
            pack_small_number(o, w, get(w, ir_item(w, slot, 1) + 8))
            pack_close(o, w, row)
        segment = get(w, segment)
    return pack_close(o, w, root)

def pack_generated_text(o:mutbuf, w:mutbuf, node:u64) -> u64:
    start = get(w, node + 8)
    count = get(w, node + 16)
    at = pack_reserve(w, 16 + count)
    if at != N:
        put(o, at, 4)
        put(o, at + 8, count)
        index = 0
        while index < count:
            store(o, at + 16 + index, byte(w, start + index))
            index = index + 1
    return 0


def ctor_frame(o:mutbuf, w:mutbuf, action:u64) -> u32:
    if get(w, S + 96) != 0:
        return ABI
    put(o, 0, CTOR_MAGIC)
    put(o, 8, action)
    put(o, 16, get(w, S + 112))
    put(o, 24, get(w, S + 120))
    put(o, 32, get(w, S + 136))
    put(o, 40, get(w, S + 160))
    put(o, 48, get(w, S + 88))
    put(o, 56, get(w, S + 128))
    return 64

def complete(w:mutbuf, error:u64) -> u64:
    put(w, S + 112, error)
    put(w, S + 120, 2000)
    put(w, S + 128, 0)
    result = ir_list(w)
    ir_append(w, result, ir_integer(w, get(w, S + 136)))
    ir_append(w, result, ir_integer(w, get(w, S + 160)))
    ir_append(w, result, ir_bool(w, get(w, S + 152)))
    if get(w, S + 136) == 0:
        ir_append(w, result, ir_null(w))
    else:
        ir_append(w, result, ir_source(w, get(w, S + 144)))
    if get(w, S + 136) < 3:
        ir_append(w, result, ir_null(w))
        ir_append(w, result, ir_null(w))
    else:
        ir_append(w, result, get(w, S + 208))
        ir_append(w, result, get(w, S + 216))
    stream_begin(w, result, 0)
    return 2

def request(w:mutbuf, kind:u64, command:u64, phase:u64) -> u64:
    put(w, S + 128, kind)
    put(w, S + 120, phase)
    put(w, S + 88, get(w, S + 88) + 1)
    stream_begin(w, command, kind)
    return 2

def unary_request(w:mutbuf, kind:u64, source:u64, phase:u64) -> u64:
    command = ir_list(w)
    ir_append(w, command, ir_integer(w, kind))
    ir_append(w, command, ir_source(w, source))
    return request(w, kind, command, phase)

def begin_constructor(w:mutbuf) -> u64:
    doc = get(w, S + 144)
    if g_shape(w, doc, K_schema | K_module | K_types | K_functions) == 0:
        return complete(w, 1)
    selected = profile(w, g_field(w, doc, K_schema))
    if selected == 0:
        return complete(w, 2)
    if get(w, S + 152) != 0 and selected != 1:
        return complete(w, 3)
    status = name_status(w, g_field(w, doc, K_module))
    if status != 0:
        return complete(w, 3 + status)
    put(w, S + 160, selected)
    put(w, S + 136, 1)
    command = ir_list(w)
    ir_append(w, command, ir_integer(w, 1))
    ir_append(w, command, ir_source(w, g_field(w, doc, K_types)))
    ir_append(w, command, ir_bool(w, choose(selected != 1, 1, 0)))
    ir_append(w, command, ir_bool(w, choose(selected >= 3, 1, 0)))
    return request(w, 1, command, 10)

def response(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    kind = get(w, S + 128)
    count = word(s, 32)
    size = word(s, 40)
    if word(s, 8) != get(w, S + 88) or word(s, 16) != kind or word(s, 24) > 1:
        return fatal(w)
    if word(s, 48) != 0 or word(s, 56) != 0 or size != length(s) - 64 or count > 262144:
        return fatal(w)
    if word(s, 24) == 1:
        if count != 0 or size != 0:
            return fatal(w)
        return ctor_frame(o, w, complete(w, 999))
    if kind == 4:
        if read_origins(s, w, count) == 0:
            return fatal(w)
    else:
        if size != count * 8:
            return fatal(w)
        expected = 1
        if kind == 1:
            expected = 0
        if kind == 2:
            params = g_field(w, get(w, S + 200), K_params)
            if g_kind(w, params) != 5:
                return fatal(w)
            expected = g_count(w, params)
        if count != expected:
            return fatal(w)
        ids = allocate(w, count * 8)
        i = 0
        while i < count:
            identifier = word(s, 64 + i * 8)
            if identifier == 0 or identifier > 144:
                return fatal(w)
            put(w, ids + i * 8, identifier)
            i = i + 1
        if kind == 1:
            put(w, S + 136, 2)
        elif kind == 2:
            put(w, S + 240, ids)
            put(w, S + 248, count)
        else:
            put(w, S + 288, get(w, ids))
    put(w, S + 128, 0)
    return ctor_frame(o, w, 0)

def read_origins(s:readbuf, w:mutbuf, count:u64) -> u64:
    if count != get(w, S + 264):
        return 0
    result = ir_list(w)
    checks = allocate(w, count * 16)
    put(w, S + 336, checks)
    at = 64
    i = 0
    while i < count:
        if at > length(s) or length(s) - at < 24:
            return 0
        flag = word(s, at)
        size = word(s, at + 8)
        offset = word(s, at + 16)
        at = at + 24
        if flag == 0:
            if size != 0 or offset != 0:
                return 0
            ir_append(w, result, ir_null(w))
        else:
            if flag != 1 or size == 0 or size > 128 or offset >= 512 or size > length(s) - at:
                return 0
            name = allocate(w, size + 16)
            put(w, name, 4)
            put(w, name + 8, size)
            j = 0
            while j < size:
                store(w, name + 16 + j, byte(s, at + j))
                j = j + 1
            at = at + size
            if name_status(w, name) != 0:
                return 0
            identifier = table_get(w, get(w, S + 360), get(w, S + 368), name)
            if identifier == 0:
                return 0
            put(w, checks + i * 16, identifier)
            put(w, checks + i * 16 + 8, offset)
            item = ir_list(w)
            ir_append(w, item, ir_node(w, 1, name + 16, size, 0))
            ir_append(w, item, ir_integer(w, offset))
            ir_append(w, result, item)
        i = i + 1
    if at != length(s):
        return 0
    put(w, S + 312, result)
    return 1

def ctor_run(s:readbuf, w:mutbuf) -> u64:
    while get(w, S + 96) == 0:
        phase = get(w, S + 120)
        if phase == 10:
            functions = g_field(w, get(w, S + 144), K_functions)
            if g_kind(w, functions) != 5 or g_count(w, functions) == 0 or g_count(w, functions) > 1024:
                return complete(w, 6)
            put(w, S + 176, functions)
            put(w, S + 184, functions + 24)
            put(w, S + 192, g_count(w, functions))
            put(w, S + 208, ir_list(w))
            put(w, S + 216, ir_list(w))
            put(w, S + 224, allocate(w, 2048 * 16))
            put(w, S + 136, 3)
            put(w, S + 120, 20)
        elif phase == 20:
            if get(w, S + 192) == 0:
                definitions = g_field(w, get(w, S + 144), K_types)
                put(w, S + 320, definitions + 24)
                put(w, S + 328, g_count(w, definitions))
                put(w, S + 120, 80)
            else:
                return begin_function(w)
        elif phase == 30:
            if accept_parameters(s, w) == 0:
                return 0
            returns = g_field(w, get(w, S + 200), K_returns)
            if g_kind(w, returns) != 5:
                return complete(w, 12)
            put(w, S + 256, allocate(w, g_count(w, returns) * 8))
            put(w, S + 264, g_count(w, returns))
            put(w, S + 272, returns + 24)
            put(w, S + 280, g_count(w, returns))
            put(w, S + 304, ir_list(w))
            put(w, S + 120, 40)
        elif phase == 40:
            if get(w, S + 280) != 0:
                return unary_request(w, 3, get(w, S + 272), 41)
            check = stored_loans(s, w)
            if check == 0:
                return complete(w, 13)
            if get(w, S + 160) == 4:
                return origin_request(w)
            put(w, S + 120, 60)
        elif phase == 41:
            identifier = get(w, S + 288)
            if issued(s, identifier) == 0:
                fatal(w)
                return 0
            index = get(w, S + 264) - get(w, S + 280)
            put(w, get(w, S + 256) + index * 8, identifier)
            ir_append(w, get(w, S + 304), ir_integer(w, identifier))
            put(w, S + 272, g_end(w, get(w, S + 272)))
            put(w, S + 280, get(w, S + 280) - 1)
            put(w, S + 120, 40)
        elif phase == 50:
            if accept_origins(s, w) == 0:
                return 0
            row = ir_list(w)
            ir_append(w, row, ir_source(w, get(w, S + 232)))
            ir_append(w, row, get(w, S + 312))
            ir_append(w, get(w, S + 216), row)
            put(w, S + 120, 60)
        elif phase == 60:
            if valid_effects(w, g_field(w, get(w, S + 200), K_effects)) == 0:
                return complete(w, 14)
            commit_function(w)
            put(w, S + 184, g_end(w, get(w, S + 184)))
            put(w, S + 192, get(w, S + 192) - 1)
            put(w, S + 120, 20)
        elif phase == 80:
            if get(w, S + 328) == 0:
                return complete(w, 0)
            definition = get(w, S + 320)
            if text_is(w, g_field(w, definition, K_kind), L_task) != 0:
                return unary_request(w, 3, g_field(w, definition, K_name), 81)
            next_definition(w)
        elif phase == 81:
            identifier = get(w, S + 288)
            if issued(s, identifier) == 0:
                fatal(w)
                return 0
            command = ir_list(w)
            ir_append(w, command, ir_integer(w, 5))
            ir_append(w, command, ir_integer(w, identifier))
            ir_append(w, command, get(w, S + 208))
            return request(w, 5, command, 82)
        elif phase == 82:
            if issued(s, get(w, S + 288)) == 0:
                fatal(w)
                return 0
            next_definition(w)
        else:
            fatal(w)
            return 0
    return 0

def begin_function(w:mutbuf) -> u64:
    fn = get(w, S + 184)
    put(w, S + 200, fn)
    fields = K_name | K_params | K_returns | K_effects | K_entry | K_blocks
    error = 7
    if get(w, S + 160) == 4 and g_field(w, fn, K_return_loans) != N:
        fields = fields | K_return_loans
        error = 8
    if g_shape(w, fn, fields) == 0:
        return complete(w, error)
    name = g_field(w, fn, K_name)
    status = name_status(w, name)
    if status != 0:
        return complete(w, 8 + status)
    if table_get(w, get(w, S + 224), 2047, name) != 0:
        return complete(w, 11)
    put(w, S + 232, name)
    return unary_request(w, 2, g_field(w, fn, K_params), 30)

def accept_parameters(s:readbuf, w:mutbuf) -> u64:
    result = ir_list(w)
    count = get(w, S + 248)
    capacity = 2
    while capacity < count * 2:
        capacity = capacity * 2
    table = allocate(w, capacity * 16)
    put(w, S + 360, table)
    put(w, S + 368, capacity - 1)
    source = g_field(w, get(w, S + 200), K_params) + 24
    i = 0
    while i < count:
        identifier = get(w, get(w, S + 240) + i * 8)
        if issued(s, identifier) == 0:
            fatal(w)
            return 0
        name = g_field(w, source, K_name)
        if name_status(w, name) != 0 or table_get(w, table, capacity - 1, name) != 0:
            fatal(w)
            return 0
        table_put(w, table, capacity - 1, name, identifier)
        row = ir_list(w)
        ir_append(w, row, ir_source(w, name))
        ir_append(w, row, ir_integer(w, identifier))
        ir_append(w, result, row)
        source = g_end(w, source)
        i = i + 1
    put(w, S + 296, result)
    return 1

def stored_loans(s:readbuf, w:mutbuf) -> u64:
    i = 0
    while i < get(w, S + 264):
        location = type_at(get(w, get(w, S + 256) + i * 8))
        if word(s, location + 37848) != 0:
            if get(w, S + 160) != 4 or word(s, location) != 0:
                return 0
        i = i + 1
    return 1

def origin_request(w:mutbuf) -> u64:
    command = ir_list(w)
    ir_append(w, command, ir_integer(w, 4))
    ir_append(w, command, ir_source(w, get(w, S + 200)))
    ir_append(w, command, get(w, S + 296))
    ir_append(w, command, get(w, S + 304))
    return request(w, 4, command, 50)

def accept_origins(s:readbuf, w:mutbuf) -> u64:
    i = 0
    while i < get(w, S + 264):
        check = get(w, S + 336) + i * 16
        identifier = get(w, check)
        if identifier != 0:
            if issued(s, identifier) == 0 or get(w, check + 8) >= word(s, type_at(identifier) + 152):
                fatal(w)
                return 0
        i = i + 1
    return 1

def valid_effects(w:mutbuf, node:u64) -> u64:
    if g_kind(w, node) != 5:
        return 0
    i = 0
    item = node + 24
    seen = 0
    duplicate = 0
    while i < g_count(w, node):
        effect = effect_id(w, item)
        if effect == 0:
            return 0
        if (seen & effect) != 0:
            duplicate = 1
        seen = seen | effect
        item = g_end(w, item)
        i = i + 1
    return choose(duplicate == 0, 1, 0)

def commit_function(w:mutbuf) -> u64:
    row = ir_list(w)
    name = get(w, S + 232)
    ir_append(w, row, ir_source(w, name))
    ir_append(w, row, get(w, S + 296))
    ir_append(w, row, get(w, S + 304))
    ir_append(w, row, ir_source(w, get(w, S + 200)))
    ir_append(w, get(w, S + 208), row)
    table_put(w, get(w, S + 224), 2047, name, 1)
    return 0

def next_definition(w:mutbuf) -> u64:
    put(w, S + 320, g_end(w, get(w, S + 320)))
    put(w, S + 328, get(w, S + 328) - 1)
    put(w, S + 120, 80)
    return 0
'''


def suffix():
    lines = ['def key_id(w:mutbuf, node:u64) -> u64:']
    for i, text in enumerate(KEYS):
        lines += [f'    if text_is(w, node, {", ".join(map(str, packed(text)))}) != 0:',
                  f'        return {1 << i}']
    lines += ['    return 0', '', 'def profile(w:mutbuf, node:u64) -> u64:']
    for i in range(1, 5):
        value = ', '.join(map(str, packed('hepta.hia.composite.v' + str(i))))
        lines += [f'    if text_is(w, node, {value}) != 0:', f'        return {i}']
    lines += ['    return 0', '', 'def effect_id(w:mutbuf, node:u64) -> u64:']
    for i, text in enumerate(('alloc', 'read', 'write', 'trap')):
        value = ', '.join(map(str, packed(text)))
        lines += [f'    if text_is(w, node, {value}) != 0:', f'        return {1 << i}']
    return '\n'.join(lines + ['    return 0']) + '\n'


def source_program(kernel):
    generic_names = {'type_at', 'issued', 'g_kind', 'g_size', 'g_count', 'g_end',
        'g_at', 'g_field', 'g_shape', 'text_is', 'prefix', 'same_text', 'name_status',
        'hash_name', 'table_slot', 'table_get', 'table_put'}
    generic = '\n'.join(ast.unparse(node) for node in ast.parse(ADMISSION).body
                        if isinstance(node, ast.FunctionDef) and node.name in generic_names)
    validation = next(node for node in ast.parse(TRANSPORT.replace('    DISPATCH', '    pass')).body
                      if isinstance(node, ast.FunctionDef) and node.name == 'validate')
    validation.name = 'validate_packet'
    body = BODY + '\n' + generic + '\n' + suffix() + '\n' + ast.unparse(validation)
    if kernel == 'render':
        body = RENDER.replace('def function_render(', 'def constructor_render(')
    elif kernel != 'owner':
        raise ValueError('unknown constructor kernel')
    literals = {'L_reserved_core': packed('__hia_'),
                'L_reserved_nominal': packed('h2internal_'), 'L_task': packed('task')}

    class Expand(ast.NodeTransformer):
        def visit_Name(self, node):
            return ast.Constant(CONSTANTS[node.id]) if node.id in CONSTANTS else node

        def visit_Call(self, node):
            node = self.generic_visit(node)
            args = []
            for arg in node.args:
                if isinstance(arg, ast.Name) and arg.id in literals:
                    args.extend(ast.Constant(value) for value in literals[arg.id])
                else:
                    args.append(arg)
            node.args = args
            return node

    literals.update({'T_' + text: packed(text) for text in (
        'op', 'init', 'definitions', 'recursive_chain', 'partial_records',
        'parameters', 'params', 'resolve', 'ref', 'origins', 'returns',
        'return_loans', 'task_protocol', 'task', 'functions')})
    tree = ast.fix_missing_locations(Expand().visit(ast.parse(body + '\n' + COMMON)))
    names = {node.name: node for node in tree.body}
    reachable = {tree.body[0].name}
    pending = list(reachable)
    while pending:
        for node in ast.walk(names[pending.pop()]):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                name = node.func.id
                if name in names and name not in reachable:
                    reachable.add(name)
                    pending.append(name)
    tree.body = [node for node in tree.body if node.name in reachable]
    return ast.unparse(tree) + '\n'


def document(kernel):
    nodes = ast.parse(source_program(kernel)).body
    names = {node.name: 'f' + str(i) for i, node in enumerate(nodes)}
    signatures = {node.name: ([arg.annotation.id for arg in node.args.args], node.returns.id)
                  for node in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = Builder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({'name': names[node.name], 'params': [builder.param(p) for p in builder.params],
            'returns': [builder.returns], 'effects': ['read', 'write', 'trap'],
            'entry': 'b0', 'blocks': builder.blocks})
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8',
        'module': 'composite_constructor_' + kernel, 'functions': functions})


if __name__ == '__main__':
    root = Path(__file__).resolve().parents[1]
    for kernel in ('owner', 'render'):
        target = root / ('examples/hia_bootstrap/composite_constructor_' + kernel + '.hepta')
        target.write_text(render_assembly(document(kernel)))
        print(target.name, target.stat().st_size)
    (root / 'hepta/hia_composite_constructor_errors.py').write_text(
        '"""Generated constructor diagnostic ABI; rejection decisions belong to HIA."""\n'
        + 'ERRORS = ' + pformat(ERRORS, width=100) + '\n')

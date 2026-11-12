"""Author all remaining record transitions and borrowing as a complete HIA owner."""
from __future__ import annotations

import ast
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_core_json_frontend import packed
from tools.generate_hia_instruction_policy import SOURCE as TRANSPORT_SOURCE
from tools.generate_hia_enum_match import BODY as MATCH_BODY
from tools.generate_hia_enum_operations import BODY as ENUM_BODY
from tools.generate_hia_record_operations import BODY as RECORD_BODY
from tools.generate_hia_task_helpers import BODY as HELPER_BODY, PRIMITIVES
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions

MAGIC = int.from_bytes(b'HIARTN01', 'little')
INPUT_BYTES = 256 << 20
OUTPUT_BYTES = 8 << 20
WORKSPACE_BYTES = 16 << 20
CONSTANTS = {'MAGIC': MAGIC, 'INPUT_BYTES': INPUT_BYTES, 'O_BYTES': OUTPUT_BYTES,
    'W_BYTES': WORKSPACE_BYTES, 'S': 4096, 'T': 8192, 'V': 2105344,
    'VF': 4202496, 'B': 6299648, 'HEAP': 6303744,
    'G': 1 << 63, 'N': (1 << 64) - 1, 'ABI': 0xfffffff1}

BODY = r'''
def record_transitions(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) > INPUT_BYTES or length(o) < O_BYTES or length(w) < W_BYTES:
        return ABI
    if validate(s, w) == 0 or tag(s, 0) != 5 or total(s, 0) != 10:
        return ABI
    i = 0
    while i < 256:
        put(w, S + i, 0)
        i = i + 8
    i = 0
    while i < 128:
        put(w, B + i, 0)
        i = i + 8
    put(w, S + 16, HEAP)
    if admit(s, w) == 0:
        return ABI
    operation = operation_id(s, element(s, 0, 2))
    if operation == 1:
        lower_begin(s, w)
    elif operation == 2:
        lower_take(s, w)
    elif operation == 3:
        lower_insert(s, w)
    elif operation == 4 or operation == 5:
        lower_complete(s, w, operation)
    else:
        lower_borrow(s, w)
    if get(w, S + 32) != 0:
        return ABI
    put(w, S + 24, 64)
    render(s, o, w)
    if get(w, S + 32) != 0:
        return ABI
    put(o, 0, MAGIC)
    put(o, 8, get(w, S + 8))
    put(o, 16, get(w, S))
    put(o, 24, get(w, S + 56))
    put(o, 32, get(w, S + 24) - 64)
    put(o, 40, 0)
    put(o, 48, 0)
    put(o, 56, 0)
    return get(w, S + 24)

def admit(s:readbuf, w:mutbuf) -> u64:
    phase = unsigned(s, element(s, 0, 0))
    serial = unsigned(s, element(s, 0, 1))
    operation = operation_id(s, element(s, 0, 2))
    if phase > 2 or serial > 8192 or operation == 0:
        return 0
    if operation == 1 and phase != 0:
        return 0
    if phase == 1 and (operation == 4 or operation == 5):
        return 0
    put(w, S, serial)
    types = element(s, 0, 4)
    values = element(s, 0, 5)
    args = element(s, 0, 6)
    if tag(s, types) != 5 or tag(s, values) != 5 or tag(s, args) != 5:
        return 0
    tc = total(s, types)
    vc = total(s, values)
    if tc > 262144 or vc > 262144 or total(s, args) > 262144:
        return 0
    put(w, S + 48, tc)
    put(w, S + 40, vc)
    node = types + 24
    i = 0
    while i < tc:
        put(w, T + i * 8, node)
        if descriptor_ok(s, node, tc) == 0:
            return 0
        node = end(s, node)
        i = i + 1
    i = 0
    while i < tc:
        if record_shape(s, w, get(w, T + i * 8)) == 0:
            return 0
        i = i + 1
    if admit_values(s, w, values) == 0:
        return 0
    at = args + 24
    i = 0
    while i < total(s, args):
        if tag(s, at) != 5 or total(s, at) != 2:
            return 0
        if name_status(s, element(s, at, 0)) != 0:
            return 0
        if unsigned(s, element(s, at, 1)) >= vc:
            return 0
        at = end(s, at)
        i = i + 1
    if declared_ok(s, w, element(s, 0, 7)) == 0:
        return 0
    resolved = element(s, 0, 8)
    outputs = element(s, 0, 9)
    if phase == 0:
        if tag(s, resolved) != 0 or tag(s, outputs) != 0:
            return 0
    else:
        if operation == 4 or operation == 5:
            if tag(s, resolved) != 0:
                return 0
        elif unsigned(s, resolved) >= tc:
            return 0
        if phase == 1:
            if tag(s, outputs) != 0:
                return 0
        elif declared_ok(s, w, outputs) == 0:
            return 0
    return 1

def empty_attrs(s:readbuf, w:mutbuf, error:u64) -> u64:
    attrs = element(s, 0, 3)
    if tag(s, attrs) != 6 or total(s, attrs) != 0:
        return refuse(w, error)
    return 1

def field_attrs(s:readbuf, w:mutbuf, error:u64) -> u64:
    attrs = element(s, 0, 3)
    if tag(s, attrs) != 6 or total(s, attrs) != 1:
        refuse(w, error)
        return N
    if text_is(s, attrs + 24, L_field) == 0:
        refuse(w, error)
        return N
    return end(s, attrs + 24)

def record_arg(s:readbuf, w:mutbuf, partial_only:u64, error:u64) -> u64:
    args = element(s, 0, 6)
    if total(s, args) != 1:
        refuse(w, error)
        return N
    arg = args + 24
    descriptor = typename(s, w, arg_type(s, w, arg))
    kind = kind_id(s, element(s, descriptor, 0))
    if kind != 5 and (partial_only != 0 or kind != 2):
        refuse(w, error)
        return N
    return arg

def projected(s:readbuf, w:mutbuf, descriptor:u64, name:u64) -> u64:
    if name_check(s, w, name, 8) == 0:
        return N
    field_node = field_lookup(s, w, descriptor, name)
    if field_node == N:
        if kind_id(s, element(s, descriptor, 0)) == 5:
            base = typename(s, w, unsigned(s, element(s, descriptor, 4)))
            if field_lookup(s, w, base, name) != N:
                refuse(w, 10)
                return N
        refuse(w, 11)
    return field_node

def base_type(s:readbuf, w:mutbuf, ident:u64) -> u64:
    descriptor = typename(s, w, ident)
    if kind_id(s, element(s, descriptor, 0)) == 5:
        return unsigned(s, element(s, descriptor, 4))
    return ident

def consume(s:readbuf, w:mutbuf, arg:u64) -> u64:
    ident = arg_id(s, arg)
    if get(w, VF + ident * 8) != 0:
        return refuse(w, 13)
    if linear(s, typename(s, w, arg_type(s, w, arg))) != 0:
        put(w, VF + ident * 8, 1)
    return 1

def check_outputs(s:readbuf, w:mutbuf, first:u64, second:u64, count:u64) -> u64:
    outputs = element(s, 0, 9)
    if total(s, outputs) != count:
        return refuse(w, 12)
    output = outputs + 24
    i = 0
    while i < count:
        expected = choose(i == 0, first, second)
        if type_equal(s, w, expected, unsigned(s, element(s, output, 1))) == 0:
            return refuse(w, 12)
        output = end(s, output)
        i = i + 1
    return 1

def output_name(s:readbuf, index:u64) -> u64:
    return element(s, element(s, element(s, 0, 9), index), 0)

def prepare_partial(s:readbuf, w:mutbuf, base:u64, current:u64, name:u64, inserting:u64) -> u64:
    descriptor = current
    if inserting != 0:
        descriptor = typename(s, w, base)
    fields = element(s, descriptor, 3)
    vector = allocate(w, 64 * 8)
    cursor = 0
    field_node = fields + 24
    i = 0
    while i < total(s, fields):
        field_name = element(s, field_node, 0)
        keep = choose(same_text(s, field_name, name) == 0, 1, 0)
        if inserting != 0:
            keep = choose(keep == 0 or field_lookup(s, w, current, field_name) != N, 1, 0)
        if keep != 0:
            put(w, vector + cursor * 8, field_node)
            cursor = cursor + 1
        field_node = end(s, field_node)
        i = i + 1
    put(w, S + 136, vector)
    put(w, S + 144, cursor)
    put(w, S + 152, base)
    return 0

def partial_result(s:readbuf, w:mutbuf) -> u64:
    ident = unsigned(s, element(s, 0, 8))
    descriptor = typename(s, w, ident)
    if kind_id(s, element(s, descriptor, 0)) != 5:
        put(w, S + 32, 1)
        return 0
    if unsigned(s, element(s, descriptor, 4)) != get(w, S + 152):
        put(w, S + 32, 1)
        return 0
    fields = element(s, descriptor, 3)
    if total(s, fields) != get(w, S + 144):
        put(w, S + 32, 1)
        return 0
    field_node = fields + 24
    i = 0
    while i < total(s, fields):
        expected = get(w, get(w, S + 136) + i * 8)
        if same_text(s, element(s, field_node, 0), element(s, expected, 0)) == 0:
            put(w, S + 32, 1)
            return 0
        if type_equal(s, w, unsigned(s, element(s, field_node, 1)), unsigned(s, element(s, expected, 1))) == 0:
            put(w, S + 32, 1)
            return 0
        field_node = end(s, field_node)
        i = i + 1
    return 1

def lower_begin(s:readbuf, w:mutbuf) -> u64:
    if empty_attrs(s, w, 3) == 0:
        return 0
    args = element(s, 0, 6)
    declared = element(s, 0, 7)
    if total(s, args) != 0 or total(s, declared) != 1:
        return refuse(w, 4)
    output = declared + 24
    typ = unsigned(s, element(s, output, 1))
    descriptor = typename(s, w, typ)
    if kind_id(s, element(s, descriptor, 0)) != 5:
        return refuse(w, 4)
    if total(s, element(s, descriptor, 3)) != 0:
        return refuse(w, 5)
    token = zero(w, 13)
    if get(w, S + 8) != 0:
        return 0
    return bind(w, element(s, output, 0), typ, singleton(w, token), 1, 0)

def move_field(s:readbuf, w:mutbuf, typ:u64, names:u64, offset:u64) -> u64:
    descriptor = typename(s, w, typ)
    count = type_width(s, descriptor)
    vector = copy_range(s, w, names, offset, count)
    flat = flat_node(s, descriptor)
    at = flat + 24
    i = 0
    while i < count:
        primitive = type_id(s, at)
        if primitive == 13 or primitive == 16:
            ident = fresh(w)
            if get(w, S + 8) != 0:
                return vector
            instruction(w, B, 4, singleton(w, get(w, vector + i * 8)), 1,
                        singleton(w, ident), singleton(w, primitive), 1, 0)
            put(w, vector + i * 8, ident)
        at = end(s, at)
        i = i + 1
    return vector

def remainder_names(s:readbuf, w:mutbuf, names:u64, offset:u64, removed:u64, token:u64, start:u64) -> u64:
    count = total(s, names) - removed + choose(start == 0, 1, 0)
    vector = allocate(w, count * 8)
    put(w, vector, token)
    at = names + 24
    i = 0
    cursor = 1
    while i < total(s, names):
        if i >= start and (i < offset or i >= offset + removed):
            put(w, vector + cursor * 8, at)
            cursor = cursor + 1
        at = end(s, at)
        i = i + 1
    return vector

def finish_take(s:readbuf, w:mutbuf, arg:u64, typ:u64, offset:u64) -> u64:
    remainder = unsigned(s, element(s, 0, 8))
    if check_outputs(s, w, typ, remainder, 2) == 0:
        return 0
    if consume(s, w, arg) == 0:
        return 0
    descriptor = typename(s, w, arg_type(s, w, arg))
    names = arg_names(s, w, arg)
    start = choose(kind_id(s, element(s, descriptor, 0)) == 5, 1, 0)
    token = 0
    if start == 1:
        token = element(s, names, 0)
    else:
        token = zero(w, 13)
        if get(w, S + 8) != 0:
            return 0
    moved = move_field(s, w, typ, names, offset)
    if get(w, S + 8) != 0:
        return 0
    width = type_width(s, typename(s, w, typ))
    bind(w, output_name(s, 0), typ, moved, width, 0)
    remaining = remainder_names(s, w, names, offset, width, token, start)
    return bind(w, output_name(s, 1), remainder, remaining, type_width(s, typename(s, w, remainder)), 0)

def lower_take(s:readbuf, w:mutbuf) -> u64:
    name = field_attrs(s, w, 6)
    if name == N:
        return 0
    arg = record_arg(s, w, 0, 7)
    if arg == N:
        return 0
    actual_type = arg_type(s, w, arg)
    descriptor = typename(s, w, actual_type)
    field_node = projected(s, w, descriptor, name)
    if field_node == N:
        return 0
    typ = unsigned(s, element(s, field_node, 1))
    offset = get(w, S + 96)
    prepare_partial(s, w, base_type(s, w, actual_type), descriptor, name, 0)
    phase = unsigned(s, element(s, 0, 0))
    if phase == 0:
        put(w, S + 56, 1)
        return 0
    if partial_result(s, w) == 0:
        return 0
    if phase == 1:
        put(w, S + 56, 3)
        return 0
    return finish_take(s, w, arg, typ, offset)

def inserted_names(s:readbuf, w:mutbuf, arg:u64, supplied:u64, typ:u64, name:u64) -> u64:
    descriptor = typename(s, w, arg_type(s, w, arg))
    target = typename(s, w, typ)
    names = arg_names(s, w, arg)
    vector = allocate(w, type_width(s, target) * 8)
    put(w, vector, element(s, names, 0))
    fields = element(s, target, 3)
    field_node = fields + 24
    cursor = 1
    i = 0
    while i < total(s, fields):
        field_name = element(s, field_node, 0)
        source = names
        offset = 0
        if same_text(s, field_name, name) != 0:
            source = arg_names(s, w, supplied)
        else:
            old_field = field_lookup(s, w, descriptor, field_name)
            if old_field == N:
                put(w, S + 32, 1)
                return vector
            offset = get(w, S + 96)
        width = type_width(s, typename(s, w, unsigned(s, element(s, field_node, 1))))
        cursor = append_range(s, w, source, offset, width, vector, cursor)
        field_node = end(s, field_node)
        i = i + 1
    return vector

def append_range(s:readbuf, w:mutbuf, names:u64, offset:u64, count:u64, vector:u64, cursor:u64) -> u64:
    at = names + 24
    i = 0
    while i < offset:
        at = end(s, at)
        i = i + 1
    i = 0
    while i < count:
        put(w, vector + cursor * 8, at)
        cursor = cursor + 1
        at = end(s, at)
        i = i + 1
    return cursor

def lower_insert(s:readbuf, w:mutbuf) -> u64:
    name = field_attrs(s, w, 14)
    if name == N:
        return 0
    args = element(s, 0, 6)
    if total(s, args) != 2:
        return refuse(w, 15)
    arg = args + 24
    supplied = end(s, arg)
    descriptor = typename(s, w, arg_type(s, w, arg))
    if kind_id(s, element(s, descriptor, 0)) != 5:
        return refuse(w, 15)
    if name_check(s, w, name, 16) == 0:
        return 0
    base = base_type(s, w, arg_type(s, w, arg))
    field_node = field_lookup(s, w, typename(s, w, base), name)
    if field_node == N:
        return refuse(w, 11)
    if field_lookup(s, w, descriptor, name) != N:
        return refuse(w, 18)
    if type_equal(s, w, arg_type(s, w, supplied), unsigned(s, element(s, field_node, 1))) == 0:
        return refuse(w, 19)
    prepare_partial(s, w, base, descriptor, name, 1)
    phase = unsigned(s, element(s, 0, 0))
    if phase == 0:
        put(w, S + 56, 1)
        return 0
    if partial_result(s, w) == 0:
        return 0
    if phase == 1:
        put(w, S + 56, 3)
        return 0
    typ = unsigned(s, element(s, 0, 8))
    if check_outputs(s, w, typ, N, 1) == 0:
        return 0
    if consume(s, w, arg) == 0 or consume(s, w, supplied) == 0:
        return 0
    return bind(w, output_name(s, 0), typ, inserted_names(s, w, arg, supplied, typ, name),
                type_width(s, typename(s, w, typ)), 0)

def fields_equal(s:readbuf, w:mutbuf, left:u64, right:u64) -> u64:
    if total(s, left) != total(s, right):
        return 0
    a = left + 24
    b = right + 24
    i = 0
    while i < total(s, left):
        if same_text(s, element(s, a, 0), element(s, b, 0)) == 0:
            return 0
        if type_equal(s, w, unsigned(s, element(s, a, 1)), unsigned(s, element(s, b, 1))) == 0:
            return 0
        a = end(s, a)
        b = end(s, b)
        i = i + 1
    return 1

def lower_complete(s:readbuf, w:mutbuf, operation:u64) -> u64:
    error = choose(operation == 4, 20, 23)
    if empty_attrs(s, w, error) == 0:
        return 0
    arg = record_arg(s, w, 1, error + 1)
    if arg == N:
        return 0
    descriptor = typename(s, w, arg_type(s, w, arg))
    fields = element(s, descriptor, 3)
    base = unsigned(s, element(s, descriptor, 4))
    if operation == 4:
        if fields_equal(s, w, fields, element(s, typename(s, w, base), 3)) == 0:
            return refuse(w, 22)
    elif total(s, fields) != 0:
        return refuse(w, 25)
    if unsigned(s, element(s, 0, 0)) == 0:
        put(w, S + 56, 3)
        return 0
    if check_outputs(s, w, base, N, choose(operation == 4, 1, 0)) == 0:
        return 0
    if consume(s, w, arg) == 0:
        return 0
    names = arg_names(s, w, arg)
    instruction(w, B, 3, singleton(w, element(s, names, 0)), 1, 0, 0, 0, 0)
    if operation == 4:
        count = total(s, names) - 1
        return bind(w, output_name(s, 0), base, copy_range(s, w, names, 1, count), count, 0)
    return 0

def borrow_attrs(s:readbuf, w:mutbuf) -> u64:
    attrs = element(s, 0, 3)
    if tag(s, attrs) != 6 or total(s, attrs) != 2:
        return refuse(w, 26)
    at = attrs + 24
    seen = 0
    i = 0
    while i < 2:
        if text_is(s, at, L_field) != 0:
            put(w, S + 112, end(s, at))
            seen = seen | 1
        elif text_is(s, at, L_mode) != 0:
            put(w, S + 120, end(s, at))
            seen = seen | 2
        at = end(s, end(s, at))
        i = i + 1
    if seen != 3:
        return refuse(w, 26)
    return 1

def lower_borrow(s:readbuf, w:mutbuf) -> u64:
    if borrow_attrs(s, w) == 0:
        return 0
    arg = record_arg(s, w, 0, 27)
    if arg == N:
        return 0
    mode = get(w, S + 120)
    code = 0
    primitive = 0
    if text_is(s, mode, L_read) != 0:
        code = 5
        primitive = 14
    elif text_is(s, mode, L_mut) != 0:
        code = 6
        primitive = 15
    else:
        return refuse(w, 28)
    put(w, S + 128, primitive)
    descriptor = typename(s, w, arg_type(s, w, arg))
    field_node = projected(s, w, descriptor, get(w, S + 112))
    if field_node == N:
        return 0
    selected = typename(s, w, unsigned(s, element(s, field_node, 1)))
    if kind_id(s, element(s, selected, 0)) != 1:
        return refuse(w, 29)
    field_type = type_id(s, element(s, flat_node(s, selected), 0))
    if field_type != 13 and field_type != 14 and field_type != 15:
        return refuse(w, 29)
    phase = unsigned(s, element(s, 0, 0))
    if phase == 0:
        put(w, S + 56, 2)
        return 0
    typ = unsigned(s, element(s, 0, 8))
    resolved = typename(s, w, typ)
    if kind_id(s, element(s, resolved, 0)) != 1 or type_id(s, element(s, flat_node(s, resolved), 0)) != primitive:
        put(w, S + 32, 1)
        return 0
    if phase == 1:
        put(w, S + 56, 3)
        return 0
    if check_outputs(s, w, typ, N, 1) == 0:
        return 0
    name = output_name(s, 0)
    bind(w, name, typ, singleton(w, name), 1, 0)
    source = element(s, arg_names(s, w, arg), get(w, S + 96))
    return instruction(w, B, code, singleton(w, source), 1, singleton(w, name), singleton(w, primitive), 1, 0)

def render_query(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    request = get(w, S + 56)
    if request == 0:
        return emit(o, w, L_null)
    if request == 3:
        emit_text(o, w, '{}')
        return 0
    if request == 2:
        if get(w, S + 128) == 14:
            emit_text(o, w, '{"type":"readbuf"}')
        else:
            emit_text(o, w, '{"type":"mutbuf"}')
        return 0
    emit_text(o, w, '{"base":')
    number(o, w, get(w, S + 152))
    emit_text(o, w, ',"fields":[')
    i = 0
    while i < get(w, S + 144):
        if i != 0:
            append_byte(o, w, 44)
        field_node = get(w, get(w, S + 136) + i * 8)
        source_name(s, o, w, element(s, field_node, 0))
        i = i + 1
    emit_text(o, w, ']}')
    return 0

def render(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    emit_text(o, w, '{"ops":')
    render_ops(s, o, w)
    emit_text(o, w, ',"consumed":[')
    i = 0
    while i < get(w, S + 40):
        if i != 0:
            append_byte(o, w, 44)
        if get(w, VF + i * 8) == 0:
            emit_text(o, w, 'false')
        else:
            emit_text(o, w, 'true')
        i = i + 1
    emit_text(o, w, '],"values":[')
    at = get(w, S + 64)
    previous = 0
    while at != 0:
        if previous != 0:
            append_byte(o, w, 44)
        append_byte(o, w, 91)
        source_name(s, o, w, get(w, at))
        append_byte(o, w, 44)
        number(o, w, get(w, at + 8))
        append_byte(o, w, 44)
        render_names(s, o, w, get(w, at + 16), get(w, at + 24))
        emit_text(o, w, ',false,false]')
        at = get(w, at + 40)
        previous = 1
    emit_text(o, w, '],"query":')
    render_query(s, o, w)
    append_byte(o, w, 125)
    return 0
'''


def source_program():
    literals = {'L_' + name: packed(value) for name, value in
                [('field', 'field'), ('mode', 'mode'), ('read', 'read'), ('mut', 'mut'), ('null', 'null')]}
    class Expand(ast.NodeTransformer):
        def visit_Expr(self, node):
            if (isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name)
                    and node.value.func.id == 'emit_text'):
                output, workspace, literal = node.value.args
                assert isinstance(literal, ast.Constant) and type(literal.value) is str
                return [ast.Expr(ast.Call(ast.Name('emit', ast.Load()),
                    [output, workspace, *(ast.Constant(value) for value in packed(literal.value[i:i+24]))], []))
                    for i in range(0, len(literal.value), 24)]
            return self.generic_visit(node)
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
    own = ast.parse(BODY)
    common = {'validate', 'word', 'put', 'get', 'tag', 'size_of', 'end', 'total',
              'element', 'text_is', 'same_text'}
    text = TRANSPORT_SOURCE.replace('    DISPATCH', '    pass')
    text = text.replace('1048576', '8388608')
    own.body.extend(node for node in ast.parse(text).body
                    if isinstance(node, ast.FunctionDef) and node.name in common)
    shared = {'unsigned', 'truth', 'prefix', 'name_status', 'name_check', 'typename',
              'flat_node', 'type_width', 'linear', 'type_equal', 'refuse', 'allocate',
              'fresh', 'singleton', 'pair', 'instruction', 'render_name', 'render_names', 'render_params'}
    own.body.extend(node for node in ast.parse(MATCH_BODY).body
                    if isinstance(node, ast.FunctionDef) and node.name in shared)
    shared = {'declared_ok', 'arg_id', 'arg_type', 'arg_names', 'number', 'constant', 'zero', 'render_ops'}
    own.body.extend(node for node in ast.parse(ENUM_BODY).body
                    if isinstance(node, ast.FunctionDef) and node.name in shared)
    shared = {'descriptor_ok', 'record_shape', 'admit_values', 'copy_range', 'bind', 'field_lookup'}
    own.body.extend(node for node in ast.parse(RECORD_BODY).body
                    if isinstance(node, ast.FunctionDef) and node.name in shared)
    utility = {'append_byte', 'emit', 'source_name'}
    own.body.extend(node for node in ast.parse(HELPER_BODY).body
                    if isinstance(node, ast.FunctionDef) and node.name in utility)
    own = Expand().visit(own)
    suffix = []
    for function, values in [('type_id', enumerate(PRIMITIVES, 1)),
        ('kind_id', enumerate(('primitive', 'record', 'enum', 'task', 'partial_record'), 1)),
        ('operation_id', enumerate(('record.begin', 'record.take', 'record.insert', 'record.finish', 'record.abandon', 'record.borrow'), 1))]:
        suffix.append('def ' + function + '(s:readbuf, node:u64) -> u64:')
        for identifier, value in values:
            suffix += ['    if text_is(s, node, ' + ', '.join(map(str, packed(value))) + ') != 0:',
                       '        return ' + str(identifier)]
        suffix += ['    return 0']
    for function, values in [('type_name', enumerate(PRIMITIVES, 1)),
        ('instruction_name', [(1, 'const'), (3, 'owner.drop'), (4, 'owner.move'),
                              (5, 'borrow.read'), (6, 'borrow.mut'), (7, 'buffer.try_new'), (8, 'chain.empty')])]:
        suffix.append('def ' + function + '(o:mutbuf, w:mutbuf, identifier:u64) -> u64:')
        for identifier, value in values:
            suffix += ['    if identifier == ' + str(identifier) + ':',
                       '        return emit(o, w, ' + ', '.join(map(str, packed(value))) + ')']
        suffix += ['    return 0']
    return ast.unparse(ast.fix_missing_locations(own)) + '\n' + '\n'.join(suffix) + '\n'


def document():
    nodes = ast.parse(source_program()).body
    assert len({node.name for node in nodes}) == len(nodes)
    names = {node.name: 'f' + str(i) for i, node in enumerate(nodes)}
    signatures = {node.name: ([arg.annotation.id for arg in node.args.args], node.returns.id) for node in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = Builder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({'name': names[node.name], 'params': [builder.param(p) for p in builder.params],
            'returns': [builder.returns], 'effects': ['read', 'write', 'trap'],
            'entry': 'b0', 'blocks': builder.blocks})
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8', 'module': 'record_transitions', 'functions': functions})


if __name__ == '__main__':
    target = Path(__file__).resolve().parents[1] / 'examples/hia_bootstrap/record_transitions.hiaasm'
    target.write_text(render_assembly(document()))
    print(target.name, target.stat().st_size)

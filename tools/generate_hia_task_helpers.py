"""Author complete nominal task-helper Core generation in ordinary HIA.

The input is lossless descriptor transport, not a host-generated lowering plan.
All generated names, instructions, blocks, cleanup, effects and control flow
are owned by this image.  The result is a complete Core function plus the
precise final fresh-name counter, including a completed semantic refusal.
"""
from __future__ import annotations

import ast
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_core_json_frontend import packed
from tools.generate_hia_instruction_policy import SOURCE as TRANSPORT_SOURCE
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions

MAGIC = int.from_bytes(b'HIATHP01', 'little')
INPUT_BYTES = 128 << 10
OUTPUT_BYTES = 4 << 20
WORKSPACE_BYTES = 2 << 20
PRIMITIVES = ('bool', 'unit', 'i8', 'i16', 'i32', 'i64', 'u8', 'u16',
              'u32', 'u64', 'isize', 'usize', 'buffer', 'readbuf', 'mutbuf', 'chain')
CONSTANTS = {'MAGIC': MAGIC, 'INPUT_BYTES': INPUT_BYTES, 'O_BYTES': OUTPUT_BYTES,
             'W_BYTES': WORKSPACE_BYTES, 'S': 4096, 'T': 8192, 'U': 12288,
             'R': 16384, 'E': 20480, 'B': 24576, 'HEAP': 32768,
             'ABI': 0xfffffff1, 'N': (1 << 64) - 1}

# A task layout has at most 512 primitive slots, including tag/token. Its
# state+result and the two poll payloads therefore have at most 510 slots.
# The transported task/state/result/step/variant arrays contain at most 2046
# primitive strings, plus two 128-byte names and eight effect strings: even
# the 24-byte typed-node envelope is below 64 KiB. 128 KiB admits every public
# descriptor. This is not an added language quota.
# There are at most five blocks, fewer than 2600 instructions (including
# padding drops), and at most 8192 generated names. The private vectors and
# instruction records fit below one MiB; two MiB leaves independent input
# validation scratch. Four MiB output is above the complete helper JSON bound.

BODY = r'''
def task_helpers(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) > INPUT_BYTES or length(w) < W_BYTES or length(o) < O_BYTES:
        return ABI
    if validate(s, w) == 0:
        return ABI
    if tag(s, 0) != 5 or total(s, 0) != 11:
        return ABI
    i = 0
    while i < 192:
        put(w, S + i, 0)
        i = i + 8
    put(w, S + 16, HEAP)
    if admit(s, w) == 0:
        return ABI
    build(s, w)
    put(w, S + 24, 64)
    emit_text(o, w, '{"helper":')
    if get(w, S + 8) != 0:
        emit_text(o, w, 'null')
    else:
        render_helper(s, o, w)
    emit_text(o, w, '}')
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
    serial = bounded_integer(s, element(s, 0, 0))
    if serial > 8192:
        return 0
    operation = operation_id(s, element(s, 0, 1))
    if operation == 0:
        return 0
    put(w, S, serial)
    put(w, S + 48, operation)
    task_count = copy_types(s, w, element(s, 0, 2), T)
    state_count = copy_types(s, w, element(s, 0, 3), U)
    result_count = copy_types(s, w, element(s, 0, 4), R)
    step_count = copy_types(s, w, element(s, 0, 5), E)
    if task_count > 512 or state_count > 512 or result_count > 512 or step_count > 512:
        return 0
    if task_count != state_count + result_count + 2 or step_count != state_count + result_count + 1:
        return 0
    if get(w, T) != 7 or get(w, T + 8) != 13 or get(w, E) != 9:
        return 0
    i = 0
    while i < state_count + result_count:
        expected = R + (i - state_count) * 8
        if i < state_count:
            expected = U + i * 8
        if get(w, T + (i + 2) * 8) != get(w, expected):
            return 0
        i = i + 1
    put(w, S + 64, task_count)
    put(w, S + 72, state_count)
    put(w, S + 80, result_count)
    put(w, S + 88, step_count)
    variants = element(s, 0, 6)
    if tag(s, variants) != 5 or total(s, variants) != 2:
        return 0
    seen = 0
    offset = 1
    i = 0
    while i < 2:
        variant = element(s, variants, i)
        if tag(s, variant) != 5 or total(s, variant) != 2:
            return 0
        name = element(s, variant, 0)
        fields = element(s, variant, 1)
        if tag(s, fields) != 5 or total(s, fields) != 1:
            return 0
        payload = element(s, fields, 0)
        expected = U
        count = state_count
        bit = 1
        if text_is(s, name, L_ready) != 0:
            expected = R
            count = result_count
            bit = 2
            put(w, S + 112, i)
            put(w, S + 104, offset)
        elif text_is(s, name, L_pending) != 0:
            put(w, S + 96, offset)
        else:
            return 0
        if (seen & bit) != 0 or tag(s, payload) != 5 or total(s, payload) != count:
            return 0
        seen = seen | bit
        j = 0
        while j < count:
            identifier = type_id(s, element(s, payload, j))
            if identifier != get(w, expected + j * 8) or identifier != get(w, E + (offset + j) * 8):
                return 0
            j = j + 1
        offset = offset + count
        i = i + 1
    poll = element(s, 0, 7)
    cancel = element(s, 0, 8)
    if name_ok(s, poll) == 0 or name_ok(s, cancel) == 0:
        return 0
    put(w, S + 120, poll)
    put(w, S + 128, cancel)
    poll_effects = effect_mask(s, element(s, 0, 9))
    cancel_effects = effect_mask(s, element(s, 0, 10))
    if poll_effects > 15 or cancel_effects > 15:
        return 0
    mask = 8
    if operation == 2:
        mask = mask | poll_effects
    if operation == 3:
        mask = mask | cancel_effects
    i = 0
    while i < task_count:
        typ = get(w, T + i * 8)
        if typ == 13 or typ == 16:
            mask = mask | 1
        i = i + 1
    put(w, S + 136, mask)
    return 1

def bounded_integer(s:readbuf, node:u64) -> u64:
    if tag(s, node) != 2 or size_of(s, node) < 1 or size_of(s, node) > 4:
        return N
    value = 0
    i = 0
    while i < size_of(s, node):
        ch = byte(s, node + 16 + i)
        if ch < 48 or ch > 57:
            return N
        value = value * 10 + ch - 48
        i = i + 1
    return value

def name_ok(s:readbuf, node:u64) -> u64:
    if tag(s, node) != 4 or size_of(s, node) < 1 or size_of(s, node) > 128:
        return 0
    i = 0
    while i < size_of(s, node):
        ch = byte(s, node + 16 + i)
        valid = (ch >= 65 and ch <= 90) or (ch >= 97 and ch <= 122) or ch == 95
        if i != 0:
            valid = valid or (ch >= 48 and ch <= 57)
        if valid == False:
            return 0
        i = i + 1
    return 1

def copy_types(s:readbuf, w:mutbuf, node:u64, target:u64) -> u64:
    if tag(s, node) != 5 or total(s, node) > 512:
        return N
    i = 0
    while i < total(s, node):
        typ = type_id(s, element(s, node, i))
        if typ == 0:
            return N
        put(w, target + i * 8, typ)
        i = i + 1
    return total(s, node)

def effect_mask(s:readbuf, node:u64) -> u64:
    if tag(s, node) != 5 or total(s, node) > 4:
        return N
    mask = 0
    i = 0
    while i < total(s, node):
        bit = effect_id(s, element(s, node, i))
        if bit == 0 or (mask & bit) != 0:
            return N
        mask = mask | bit
        i = i + 1
    return mask

def refuse(w:mutbuf, code:u64) -> u64:
    if get(w, S + 8) == 0:
        put(w, S + 8, code)
    return 0

def fresh(w:mutbuf) -> u64:
    if get(w, S + 8) != 0:
        return 0
    serial = get(w, S)
    if serial >= 8192:
        return refuse(w, 1)
    put(w, S, serial + 1)
    return serial + 1

def allocate(w:mutbuf, size:u64) -> u64:
    start = get(w, S + 16)
    if start > W_BYTES or size > W_BYTES - start:
        refuse(w, 4)
        return 0
    put(w, S + 16, start + size)
    return start

def singleton(w:mutbuf, value:u64) -> u64:
    at = allocate(w, 8)
    put(w, at, value)
    return at

def pair(w:mutbuf, a:u64, b:u64) -> u64:
    at = allocate(w, 16)
    put(w, at, a)
    put(w, at + 8, b)
    return at

def triple(w:mutbuf, a:u64, b:u64, c:u64) -> u64:
    at = allocate(w, 24)
    put(w, at, a)
    put(w, at + 8, b)
    put(w, at + 16, c)
    return at

def concatenate(w:mutbuf, a:u64, an:u64, b:u64, bn:u64) -> u64:
    at = allocate(w, (an + bn) * 8)
    i = 0
    while i < an + bn:
        source = b + (i - an) * 8
        if i < an:
            source = a + i * 8
        put(w, at + i * 8, get(w, source))
        i = i + 1
    return at

def names(w:mutbuf, count:u64) -> u64:
    at = allocate(w, count * 8)
    i = 0
    while i < count:
        put(w, at + i * 8, fresh(w))
        i = i + 1
    return at

def block(w:mutbuf, types:u64, count:u64, reverse:u64) -> u64:
    index = get(w, S + 40)
    if index >= 5:
        refuse(w, 4)
        return B
    at = B + index * 128
    put(w, S + 40, index + 1)
    i = 0
    while i < 128:
        put(w, at + i, 0)
        i = i + 8
    ident = 0
    if reverse == 0:
        ident = fresh(w)
    values = names(w, count)
    if reverse != 0:
        ident = fresh(w)
    put(w, at, ident)
    put(w, at + 8, values)
    put(w, at + 16, types)
    put(w, at + 24, count)
    return at

def instruction(w:mutbuf, target:u64, code:u64, args:u64, argc:u64, results:u64, types:u64, count:u64, attribute:u64) -> u64:
    at = allocate(w, 64)
    put(w, at, code)
    put(w, at + 8, args)
    put(w, at + 16, argc)
    put(w, at + 24, results)
    put(w, at + 32, types)
    put(w, at + 40, count)
    put(w, at + 48, attribute)
    put(w, at + 56, 0)
    previous = get(w, target + 40)
    if previous == 0:
        put(w, target + 32, at)
    else:
        put(w, previous + 56, at)
    put(w, target + 40, at)
    return 0

def constant(w:mutbuf, target:u64, typ:u64, value:u64) -> u64:
    ident = fresh(w)
    instruction(w, target, 1, 0, 0, singleton(w, ident), singleton(w, typ), 1, value)
    return ident

def ret(w:mutbuf, target:u64, values:u64, count:u64) -> u64:
    put(w, target + 48, 1)
    put(w, target + 56, values)
    put(w, target + 64, count)
    return 0

def branch(w:mutbuf, target:u64, cond:u64, yes:u64, ya:u64, no:u64, na:u64) -> u64:
    put(w, target + 48, 3)
    put(w, target + 56, cond)
    put(w, target + 72, yes)
    put(w, target + 80, ya)
    put(w, target + 88, get(w, yes + 24))
    put(w, target + 96, no)
    put(w, target + 104, na)
    put(w, target + 112, get(w, no + 24))
    return 0

def drop(w:mutbuf, target:u64, values:u64, types:u64, count:u64) -> u64:
    i = 0
    while i < count:
        typ = get(w, types + i * 8)
        if typ == 13 or typ == 16:
            instruction(w, target, 5, values + i * 8, 1, 0, 0, 0, 0)
        elif typ == 14 or typ == 15:
            refuse(w, 3)
        i = i + 1
    return 0

def zeros(w:mutbuf, target:u64, types:u64, count:u64) -> u64:
    values = allocate(w, count * 8)
    i = 0
    while i < count:
        typ = get(w, types + i * 8)
        ident = 0
        if typ == 13:
            zero = constant(w, target, 12, 0)
            ident = fresh(w)
            ok = fresh(w)
            instruction(w, target, 7, singleton(w, zero), 1, pair(w, ident, ok), pair(w, 13, 1), 2, 0)
        elif typ == 16:
            ident = fresh(w)
            instruction(w, target, 8, 0, 0, singleton(w, ident), singleton(w, 16), 1, 0)
        elif typ == 14 or typ == 15:
            refuse(w, 2)
        else:
            ident = constant(w, target, typ, 0)
        put(w, values + i * 8, ident)
        i = i + 1
    return values

def build(s:readbuf, w:mutbuf) -> u64:
    put(w, S + 56, fresh(w))
    count = get(w, S + 64)
    entry = block(w, T, count, 0)
    failure = block(w, T, count, 1)
    put(w, failure + 48, 2)
    operation = get(w, S + 48)
    if operation == 3:
        build_cancel(w, entry, failure)
        return 0
    run = block(w, T, count, 0)
    needed = 0
    if operation == 2:
        needed = 1
    if operation == 4:
        needed = 2
    if operation == 5:
        needed = 3
    expected = constant(w, entry, 7, needed)
    matches = fresh(w)
    values = get(w, entry + 8)
    instruction(w, entry, 2, pair(w, get(w, values), expected), 2, singleton(w, matches), singleton(w, 1), 1, 0)
    branch(w, entry, matches, run, values, failure, values)
    active = get(w, run + 8)
    state_count = get(w, S + 72)
    result_count = get(w, S + 80)
    if operation == 1:
        tag_value = constant(w, run, 7, 1)
        ret(w, run, concatenate(w, singleton(w, tag_value), 1, active + 8, count - 1), count)
    elif operation == 4:
        drop(w, run, active + 8, T + 8, state_count + 1)
        ret(w, run, active + (state_count + 2) * 8, result_count)
    elif operation == 5:
        drop(w, run, active + 8, T + 8, count - 1)
        ret(w, run, 0, 0)
    else:
        build_poll(w, run)
    return 0

def build_poll(w:mutbuf, run:u64) -> u64:
    active = get(w, run + 8)
    state_count = get(w, S + 72)
    result_count = get(w, S + 80)
    step_count = get(w, S + 88)
    token = get(w, active + 8)
    drop(w, run, active + (state_count + 2) * 8, R, result_count)
    emitted = names(w, step_count)
    instruction(w, run, 6, active + 16, state_count, emitted, E, step_count, get(w, S + 120))
    limit = constant(w, run, 9, 1)
    valid = fresh(w)
    instruction(w, run, 3, pair(w, get(w, emitted), limit), 2, singleton(w, valid), singleton(w, 1), 1, 0)
    carried_types = concatenate(w, singleton(w, 13), 1, E, step_count)
    carried = concatenate(w, singleton(w, token), 1, emitted, step_count)
    checked = block(w, carried_types, step_count + 1, 1)
    invalid = block(w, carried_types, step_count + 1, 1)
    put(w, invalid + 48, 2)
    branch(w, run, valid, checked, carried, invalid, carried)
    values = get(w, checked + 8)
    token = get(w, values)
    emitted = values + 8
    index = constant(w, checked, 9, get(w, S + 112))
    ready = fresh(w)
    instruction(w, checked, 2, pair(w, get(w, emitted), index), 2, singleton(w, ready), singleton(w, 1), 1, 0)
    succeeded = constant(w, checked, 7, 2)
    running = constant(w, checked, 7, 1)
    tag_value = fresh(w)
    instruction(w, checked, 4, triple(w, ready, succeeded, running), 3, singleton(w, tag_value), singleton(w, 7), 1, 0)
    payload = concatenate(w, emitted + get(w, S + 96) * 8, state_count,
                          emitted + get(w, S + 104) * 8, result_count)
    values = concatenate(w, pair(w, tag_value, token), 2, payload, state_count + result_count)
    ret(w, checked, values, state_count + result_count + 2)
    return 0

def build_cancel(w:mutbuf, entry:u64, failure:u64) -> u64:
    count = get(w, S + 64)
    state_count = get(w, S + 72)
    result_count = get(w, S + 80)
    cleanup = block(w, T, count, 0)
    stopped = block(w, T, count, 0)
    unchanged = block(w, T, count, 0)
    values = get(w, entry + 8)
    active = get(w, cleanup + 8)
    stopped_values = get(w, stopped + 8)
    terminal = get(w, unchanged + 8)
    two = constant(w, entry, 7, 2)
    live = fresh(w)
    instruction(w, entry, 9, pair(w, get(w, values), two), 2, singleton(w, live), singleton(w, 1), 1, 0)
    branch(w, entry, live, cleanup, values, stopped, values)
    three = constant(w, stopped, 7, 3)
    valid = fresh(w)
    instruction(w, stopped, 3, pair(w, get(w, stopped_values), three), 2, singleton(w, valid), singleton(w, 1), 1, 0)
    branch(w, stopped, valid, unchanged, stopped_values, failure, stopped_values)
    ret(w, unchanged, terminal, count)
    instruction(w, cleanup, 6, active + 16, state_count, 0, 0, 0, get(w, S + 128))
    drop(w, cleanup, active + (state_count + 2) * 8, R, result_count)
    tag_value = constant(w, cleanup, 7, 3)
    types = concatenate(w, U, state_count, R, result_count)
    padding = zeros(w, cleanup, types, state_count + result_count)
    values = concatenate(w, pair(w, tag_value, get(w, active + 8)), 2, padding, state_count + result_count)
    ret(w, cleanup, values, count)
    return 0

def append_byte(o:mutbuf, w:mutbuf, value:u64) -> u64:
    at = get(w, S + 24)
    if at >= O_BYTES:
        put(w, S + 32, 1)
    else:
        store(o, at, value)
        put(w, S + 24, at + 1)
    return 0

def emit(o:mutbuf, w:mutbuf, n:u64, a:u64, b:u64, c:u64) -> u64:
    i = 0
    while i < n:
        word_value = a
        if i >= 8:
            word_value = b
        if i >= 16:
            word_value = c
        append_byte(o, w, (word_value >> ((i & 7) * 8)) & 255)
        i = i + 1
    return 0

def number(o:mutbuf, w:mutbuf, value:u64) -> u64:
    divisor = 1000
    started = 0
    while divisor != 0:
        digit = 0
        while value >= divisor:
            value = value - divisor
            digit = digit + 1
        if digit != 0 or started != 0 or divisor == 1:
            append_byte(o, w, digit + 48)
            started = 1
        if divisor == 1000:
            divisor = 100
        elif divisor == 100:
            divisor = 10
        elif divisor == 10:
            divisor = 1
        else:
            divisor = 0
    return 0

def generated(o:mutbuf, w:mutbuf, value:u64) -> u64:
    emit_text(o, w, '"h2internal_')
    number(o, w, value)
    append_byte(o, w, 34)
    return 0

def source_name(s:readbuf, o:mutbuf, w:mutbuf, node:u64) -> u64:
    append_byte(o, w, 34)
    i = 0
    while i < size_of(s, node):
        append_byte(o, w, byte(s, node + 16 + i))
        i = i + 1
    append_byte(o, w, 34)
    return 0

def render_names(o:mutbuf, w:mutbuf, values:u64, count:u64) -> u64:
    append_byte(o, w, 91)
    i = 0
    while i < count:
        if i != 0:
            append_byte(o, w, 44)
        generated(o, w, get(w, values + i * 8))
        i = i + 1
    append_byte(o, w, 93)
    return 0

def render_types(o:mutbuf, w:mutbuf, types:u64, count:u64) -> u64:
    append_byte(o, w, 91)
    i = 0
    while i < count:
        if i != 0:
            append_byte(o, w, 44)
        append_byte(o, w, 34)
        type_name(o, w, get(w, types + i * 8))
        append_byte(o, w, 34)
        i = i + 1
    append_byte(o, w, 93)
    return 0

def render_params(o:mutbuf, w:mutbuf, values:u64, types:u64, count:u64) -> u64:
    append_byte(o, w, 91)
    i = 0
    while i < count:
        if i != 0:
            append_byte(o, w, 44)
        emit_text(o, w, '{"name":')
        generated(o, w, get(w, values + i * 8))
        emit_text(o, w, ',"type":"')
        type_name(o, w, get(w, types + i * 8))
        emit_text(o, w, '"}')
        i = i + 1
    append_byte(o, w, 93)
    return 0

def render_helper(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    emit_text(o, w, '{"name":')
    generated(o, w, get(w, S + 56))
    emit_text(o, w, ',"params":')
    render_params(o, w, get(w, B + 8), T, get(w, S + 64))
    emit_text(o, w, ',"returns":')
    operation = get(w, S + 48)
    if operation == 4:
        render_types(o, w, R, get(w, S + 80))
    elif operation == 5:
        render_types(o, w, 0, 0)
    else:
        render_types(o, w, T, get(w, S + 64))
    emit_text(o, w, ',"effects":')
    render_effects(o, w, get(w, S + 136))
    emit_text(o, w, ',"entry":')
    generated(o, w, get(w, B))
    emit_text(o, w, ',"blocks":[')
    render_block(s, o, w, B)
    index = 2
    while index < get(w, S + 40):
        append_byte(o, w, 44)
        render_block(s, o, w, B + index * 128)
        index = index + 1
    append_byte(o, w, 44)
    render_block(s, o, w, B + 128)
    emit_text(o, w, ']}')
    return 0

def render_effects(o:mutbuf, w:mutbuf, mask:u64) -> u64:
    append_byte(o, w, 91)
    previous = 0
    if (mask & 1) != 0:
        emit_text(o, w, '"alloc"')
        previous = 1
    if (mask & 2) != 0:
        if previous != 0:
            append_byte(o, w, 44)
        emit_text(o, w, '"read"')
        previous = 1
    if (mask & 8) != 0:
        if previous != 0:
            append_byte(o, w, 44)
        emit_text(o, w, '"trap"')
        previous = 1
    if (mask & 4) != 0:
        if previous != 0:
            append_byte(o, w, 44)
        emit_text(o, w, '"write"')
    append_byte(o, w, 93)
    return 0

def render_block(s:readbuf, o:mutbuf, w:mutbuf, at:u64) -> u64:
    emit_text(o, w, '{"id":')
    generated(o, w, get(w, at))
    emit_text(o, w, ',"params":')
    render_params(o, w, get(w, at + 8), get(w, at + 16), get(w, at + 24))
    emit_text(o, w, ',"ops":[')
    op = get(w, at + 32)
    previous = 0
    while op != 0:
        if previous != 0:
            append_byte(o, w, 44)
        render_instruction(s, o, w, op)
        previous = 1
        op = get(w, op + 56)
    emit_text(o, w, '],"term":')
    render_term(o, w, at)
    append_byte(o, w, 125)
    return 0

def render_instruction(s:readbuf, o:mutbuf, w:mutbuf, at:u64) -> u64:
    code = get(w, at)
    emit_text(o, w, '{"op":"')
    instruction_name(o, w, code)
    emit_text(o, w, '","args":')
    render_names(o, w, get(w, at + 8), get(w, at + 16))
    emit_text(o, w, ',"out":')
    render_params(o, w, get(w, at + 24), get(w, at + 32), get(w, at + 40))
    emit_text(o, w, ',"attrs":{')
    if code == 1:
        emit_text(o, w, '"value":')
        typ = get(w, get(w, at + 32))
        if typ == 1:
            emit_text(o, w, 'false')
        elif typ == 2:
            emit_text(o, w, 'null')
        else:
            number(o, w, get(w, at + 48))
    if code == 6:
        emit_text(o, w, '"function":')
        source_name(s, o, w, get(w, at + 48))
    emit_text(o, w, '}}')
    return 0

def render_edge(o:mutbuf, w:mutbuf, target:u64, args:u64, count:u64) -> u64:
    emit_text(o, w, '{"target":')
    generated(o, w, get(w, target))
    emit_text(o, w, ',"args":')
    render_names(o, w, args, count)
    append_byte(o, w, 125)
    return 0

def render_term(o:mutbuf, w:mutbuf, at:u64) -> u64:
    kind = get(w, at + 48)
    if kind == 1:
        emit_text(o, w, '{"op":"ret","values":')
        render_names(o, w, get(w, at + 56), get(w, at + 64))
        append_byte(o, w, 125)
    elif kind == 2:
        emit_text(o, w, '{"op":"trap","code":"user"}')
    else:
        emit_text(o, w, '{"op":"branch","cond":')
        generated(o, w, get(w, at + 56))
        emit_text(o, w, ',"then":')
        render_edge(o, w, get(w, at + 72), get(w, at + 80), get(w, at + 88))
        emit_text(o, w, ',"else":')
        render_edge(o, w, get(w, at + 96), get(w, at + 104), get(w, at + 112))
        append_byte(o, w, 125)
    return 0
'''


def source_program():
    literals = {'L_' + name: packed(name) for name in ('pending', 'ready')}

    class Expand(ast.NodeTransformer):
        def visit_Expr(self, node):
            if (isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name)
                    and node.value.func.id == 'emit_text'):
                output, workspace, literal = node.value.args
                assert isinstance(literal, ast.Constant) and type(literal.value) is str
                return [ast.Expr(ast.Call(ast.Name('emit', ast.Load()),
                    [output, workspace, *(ast.Constant(value) for value in packed(literal.value[i:i + 24]))], []))
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

    own = Expand().visit(ast.parse(BODY))
    common_names = {'validate', 'word', 'put', 'get', 'tag', 'size_of', 'end', 'total', 'element', 'text_is'}
    common = [node for node in ast.parse(TRANSPORT_SOURCE.replace('    DISPATCH', '    pass')).body
              if isinstance(node, ast.FunctionDef) and node.name in common_names]
    suffix = []
    for function, values in [('type_id', enumerate(PRIMITIVES, 1)),
        ('operation_id', enumerate(('start', 'poll', 'cancel', 'join', 'close'), 1)),
        ('effect_id', zip((1, 2, 4, 8), ('alloc', 'read', 'write', 'trap')))]:
        suffix.append('def ' + function + '(s:readbuf, node:u64) -> u64:')
        for identifier, value in values:
            suffix += ['    if text_is(s, node, ' + ', '.join(map(str, packed(value))) + ') != 0:',
                       '        return ' + str(identifier)]
        suffix += ['    return 0']
    for function, values in [('type_name', PRIMITIVES), ('instruction_name',
        ('const', 'compare.eq', 'compare.le', 'select', 'owner.drop', 'call',
         'buffer.try_new', 'chain.empty', 'compare.lt'))]:
        suffix.append('def ' + function + '(o:mutbuf, w:mutbuf, identifier:u64) -> u64:')
        for identifier, value in enumerate(values, 1):
            suffix += ['    if identifier == ' + str(identifier) + ':',
                       '        return emit(o, w, ' + ', '.join(map(str, packed(value))) + ')']
        suffix += ['    return 0']
    own.body.extend(common)
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
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8', 'module': 'task_helpers', 'functions': functions})


if __name__ == '__main__':
    target = Path(__file__).resolve().parents[1] / 'examples/hia_bootstrap/task_helpers.hepta'
    target.write_text(render_assembly(document()))
    print(target.name, target.stat().st_size)

"""New complete primitive assembly text renderer; no inherited execution.
Input is the actual complete admitted Core JSON view and private representation
metadata. This owner never substitutes for initial verification or the mandatory
fresh whole assembly/Core roundtrip performed by its native coordinator.
"""
from hashlib import sha256
from pathlib import Path
import ast
from tools.generate_hia_json_decode import DECODER_SOURCE
from tools.generate_hia_json_preflight import SOURCE as PREFLIGHT_SOURCE
def magic(x):return int.from_bytes(x.encode("ascii"),"little")
CONSTANTS=dict(BAD=0xfffffffd,GROW=0xfffffffe,MAX=(1<<64)-1,
 COMMAND=magic("HIAARC01"),STATE=magic("HIAARS01"),EVENT=magic("HIAARE01"),
 PHASE=16,LEASE=24,SEQ=32,SOURCE_N=40,STRUCTURED=48,ARENA=56,ARENA_N=64,
 SCRATCH=72,SCRATCH_N=80,OUTPUT=88,OUTPUT_N=96,CURSOR=104,MODE=112,NEEDED=120,
 UPPER_NODES=128,ACTUAL_NODES=136,WRITE_END=144,FAULT=152,ERROR=160,
 HEAD=384,INDEX=1024,TEXT=3072,ERROR_TEXT=6144,BASE=8192)
LITERALS={
 "schema":"schema","module":"module","exports":"exports","functions":"functions",
 "name":"name","params":"params","returns":"returns","effects":"effects","entry":"entry",
 "blocks":"blocks","return_loans":"return_loans","id":"id","ops":"ops","term":"term",
 "op":"op","args":"args","out":"out","attrs":"attrs","type":"type","values":"values",
 "target":"target","cond":"cond","then":"then","else":"else","code":"code",
 "v6":"hepta.hia.program.v6","v7":"hepta.hia.program.v7","v8":"hepta.hia.program.v8",
 "header":"hia-asm.v1 ","exports_text":"exports(","fn_text":"fn ","arrow":") -> (",
 "effects_text":") effects(","entry_text":") entry(","loans_text":" return_loans(",
 "block_text":"block ","indent":"  ","assign":" = ","ret":"ret","jump":"jump",
 "branch":"branch","trap":"trap","ret_text":"ret(","jump_text":"jump ",
 "branch_text":"branch ","trap_text":"trap ","end":"end\n",
 "profile":"E_HIA_ASSEMBLY_PROFILE: render requires explicit primitive v6/v7/v8 Core; use the existing adapter first",
}
BODY=r'''
def entry(s:readbuf, r:readbuf, w:mutbuf) -> u32:
    if length(w) < BASE:
        return BAD
    if get(w, 8) != 0:
        return BAD
    if valid(s, r) == 0:
        return poison(w)
    if get(w, 0) == 0:
        put(w, 0, STATE)
        put(w, PHASE, 1)
        put(w, LEASE, uint(r, 16))
        put(w, SEQ, uint(r, 24))
        put(w, SOURCE_N, length(s))
        put(w, STRUCTURED, uint(r, 40))
        copy_read(w, r, HEAD, 0, 96)
        literal_table(w)
        if get(w, STRUCTURED) != 0:
            return profile_refusal(w)
        if measure(s, w) == 0:
            return poison(w)
        arena = aligned(BASE + length(s))
        size = 64 + get(w, UPPER_NODES) * 56 + length(s)
        if size < 2208:
            size = 2208
        scratch = aligned(arena + size)
        bound = (length(s) >> 2) + 1
        if bound > 262144:
            bound = 262144
        slots = 2
        while slots < bound * 2:
            slots = slots * 2
        scratch_n = slots * 8
        if scratch_n < 3248:
            scratch_n = 3248
        put(w, ARENA, arena)
        put(w, ARENA_N, size)
        put(w, SCRATCH, scratch)
        put(w, SCRATCH_N, scratch_n)
        put(w, OUTPUT, aligned(scratch + scratch_n))
    else:
        if get(w, 0) != STATE or get(w, PHASE) < 1 or get(w, PHASE) > 2:
            return poison(w)
        if get(w, SOURCE_N) != length(s):
            return poison(w)
        i = 0
        while i < 96:
            if byte(r, i) != byte(w, HEAD + i):
                return poison(w)
            i = i + 1
    if layout(w) == 0:
        return poison(w)
    if length(w) < get(w, OUTPUT):
        return growing(w, get(w, OUTPUT))
    if get(w, PHASE) == 1:
        copy_read(w, s, BASE, 0, length(s))
        put(w, get(w, SCRATCH) + 48, 262144)
        put(w, get(w, SCRATCH) + 56, 64)
        status = rd_decode_json(s, get(w, ARENA), get(w, SCRATCH), w)
        if status >= 4294967292:
            return poison(w)
        arena = get(w, ARENA)
        if get(w, arena) != 5208772604367785521 or get(w, arena + 40) != length(s):
            return poison(w)
        put(w, ACTUAL_NODES, get(w, arena + 8))
        if get(w, ACTUAL_NODES) == 0 or get(w, ACTUAL_NODES) > 262144 or get(w, ACTUAL_NODES) > get(w, UPPER_NODES):
            return poison(w)
        if ar(w, 0, 0) != 6:
            return poison(w)
        schema = field(w, 0, L_schema)
        if schema == MAX or ar(w, schema, 0) != 4:
            return poison(w)
        if string_is(w, schema, L_v6) == 0 and string_is(w, schema, L_v7) == 0 and string_is(w, schema, L_v8) == 0:
            return profile_refusal(w)
        put(w, MODE, 0)
        put(w, CURSOR, get(w, OUTPUT))
        if render(s, w) == 0 or get(w, FAULT) != 0:
            return poison(w)
        put(w, OUTPUT_N, get(w, CURSOR) - get(w, OUTPUT))
        put(w, NEEDED, get(w, CURSOR))
        put(w, PHASE, 2)
    else:
        i = 0
        while i < length(s):
            if byte(s, i) != byte(w, BASE + i):
                return poison(w)
            i = i + 1
    if get(w, NEEDED) < get(w, OUTPUT) or get(w, OUTPUT_N) != get(w, NEEDED) - get(w, OUTPUT):
        return poison(w)
    if length(w) < get(w, NEEDED):
        return growing(w, get(w, NEEDED))
    put(w, WRITE_END, get(w, NEEDED))
    put(w, MODE, 1)
    put(w, CURSOR, get(w, OUTPUT))
    if render(s, w) == 0 or get(w, FAULT) != 0 or get(w, CURSOR) != get(w, NEEDED):
        return poison(w)
    put(w, PHASE, 3)
    emit(w, 0, get(w, OUTPUT), get(w, OUTPUT_N), get(w, NEEDED))
    return 128

def valid(s:readbuf, r:readbuf) -> u64:
    if length(r) != 96 or uint(r, 0) != COMMAND or uint(r, 8) != 1:
        return 0
    if uint(r, 16) == 0 or uint(r, 24) == 0 or uint(r, 32) != length(s):
        return 0
    if length(s) == 0 or length(s) > 8388608 or uint(r, 40) > 1:
        return 0
    i = 48
    while i < 96:
        if uint(r, i) != 0:
            return 0
        i = i + 8
    return 1

def layout(w:mutbuf) -> u64:
    if get(w, ARENA) != aligned(BASE + get(w, SOURCE_N)):
        return 0
    size = 64 + get(w, UPPER_NODES) * 56 + get(w, SOURCE_N)
    if size < 2208:
        size = 2208
    if get(w, ARENA_N) != size or get(w, SCRATCH) != aligned(get(w, ARENA) + size):
        return 0
    bound = (get(w, SOURCE_N) >> 2) + 1
    if bound > 262144:
        bound = 262144
    slots = 2
    while slots < bound * 2:
        slots = slots * 2
    size = slots * 8
    if size < 3248:
        size = 3248
    if get(w, SCRATCH_N) != size or get(w, OUTPUT) != aligned(get(w, SCRATCH) + size):
        return 0
    return 1

def aligned(n:u64) -> u64:
    return (n + 7) & 18446744073709551608

def region_size(w:mutbuf, base:u64) -> u64:
    if base == get(w, ARENA):
        return get(w, ARENA_N)
    if base == get(w, SCRATCH):
        return get(w, SCRATCH_N)
    put(w, FAULT, 1)
    return 0

def poison(w:mutbuf) -> u32:
    put(w, 8, 1)
    emit(w, 3, 0, 0, 0)
    return BAD

def growing(w:mutbuf, n:u64) -> u32:
    emit(w, 1, 0, 0, n)
    return GROW

def profile_refusal(w:mutbuf) -> u32:
    put(w, ERROR, 1)
    put(w, MODE, 1)
    put(w, CURSOR, ERROR_TEXT)
    put(w, WRITE_END, BASE)
    text(w, L_profile)
    if get(w, FAULT) != 0:
        return poison(w)
    put(w, PHASE, 3)
    emit(w, 2, ERROR_TEXT, get(w, CURSOR) - ERROR_TEXT, 0)
    return 128

def emit(w:mutbuf, action:u64, at:u64, n:u64, need:u64) -> u64:
    zero(w, 256, 128)
    put(w, 256, EVENT)
    put(w, 264, action)
    put(w, 272, get(w, LEASE))
    put(w, 280, get(w, SEQ))
    put(w, 288, get(w, ERROR))
    put(w, 312, at)
    put(w, 320, n)
    put(w, 336, get(w, SOURCE_N))
    put(w, 344, need)
    return 0

def measure(s:readbuf, w:mutbuf) -> u64:
    at = 0
    nodes = 0
    depth = 0
    while at < length(s):
        c = byte(s, at)
        if c == 34:
            nodes = nodes + 1
            at = at + 1
            closed = 0
            while at < length(s):
                c = byte(s, at)
                at = at + 1
                if c == 34:
                    closed = 1
                    break
                if c == 92:
                    if at == length(s):
                        return 0
                    at = at + 1
            if closed == 0:
                return 0
        elif c == 91 or c == 123:
            depth = depth + 1
            nodes = nodes + 1
            at = at + 1
        elif c == 93 or c == 125:
            if depth == 0:
                return 0
            depth = depth - 1
            at = at + 1
        elif c == 32 or c == 9 or c == 10 or c == 13 or c == 44 or c == 58:
            at = at + 1
        else:
            nodes = nodes + 1
            while at < length(s):
                c = byte(s, at)
                if c == 34 or c == 91 or c == 93 or c == 123 or c == 125 or c == 44 or c == 58 or c == 32 or c == 9 or c == 10 or c == 13:
                    break
                at = at + 1
    if depth != 0 or nodes == 0:
        return 0
    put(w, UPPER_NODES, nodes)
    return 1

def render(s:readbuf, w:mutbuf) -> u64:
    text(w, L_header)
    string_out(w, field(w, 0, L_schema))
    append(w, 32)
    string_out(w, field(w, 0, L_module))
    append(w, 10)
    exports = field(w, 0, L_exports)
    if exports != MAX:
        text(w, L_exports_text)
        if string_list(w, exports) == 0:
            return 0
        append(w, 41)
        append(w, 10)
    functions = field(w, 0, L_functions)
    if functions == MAX or ar(w, functions, 0) != 5:
        return 0
    count = ar(w, functions, 32)
    if count > get(w, ACTUAL_NODES):
        return 0
    child = ar(w, functions, 24)
    index = 0
    while index < count:
        if child == MAX or render_function(s, w, child) == 0:
            return 0
        child = ar(w, child, 16)
        index = index + 1
    if child != MAX:
        return 0
    return 1

def render_function(s:readbuf, w:mutbuf, function:u64) -> u64:
    if ar(w, function, 0) != 6:
        return 0
    text(w, L_fn_text)
    string_out(w, field(w, function, L_name))
    append(w, 40)
    if parameters(w, field(w, function, L_params)) == 0:
        return 0
    text(w, L_arrow)
    if string_list(w, field(w, function, L_returns)) == 0:
        return 0
    text(w, L_effects_text)
    if string_list(w, field(w, function, L_effects)) == 0:
        return 0
    text(w, L_entry_text)
    string_out(w, field(w, function, L_entry))
    append(w, 41)
    loans = field(w, function, L_return_loans)
    if loans != MAX:
        text(w, L_loans_text)
        if json_value(s, w, loans) == 0:
            return 0
        append(w, 41)
    append(w, 10)
    blocks = field(w, function, L_blocks)
    if blocks == MAX or ar(w, blocks, 0) != 5:
        return 0
    count = ar(w, blocks, 32)
    if count > get(w, ACTUAL_NODES):
        return 0
    child = ar(w, blocks, 24)
    index = 0
    while index < count:
        if child == MAX or render_block(s, w, child) == 0:
            return 0
        child = ar(w, child, 16)
        index = index + 1
    if child != MAX:
        return 0
    text(w, L_end)
    return 1

def render_block(s:readbuf, w:mutbuf, block:u64) -> u64:
    if ar(w, block, 0) != 6:
        return 0
    text(w, L_block_text)
    string_out(w, field(w, block, L_id))
    append(w, 40)
    if parameters(w, field(w, block, L_params)) == 0:
        return 0
    append(w, 41)
    append(w, 10)
    operations = field(w, block, L_ops)
    if operations == MAX or ar(w, operations, 0) != 5:
        return 0
    count = ar(w, operations, 32)
    if count > get(w, ACTUAL_NODES):
        return 0
    child = ar(w, operations, 24)
    index = 0
    while index < count:
        if child == MAX or render_operation(s, w, child) == 0:
            return 0
        child = ar(w, child, 16)
        index = index + 1
    if child != MAX:
        return 0
    text(w, L_indent)
    term = field(w, block, L_term)
    if term == MAX or ar(w, term, 0) != 6:
        return 0
    op = field(w, term, L_op)
    if string_is(w, op, L_ret) != 0:
        text(w, L_ret_text)
        if string_list(w, field(w, term, L_values)) == 0:
            return 0
        append(w, 41)
    elif string_is(w, op, L_jump) != 0:
        text(w, L_jump_text)
        if target(w, term) == 0:
            return 0
    elif string_is(w, op, L_branch) != 0:
        text(w, L_branch_text)
        string_out(w, field(w, term, L_cond))
        append(w, 32)
        if target(w, field(w, term, L_then)) == 0:
            return 0
        append(w, 32)
        if target(w, field(w, term, L_else)) == 0:
            return 0
    else:
        text(w, L_trap_text)
        string_out(w, field(w, term, L_code))
    append(w, 10)
    return 1

def render_operation(s:readbuf, w:mutbuf, operation:u64) -> u64:
    if ar(w, operation, 0) != 6:
        return 0
    text(w, L_indent)
    outputs = field(w, operation, L_out)
    if outputs == MAX or ar(w, outputs, 0) != 5:
        return 0
    if ar(w, outputs, 32) == 0:
        append(w, 95)
    elif parameters(w, outputs) == 0:
        return 0
    text(w, L_assign)
    string_out(w, field(w, operation, L_op))
    append(w, 40)
    if string_list(w, field(w, operation, L_args)) == 0:
        return 0
    append(w, 41)
    attributes = field(w, operation, L_attrs)
    if attributes == MAX or ar(w, attributes, 0) != 6:
        return 0
    if ar(w, attributes, 32) != 0:
        append(w, 32)
        if json_value(s, w, attributes) == 0:
            return 0
    append(w, 10)
    return 1

def target(w:mutbuf, node:u64) -> u64:
    if node == MAX or ar(w, node, 0) != 6:
        return 0
    string_out(w, field(w, node, L_target))
    append(w, 40)
    if string_list(w, field(w, node, L_args)) == 0:
        return 0
    append(w, 41)
    return 1

def parameters(w:mutbuf, node:u64) -> u64:
    if node == MAX or ar(w, node, 0) != 5:
        return 0
    count = ar(w, node, 32)
    if count > get(w, ACTUAL_NODES):
        return 0
    child = ar(w, node, 24)
    i = 0
    while i < count:
        if child == MAX or ar(w, child, 0) != 6:
            return 0
        if i != 0:
            append(w, 44)
        string_out(w, field(w, child, L_name))
        append(w, 58)
        string_out(w, field(w, child, L_type))
        child = ar(w, child, 16)
        i = i + 1
    if child != MAX:
        return 0
    return 1

def string_list(w:mutbuf, node:u64) -> u64:
    if node == MAX or ar(w, node, 0) != 5:
        return 0
    count = ar(w, node, 32)
    if count > get(w, ACTUAL_NODES):
        return 0
    child = ar(w, node, 24)
    i = 0
    while i < count:
        if child == MAX or ar(w, child, 0) != 4:
            return 0
        if i != 0:
            append(w, 44)
        string_out(w, child)
        child = ar(w, child, 16)
        i = i + 1
    if child != MAX:
        return 0
    return 1

def field(w:mutbuf, object:u64, key:u64) -> u64:
    if object == MAX or ar(w, object, 0) != 6:
        put(w, FAULT, 1)
        return MAX
    count = ar(w, object, 32)
    if count > get(w, ACTUAL_NODES):
        put(w, FAULT, 1)
        return MAX
    child = ar(w, object, 24)
    seen = 0
    while seen < count:
        if child == MAX:
            put(w, FAULT, 1)
            return MAX
        if span_is(w, ar(w, child, 40), ar(w, child, 48), key) != 0:
            return child
        child = ar(w, child, 16)
        seen = seen + 1
    if child != MAX:
        put(w, FAULT, 1)
    return MAX

def ar(w:mutbuf, node:u64, field:u64) -> u64:
    if node >= get(w, ACTUAL_NODES) or field > 48 or (field & 7) != 0:
        put(w, FAULT, 1)
        return 0
    return get(w, get(w, ARENA) + 64 + node * 56 + field)

def ar_put(w:mutbuf, node:u64, field:u64, value:u64) -> u64:
    if node >= get(w, ACTUAL_NODES) or field > 48 or (field & 7) != 0:
        put(w, FAULT, 1)
        return 0
    put(w, get(w, ARENA) + 64 + node * 56 + field, value)
    return 1

def string_span(w:mutbuf, at:u64, size:u64) -> u64:
    arena = get(w, ARENA)
    begin = get(w, arena + 16)
    end = get(w, arena + 24)
    if begin > end or end > get(w, ARENA_N) or at < begin or at > end or size > end - at:
        put(w, FAULT, 1)
        return 0
    return 1

def string_out(w:mutbuf, node:u64) -> u64:
    if node == MAX or ar(w, node, 0) != 4:
        put(w, FAULT, 1)
        return 0
    return arena_span(w, ar(w, node, 24), ar(w, node, 32))

def arena_span(w:mutbuf, start:u64, size:u64) -> u64:
    if string_span(w, start, size) == 0:
        return 0
    i = 0
    while i < size:
        append(w, byte(w, get(w, ARENA) + start + i))
        i = i + 1
    return 1

def span_is(w:mutbuf, start:u64, size:u64, code:u64) -> u64:
    if string_span(w, start, size) == 0:
        return 0
    n = get(w, INDEX + code * 16 + 8)
    at = get(w, INDEX + code * 16)
    if n != size:
        return 0
    i = 0
    while i < n:
        if byte(w, get(w, ARENA) + start + i) != byte(w, at + i):
            return 0
        i = i + 1
    return 1

def string_is(w:mutbuf, node:u64, code:u64) -> u64:
    if node == MAX or ar(w, node, 0) != 4:
        put(w, FAULT, 1)
        return 0
    return span_is(w, ar(w, node, 24), ar(w, node, 32), code)

def json_string(w:mutbuf, start:u64, size:u64) -> u64:
    if string_span(w, start, size) == 0:
        return 0
    append(w, 34)
    at = 0
    while at < size:
        value = byte(w, get(w, ARENA) + start + at)
        if value < 32:
            append(w, 92)
            escape = 0
            if value == 8:
                escape = 98
            elif value == 9:
                escape = 116
            elif value == 10:
                escape = 110
            elif value == 12:
                escape = 102
            elif value == 13:
                escape = 114
            if escape != 0:
                append(w, escape)
            else:
                append(w, 117)
                append(w, 48)
                append(w, 48)
                append(w, hex_digit(value >> 4))
                append(w, hex_digit(value & 15))
        else:
            if value == 34 or value == 92:
                append(w, 92)
            append(w, value)
        at = at + 1
    append(w, 34)
    return 1

def json_value(s:readbuf, w:mutbuf, root:u64) -> u64:
    if root >= get(w, ACTUAL_NODES):
        return 0
    node = root
    going = 1
    steps = 0
    while going != 0:
        steps = steps + 1
        if steps > get(w, ACTUAL_NODES) * 4 or get(w, FAULT) != 0:
            return 0
        kind = ar(w, node, 0)
        parent = ar(w, node, 8)
        if node != root and parent != MAX and ar(w, parent, 0) == 6:
            if json_string(w, ar(w, node, 40), ar(w, node, 48)) == 0:
                return 0
            append(w, 58)
        complete = 1
        if kind == 5 or kind == 6:
            if kind == 6:
                sort_object(w, node)
            if kind == 5:
                append(w, 91)
            else:
                append(w, 123)
            if ar(w, node, 32) == 0:
                if kind == 5:
                    append(w, 93)
                else:
                    append(w, 125)
            else:
                node = ar(w, node, 24)
                complete = 0
        elif kind == 4:
            if json_string(w, ar(w, node, 24), ar(w, node, 32)) == 0:
                return 0
        elif kind < 4:
            at = ar(w, node, 24)
            size = ar(w, node, 32)
            if at > length(s) or size > length(s) - at:
                return 0
            if kind == 3 and size == 2 and byte(s, at) == 45 and byte(s, at + 1) == 48:
                append(w, 48)
            else:
                i = 0
                while i < size:
                    append(w, byte(s, at + i))
                    i = i + 1
        else:
            return 0
        if complete != 0:
            moving = 1
            while moving != 0:
                steps = steps + 1
                if steps > get(w, ACTUAL_NODES) * 4 or get(w, FAULT) != 0:
                    return 0
                if node == root:
                    going = 0
                    moving = 0
                else:
                    sibling = ar(w, node, 16)
                    if sibling != MAX:
                        append(w, 44)
                        node = sibling
                        moving = 0
                    else:
                        node = ar(w, node, 8)
                        if node == MAX:
                            return 0
                        if ar(w, node, 0) == 5:
                            append(w, 93)
                        else:
                            append(w, 125)
    return 1

def key_less(w:mutbuf, a:u64, b:u64) -> u64:
    aa = ar(w, a, 40)
    bb = ar(w, b, 40)
    na = ar(w, a, 48)
    nb = ar(w, b, 48)
    if string_span(w, aa, na) == 0 or string_span(w, bb, nb) == 0:
        return 0
    at = 0
    while at < na and at < nb:
        x = byte(w, get(w, ARENA) + aa + at)
        y = byte(w, get(w, ARENA) + bb + at)
        if x < y:
            return 1
        if x > y:
            return 0
        at = at + 1
    if na <= nb:
        return 1
    return 0

def sort_object(w:mutbuf, node:u64) -> u64:
    count = ar(w, node, 32)
    head = ar(w, node, 24)
    if count > get(w, ACTUAL_NODES):
        put(w, FAULT, 1)
        return 0
    width = 1
    while width < count:
        p = head
        head = MAX
        tail = MAX
        visited = 0
        while p != MAX:
            if visited >= count:
                put(w, FAULT, 1)
                return 0
            q = p
            left = 0
            while left < width and q != MAX:
                q = ar(w, q, 16)
                left = left + 1
            right = width
            element = 0
            while left > 0 or (right > 0 and q != MAX):
                take_left = 0
                if left > 0:
                    if right == 0 or q == MAX or key_less(w, p, q) != 0:
                        take_left = 1
                if take_left != 0:
                    element = p
                    p = ar(w, p, 16)
                    left = left - 1
                else:
                    element = q
                    q = ar(w, q, 16)
                    right = right - 1
                if tail == MAX:
                    head = element
                else:
                    ar_put(w, tail, 16, element)
                tail = element
                visited = visited + 1
                if visited > count:
                    put(w, FAULT, 1)
                    return 0
            p = q
        if tail == MAX or visited != count:
            put(w, FAULT, 1)
            return 0
        ar_put(w, tail, 16, MAX)
        width = width * 2
    ar_put(w, node, 24, head)
    return 1

def hex_digit(value:u64) -> u64:
    if value < 10:
        return value + 48
    return value + 87

def append(w:mutbuf, value:u64) -> u64:
    at = get(w, CURSOR)
    if at == MAX:
        put(w, FAULT, 1)
        return 0
    if get(w, MODE) != 0:
        if at >= length(w) or at >= get(w, WRITE_END):
            put(w, FAULT, 1)
            return 0
        store(w, at, value)
    put(w, CURSOR, at + 1)
    return 1

def text(w:mutbuf, code:u64) -> u64:
    at = get(w, INDEX + code * 16)
    size = get(w, INDEX + code * 16 + 8)
    i = 0
    while i < size:
        append(w, byte(w, at + i))
        i = i + 1
    return 1

def copy_read(w:mutbuf, s:readbuf, target:u64, at:u64, size:u64) -> u64:
    i = 0
    while i < size:
        store(w, target + i, byte(s, at + i))
        i = i + 1
    return 0

def zero(w:mutbuf, at:u64, size:u64) -> u64:
    i = 0
    while i < size:
        store(w, at + i, 0)
        i = i + 1
    return 0

def uint(s:readbuf, at:u64) -> u64:
    value = 0
    i = 0
    while i < 8:
        value = value | (byte(s, at + i) << (i * 8))
        i = i + 1
    return value

def get(w:mutbuf, at:u64) -> u64:
    value = 0
    i = 0
    while i < 8:
        value = value | (byte(w, at + i) << (i * 8))
        i = i + 1
    return value

def put(w:mutbuf, at:u64, value:u64) -> u64:
    i = 0
    while i < 8:
        store(w, at + i, (value >> (i * 8)) & 255)
        i = i + 1
    return 0
'''
def rebase_decoder():
    old="            if index == length(s):\n                return 0"
    new="            if index == length(s):\n                put(w, 64, nodes)\n                return 0"
    assert PREFLIGHT_SOURCE.count(old)==1
    nodes=ast.parse(DECODER_SOURCE+PREFLIGHT_SOURCE.replace(old,new,1)).body
    names={n.name for n in nodes}-{"get","put"}
    class Rebase(ast.NodeTransformer):
        def __init__(self,buffers):self.buffers=buffers
        def visit_Call(self,n):
            if not isinstance(n.func,ast.Name):return self.generic_visit(n)
            fn=n.func.id
            if fn in ("get","put"):
                buffer=n.args[0];assert isinstance(buffer,ast.Name) and buffer.id in self.buffers
                args=[ast.Name("arena",ast.Load()),ast.BinOp(ast.Name(buffer.id,ast.Load()),ast.Add(),self.visit(n.args[1]))]
                args.extend(self.visit(a) for a in n.args[2:])
                return ast.copy_location(ast.Call(ast.Name(fn,ast.Load()),args,[]),n)
            if fn=="length" and isinstance(n.args[0],ast.Name) and n.args[0].id in self.buffers:
                return ast.copy_location(ast.Call(ast.Name("region_size",ast.Load()),[ast.Name("arena",ast.Load()),n.args[0]],[]),n)
            if fn in ("byte","store") and isinstance(n.args[0],ast.Name) and n.args[0].id in self.buffers:
                args=[ast.Name("arena",ast.Load()),ast.BinOp(n.args[0],ast.Add(),self.visit(n.args[1]))]
                args.extend(self.visit(a) for a in n.args[2:])
                return ast.copy_location(ast.Call(ast.Name(fn,ast.Load()),args,[]),n)
            if fn in names:
                return ast.copy_location(ast.Call(ast.Name("rd_"+fn,ast.Load()),[self.visit(a) for a in n.args]+[ast.Name("arena",ast.Load())],[]),n)
            return self.generic_visit(n)
    result=[]
    for node in nodes:
        if node.name not in names:continue
        buffers={a.arg for a in node.args.args if a.annotation.id=="mutbuf"}
        node=Rebase(buffers).visit(node)
        for a in node.args.args:
            if a.arg in buffers:a.annotation=ast.Name("u64",ast.Load())
        node.args.args.append(ast.arg(arg="arena",annotation=ast.Name("mutbuf",ast.Load())))
        node.name="rd_"+node.name
        # At the original eight-MiB/262144-node profile all original returned
        # u32 statuses and arena lengths fit unchanged in u64.
        node.returns=ast.Name("u64",ast.Load())
        result.append(ast.fix_missing_locations(node))
    return "\n".join(ast.unparse(n) for n in result)+"\n"

def source():
    import tools.generate_hia_json_decode as decoder
    import tools.generate_hia_json_preflight as preflight
    decoder_raw=Path(decoder.__file__).read_bytes();preflight_raw=Path(preflight.__file__).read_bytes()
    assert sha256(preflight_raw).hexdigest()=="293e22e217cba119dad1c7a4e04b5a9cd714cbeafdfdc4c9b15f4f716557896c"
    assert sha256(decoder_raw).hexdigest()=="fffc97c704cc75ad88239fe79d7b7f83418199a732364f834e006ebfd5f8548f"
    for raw,name,loaded in ((decoder_raw,"DECODER_SOURCE",DECODER_SOURCE),(preflight_raw,"SOURCE",PREFLIGHT_SOURCE)):
        values=[ast.literal_eval(n.value) for n in ast.parse(raw).body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id==name for t in n.targets)]
        assert values==[loaded],name
    constants=dict(CONSTANTS);raw=bytearray(constants["TEXT"])
    for i,(name,text) in enumerate(LITERALS.items()):
        constants["L_"+name]=i
        data=text.encode();at=len(raw);raw.extend(data);row=constants["INDEX"]+16*i
        raw[row:row+8]=at.to_bytes(8,"little");raw[row+8:row+16]=len(data).to_bytes(8,"little")
    assert len(raw)<constants["ERROR_TEXT"]
    writes=[(i,int.from_bytes(raw[i:i+8].ljust(8,b"\0"),"little")) for i in range(constants["INDEX"],len(raw),8) if any(raw[i:i+8])]
    functions=[];calls=[]
    for start in range(0,len(writes),24):
        name="literals_"+str(start//24);calls.append("    "+name+"(w)")
        lines=["def "+name+"(w:mutbuf) -> u64:"]
        lines+=["    put(w, "+str(at)+", "+str(value)+")" for at,value in writes[start:start+24]]
        lines+=["    return 0"];functions.append("\n".join(lines))
    table="def literal_table(w:mutbuf) -> u64:\n"+"\n".join(calls)+"\n    return 0\n"
    result=BODY+"\n"+rebase_decoder()+"\n"+table+"\n".join(functions)+"\n"
    nodes=ast.parse(result).body
    for fn in nodes:
        if fn.name=="get":fn.body=ast.parse("return "+" | ".join("(byte(w, at + %d) << %d)"%(i,8*i) for i in range(8))).body
        elif fn.name=="put":fn.body=ast.parse("\n".join("store(w, at + %d, (value >> %d) & 255)"%(i,8*i) for i in range(8))+"\nreturn 0").body
    return "\n".join(ast.unparse(ast.fix_missing_locations(n)) for n in nodes)+"\n",constants,dict(
        status="NEW_AUTHORING_ONLY",requires_actual_prior_Core_admission=True,grants_no_admission=True,
        performs_no_roundtrip_admission_itself=True,source_maximum_is_prior_Core_8388608=True,
        no_render_output_byte_or_line_or_function_quota=True,complete_original_render_syntax=True,
        preflight_source_sha256=sha256(preflight_raw).hexdigest(),decoder_source_sha256=sha256(decoder_raw).hexdigest(),
        private_immutable_before_initial_GROW=True,source_copied_and_rechecked_on_output_GROW=True,
        structured_flag_requires_actual_admission_receipt=True)

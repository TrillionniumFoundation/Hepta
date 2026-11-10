"""Native complete type-validity and explicit generic-argument controllers.

No recursive HIA calls: continuation frames preserve diagnostic/return ordering.
This is authored HIA assembly through the same scalar Core authoring generator.
"""
NAMES=('u64','IoReactor','IoRequest','TaskGroup','Sender','Cancellation','Owned','Task',
       'array','slice','Buffer','raw_const','raw_mut','_','bool','Unit',
       'i8','i16','i32','i64','i128','isize','u8','u16','u32','u128','usize','f32','f64')
SOURCE=r'''
def same_name(s:readbuf, symbol:u64, first:u64, second:u64, size:u64) -> u64:
    row = word(s, 112) + symbol * 16
    begin = word(s, row)
    if word(s, row + 8) - begin != size:
        return 0
    at = word(s, 120) + begin
    i = 0
    while i < size:
        value = first
        shift = i * 8
        if i >= 8:
            value = second
            shift = (i - 8) * 8
        if byte(s, at + i) != ((value >> shift) & 255):
            return 0
        i = i + 1
    return 1

def config(s:readbuf, index:u64) -> u64:
    at = word(s, 104) + (word(s, 32) + word(s, 48) + word(s, 56) + word(s, 64)) * 8
    return word(s, at + index * 8)

def validate_config(s:readbuf) -> u64:
    if word(s, 72) < 7:
        return 1
    if config(s, 0) > 8192 or config(s, 1) > 8192 or config(s, 2) > 1 or config(s, 3) > 15 or config(s, 4) > word(s, 24) or config(s, 5) > 4096 or config(s, 6) > 1:
        return 1
    if word(s, 72) != 7 + config(s, 0) + config(s, 1) + config(s, 5) * 2:
        return 1
    if word(s, 8) == 4 and (config(s, 5) != 0 or config(s, 6) != 0):
        return 1
    i = 7
    while i < word(s, 72):
        if config(s, i) >= word(s, 40):
            return 1
        i = i + 1
    return 0

def has_type_parameter(s:readbuf, name:u64) -> u64:
    i = 0
    while i < config(s, 0):
        if config(s, 7 + i) == name:
            return 1
        i = i + 1
    return 0

def has_lifetime(s:readbuf, name:u64) -> u64:
    if config(s, 2) == 1 and named(s, name, N__) == 1:
        return 1
    i = 0
    while i < config(s, 1):
        if config(s, 7 + config(s, 0) + i) == name:
            return 1
        i = i + 1
    return 0

def configure_query(s:readbuf, w:mutbuf, kind:u64) -> u64:
    if kind == 0 or kind == 1:
        return 0
    put_query(w, 32, 0)
    i = 0
    while i < word(s, 40):
        hit = 0
        if kind == 2 or kind == 5:
            if named(s, i, N_IoReactor) == 1 or named(s, i, N_IoRequest) == 1:
                hit = 1
        if kind == 2:
            if named(s, i, N_Task) == 1 or named(s, i, N_TaskGroup) == 1:
                hit = 1
        if kind == 3 and named(s, i, N_Cancellation) == 1:
            hit = 1
        if kind == 4 and named(s, i, N_Sender) == 1:
            hit = 1
        store(w, 680256 + 532736 + i, hit)
        i = i + 1
    return 0

def validation_query(s:readbuf, w:mutbuf, ref:u64, kind:u64) -> u64:
    env = get(w, 8)
    bindings = get(w, 16)
    code = prepare_query(s, w)
    if code == 0:
        configure_query(s, w, kind)
        put_query(w, 256, ref)
        mode = 1
        if kind == 1:
            mode = 2
        code = query_query(s, w, mode)
    put(w, 8, env)
    put(w, 16, bindings)
    return code

def type_child(s:readbuf, node:u64, index:u64) -> u64:
    return word(s, word(s, 104) + (word(s, 128 + node * 64 + 8) + index) * 8)

def exact_u64(s:readbuf, node:u64) -> u64:
    at = 128 + node * 64
    if named(s, word(s, at), N_u64) == 1 and word(s, at + 16) == 0 and word(s, at + 32) == 0 and word(s, at + 40) == 0:
        return 1
    return 0

def exact_task_argument(s:readbuf, node:u64) -> u64:
    at = 128 + node * 64
    if word(s, at + 16) == 1 and word(s, at + 32) == 0 and word(s, at + 40) == 0:
        return exact_u64(s, type_child(s, node, 0))
    return 0

def emit_type_error(s:readbuf, w:mutbuf, kind:u64, ref:u64, first:u64, second:u64) -> u64:
    if get(w, 128) >= 32768:
        return 4294967292
    clone = clone_type(s, w, ref)
    if clone == 18446744073709551615:
        return 4294967292
    at = 5325456 + get(w, 128) * 32
    put(w, at, kind)
    put(w, at + 8, clone)
    put(w, at + 16, first)
    put(w, at + 24, second)
    put(w, 128, get(w, 128) + 1)
    return 0

def type_push(w:mutbuf, node:u64, flags:u64) -> u64:
    if get(w, 112) >= 8192:
        return 4294967292
    at = 4932240 + get(w, 112) * 48
    put(w, at, node)
    put(w, at + 8, flags)
    put(w, at + 16, 0)
    put(w, at + 24, 0)
    put(w, at + 32, 0)
    put(w, at + 40, 1)
    put(w, 112, get(w, 112) + 1)
    return 0

def type_finish(w:mutbuf, good:u64) -> u64:
    put(w, 120, good)
    put(w, 112, get(w, 112) - 1)
    return 0

def type_lifetimes(s:readbuf, w:mutbuf, node:u64) -> u64:
    at = 128 + node * 64
    name = word(s, at)
    count = 0
    declaration = get(w, 614720 + name * 8)
    if declaration != 0 and declaration <= config(s, 4):
        count = word(s, word(s, 96) + (declaration - 1) * 48 + 40)
    if is_reference(s, name) == 1:
        count = 1
    if word(s, at + 32) != count:
        code = emit_type_error(s, w, 1, node, count, 0)
        if code != 0:
            return code
    i = 0
    while i < word(s, at + 32):
        life = word(s, word(s, 104) + (word(s, at + 24) + i) * 8)
        if has_lifetime(s, life) == 0:
            code = emit_type_error(s, w, 2, node, i, 0)
            if code != 0:
                return code
        i = i + 1
    return 0

def type_reference(s:readbuf, w:mutbuf, row:u64) -> u64:
    node = get(w, row)
    at = 128 + node * 64
    if (get(w, row + 8) & 8) == 0 or word(s, at + 16) != 1 or word(s, at + 40) != 0:
        code = emit_type_error(s, w, 3, node, 0, 0)
        type_finish(w, 0)
        return code
    child = type_child(s, node, 0)
    answer = validation_query(s, w, child, 5)
    if answer > 1:
        return answer
    if answer == 1:
        code = emit_type_error(s, w, 4, node, 0, 0)
        if code != 0:
            return code
    answer = validation_query(s, w, child, 1)
    if answer > 1:
        return answer
    name = word(s, 128 + child * 64)
    if answer == 1 or named(s, name, N_raw_const) == 1 or named(s, name, N_raw_mut) == 1:
        code = emit_type_error(s, w, 5, node, 0, 0)
        if code != 0:
            return code
    put(w, row + 16, 1)
    return type_push(w, child, 1)

def type_leaf(s:readbuf, w:mutbuf, row:u64) -> u64:
    node = get(w, row)
    at = 128 + node * 64
    name = word(s, at)
    kind = 0
    if has_type_parameter(s, name) == 1:
        kind = 6
    elif named(s, name, N_IoReactor) == 1 or named(s, name, N_IoRequest) == 1:
        kind = 7
    elif named(s, name, N_TaskGroup) == 1:
        kind = 8
    elif named(s, name, N_Sender) == 1:
        if (get(w, row + 8) & 4) == 0 or exact_task_argument(s, node) == 0:
            code = emit_type_error(s, w, 9, node, 0, 0)
            type_finish(w, 0)
            return code
        return type_finish(w, 1)
    elif named(s, name, N_Cancellation) == 1:
        if (get(w, row + 8) & 2) == 0 or word(s, at + 16) != 0 or word(s, at + 40) != 0:
            code = emit_type_error(s, w, 10, node, 0, 0)
            type_finish(w, 0)
            return code
        return type_finish(w, 1)
    elif primitive(s, name) == 1:
        kind = 11
    else:
        return 2
    if word(s, at + 16) != 0 or word(s, at + 40) != 0:
        code = emit_type_error(s, w, kind, node, 0, 0)
        type_finish(w, 0)
        return code
    return type_finish(w, 1)

def type_container(s:readbuf, w:mutbuf, row:u64) -> u64:
    node = get(w, row)
    at = 128 + node * 64
    name = word(s, at)
    kind = 0
    if word(s, at + 16) != 1:
        kind = 12
    elif named(s, name, N_array) == 1:
        if word(s, at + 40) != 1:
            kind = 13
        else:
            symbol = word(s, at + 48)
            begin = word(s, word(s, 112) + symbol * 16)
            end = word(s, word(s, 112) + symbol * 16 + 8)
            if begin == end or byte(s, word(s, 120) + begin) == 45:
                kind = 13
    elif word(s, at + 40) != 0:
        kind = 14
    if kind == 0 and named(s, name, N_slice) == 1 and (get(w, row + 8) & 1) == 0:
        kind = 15
    if kind != 0:
        code = emit_type_error(s, w, kind, node, 0, 0)
        type_finish(w, 0)
        return code
    put(w, row + 16, 2)
    return type_push(w, type_child(s, node, 0), 0)

def type_container_finish(s:readbuf, w:mutbuf, row:u64) -> u64:
    node = get(w, row)
    child = type_child(s, node, 0)
    good = get(w, 120)
    answer = validation_query(s, w, child, 1)
    if answer > 1:
        return answer
    if answer == 1:
        code = emit_type_error(s, w, 16, node, 0, 0)
        if code != 0:
            return code
        good = 0
    if named(s, word(s, 128 + node * 64), N_Task) == 1 and exact_task_argument(s, node) == 0:
        code = emit_type_error(s, w, 17, node, 0, 0)
        if code != 0:
            return code
        good = 0
    answer = validation_query(s, w, child, 0)
    if answer > 1:
        return answer
    if answer == 1:
        code = emit_type_error(s, w, 18, node, 0, 0)
        if code != 0:
            return code
        good = 0
    return type_finish(w, good)

def generic_count(s:readbuf, w:mutbuf, row:u64) -> u64:
    if word(s, 8) == 5 and row == 4932240:
        return config(s, 5)
    name = word(s, 128 + get(w, row) * 64)
    declaration = get(w, 614720 + name * 8) - 1
    return word(s, word(s, 96) + declaration * 48 + 16)

def generic_start(s:readbuf, w:mutbuf, row:u64) -> u64:
    node = get(w, row)
    count = generic_count(s, w, row)
    args = word(s, 128 + node * 64 + 16)
    put(w, row + 32, get(w, 128))
    put(w, row + 16, 3)
    if count != args:
        return emit_type_error(s, w, 19, node, count, args)
    return 0

def generic_argument_finish(s:readbuf, w:mutbuf, row:u64) -> u64:
    node = get(w, row)
    index = get(w, row + 24)
    child = type_child(s, node, index)
    answer = validation_query(s, w, child, 1)
    if answer > 1:
        return answer
    if answer == 1:
        code = emit_type_error(s, w, 20, child, 0, 0)
        if code != 0:
            return code
    linear = validation_query(s, w, child, 0)
    scoped = validation_query(s, w, child, 2)
    cancel = validation_query(s, w, child, 3)
    sender = validation_query(s, w, child, 4)
    if linear > 1 or scoped > 1 or cancel > 1 or sender > 1:
        return 4294967292
    allow = 1
    owned = 0
    if word(s, 8) == 5 and row == 4932240:
        allow = config(s, 6)
        if index < config(s, 5):
            bound = config(s, 7 + config(s, 0) + config(s, 1) + config(s, 5) + index)
            owned = named(s, bound, N_Owned)
    if (linear == 1 and allow == 0 and owned == 0) or scoped == 1 or cancel == 1 or sender == 1 or named(s, word(s, 128 + child * 64), N_slice) == 1:
        detail = owned
        if allow == 1:
            detail = 2
        code = emit_type_error(s, w, 21, child, detail, 0)
        if code != 0:
            return code
    elif allow == 0 and owned == 1 and linear == 0:
        code = emit_type_error(s, w, 22, child, 0, 0)
        if code != 0:
            return code
    put(w, row + 24, index + 1)
    put(w, row + 16, 3)
    return 0

def type_nominal_finish(s:readbuf, w:mutbuf, row:u64) -> u64:
    node = get(w, row)
    if word(s, 8) == 5 and row == 4932240:
        return type_finish(w, 1)
    if word(s, 128 + node * 64 + 40) != 0:
        code = emit_type_error(s, w, 23, node, 0, 0)
        if code != 0:
            return code
    kind = 2
    while kind < 5:
        answer = validation_query(s, w, node, kind)
        if answer > 1:
            return answer
        if answer == 1:
            code = emit_type_error(s, w, 22 + kind, node, 0, 0)
            type_finish(w, 0)
            return code
        kind = kind + 1
    env = get(w, 8)
    bindings = get(w, 16)
    put(w, 0, 1)
    put(w, 256, node)
    code = owned_walk(s, w)
    if code == 0:
        i = 0
        while i < get(w, 56):
            code = emit_type_error(s, w, 27, get(w, 2900624 + i * 8), 0, 0)
            if code != 0:
                return code
            i = i + 1
    put(w, 8, env)
    put(w, 16, bindings)
    if code != 0:
        return code
    good = 0
    if get(w, 128) == get(w, row + 32):
        good = 1
    return type_finish(w, good)

def type_step(s:readbuf, w:mutbuf, row:u64) -> u64:
    node = get(w, row)
    at = 128 + node * 64
    name = word(s, at)
    code = type_lifetimes(s, w, node)
    if code != 0:
        return code
    if is_reference(s, name) == 1:
        return type_reference(s, w, row)
    code = type_leaf(s, w, row)
    if code != 2:
        return code
    if is_owned_container(s, name) == 1 or named(s, name, N_Task) == 1:
        return type_container(s, w, row)
    if get(w, 614720 + name * 8) != 0:
        return generic_start(s, w, row)
    code = emit_type_error(s, w, 28, node, 0, 0)
    type_finish(w, 0)
    return code

def validate_type_walk(s:readbuf, w:mutbuf) -> u64:
    put(w, 80, 0)
    put(w, 88, 0)
    put(w, 112, 0)
    put(w, 120, 0)
    put(w, 128, 0)
    type_push(w, word(s, 80), config(s, 3))
    if word(s, 8) == 5:
        code = generic_start(s, w, 4932240)
        if code != 0:
            return code
    while get(w, 112) != 0:
        row = 4932240 + (get(w, 112) - 1) * 48
        stage = get(w, row + 16)
        code = 0
        if stage == 0:
            code = type_step(s, w, row)
        elif stage == 1:
            type_finish(w, get(w, 120))
        elif stage == 2:
            code = type_container_finish(s, w, row)
        elif stage == 3:
            if get(w, row + 24) < word(s, 128 + get(w, row) * 64 + 16):
                put(w, row + 16, 4)
                code = type_push(w, type_child(s, get(w, row), get(w, row + 24)), 0)
            else:
                code = type_nominal_finish(s, w, row)
        elif stage == 4:
            code = generic_argument_finish(s, w, row)
        else:
            return 4294967293
        if code != 0:
            return code
    return 0

def type_result(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    mappings = 0
    if word(s, 8) == 5:
        mappings = config(s, 5)
    size = 64 + get(w, 128) * 32 + mappings * 16 + get(w, 80) * 24 + get(w, 88) * 8
    if length(o) < size:
        return 4294967294
    put(o, 0, 3549479791681612111)
    put(o, 8, get(w, 120))
    put(o, 16, get(w, 128))
    put(o, 24, get(w, 80))
    put(o, 32, get(w, 88))
    put(o, 40, word(s, 8))
    put(o, 48, mappings)
    put(o, 56, 0)
    at = 64
    i = 0
    while i < get(w, 128) * 4:
        put(o, at + i * 8, get(w, 5325456 + i * 8))
        i = i + 1
    at = at + get(w, 128) * 32
    i = 0
    while i < mappings:
        value = 18446744073709551615
        if i < word(s, 128 + word(s, 80) * 64 + 16):
            value = type_child(s, word(s, 80), i)
        put(o, at + i * 16, i)
        put(o, at + i * 16 + 8, value)
        i = i + 1
    at = at + mappings * 16
    i = 0
    while i < get(w, 80) * 3:
        put(o, at + i * 8, get(w, 3621520 + i * 8))
        i = i + 1
    at = at + get(w, 80) * 24
    i = 0
    while i < get(w, 88):
        put(o, at + i * 8, get(w, 4407952 + i * 8))
        i = i + 1
    return size
'''
SOURCE+='\ndef named(s:readbuf, symbol:u64, name:u64) -> u64:\n'
for i,name in enumerate(NAMES,1):
    encoded=name.encode();first=int.from_bytes(encoded[:8],'little');second=int.from_bytes(encoded[8:],'little')
    SOURCE+=f'    if name == {i}:\n        return same_name(s, symbol, {first}, {second}, {len(encoded)})\n'
SOURCE+='    return 0\n\ndef primitive(s:readbuf, name:u64) -> u64:\n'
SOURCE+='    if '+' or '.join('named(s, name, '+str(NAMES.index(n)+1)+') == 1' for n in ('u64','bool','Unit','i8','i16','i32','i64','i128','isize','u8','u16','u32','u128','usize','f32','f64'))+':\n        return 1\n    return 0\n'
# Longest-name replacement avoids N_Task being a prefix of N_TaskGroup.
for i,name in sorted(enumerate(NAMES,1),key=lambda p:-len(p[1])):SOURCE=SOURCE.replace('N_'+name,str(i))

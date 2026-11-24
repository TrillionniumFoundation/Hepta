"""Author an independent resource oracle backend from admitted reference wire.

The borrowed-only bootstrap seed remains unchanged. This separate profile uses
two-word value slots and the original general backend's libc resource contract,
and emits an ordinary relocatable object for the existing HIA shared linker.
It must be constructed by the independently bootstrapped source toolchain.
"""
from pathlib import Path
import ast
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_worker_config_json import document
from tools.generate_hia_seed_backend import program as borrowed_program

ROOT=Path(__file__).resolve().parents[1]
SOURCE=r"""
def seed_owned_backend(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 80 or length(s) > 1048576 or length(o) != 1048576 or length(w) < 1048576:
        return 4294967293
    if header(s, w) == 0 or instructions(s, w) == 0:
        return 4294967295
    i = 0
    while i < get(w, 72):
        if get(w, 280 + i * 32) == 18446744073709551615:
            return 4294967295
        i = i + 1
    put(w, 8, 1)
    generate(s, o, w)
    object_layout(w)
    total = get(w, 120)
    if get(w, 16) != 0 or total > length(o):
        return 4294967294
    put(w, 8, 0)
    generate(s, o, w)
    object_layout(w)
    if get(w, 16) != 0 or total != get(w, 120):
        return 4294967295
    if resolve(o, w) == 0:
        return 4294967295
    object_emit(o, w)
    return total

def header(s:readbuf, w:mutbuf) -> u64:
    if borrowed_header(s, w) == 0:
        return 0
    put(w, 80, ((get(w, 56) + get(w, 64)) * 16 + 79) & 18446744073709551600)
    put(w, 96, 0 - (get(w, 56) + get(w, 64)) * 16 - 16)
    put(w, 136, 0 - (get(w, 56) + get(w, 64)) * 16 - 48)
    i = 0
    while i < get(w, 72):
        put(w, 280 + i * 32, 18446744073709551615)
        i = i + 1
    put(w, 280, 1)
    return 1

def edge_boundary(s:readbuf, w:mutbuf, edge:u64, after:u64) -> u64:
    if edge > get(w, 88) or get(w, 88) - edge < 24:
        return 0
    return boundary(s, w, word(s, edge + 8), after)

def boundaries(s:readbuf, w:mutbuf, at:u64, op:u64) -> u64:
    if borrowed_boundaries(s, w, at, op) == 0:
        return 0
    if op == 36:
        return edge_boundary(s, w, word(s, at + 8), at + 64)
    if op == 37:
        if edge_boundary(s, w, word(s, at + 16), at + 64) == 0:
            return 0
        return edge_boundary(s, w, word(s, at + 24), at + 64)
    return 1

def returns(w:mutbuf, function:u64, count:u64) -> u64:
    if count > get(w, 64):
        return 0
    previous = get(w, 280 + function * 32)
    if previous != 18446744073709551615 and previous != count:
        return 0
    put(w, 280 + function * 32, count)
    return 1

def command(s:readbuf, w:mutbuf, at:u64, owner:u64) -> u64:
    op = word(s, at)
    if op <= 27:
        return scalar_admit(s, w, at, op)
    if op == 32:
        return choose(word(s, at + 8) < get(w, 56) and zero_tail(s, at, 3) == 1, 1, 0)
    if op == 33:
        callee = word(s, at + 8)
        count = word(s, at + 24)
        output_count = word(s, at + 40)
        if callee >= get(w, 72) or zero_tail(s, at, 6) == 0:
            return 0
        if register_list(s, w, word(s, at + 16), count) == 0 or register_list(s, w, word(s, at + 32), output_count) == 0:
            return 0
        previous = get(w, 256 + callee * 32)
        if previous != 18446744073709551615 and previous != count:
            return 0
        put(w, 256 + callee * 32, count)
        return returns(w, callee, output_count)
    if op == 34:
        if register_list(s, w, word(s, at + 8), word(s, at + 16)) == 0 or zero_tail(s, at, 3) == 0:
            return 0
        return returns(w, owner, word(s, at + 16))
    if op == 35:
        return choose(word(s, at + 8) <= 4 and zero_tail(s, at, 2) == 1, 1, 0)
    if op == 36:
        return choose(edge_admit(s, w, word(s, at + 8), owner) == 1 and zero_tail(s, at, 2) == 1, 1, 0)
    if op == 37:
        return choose(word(s, at + 8) < get(w, 56) and edge_admit(s, w, word(s, at + 16), owner) == 1 and edge_admit(s, w, word(s, at + 24), owner) == 1 and zero_tail(s, at, 4) == 1, 1, 0)
    if op == 38:
        return resource_admit(s, w, at)
    return 0

def resource_admit(s:readbuf, w:mutbuf, at:u64) -> u64:
    site = word(s, at + 8)
    if data(s, w, site, 32) == 0 or zero_tail(s, at, 6) == 0:
        return 0
    op = word(s, site)
    kind = word(s, site + 8)
    inputs = word(s, site + 16)
    outputs = word(s, site + 24)
    want_in = 0
    want_out = 0
    if op == 1 or op == 2:
        if kind != 0:
            return 0
        want_in = 1
        want_out = op
    elif op == 3:
        if kind != 1 and kind != 3 and kind != 4:
            return 0
        want_in = 1
        want_out = 1
    elif op == 4 or op == 24 or op == 25:
        if kind != 3 and kind != 4:
            return 0
        want_in = 2
        want_out = 1
    elif op == 5 or op == 26 or op == 27:
        if kind != 4:
            return 0
        want_in = 3
    elif op >= 6 and op <= 11:
        if kind != 4:
            return 0
        want_in = 2
        if op == 7 or op == 10:
            want_in = 4
        elif op == 8 or op == 11:
            want_in = 3
        elif op == 9:
            want_in = 5
    elif op == 12 or op == 13:
        if kind != 1 and kind != 4 and (op != 12 or kind != 3):
            return 0
        want_in = 1
        want_out = 1
    elif op == 14:
        if kind != 3 and kind != 4:
            return 0
        want_in = 1
    elif op == 15 or op == 16:
        if kind != 1 and kind != 2:
            return 0
        want_in = 1
        want_out = 16 - op
    elif op == 17:
        if kind != 0:
            return 0
        want_out = 1
    elif op >= 18 and op <= 22:
        if kind != 2:
            return 0
        want_in = choose(op == 19, 2, 1)
        want_out = choose(op == 19 or op == 20, 3, 1)
    else:
        return 0
    if inputs != want_in or outputs != want_out or word(s, at + 24) != inputs or word(s, at + 40) != outputs:
        return 0
    return choose(register_list(s, w, word(s, at + 16), inputs) == 1 and register_list(s, w, word(s, at + 32), outputs) == 1, 1, 0)

def generate(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    put(w, 0, 64)
    put(w, 16, 0)
    put(w, 24, 0)
    put(w, 104, 0)
    public_entry(o, w)
    put(w, 128, get(w, 0) - 64)
    at = get(w, 40)
    owner = 0
    while at < get(w, 48):
        if owner + 1 < get(w, 72) and at == get(w, 304 + owner * 32):
            owner = owner + 1
        if at == get(w, 272 + owner * 32):
            put(w, 264 + owner * 32, get(w, 0))
            function_entry(o, w, get(w, 256 + owner * 32))
        put(w, 8192 + ((at - get(w, 40)) >> 6) * 8, get(w, 0))
        instruction(s, o, w, at)
        at = at + 64
    put(w, 32, get(w, 0))
    external_call(o, w, 0)
    enc(o, w, 32, 0, 0, 0, 0, 0)
    put(w, 112, get(w, 0))
    return 0

def external_call(o:mutbuf, w:mutbuf, symbol:u64) -> u64:
    enc(o, w, 35, 0, 0, 0, 0, 0)
    index = get(w, 104)
    if index >= 16384 or symbol > 6:
        put(w, 16, 4)
    else:
        put(w, 700416 + index * 16, get(w, 0) - 64)
        put(w, 700424 + index * 16, symbol + 3)
        put(w, 104, index + 1)
    little(o, w, 0, 4)
    return 0

def value_load(o:mutbuf, w:mutbuf, reg:u64, slot:u64) -> u64:
    return load(o, w, reg, 5, 0 - 32 - slot * 16)

def high_load(o:mutbuf, w:mutbuf, reg:u64, slot:u64) -> u64:
    return load(o, w, reg, 5, 0 - 24 - slot * 16)

def value_save(o:mutbuf, w:mutbuf, reg:u64, slot:u64) -> u64:
    save(o, w, reg, 5, 0 - 32 - slot * 16)
    immediate(o, w, 11, 0)
    return high_save(o, w, 11, slot)

def high_save(o:mutbuf, w:mutbuf, reg:u64, slot:u64) -> u64:
    return save(o, w, reg, 5, 0 - 24 - slot * 16)

def pair_copy(o:mutbuf, w:mutbuf, source:u64, destination:u64) -> u64:
    value_load(o, w, 0, source)
    high_load(o, w, 2, source)
    value_save(o, w, 0, destination)
    high_save(o, w, 2, destination)
    return 0

def scalar_constant(o:mutbuf, w:mutbuf, slot:u64, value:u64) -> u64:
    immediate(o, w, 0, value)
    return value_save(o, w, 0, slot)

def public_entry(o:mutbuf, w:mutbuf) -> u64:
    prologue(o, w, 80)
    save(o, w, 7, 5, 0 - 64)
    save(o, w, 6, 5, 0 - 56)
    save(o, w, 2, 5, 0 - 48)
    save(o, w, 1, 5, 0 - 40)
    save(o, w, 8, 5, 0 - 32)
    save(o, w, 9, 5, 0 - 24)
    address(o, w, 7, 5, 0 - 64)
    address(o, w, 6, 5, 0 - 16)
    patch(o, w, 35, 0, 9223372036854775808)
    load(o, w, 0, 5, 0 - 16)
    normalize(o, w, 32)
    enc(o, w, 31, 0, 0, 0, 0, 0)
    enc(o, w, 30, 0, 0, 0, 0, 0)
    return 0

def function_entry(o:mutbuf, w:mutbuf, count:u64) -> u64:
    prologue(o, w, get(w, 80))
    save(o, w, 6, 5, 0 - 8)
    i = 0
    while i < count:
        load(o, w, 0, 7, i * 16)
        save(o, w, 0, 5, 0 - 32 - i * 16)
        load(o, w, 0, 7, i * 16 + 8)
        high_save(o, w, 0, i)
        i = i + 1
    return 0

def stage(s:readbuf, o:mutbuf, w:mutbuf, list:u64, count:u64) -> u64:
    i = 0
    while i < count:
        slot = word(s, list + i * 8)
        value_load(o, w, 0, slot)
        save(o, w, 0, 5, get(w, 96) + i * 16)
        high_load(o, w, 0, slot)
        save(o, w, 0, 5, get(w, 96) + i * 16 + 8)
        i = i + 1
    return 0

def restore(s:readbuf, o:mutbuf, w:mutbuf, list:u64, count:u64, edge:u64) -> u64:
    i = 0
    while i < count:
        slot = i
        if edge == 0:
            slot = word(s, list + i * 8)
        load(o, w, 0, 5, get(w, 96) + i * 16)
        value_save(o, w, 0, slot)
        load(o, w, 0, 5, get(w, 96) + i * 16 + 8)
        high_save(o, w, 0, slot)
        i = i + 1
    return 0

def edge(s:readbuf, o:mutbuf, w:mutbuf, record:u64) -> u64:
    count = word(s, record + 16)
    stage(s, o, w, word(s, record + 8), count)
    restore(s, o, w, 0, count, 1)
    patch(o, w, 33, 0, word(s, record))
    return 0

def instruction(s:readbuf, o:mutbuf, w:mutbuf, at:u64) -> u64:
    op = word(s, at)
    if op <= 27:
        scalar(s, o, w, at, op)
    elif op == 32:
        scalar_constant(o, w, word(s, at + 8), word(s, at + 16))
    elif op == 33:
        stage(s, o, w, word(s, at + 16), word(s, at + 24))
        address(o, w, 7, 5, get(w, 96))
        address(o, w, 6, 5, get(w, 96))
        patch(o, w, 35, 0, 9223372036854775808 | word(s, at + 8))
        restore(s, o, w, word(s, at + 32), word(s, at + 40), 0)
    elif op == 34:
        i = 0
        load(o, w, 6, 5, 0 - 8)
        while i < word(s, at + 16):
            slot = word(s, word(s, at + 8) + i * 8)
            value_load(o, w, 0, slot)
            save(o, w, 0, 6, i * 16)
            high_load(o, w, 0, slot)
            save(o, w, 0, 6, i * 16 + 8)
            i = i + 1
        enc(o, w, 31, 0, 0, 0, 0, 0)
        enc(o, w, 30, 0, 0, 0, 0, 0)
    elif op == 35:
        patch(o, w, 33, 0, 13835058055282163712)
    elif op == 36:
        edge(s, o, w, word(s, at + 8))
    elif op == 37:
        value_load(o, w, 0, word(s, at + 8))
        enc(o, w, 15, 0, 0, 0, 0, 0)
        other = patch(o, w, 34, 4, 0)
        edge(s, o, w, word(s, at + 16))
        absolute_target(w, other, get(w, 0))
        edge(s, o, w, word(s, at + 24))
    else:
        resource(s, o, w, at)
    return 0
"""

SOURCE+=r"""
def resource(s:readbuf, o:mutbuf, w:mutbuf, at:u64) -> u64:
    site = word(s, at + 8)
    code = word(s, site)
    kind = word(s, site + 8)
    args = word(s, at + 16)
    outputs = word(s, at + 32)
    if code == 1 or code == 2:
        allocate(o, w, word(s, args), word(s, outputs), choose(code == 2, word(s, outputs + 8), 0), code)
    elif code == 3:
        high_load(o, w, 0, word(s, args))
        value_save(o, w, 0, word(s, outputs))
    elif code == 4 or code == 5 or code >= 24:
        memory_resource(s, o, w, code, args, outputs)
    elif code >= 6 and code <= 10:
        bulk_resource(s, o, w, code, args)
    elif code == 11:
        swap_resource(s, o, w, args)
    elif code == 12 or code == 13 or code == 15:
        pair_copy(o, w, word(s, args), word(s, outputs))
    elif code == 16:
        if kind == 2:
            drop_chain(o, w, word(s, args))
        else:
            value_load(o, w, 7, word(s, args))
            enc(o, w, 15, 7, 7, 0, 0, 0)
            done = patch(o, w, 34, 4, 0)
            external_call(o, w, 3)
            absolute_target(w, done, get(w, 0))
    elif code == 17:
        scalar_constant(o, w, word(s, outputs), 0)
    elif code == 18:
        value_load(o, w, 0, word(s, args))
        enc(o, w, 15, 0, 0, 0, 0, 0)
        immediate(o, w, 0, 0)
        enc(o, w, 26, 0, 0, 0, 4, 0)
        value_save(o, w, 0, word(s, outputs))
    elif code == 19:
        push_chain(s, o, w, args, outputs)
    elif code == 20:
        pop_chain(s, o, w, word(s, args), outputs)
    elif code == 21 or code == 22:
        value_load(o, w, 2, word(s, args))
        enc(o, w, 15, 2, 2, 0, 0, 0)
        failure(o, w, 4)
        load(o, w, 0, 2, 0)
        value_save(o, w, 0, word(s, outputs))
        load(o, w, 0, 2, 8)
        high_save(o, w, 0, word(s, outputs))
    return 0

def allocate(o:mutbuf, w:mutbuf, size:u64, output:u64, ok:u64, operation:u64) -> u64:
    value_load(o, w, 6, size)
    enc(o, w, 15, 6, 6, 0, 0, 0)
    empty = patch(o, w, 34, 4, 0)
    immediate(o, w, 11, 9223372036854775807)
    enc(o, w, 14, 6, 11, 0, 0, 0)
    oversized = patch(o, w, 34, 7, 0)
    immediate(o, w, 7, 1)
    external_call(o, w, 1)
    enc(o, w, 15, 0, 0, 0, 0, 0)
    failed = patch(o, w, 34, 4, 0)
    value_save(o, w, 0, output)
    value_load(o, w, 0, size)
    high_save(o, w, 0, output)
    if operation == 2:
        scalar_constant(o, w, ok, 1)
    done = patch(o, w, 33, 0, 0)
    absolute_target(w, empty, get(w, 0))
    scalar_constant(o, w, output, 0)
    if operation == 2:
        scalar_constant(o, w, ok, 1)
    empty_done = patch(o, w, 33, 0, 0)
    absolute_target(w, oversized, get(w, 0))
    absolute_target(w, failed, get(w, 0))
    if operation == 1:
        patch(o, w, 33, 0, 13835058055282163712)
    else:
        scalar_constant(o, w, output, 0)
        scalar_constant(o, w, ok, 0)
    absolute_target(w, done, get(w, 0))
    absolute_target(w, empty_done, get(w, 0))
    return 0

def memory_resource(s:readbuf, o:mutbuf, w:mutbuf, operation:u64, args:u64, outputs:u64) -> u64:
    buffer = word(s, args)
    high_load(o, w, 2, buffer)
    value_load(o, w, 1, word(s, args + 8))
    enc(o, w, 14, 1, 2, 0, 0, 0)
    if operation == 4 or operation == 5:
        failure(o, w, 3)
    else:
        failure(o, w, 7)
        enc(o, w, 10, 2, 1, 0, 0, 0)
        immediate(o, w, 11, 8)
        enc(o, w, 14, 2, 11, 0, 0, 0)
        failure(o, w, 2)
    value_load(o, w, 0, buffer)
    enc(o, w, 9, 0, 1, 0, 0, 0)
    if operation == 4:
        enc(o, w, 7, 0, 0, 0, 0, 0)
        value_save(o, w, 0, word(s, outputs))
    elif operation == 24 or operation == 25:
        load(o, w, 0, 0, 0)
        if operation == 25:
            little(o, w, 13111112, 3)
        value_save(o, w, 0, word(s, outputs))
    else:
        value_load(o, w, 1, word(s, args + 16))
        if operation == 5:
            enc(o, w, 8, 1, 0, 0, 0, 0)
        else:
            if operation == 27:
                little(o, w, 13176648, 3)
            save(o, w, 1, 0, 0)
    return 0

def range_guard(o:mutbuf, w:mutbuf, buffer:u64, offset:u64, size:u64) -> u64:
    high_load(o, w, 0, buffer)
    value_load(o, w, 1, offset)
    enc(o, w, 14, 1, 0, 0, 0, 0)
    failure(o, w, 7)
    enc(o, w, 10, 0, 1, 0, 0, 0)
    value_load(o, w, 1, size)
    enc(o, w, 14, 1, 0, 0, 0, 0)
    failure(o, w, 7)
    return 0

def bulk_resource(s:readbuf, o:mutbuf, w:mutbuf, operation:u64, args:u64) -> u64:
    first = word(s, args)
    if operation == 6:
        high_load(o, w, 2, first)
    elif operation == 8:
        value_load(o, w, 2, word(s, args + 16))
        high_load(o, w, 0, first)
        enc(o, w, 14, 2, 0, 0, 0, 0)
        failure(o, w, 7)
        high_load(o, w, 0, word(s, args + 8))
        enc(o, w, 14, 2, 0, 0, 0, 0)
        failure(o, w, 7)
    elif operation == 7:
        range_guard(o, w, first, word(s, args + 8), word(s, args + 16))
        value_load(o, w, 2, word(s, args + 16))
    elif operation == 10:
        range_guard(o, w, first, word(s, args + 8), word(s, args + 24))
        range_guard(o, w, first, word(s, args + 16), word(s, args + 24))
        value_load(o, w, 2, word(s, args + 24))
    else:
        range_guard(o, w, first, word(s, args + 16), word(s, args + 32))
        range_guard(o, w, word(s, args + 8), word(s, args + 24), word(s, args + 32))
        value_load(o, w, 2, word(s, args + 32))
    enc(o, w, 15, 2, 2, 0, 0, 0)
    done = patch(o, w, 34, 4, 0)
    value_load(o, w, 7, first)
    if operation == 6 or operation == 7:
        if operation == 7:
            value_load(o, w, 0, word(s, args + 8))
            enc(o, w, 9, 7, 0, 0, 0, 0)
            value_load(o, w, 6, word(s, args + 24))
        else:
            value_load(o, w, 6, word(s, args + 8))
        external_call(o, w, 4)
    else:
        if operation == 10:
            value_load(o, w, 6, first)
        else:
            value_load(o, w, 6, word(s, args + 8))
        if operation == 9 or operation == 10:
            at = choose(operation == 10, 8, 16)
            value_load(o, w, 0, word(s, args + at))
            enc(o, w, 9, 7, 0, 0, 0, 0)
            value_load(o, w, 0, word(s, args + at + 8))
            enc(o, w, 9, 6, 0, 0, 0, 0)
        external_call(o, w, choose(operation == 10, 6, 5))
    absolute_target(w, done, get(w, 0))
    return 0

def swap_resource(s:readbuf, o:mutbuf, w:mutbuf, args:u64) -> u64:
    buffer = word(s, args)
    high_load(o, w, 2, buffer)
    value_load(o, w, 1, word(s, args + 8))
    enc(o, w, 14, 1, 2, 0, 0, 0)
    failure(o, w, 3)
    value_load(o, w, 8, word(s, args + 16))
    enc(o, w, 14, 8, 2, 0, 0, 0)
    failure(o, w, 3)
    value_load(o, w, 7, buffer)
    enc(o, w, 2, 6, 7, 0, 0, 0)
    enc(o, w, 9, 7, 1, 0, 0, 0)
    enc(o, w, 9, 6, 8, 0, 0, 0)
    enc(o, w, 7, 0, 7, 0, 0, 0)
    enc(o, w, 7, 1, 6, 0, 0, 0)
    enc(o, w, 8, 1, 7, 0, 0, 0)
    enc(o, w, 8, 0, 6, 0, 0, 0)
    return 0

def push_chain(s:readbuf, o:mutbuf, w:mutbuf, args:u64, outputs:u64) -> u64:
    chain = word(s, args)
    payload = word(s, args + 8)
    output_chain = word(s, outputs)
    output_buffer = word(s, outputs + 8)
    output_ok = word(s, outputs + 16)
    immediate(o, w, 7, 24)
    external_call(o, w, 2)
    enc(o, w, 15, 0, 0, 0, 0, 0)
    failed = patch(o, w, 34, 4, 0)
    value_save(o, w, 0, output_chain)
    enc(o, w, 2, 2, 0, 0, 0, 0)
    value_load(o, w, 0, payload)
    save(o, w, 0, 2, 0)
    high_load(o, w, 0, payload)
    save(o, w, 0, 2, 8)
    value_load(o, w, 0, chain)
    save(o, w, 0, 2, 16)
    scalar_constant(o, w, output_buffer, 0)
    scalar_constant(o, w, output_ok, 1)
    done = patch(o, w, 33, 0, 0)
    absolute_target(w, failed, get(w, 0))
    pair_copy(o, w, chain, output_chain)
    pair_copy(o, w, payload, output_buffer)
    scalar_constant(o, w, output_ok, 0)
    absolute_target(w, done, get(w, 0))
    return 0

def pop_chain(s:readbuf, o:mutbuf, w:mutbuf, chain:u64, outputs:u64) -> u64:
    output_chain = word(s, outputs)
    output_buffer = word(s, outputs + 8)
    output_ok = word(s, outputs + 16)
    value_load(o, w, 7, chain)
    enc(o, w, 15, 7, 7, 0, 0, 0)
    empty = patch(o, w, 34, 4, 0)
    load(o, w, 0, 7, 0)
    value_save(o, w, 0, output_buffer)
    load(o, w, 0, 7, 8)
    high_save(o, w, 0, output_buffer)
    load(o, w, 0, 7, 16)
    value_save(o, w, 0, output_chain)
    external_call(o, w, 3)
    scalar_constant(o, w, output_ok, 1)
    done = patch(o, w, 33, 0, 0)
    absolute_target(w, empty, get(w, 0))
    scalar_constant(o, w, output_chain, 0)
    scalar_constant(o, w, output_buffer, 0)
    scalar_constant(o, w, output_ok, 0)
    absolute_target(w, done, get(w, 0))
    return 0

def drop_chain(o:mutbuf, w:mutbuf, chain:u64) -> u64:
    temporary = get(w, 136)
    value_load(o, w, 0, chain)
    save(o, w, 0, 5, temporary)
    loop = get(w, 0)
    load(o, w, 2, 5, temporary)
    enc(o, w, 15, 2, 2, 0, 0, 0)
    done = patch(o, w, 34, 4, 0)
    load(o, w, 0, 2, 16)
    save(o, w, 0, 5, temporary + 8)
    load(o, w, 7, 2, 0)
    enc(o, w, 15, 7, 7, 0, 0, 0)
    node = patch(o, w, 34, 4, 0)
    external_call(o, w, 3)
    absolute_target(w, node, get(w, 0))
    load(o, w, 7, 5, temporary)
    external_call(o, w, 3)
    load(o, w, 0, 5, temporary + 8)
    save(o, w, 0, 5, temporary)
    patch(o, w, 33, 0, 4611686018427387904 | loop)
    absolute_target(w, done, get(w, 0))
    return 0
"""

SOURCE+=r"""
def object_layout(w:mutbuf) -> u64:
    rela = (get(w, 112) + 7) & 18446744073709551608
    sym = rela + get(w, 104) * 24
    strings = sym + 240
    names = strings + @STRING_SIZE@
    shoff = (names + @SECTION_SIZE@ + 7) & 18446744073709551608
    put(w, 144, rela)
    put(w, 152, sym)
    put(w, 160, strings)
    put(w, 168, names)
    put(w, 176, shoff)
    put(w, 120, shoff + 448)
    return 0

def write_field(o:mutbuf, at:u64, value:u64, count:u64) -> u64:
    i = 0
    while i < count:
        store(o, at + i, (value >> (i * 8)) & 255)
        i = i + 1
    return 0

def object_symbol(o:mutbuf, at:u64, name:u64, tag:u64, value:u64, size:u64) -> u64:
    write_field(o, at, name, 4)
    write_field(o, at + 4, tag, 4)
    put(o, at + 8, value)
    put(o, at + 16, size)
    return 0

def object_section(o:mutbuf, at:u64, name:u64, kind:u64, flags:u64, offset:u64, size:u64, link:u64, info:u64, alignment:u64, entry:u64) -> u64:
    write_field(o, at, name, 4)
    write_field(o, at + 4, kind, 4)
    put(o, at + 8, flags)
    put(o, at + 24, offset)
    put(o, at + 32, size)
    write_field(o, at + 40, link, 4)
    write_field(o, at + 44, info, 4)
    put(o, at + 48, alignment)
    put(o, at + 56, entry)
    return 0

def object_emit(o:mutbuf, w:mutbuf) -> u64:
    i = 0
    while i < 64:
        store(o, i, 0)
        i = i + 1
    i = get(w, 112)
    while i < get(w, 120):
        store(o, i, 0)
        i = i + 1
    put(o, 0, 282584257676671)
    put(o, 16, 4299030529)
    put(o, 40, get(w, 176))
    put(o, 48, 274877906944)
    put(o, 56, 1407404952518656)
    rela = get(w, 144)
    sym = get(w, 152)
    strings = get(w, 160)
    names = get(w, 168)
    sh = get(w, 176)
    object_symbol(o, sym + 24, 0, 65539, 0, 0)
    object_symbol(o, sym + 48, 1, 65554, 0, get(w, 128))
    object_strings(o, strings)
    object_names(o, names)
    object_imports(o, sym)
    i = 0
    while i < get(w, 104):
        put(o, rela + i * 24, get(w, 700416 + i * 16))
        put(o, rela + i * 24 + 8, (get(w, 700424 + i * 16) << 32) | 4)
        put(o, rela + i * 24 + 16, 18446744073709551612)
        i = i + 1
    object_section(o, sh + 64, @NAME_TEXT@, 1, 6, 64, get(w, 112) - 64, 0, 0, 16, 0)
    object_section(o, sh + 128, @NAME_RELA@, 4, 0, rela, get(w, 104) * 24, 3, 1, 8, 24)
    object_section(o, sh + 192, @NAME_SYM@, 2, 0, sym, 240, 4, 2, 8, 24)
    object_section(o, sh + 256, @NAME_STR@, 3, 0, strings, @STRING_SIZE@, 0, 0, 1, 0)
    object_section(o, sh + 320, @NAME_NAMES@, 3, 0, names, @SECTION_SIZE@, 0, 0, 1, 0)
    object_section(o, sh + 384, @NAME_STACK@, 1, 0, names + @SECTION_SIZE@, 0, 0, 0, 1, 0)
    return 0
"""

IMPORTS=('abort','calloc','malloc','free','memset','memcpy','memmove')
STRINGS=b'\0f0\0'+b''.join(x.encode()+b'\0' for x in IMPORTS)
SECTION_NAMES=(('.text','TEXT'),('.rela.text','RELA'),('.symtab','SYM'),('.strtab','STR'),('.shstrtab','NAMES'),('.note.GNU-stack','STACK'))
NAMES=b'\0'+b''.join(x.encode()+b'\0' for x,_ in SECTION_NAMES)
SOURCE=SOURCE.replace('@STRING_SIZE@',str(len(STRINGS))).replace('@SECTION_SIZE@',str(len(NAMES)))
for name,label in SECTION_NAMES:SOURCE=SOURCE.replace('@NAME_'+label+'@',str(NAMES.index(name.encode()+b'\0')))
def literal_function(name,raw):
 lines=[f'def {name}(o:mutbuf, at:u64) -> u64:']
 for i in range(0,len(raw),8):
  data=raw[i:i+8];lines.append(f'    write_field(o, at + {i}, {int.from_bytes(data,"little")}, {len(data)})')
 return '\n'.join(lines+['    return 0'])
SOURCE+='\n'+literal_function('object_strings',STRINGS)+'\n'+literal_function('object_names',NAMES)
SOURCE+='\ndef object_imports(o:mutbuf, sym:u64) -> u64:\n'
for i,name in enumerate(IMPORTS):SOURCE+=f'    object_symbol(o, sym + {(i+3)*24}, {STRINGS.index(name.encode()+bytes(1))}, 16, 0, 0)\n'
SOURCE+='    return 0\n'

def program():
 old=ast.parse(borrowed_program());new=ast.parse(SOURCE);replaced={n.name for n in new.body if isinstance(n,ast.FunctionDef)}
 kept=[]
 for node in old.body:
  if not isinstance(node,ast.FunctionDef):raise ValueError('seed source must contain only functions')
  if node.name=='seed_backend':continue
  if node.name=='header':node.name='borrowed_header';kept.append(node)
  elif node.name=='boundaries':node.name='borrowed_boundaries';kept.append(node)
  elif node.name not in replaced:kept.append(node)
 return '\n\n'.join(ast.unparse(n) for n in [*new.body,*kept])

def main():
 d=document(program(),'seed_owned_backend')
 raw=render_assembly(d).encode();(ROOT/'examples/hia_bootstrap/seed_owned_backend.hepta').write_bytes(raw)
 print('SEED_OWNED_BACKEND_SOURCE',len(raw),len(d['functions']),sum(len(f['blocks']) for f in d['functions']),sum(len(b['ops']) for f in d['functions'] for b in f['blocks']))
if __name__=='__main__':main()

"""Author a finite independent seed backend over the existing HIA reference wire.

The checked HIA output reuses the numeric machine_encoding byte owner. It does
not execute the selfhost compiler or use a successor compiler while producing
B0. This is a deliberately bounded unsigned, borrowed-buffer seed profile,
not the general Core native backend and not a substitute for qualification.
"""
from pathlib import Path
from tempfile import TemporaryDirectory
import ast
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_worker_config_json import document
from tools.generate_hia_machine_encoding import SOURCE as ENCODING_SOURCE
ROOT=Path(__file__).resolve().parents[1]
SOURCE='examples/hia_bootstrap/seed_backend.hepta'
PROGRAM=r'''
def seed_backend(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 80 or length(s) > 1048576 or length(o) != 1048576 or length(w) < 1048576:
        return 4294967293
    if header(s, w) == 0:
        return 4294967295
    if instructions(s, w) == 0:
        return 4294967295
    put(w, 8, 1)
    generate(s, o, w)
    size = get(w, 0)
    if get(w, 16) != 0 or size > length(o):
        return 4294967294
    put(w, 8, 0)
    generate(s, o, w)
    if get(w, 16) != 0 or size != get(w, 0):
        return 4294967295
    if resolve(o, w) == 0:
        return 4294967295
    return size

def header(s:readbuf, w:mutbuf) -> u64:
    if word(s, 0) != 3616488701627091272:
        return 0
    registers = word(s, 8)
    bounce = word(s, 16)
    end = word(s, 24)
    if registers < 3 or registers > 2048 or bounce == 0 or bounce > 64:
        return 0
    if end < 72 or end > length(s) - 8 or end + 8 != length(s) or end & 7 != 0:
        return 0
    if word(s, 32) != 1 or word(s, 40) != 1 or word(s, 48) != 0 or word(s, 56) != 0 or word(s, end) != 8:
        return 0
    start = word(s, 64)
    if start < 72 or start & 7 != 0 or start > end:
        return 0
    functions = (start - 64) >> 3
    if functions == 0 or functions > 128:
        return 0
    put(w, 40, start)
    put(w, 48, end)
    put(w, 56, registers)
    put(w, 64, bounce)
    put(w, 72, functions)
    put(w, 80, ((registers + bounce + 1) * 8 + 15) & 18446744073709551600)
    put(w, 88, end)
    put(w, 96, 0 - (registers + bounce + 1) * 8)
    index = 0
    previous = 0
    while index < functions:
        entry = word(s, 64 + index * 8)
        if entry < start or entry >= end or (entry - start) & 63 != 0 or (index != 0 and entry <= previous):
            return 0
        put(w, 256 + index * 32, 18446744073709551615)
        put(w, 272 + index * 32, entry)
        previous = entry
        index = index + 1
    put(w, 256, 3)
    return 1

def boundary(s:readbuf, w:mutbuf, pointer:u64, after:u64) -> u64:
    if pointer < after or pointer > get(w, 88) or pointer & 7 != 0:
        return 0
    if pointer < get(w, 48):
        put(w, 48, pointer)
    return 1

def boundaries(s:readbuf, w:mutbuf, at:u64, op:u64) -> u64:
    after = at + 64
    if op == 33 or op == 38:
        if boundary(s, w, word(s, at + 16), after) == 0 or boundary(s, w, word(s, at + 32), after) == 0:
            return 0
        if op == 38 and boundary(s, w, word(s, at + 8), after) == 0:
            return 0
    elif op == 34 or op == 36:
        if boundary(s, w, word(s, at + 8), after) == 0:
            return 0
    elif op == 37:
        if boundary(s, w, word(s, at + 16), after) == 0 or boundary(s, w, word(s, at + 24), after) == 0:
            return 0
    return 1

def instructions(s:readbuf, w:mutbuf) -> u64:
    at = get(w, 40)
    count = 0
    while at < get(w, 48):
        if get(w, 48) - at < 64 or count >= 16384:
            return 0
        op = word(s, at)
        if op == 0 or op > 38 or (op >= 28 and op <= 31):
            return 0
        if boundaries(s, w, at, op) == 0:
            return 0
        at = at + 64
        count = count + 1
    if at != get(w, 48) or count == 0:
        return 0
    index = 0
    while index < get(w, 72):
        if get(w, 272 + index * 32) >= at:
            return 0
        index = index + 1
    at = get(w, 40)
    owner = 0
    while at < get(w, 48):
        if owner + 1 < get(w, 72) and at == get(w, 304 + owner * 32):
            owner = owner + 1
        if command(s, w, at, owner) == 0:
            return 0
        at = at + 64
    index = 0
    while index < get(w, 72):
        if get(w, 256 + index * 32) == 18446744073709551615:
            return 0
        index = index + 1
    return 1

def data(s:readbuf, w:mutbuf, at:u64, size:u64) -> u64:
    return choose(at >= get(w, 48) and at <= get(w, 88) and size <= get(w, 88) - at and at & 7 == 0, 1, 0)

def register_list(s:readbuf, w:mutbuf, at:u64, count:u64) -> u64:
    if count > get(w, 64) or count > get(w, 56) or data(s, w, at, count * 8) == 0:
        return 0
    i = 0
    while i < count:
        if word(s, at + 8 * i) >= get(w, 56):
            return 0
        i = i + 1
    return 1

def edge_admit(s:readbuf, w:mutbuf, at:u64, owner:u64) -> u64:
    if data(s, w, at, 24) == 0:
        return 0
    target = word(s, at)
    stop = get(w, 48)
    if owner + 1 < get(w, 72):
        stop = get(w, 304 + owner * 32)
    if target < get(w, 272 + owner * 32) or target >= stop or (target - get(w, 40)) & 63 != 0:
        return 0
    return register_list(s, w, word(s, at + 8), word(s, at + 16))

def zero_tail(s:readbuf, at:u64, first:u64) -> u64:
    while first < 8:
        if word(s, at + first * 8) != 0:
            return 0
        first = first + 1
    return 1

def scalar_admit(s:readbuf, w:mutbuf, at:u64, op:u64) -> u64:
    if op == 4 or op == 5 or op == 6 or op == 7 or op == 8 or op == 11 or op == 26:
        return 0
    if word(s, at + 8) >= get(w, 56) or word(s, at + 16) >= get(w, 56) or word(s, at + 24) >= get(w, 56) or word(s, at + 32) >= get(w, 56) or word(s, at + 48) != 0:
        return 0
    width = word(s, at + 40)
    typ = word(s, at + 56)
    if width == 1:
        return choose(typ == 0, 1, 0)
    if width == 8:
        return choose(typ == 6, 1, 0)
    if width == 16:
        return choose(typ == 7, 1, 0)
    if width == 32:
        return choose(typ == 8, 1, 0)
    if width == 64:
        return choose(typ == 9 or typ == 11, 1, 0)
    return 0

def resource_admit(s:readbuf, w:mutbuf, at:u64) -> u64:
    site = word(s, at + 8)
    if data(s, w, site, 32) == 0 or zero_tail(s, at, 6) == 0:
        return 0
    op = word(s, site)
    kind = word(s, site + 8)
    inputs = word(s, site + 16)
    outputs = word(s, site + 24)
    if kind != 3 and kind != 4:
        return 0
    if op == 3:
        if inputs != 1 or outputs != 1:
            return 0
    elif op == 4 or op == 24:
        if inputs != 2 or outputs != 1:
            return 0
    elif op == 5:
        if inputs != 3 or outputs != 0 or kind != 4:
            return 0
    elif op == 7:
        if inputs != 4 or outputs != 0 or kind != 4:
            return 0
    else:
        return 0
    if word(s, at + 24) != inputs or word(s, at + 40) != outputs:
        return 0
    return choose(register_list(s, w, word(s, at + 16), inputs) == 1 and register_list(s, w, word(s, at + 32), outputs) == 1, 1, 0)

def command(s:readbuf, w:mutbuf, at:u64, owner:u64) -> u64:
    op = word(s, at)
    if op <= 27:
        return scalar_admit(s, w, at, op)
    if op == 32:
        return choose(word(s, at + 8) < get(w, 56) and zero_tail(s, at, 3) == 1, 1, 0)
    if op == 33:
        callee = word(s, at + 8)
        count = word(s, at + 24)
        if callee >= get(w, 72) or word(s, at + 40) != 1 or zero_tail(s, at, 6) == 0:
            return 0
        if register_list(s, w, word(s, at + 16), count) == 0 or register_list(s, w, word(s, at + 32), 1) == 0:
            return 0
        previous = get(w, 256 + callee * 32)
        if previous != 18446744073709551615 and previous != count:
            return 0
        put(w, 256 + callee * 32, count)
        return 1
    if op == 34:
        return choose(word(s, at + 16) == 1 and register_list(s, w, word(s, at + 8), 1) == 1 and zero_tail(s, at, 3) == 1, 1, 0)
    if op == 35:
        return choose(word(s, at + 8) <= 4 and zero_tail(s, at, 2) == 1, 1, 0)
    if op == 36:
        return choose(edge_admit(s, w, word(s, at + 8), owner) == 1 and zero_tail(s, at, 2) == 1, 1, 0)
    if op == 37:
        return choose(word(s, at + 8) < get(w, 56) and edge_admit(s, w, word(s, at + 16), owner) == 1 and edge_admit(s, w, word(s, at + 24), owner) == 1 and zero_tail(s, at, 4) == 1, 1, 0)
    if op == 38:
        return resource_admit(s, w, at)
    return 0
'''
PROGRAM+=r'''
def generate(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    put(w, 0, 0)
    put(w, 16, 0)
    put(w, 24, 0)
    public_entry(o, w)
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
    enc(o, w, 32, 0, 0, 0, 0, 0)
    return 0

def enc(o:mutbuf, w:mutbuf, command:u64, r:u64, m:u64, value:u64, auxiliary:u64, mode:u64) -> u64:
    if valid(command, r, m, value, auxiliary, mode, 0) == 0:
        put(w, 16, 2)
        return 0
    if command <= 15:
        encode_data(o, w, command, r, m, value, auxiliary, mode, 0)
    elif command <= 27:
        encode_arithmetic(o, w, command, r, m, value, auxiliary, mode, 0)
    else:
        encode_control(o, w, command, r, value, auxiliary)
    return 0

def immediate(o:mutbuf, w:mutbuf, reg:u64, value:u64) -> u64:
    return enc(o, w, 3, reg, 0, value, 0, 0)

def load(o:mutbuf, w:mutbuf, reg:u64, base:u64, disp:u64) -> u64:
    return enc(o, w, 4, reg, base, disp, 0, 0)

def save(o:mutbuf, w:mutbuf, reg:u64, base:u64, disp:u64) -> u64:
    return enc(o, w, 5, reg, base, disp, 0, 0)

def address(o:mutbuf, w:mutbuf, reg:u64, base:u64, disp:u64) -> u64:
    return enc(o, w, 6, reg, base, disp, 0, 0)

def value_load(o:mutbuf, w:mutbuf, reg:u64, slot:u64) -> u64:
    return load(o, w, reg, 5, 0 - 16 - slot * 8)

def value_save(o:mutbuf, w:mutbuf, reg:u64, slot:u64) -> u64:
    return save(o, w, reg, 5, 0 - 16 - slot * 8)

def patch(o:mutbuf, w:mutbuf, prefix:u64, condition:u64, target:u64) -> u64:
    enc(o, w, prefix, 0, 0, 0, condition, 0)
    index = get(w, 24)
    if index >= 32768:
        put(w, 16, 3)
        return 18446744073709551615
    put(w, 147456 + index * 16, get(w, 0))
    put(w, 147464 + index * 16, target)
    put(w, 24, index + 1)
    little(o, w, 0, 4)
    return index

def absolute_target(w:mutbuf, index:u64, target:u64) -> u64:
    if index < 32768:
        put(w, 147464 + index * 16, 4611686018427387904 | target)
    return 0

def failure(o:mutbuf, w:mutbuf, condition:u64) -> u64:
    patch(o, w, 34, condition, 13835058055282163712)
    return 0

def resolve(o:mutbuf, w:mutbuf) -> u64:
    index = 0
    while index < get(w, 24):
        position = get(w, 147456 + index * 16)
        tagged = get(w, 147464 + index * 16)
        kind = tagged >> 62
        target = tagged & 4611686018427387903
        if kind == 0:
            if target < get(w, 40) or target >= get(w, 48) or (target - get(w, 40)) & 63 != 0:
                return 0
            target = get(w, 8192 + ((target - get(w, 40)) >> 6) * 8)
        elif kind == 2:
            if target >= get(w, 72):
                return 0
            target = get(w, 264 + target * 32)
        elif kind == 3:
            target = get(w, 32)
        if position > get(w, 0) or get(w, 0) - position < 4 or target >= get(w, 0):
            return 0
        displacement = target - position - 4
        i = 0
        while i < 4:
            store(o, position + i, (displacement >> (i * 8)) & 255)
            i = i + 1
        index = index + 1
    return 1

def prologue(o:mutbuf, w:mutbuf, frame:u64) -> u64:
    enc(o, w, 28, 5, 0, 0, 0, 0)
    enc(o, w, 2, 5, 4, 0, 0, 0)
    while frame != 0:
        piece = choose(frame > 4096, 4096, frame)
        enc(o, w, 16, 4, 0, piece, 3, 0)
        load(o, w, 11, 4, 0)
        frame = frame - piece
    return 0

def public_entry(o:mutbuf, w:mutbuf) -> u64:
    prologue(o, w, 112)
    save(o, w, 7, 5, 0 - 80)
    save(o, w, 6, 5, 0 - 72)
    save(o, w, 2, 5, 0 - 64)
    save(o, w, 1, 5, 0 - 56)
    save(o, w, 8, 5, 0 - 48)
    save(o, w, 9, 5, 0 - 40)
    address(o, w, 0, 5, 0 - 80)
    save(o, w, 0, 5, 0 - 104)
    address(o, w, 0, 5, 0 - 64)
    save(o, w, 0, 5, 0 - 96)
    address(o, w, 0, 5, 0 - 48)
    save(o, w, 0, 5, 0 - 88)
    address(o, w, 7, 5, 0 - 104)
    address(o, w, 6, 5, 0 - 32)
    patch(o, w, 35, 0, 9223372036854775808)
    load(o, w, 0, 5, 0 - 32)
    normalize(o, w, 32)
    enc(o, w, 31, 0, 0, 0, 0, 0)
    enc(o, w, 30, 0, 0, 0, 0, 0)
    return 0

def function_entry(o:mutbuf, w:mutbuf, count:u64) -> u64:
    prologue(o, w, get(w, 80))
    save(o, w, 6, 5, 0 - 8)
    index = 0
    while index < count:
        load(o, w, 0, 7, index * 8)
        value_save(o, w, 0, index)
        index = index + 1
    return 0

def stage(s:readbuf, o:mutbuf, w:mutbuf, list:u64, count:u64) -> u64:
    index = 0
    while index < count:
        value_load(o, w, 0, word(s, list + index * 8))
        save(o, w, 0, 5, get(w, 96) + index * 8)
        index = index + 1
    return 0

def edge(s:readbuf, o:mutbuf, w:mutbuf, record:u64) -> u64:
    count = word(s, record + 16)
    stage(s, o, w, word(s, record + 8), count)
    index = 0
    while index < count:
        load(o, w, 0, 5, get(w, 96) + index * 8)
        value_save(o, w, 0, index)
        index = index + 1
    patch(o, w, 33, 0, word(s, record))
    return 0

def instruction(s:readbuf, o:mutbuf, w:mutbuf, at:u64) -> u64:
    op = word(s, at)
    if op <= 27:
        scalar(s, o, w, at, op)
    elif op == 32:
        immediate(o, w, 0, word(s, at + 16))
        value_save(o, w, 0, word(s, at + 8))
    elif op == 33:
        stage(s, o, w, word(s, at + 16), word(s, at + 24))
        address(o, w, 7, 5, get(w, 96))
        address(o, w, 6, 5, get(w, 96))
        patch(o, w, 35, 0, 9223372036854775808 | word(s, at + 8))
        load(o, w, 0, 5, get(w, 96))
        value_save(o, w, 0, word(s, word(s, at + 32)))
    elif op == 34:
        value_load(o, w, 0, word(s, word(s, at + 8)))
        load(o, w, 6, 5, 0 - 8)
        save(o, w, 0, 6, 0)
        enc(o, w, 31, 0, 0, 0, 0, 0)
        enc(o, w, 30, 0, 0, 0, 0, 0)
    elif op == 35:
        enc(o, w, 32, 0, 0, 0, 0, 0)
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

def normalize(o:mutbuf, w:mutbuf, width:u64) -> u64:
    if width < 64:
        enc(o, w, 17, 0, 0, 64 - width, 0, 0)
        enc(o, w, 17, 0, 0, 64 - width, 1, 0)
    return 0

def condition(op:u64) -> u64:
    if op == 16:
        return 4
    if op == 17:
        return 5
    if op == 18:
        return 2
    if op == 19:
        return 6
    if op == 20:
        return 7
    return 3

def scalar(s:readbuf, o:mutbuf, w:mutbuf, at:u64, op:u64) -> u64:
    value_load(o, w, 0, word(s, at + 16))
    value_load(o, w, 1, word(s, at + 24))
    width = word(s, at + 40)
    if op == 1:
        enc(o, w, 9, 0, 1, 0, 0, 0)
    elif op == 2:
        enc(o, w, 10, 0, 1, 0, 0, 0)
    elif op == 3:
        enc(o, w, 18, 0, 1, 0, 0, 0)
    elif op == 9 or op == 10:
        immediate(o, w, 11, width)
        enc(o, w, 14, 1, 11, 0, 0, 0)
        failure(o, w, 3)
        enc(o, w, 17, 0, 0, 0, choose(op == 9, 0, 1), 1)
    elif op == 12 or op == 13 or op == 14:
        enc(o, w, op - 1, 0, 1, 0, 0, 0)
    elif op == 15:
        enc(o, w, 24, 0, 0, 0, 0, 0)
    elif op >= 16 and op <= 21:
        enc(o, w, 14, 0, 1, 0, 0, 0)
        immediate(o, w, 0, 0)
        enc(o, w, 26, 0, 0, 0, condition(op), 0)
    elif op == 22 or op == 23:
        enc(o, w, choose(op == 22, 11, 12), 0, 1, 0, 0, 0)
    elif op == 24:
        enc(o, w, 15, 0, 0, 0, 0, 0)
        immediate(o, w, 0, 0)
        enc(o, w, 26, 0, 0, 0, 4, 0)
    elif op == 27:
        value_load(o, w, 2, word(s, at + 32))
        enc(o, w, 15, 0, 0, 0, 0, 0)
        enc(o, w, 2, 0, 2, 0, 0, 0)
        enc(o, w, 27, 0, 1, 0, 5, 0)
    normalize(o, w, width)
    value_save(o, w, 0, word(s, at + 8))
    return 0

def resource(s:readbuf, o:mutbuf, w:mutbuf, at:u64) -> u64:
    site = word(s, at + 8)
    code = word(s, site)
    inputs = word(s, at + 16)
    value_load(o, w, 0, word(s, inputs))
    if code == 3:
        load(o, w, 0, 0, 8)
        value_save(o, w, 0, word(s, word(s, at + 32)))
        return 0
    value_load(o, w, 1, word(s, inputs + 8))
    load(o, w, 2, 0, 8)
    enc(o, w, 14, 1, 2, 0, 0, 0)
    if code == 4 or code == 5:
        failure(o, w, 3)
    else:
        failure(o, w, 7)
        enc(o, w, 10, 2, 1, 0, 0, 0)
        if code == 24:
            immediate(o, w, 11, 8)
            enc(o, w, 14, 2, 11, 0, 0, 0)
            failure(o, w, 2)
        else:
            value_load(o, w, 8, word(s, inputs + 16))
            enc(o, w, 14, 8, 2, 0, 0, 0)
            failure(o, w, 7)
    load(o, w, 0, 0, 0)
    enc(o, w, 9, 0, 1, 0, 0, 0)
    if code == 4:
        enc(o, w, 7, 0, 0, 0, 0, 0)
    elif code == 24:
        load(o, w, 0, 0, 0)
    elif code == 5:
        value_load(o, w, 2, word(s, inputs + 16))
        enc(o, w, 8, 2, 0, 0, 0, 0)
        return 0
    else:
        enc(o, w, 2, 7, 0, 0, 0, 0)
        value_load(o, w, 0, word(s, inputs + 24))
        enc(o, w, 2, 1, 8, 0, 0, 0)
        enc(o, w, 15, 1, 1, 0, 0, 0)
        done = patch(o, w, 34, 4, 0)
        loop = get(w, 0)
        enc(o, w, 8, 0, 7, 0, 0, 0)
        enc(o, w, 16, 7, 0, 1, 0, 0)
        enc(o, w, 16, 1, 0, 1, 3, 0)
        patch(o, w, 34, 5, 4611686018427387904 | loop)
        absolute_target(w, done, get(w, 0))
        return 0
    value_save(o, w, 0, word(s, word(s, at + 32)))
    return 0
'''

EMIT=r'''
def emit(o:mutbuf, w:mutbuf, value:u64) -> u64:
    at = get(w, 0)
    if at >= length(o):
        put(w, 16, 1)
    elif get(w, 8) == 0:
        store(o, at, value)
    put(w, 0, at + 1)
    return 0
'''

def program():
    tree=ast.parse(ENCODING_SOURCE)
    helpers=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name not in ('machine_encoding','emit','out_word')]
    return PROGRAM.replace('3616488701627091272',str(int.from_bytes(b'HIAERW02','little')))+'\n'+EMIT+'\n'+'\n\n'.join(ast.unparse(n) for n in helpers)

def assembly_packer():
    from tools.generate_hia_native_filter import source_program, elf_header, bind_adapter
    from tools.build_hia_agent_batch_commit import assemble_adapter
    source=(ROOT/'tools/hia_core_edit_import_assembly.S').read_bytes()
    with TemporaryDirectory(prefix='hia-independent-assembly-adapter-') as directory:
        stub,symbols,identity=assemble_adapter(Path(directory),'tools/hia_core_edit_import_assembly.S',source)
    names=('syntax_call_hole','core_call_hole','canonical_call_hole','presentation_images_hole')
    holes=tuple(symbols[name] for name in names)
    if any(stub[h-1:h+4]!=bytes.fromhex('e800000000') for h in holes[:3]) or stub[holes[3]-3:holes[3]+4]!=bytes.fromhex('488d0500000000'):
        raise ValueError('existing assembly transport relocation identity differs')
    prefix=elf_header()+stub
    body=ast.parse(source_program(magic=int.from_bytes(b'HIASBA01','little'),image_template=(prefix,tuple(len(elf_header())+h for h in holes)),separate_sections=True,pack_limit=4*(1<<20)+4096)).body
    main=body[0];statements=[];pending=[];helpers=[]
    def flush():
        if not pending:return
        name='prefix_'+str(len(helpers));helpers.append(ast.FunctionDef(name=name,args=ast.arguments(posonlyargs=[],args=[ast.arg(arg='o',annotation=ast.Name(id='mutbuf',ctx=ast.Load()))],kwonlyargs=[],kw_defaults=[],defaults=[]),body=[*pending,ast.Return(value=ast.Constant(value=0))],decorator_list=[],returns=ast.Name(id='u64',ctx=ast.Load())))
        statements.append(ast.Expr(value=ast.Call(func=ast.Name(id=name,ctx=ast.Load()),args=[ast.Name(id='o',ctx=ast.Load())],keywords=[])));pending.clear()
    for node in main.body:
        literal=(isinstance(node,ast.Expr) and isinstance(node.value,ast.Call) and isinstance(node.value.func,ast.Name) and node.value.func.id=='write' and len(node.value.args)==4 and all(isinstance(v,ast.Constant) for v in node.value.args[1:]))
        if literal:
            pending.append(node)
            if len(pending)==32:flush()
        else:flush();statements.append(node)
    flush();main.body=statements
    text='\n\n'.join(ast.unparse(ast.fix_missing_locations(n)) for n in [*body,*helpers])
    generated=document(text,'seed_backend_assembly_packer')
    return bind_adapter(generated,source,stub,holes)

def main():
    d=document(program(),'seed_backend')
    raw=render_assembly(d).encode()
    (ROOT/SOURCE).write_bytes(raw)
    print('SEED_BACKEND_SOURCE',len(raw),len(d['functions']),sum(len(f['blocks']) for f in d['functions']),sum(len(b['ops']) for f in d['functions'] for b in f['blocks']))
    from tools.generate_hia_native_filter import document as filter_document
    generated={'seed_backend_filter_packer':filter_document(wire_bytes=1<<20,output_bytes=1<<20,workspace_bytes=1<<20,module='seed_backend_filter_packer'),'seed_backend_assembly_packer':assembly_packer()}
    for name, doc in generated.items():
        raw=render_assembly(doc).encode();(ROOT/'examples/hia_bootstrap'/ (name+'.hepta')).write_bytes(raw);print('SEED_PACKER_SOURCE',name,len(raw),len(doc['functions']),sum(len(f['blocks']) for f in doc['functions']),sum(len(b['ops']) for f in doc['functions'] for b in f['blocks']))

if __name__=='__main__':main()

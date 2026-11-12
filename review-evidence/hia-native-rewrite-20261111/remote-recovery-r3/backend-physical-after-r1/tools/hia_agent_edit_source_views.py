"""Author complete normalized type-service requests from issued metadata IR.

Only HIA chooses normalized command fields and order. The private native
coordinator supplies immutable IR/source leases and the continuation identity.
This development component does not dispatch semantic owners or normalize Core.
"""
from __future__ import annotations
import ast
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_core_json_frontend import packed
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions

CONSTANTS={
    'CONFIG':int.from_bytes(b'HIASVP01','little'),
    'EVENT':int.from_bytes(b'HIASVE01','little'),
    'IR_MAGIC':int.from_bytes(b'HIAOIS01','little'),
    'SOURCE_MAGIC':int.from_bytes(b'HIASIL01','little'),
    'CTOR_MAGIC':int.from_bytes(b'HIACTK01','little'),
    'FN_MAGIC':int.from_bytes(b'HIAFNC01','little'),
    'BAD':0xfffffffd,'MAX':(1<<64)-1,'REF':1<<63,
    'IR_BASE':131328,'STACK':512,
    'STATUS':256,'ERROR':264,'MODE':272,'CURSOR':280,'BASE':288,
    'LIMIT':296,'ROOT':304,'OP':312,'COUNT':320,'DEPTH':328,
    'EXPECTED':336,'SAVED_CONTEXT':344,'SAVED_KIND':352,'SAVED_LEASE':360,
    'SAVED_STREAM':368,'SAVED_REQUEST':376,'SAVED_IR_SIZE':384,
    'SAVED_SOURCE_SIZE':392,'SAVED_NODES':400,
}
LITERALS=('op','init','definitions','recursive_chain','partial_records',
          'parameters','params','resolve','ref','partial','base','initialized',
          'origins','returns','return_loans','task_protocol','task','functions')
SOURCE=r'''
def type_request(s:readbuf, r:readbuf, w:mutbuf) -> u32:
    if length(w) < STACK:
        return BAD
    if get(w, STATUS) >= 2:
        return refuse(w, 1)
    if admission(s, r, w) == 0:
        return refuse(w, 2)
    nodes = word(s, 136)
    if nodes > (MAX - STACK) >> 5:
        return refuse(w, 3)
    base = STACK + nodes * 32
    put(w, BASE, base)
    put(w, LIMIT, nodes)
    if base > length(w):
        return event(w, 1, base, 0)
    put(w, MODE, 0)
    put(w, CURSOR, 0)
    put(w, ERROR, 0)
    project(s, r, w)
    if get(w, ERROR) != 0:
        return refuse(w, get(w, ERROR))
    size = get(w, CURSOR)
    if size > MAX - base:
        return refuse(w, 4)
    if size > length(w) - base:
        return event(w, 1, base + size, size)
    put(w, EXPECTED, size)
    put(w, MODE, 1)
    put(w, CURSOR, 0)
    project(s, r, w)
    if get(w, ERROR) != 0 or get(w, CURSOR) != size:
        return refuse(w, 5)
    put(w, STATUS, 2)
    return event(w, 0, base + size, size)

def word(s:readbuf, at:u64) -> u64:
    result = 0
    i = 0
    while i < 8:
        result = result | (byte(s, at + i) << (i * 8))
        i = i + 1
    return result

def get(w:mutbuf, at:u64) -> u64:
    result = 0
    i = 0
    while i < 8:
        result = result | (byte(w, at + i) << (i * 8))
        i = i + 1
    return result

def put(w:mutbuf, at:u64, value:u64) -> u64:
    i = 0
    while i < 8:
        store(w, at + i, (value >> (i * 8)) & 255)
        i = i + 1
    return 0

def fail(w:mutbuf, error:u64) -> u64:
    if get(w, ERROR) == 0:
        put(w, ERROR, error)
    return 0

def refuse(w:mutbuf, error:u64) -> u32:
    put(w, STATUS, 3)
    put(w, ERROR, error)
    event(w, 2, 0, 0)
    return BAD

def event(w:mutbuf, action:u64, needed:u64, size:u64) -> u32:
    if action == 1:
        put(w, STATUS, 1)
    put(w, 0, EVENT)
    put(w, 8, action)
    put(w, 16, get(w, OP))
    put(w, 24, get(w, SAVED_KIND))
    put(w, 32, get(w, SAVED_REQUEST))
    put(w, 40, get(w, SAVED_LEASE))
    put(w, 48, get(w, SAVED_STREAM))
    put(w, 56, get(w, BASE))
    put(w, 64, size)
    put(w, 72, needed)
    put(w, 80, get(w, ERROR))
    put(w, 88, 0)
    put(w, 96, 0)
    put(w, 104, 0)
    put(w, 112, 0)
    put(w, 120, 0)
    return 128

def admission(s:readbuf, r:readbuf, w:mutbuf) -> u64:
    if length(s) < IR_BASE or length(r) < 80:
        return 0
    if word(s, 0) != IR_MAGIC or word(s, 8) != 2 or word(s, 184) != 0:
        return 0
    if word(s, 128) != 0 or word(s, 136) == 0:
        return 0
    if word(s, 144) < IR_BASE + 80 or word(s, 144) > length(s) or word(s, 144) >= REF:
        return 0
    if word(s, 120) < IR_BASE or word(s, 120) > word(s, 144) - 80:
        return 0
    if (word(s, 120) & 7) != 0:
        return 0
    if word(r, 0) != SOURCE_MAGIC or word(r, 24) != 64:
        return 0
    if word(r, 8) != word(s, 88) or word(r, 16) != word(s, 104):
        return 0
    if word(r, 32) != word(s, 96) or length(r) != word(s, 112):
        return 0
    if word(r, 40) != length(r) or word(r, 48) != 0 or word(r, 56) != 0:
        return 0
    if get(w, 128) != CONFIG or get(w, 136) == 0 or get(w, 136) > 2:
        return 0
    i = 176
    while i < 256:
        if get(w, i) != 0:
            return 0
        i = i + 8
    if get(w, 144) != word(s, 40) or get(w, 152) != word(s, 16):
        return 0
    if get(w, 160) != word(s, 24) or get(w, 168) != word(s, 48):
        return 0
    if get(w, 136) == 1:
        if word(s, 32) != CTOR_MAGIC or word(s, 56) != 0 or word(s, 64) != 0:
            return 0
    elif word(s, 32) != FN_MAGIC:
        return 0
    if get(w, STATUS) == 0:
        put(w, SAVED_CONTEXT, get(w, 136))
        put(w, SAVED_KIND, get(w, 144))
        put(w, SAVED_LEASE, get(w, 152))
        put(w, SAVED_STREAM, get(w, 160))
        put(w, SAVED_REQUEST, get(w, 168))
        put(w, SAVED_IR_SIZE, word(s, 144))
        put(w, SAVED_SOURCE_SIZE, length(r))
        put(w, SAVED_NODES, word(s, 136))
        put(w, ROOT, word(s, 120))
    else:
        if get(w, SAVED_CONTEXT) != get(w, 136) or get(w, SAVED_KIND) != get(w, 144):
            return 0
        if get(w, SAVED_LEASE) != get(w, 152) or get(w, SAVED_STREAM) != get(w, 160):
            return 0
        if get(w, SAVED_REQUEST) != get(w, 168) or get(w, ROOT) != word(s, 120):
            return 0
        if get(w, SAVED_IR_SIZE) != word(s, 144) or get(w, SAVED_SOURCE_SIZE) != length(r):
            return 0
        if get(w, SAVED_NODES) != word(s, 136):
            return 0
    return 1

def resolved(s:readbuf, view:u64) -> u64:
    if view >= REF:
        return view
    if word(s, view) == 0:
        return REF + word(s, view + 8)
    return view

def kind(s:readbuf, r:readbuf, view:u64) -> u64:
    view = resolved(s, view)
    if view >= REF:
        return word(r, 64 + view - REF)
    value = word(s, view)
    if value == 1:
        return 4
    if value == 3:
        return 1
    if value == 4:
        return 0
    return value

def count(s:readbuf, r:readbuf, view:u64) -> u64:
    view = resolved(s, view)
    if view >= REF:
        return word(r, 64 + view - REF + 16)
    return word(s, view + 16)

def child(s:readbuf, r:readbuf, view:u64, index:u64) -> u64:
    view = resolved(s, view)
    total = count(s, r, view)
    k = kind(s, r, view)
    if k == 6:
        if total >= REF:
            return 0
        total = total * 2
    elif k != 5:
        return 0
    if index >= total:
        return 0
    if view >= REF:
        at = 64 + view - REF + 24
        i = 0
        while i < index:
            at = at + 16 + word(r, at + 8)
            i = i + 1
        return REF + at - 64
    at = word(s, view + 24)
    i = 0
    while i < index and at != 0:
        at = word(s, at + 48)
        i = i + 1
    return at

def following(s:readbuf, r:readbuf, view:u64) -> u64:
    if view >= REF:
        return view + 16 + word(r, 64 + view - REF + 8)
    return word(s, view + 48)

def list_shape(s:readbuf, r:readbuf, view:u64, size:u64) -> u64:
    if view == 0:
        return 0
    if kind(s, r, view) != 5:
        return 0
    return choose(count(s, r, view) == size, 1, 0)

def text_size(s:readbuf, r:readbuf, view:u64) -> u64:
    view = resolved(s, view)
    if view >= REF:
        return word(r, 64 + view - REF + 8)
    return word(s, view + 16)

def text_byte(s:readbuf, r:readbuf, view:u64, at:u64) -> u64:
    view = resolved(s, view)
    if view >= REF:
        return byte(r, 64 + view - REF + 16 + at)
    return byte(s, word(s, view + 8) + at)

def text_equal(s:readbuf, r:readbuf, left:u64, right:u64) -> u64:
    if text_size(s, r, left) != text_size(s, r, right):
        return 0
    i = 0
    while i < text_size(s, r, left):
        a = text_byte(s, r, left, i)
        b = text_byte(s, r, right, i)
        if a != b:
            return 0
        i = i + 1
    return 1

def text_is(s:readbuf, r:readbuf, view:u64, size:u64, a:u64, b:u64, c:u64) -> u64:
    if kind(s, r, view) != 4 or text_size(s, r, view) != size:
        return 0
    i = 0
    while i < size:
        part = a
        if i >= 8:
            part = b
        if i >= 16:
            part = c
        if text_byte(s, r, view, i) != ((part >> ((i & 7) * 8)) & 255):
            return 0
        i = i + 1
    return 1

def field(s:readbuf, r:readbuf, view:u64, size:u64, a:u64, b:u64, c:u64) -> u64:
    if kind(s, r, view) != 6:
        return 0
    i = 0
    key = child(s, r, view, 0)
    while i < count(s, r, view):
        value = following(s, r, key)
        if text_is(s, r, key, size, a, b, c) != 0:
            return value
        key = following(s, r, value)
        i = i + 1
    return 0

def unsigned(s:readbuf, r:readbuf, view:u64) -> u64:
    if kind(s, r, view) != 2:
        return MAX
    view = resolved(s, view)
    if view < REF:
        return word(s, view + 8)
    at = 64 + view - REF + 16
    size = word(r, at - 8)
    value = 0
    i = 0
    while i < size:
        digit = byte(r, at + i)
        if digit < 48 or digit > 57:
            return MAX
        digit = digit - 48
        if value > 1844674407370955161 or (value == 1844674407370955161 and digit > 5):
            return MAX
        value = value * 10 + digit
        i = i + 1
    return value

def reserve(w:mutbuf, size:u64) -> u64:
    at = get(w, CURSOR)
    if size > MAX - at:
        fail(w, 6)
        return 0
    if get(w, MODE) == 1:
        base = get(w, BASE)
        if at > length(w) - base or size > length(w) - base - at:
            fail(w, 7)
            return 0
    put(w, CURSOR, at + size)
    return at

def header(w:mutbuf, k:u64, size:u64) -> u64:
    at = reserve(w, 16)
    if get(w, MODE) == 1 and get(w, ERROR) == 0:
        put(w, get(w, BASE) + at, k)
        put(w, get(w, BASE) + at + 8, size)
    return at

def literal(w:mutbuf, size:u64, a:u64, b:u64, c:u64) -> u64:
    header(w, 4, size)
    at = reserve(w, size)
    if get(w, MODE) == 0 or get(w, ERROR) != 0:
        return 0
    i = 0
    while i < size:
        part = a
        if i >= 8:
            part = b
        if i >= 16:
            part = c
        store(w, get(w, BASE) + at + i, (part >> ((i & 7) * 8)) & 255)
        i = i + 1
    return 0

def container(w:mutbuf, k:u64, size:u64) -> u64:
    at = header(w, k, 0)
    payload = reserve(w, 8)
    if get(w, MODE) == 1 and get(w, ERROR) == 0:
        put(w, get(w, BASE) + payload, size)
    return at

def finish(w:mutbuf, at:u64) -> u64:
    if get(w, MODE) == 1 and get(w, ERROR) == 0:
        put(w, get(w, BASE) + at + 8, get(w, CURSOR) - at - 16)
    return 0

def integer(w:mutbuf, value:u64) -> u64:
    digits = 1
    while digits < 20 and value >= power(digits):
        digits = digits + 1
    header(w, 2, digits)
    at = reserve(w, digits)
    if get(w, MODE) == 0 or get(w, ERROR) != 0:
        return 0
    i = 0
    while i < digits:
        divisor = power(digits - i - 1)
        digit = 0
        while value >= divisor:
            value = value - divisor
            digit = digit + 1
        store(w, get(w, BASE) + at + i, 48 + digit)
        i = i + 1
    return 0

def scalar(s:readbuf, w:mutbuf, node:u64) -> u64:
    k = word(s, node)
    if k == 1:
        size = word(s, node + 16)
        header(w, 4, size)
        at = reserve(w, size)
        if get(w, MODE) == 1 and get(w, ERROR) == 0:
            copy_bytes(w, s, get(w, BASE) + at, word(s, node + 8), size)
    elif k == 2:
        integer(w, word(s, node + 8))
    elif k == 3:
        header(w, 1, 1)
        at = reserve(w, 1)
        if get(w, MODE) == 1 and get(w, ERROR) == 0:
            store(w, get(w, BASE) + at, word(s, node + 8))
    elif k == 4:
        header(w, 0, 0)
    else:
        return fail(w, 8)
    return 0

def source_value(r:readbuf, w:mutbuf, view:u64) -> u64:
    at = 64 + view - REF
    size = 16 + word(r, at + 8)
    out = reserve(w, size)
    if get(w, MODE) == 1 and get(w, ERROR) == 0:
        copy_bytes(w, r, get(w, BASE) + out, at, size)
    return 0

def push(w:mutbuf, view:u64, depth:u64) -> u64:
    if depth >= get(w, LIMIT):
        return fail(w, 9)
    put(w, DEPTH, depth)
    at = STACK + depth * 32
    put(w, at, view)
    put(w, at + 8, 0)
    put(w, at + 16, 0)
    put(w, at + 24, 0)
    return 0

def emit_view(s:readbuf, r:readbuf, w:mutbuf, view:u64) -> u64:
    put(w, COUNT, 0)
    push(w, view, 0)
    going = True
    while going and get(w, ERROR) == 0:
        frame = STACK + get(w, DEPTH) * 32
        view = resolved(s, get(w, frame))
        pop = False
        if get(w, frame + 8) == 0:
            if get(w, COUNT) >= get(w, LIMIT):
                return fail(w, 10)
            put(w, COUNT, get(w, COUNT) + 1)
            if view >= REF:
                source_value(r, w, view)
                pop = True
            else:
                k = word(s, view)
                if k >= 5:
                    start = container(w, k, word(s, view + 16))
                    put(w, frame + 8, 1)
                    put(w, frame + 16, word(s, view + 24))
                    put(w, frame + 24, start)
                else:
                    scalar(s, w, view)
                    pop = True
        else:
            next_ = get(w, frame + 16)
            if next_ == 0:
                finish(w, get(w, frame + 24))
                pop = True
            else:
                put(w, frame + 16, word(s, next_ + 48))
                push(w, next_, get(w, DEPTH) + 1)
        if pop:
            if get(w, DEPTH) == 0:
                going = False
            else:
                put(w, DEPTH, get(w, DEPTH) - 1)
    return 0

def parameter_pairs(s:readbuf, r:readbuf, w:mutbuf, view:u64) -> u64:
    if kind(s, r, view) != 5:
        return fail(w, 11)
    i = 0
    row = child(s, r, view, 0)
    while i < count(s, r, view):
        if list_shape(s, r, row, 2) == 0:
            return fail(w, 12)
        if kind(s, r, child(s, r, row, 0)) != 4 or kind(s, r, child(s, r, row, 1)) != 2:
            return fail(w, 13)
        row = following(s, r, row)
        i = i + 1
    return 1

def identifiers(s:readbuf, r:readbuf, w:mutbuf, view:u64) -> u64:
    if kind(s, r, view) != 5:
        return fail(w, 14)
    i = 0
    item = child(s, r, view, 0)
    while i < count(s, r, view):
        if kind(s, r, item) != 2:
            return fail(w, 15)
        item = following(s, r, item)
        i = i + 1
    return 1

def registry_row(s:readbuf, r:readbuf, w:mutbuf, registry:u64, row:u64) -> u64:
    width = choose(get(w, SAVED_CONTEXT) == 1, 4, 3)
    if list_shape(s, r, row, width) == 0:
        return fail(w, 16)
    name = child(s, r, row, 0)
    if kind(s, r, name) != 4:
        return fail(w, 17)
    previous_row = child(s, r, registry, 0)
    while previous_row != row:
        previous = child(s, r, previous_row, 0)
        if text_equal(s, r, name, previous) != 0:
            return fail(w, 18)
        previous_row = following(s, r, previous_row)
    if width == 4 and kind(s, r, child(s, r, row, 3)) != 6:
        return fail(w, 19)
    if parameter_pairs(s, r, w, child(s, r, row, 1)) == 0:
        return 0
    if identifiers(s, r, w, child(s, r, row, 2)) == 0:
        return 0
    return 1

def task_registry(s:readbuf, r:readbuf, w:mutbuf, registry:u64) -> u64:
    if kind(s, r, registry) != 5:
        return fail(w, 20)
    i = 0
    row = child(s, r, registry, 0)
    while i < count(s, r, registry):
        if registry_row(s, r, w, registry, row) == 0:
            return 0
        row = following(s, r, row)
        i = i + 1
    outer = container(w, 5, count(s, r, registry))
    i = 0
    row = child(s, r, registry, 0)
    while i < count(s, r, registry):
        item = container(w, 5, 3)
        emit_view(s, r, w, child(s, r, row, 0))
        emit_parameter_ids(s, r, w, child(s, r, row, 1))
        emit_view(s, r, w, child(s, r, row, 2))
        finish(w, item)
        row = following(s, r, row)
        i = i + 1
    finish(w, outer)
    return 1

def emit_parameter_ids(s:readbuf, r:readbuf, w:mutbuf, params:u64) -> u64:
    start = container(w, 5, count(s, r, params))
    i = 0
    row = child(s, r, params, 0)
    while i < count(s, r, params):
        emit_view(s, r, w, child(s, r, row, 1))
        row = following(s, r, row)
        i = i + 1
    finish(w, start)
    return 0

def initializer(s:readbuf, r:readbuf, w:mutbuf, command:u64) -> u64:
    if list_shape(s, r, command, 4) == 0:
        return fail(w, 21)
    if kind(s, r, child(s, r, command, 2)) != 1 or kind(s, r, child(s, r, command, 3)) != 1:
        return fail(w, 22)
    root = container(w, 6, 4)
    literal(w, L_op)
    literal(w, L_init)
    literal(w, L_definitions)
    emit_view(s, r, w, child(s, r, command, 1))
    literal(w, L_recursive_chain)
    emit_view(s, r, w, child(s, r, command, 2))
    literal(w, L_partial_records)
    emit_view(s, r, w, child(s, r, command, 3))
    finish(w, root)
    return 1

def unary(s:readbuf, r:readbuf, w:mutbuf, command:u64, operation:u64) -> u64:
    if list_shape(s, r, command, 2) == 0:
        return fail(w, 23)
    root = container(w, 6, 2)
    literal(w, L_op)
    if operation == 2:
        literal(w, L_parameters)
        literal(w, L_params)
    else:
        literal(w, L_resolve)
        literal(w, L_ref)
    emit_view(s, r, w, child(s, r, command, 1))
    finish(w, root)
    return 1

def partial(s:readbuf, r:readbuf, w:mutbuf, command:u64) -> u64:
    if list_shape(s, r, command, 3) == 0:
        return fail(w, 24)
    if kind(s, r, child(s, r, command, 1)) != 2 or kind(s, r, child(s, r, command, 2)) != 5:
        return fail(w, 25)
    root = container(w, 6, 3)
    literal(w, L_op)
    literal(w, L_partial)
    literal(w, L_base)
    emit_view(s, r, w, child(s, r, command, 1))
    literal(w, L_initialized)
    emit_view(s, r, w, child(s, r, command, 2))
    finish(w, root)
    return 1

def origins(s:readbuf, r:readbuf, w:mutbuf, command:u64) -> u64:
    if list_shape(s, r, command, 4) == 0:
        return fail(w, 26)
    function = child(s, r, command, 1)
    if kind(s, r, function) != 6:
        return fail(w, 27)
    if parameter_pairs(s, r, w, child(s, r, command, 2)) == 0:
        return 0
    if identifiers(s, r, w, child(s, r, command, 3)) == 0:
        return 0
    annotation = field(s, r, function, L_return_loans)
    root = container(w, 6, choose(annotation == 0, 3, 4))
    literal(w, L_op)
    literal(w, L_origins)
    literal(w, L_params)
    emit_view(s, r, w, child(s, r, command, 2))
    literal(w, L_returns)
    emit_view(s, r, w, child(s, r, command, 3))
    if annotation != 0:
        literal(w, L_return_loans)
        emit_view(s, r, w, annotation)
    finish(w, root)
    return 1

def task(s:readbuf, r:readbuf, w:mutbuf, command:u64) -> u64:
    width = choose(get(w, SAVED_CONTEXT) == 1, 3, 2)
    if list_shape(s, r, command, width) == 0:
        return fail(w, 28)
    if kind(s, r, child(s, r, command, 1)) != 2:
        return fail(w, 29)
    registry = 0
    if width == 3:
        registry = child(s, r, command, 2)
    else:
        if list_shape(s, r, REF, 7) == 0:
            return fail(w, 30)
        registry = child(s, r, REF, 1)
    root = container(w, 6, 3)
    literal(w, L_op)
    literal(w, L_task_protocol)
    literal(w, L_task)
    emit_view(s, r, w, child(s, r, command, 1))
    literal(w, L_functions)
    if task_registry(s, r, w, registry) == 0:
        return 0
    finish(w, root)
    return 1

def project(s:readbuf, r:readbuf, w:mutbuf) -> u64:
    command = get(w, ROOT)
    context = get(w, SAVED_CONTEXT)
    operation = get(w, SAVED_KIND)
    if kind(s, r, command) != 5 or count(s, r, command) == 0:
        return fail(w, 31)
    if unsigned(s, r, child(s, r, command, 0)) != operation:
        return fail(w, 32)
    if context == 1:
        if list_shape(s, r, REF, 2) == 0 or operation == 0 or operation > 5:
            return fail(w, 33)
    elif operation < 2 or operation > 5:
        return fail(w, 34)
    canonical = operation
    if operation == 4 and context == 1:
        canonical = 5
    if operation == 5:
        canonical = 6
    put(w, OP, canonical)
    if canonical == 1:
        return initializer(s, r, w, command)
    if canonical == 2 or canonical == 3:
        return unary(s, r, w, command, canonical)
    if canonical == 4:
        return partial(s, r, w, command)
    if canonical == 5:
        return origins(s, r, w, command)
    return task(s, r, w, command)
'''

class CopyBuilder(Builder):
    def expr(self, expression):
        if isinstance(expression, ast.Call) and isinstance(expression.func, ast.Name) and expression.func.id=='copy_bytes':
            values=[self.expr(v) for v in expression.args]
            assert len(values)==5 and values[0][1]=='mutbuf' and values[1][1]=='readbuf'
            return self.op('buffer.copy_range',values[:2]+[self.cast(v,'usize') for v in values[2:]])
        return super().expr(expression)

def source_program():
    powers=['def power(index:u64) -> u64:']
    for i in range(20):
        powers.extend(['    if index == '+str(i)+':','        return '+str(10**i)])
    powers.append('    return 1')
    literals={'L_'+name:packed(name) for name in LITERALS}
    class Expand(ast.NodeTransformer):
        def visit_Name(self,node):
            return ast.copy_location(ast.Constant(CONSTANTS[node.id]),node) if node.id in CONSTANTS else node
        def visit_Call(self,node):
            node=self.generic_visit(node);args=[]
            for arg in node.args:
                if isinstance(arg,ast.Name) and arg.id in literals:
                    args.extend(ast.Constant(v) for v in literals[arg.id])
                else:args.append(arg)
            node.args=args
            return node
    tree=ast.fix_missing_locations(Expand().visit(ast.parse(SOURCE+'\n'+'\n'.join(powers))))
    return ast.unparse(tree)+'\n'

def document():
    nodes=ast.parse(source_program()).body
    names={node.name:'f'+str(i+1) for i,node in enumerate(nodes)}
    signatures={node.name:([a.annotation.id for a in node.args.args],node.returns.id) for node in nodes}
    total=total_scalar_functions(nodes)
    params=[{'name':'v0','type':'readbuf'},{'name':'v1','type':'mutbuf'},{'name':'v2','type':'mutbuf'}]
    functions=[{'name':'f0','params':params,'returns':['u32'],'effects':['read','write','trap'],'entry':'b0',
        'blocks':[{'id':'b0','params':params,'ops':[
            {'op':'borrow.read','args':['v1'],'out':[{'name':'v3','type':'readbuf'}],'attrs':{}},
            {'op':'call','args':['v0','v3','v2'],'out':[{'name':'v4','type':'u32'}],'attrs':{'function':names['type_request']}},
            {'op':'loan.end','args':['v3'],'out':[],'attrs':{}}],'term':{'op':'ret','values':['v4']}}]}]
    for node in nodes:
        builder=CopyBuilder(node,names,signatures,total);builder.statements(node.body)
        functions.append({'name':names[node.name],'params':[builder.param(v) for v in builder.params],
            'returns':[builder.returns],'effects':['read','write','trap'],'entry':'b0','blocks':builder.blocks})
    return compact_authoring_cfg({'schema':'hepta.hia.program.v8','module':'composite_type_requests','functions':functions})

if __name__=='__main__':
    target=Path(__file__).resolve().parents[1]/'examples/hia_bootstrap/composite_type_requests.hiaasm'
    target.write_text(render_assembly(document()))
    print(target.name,target.stat().st_size)

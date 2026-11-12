"""Native transient object/result ownership below all namespace row operations.

The generated program owns handles, vectors, projection, result snapshots and
retirement. It has no SQLite or host semantic callback. Physical views, indices,
logging and migration are deliberately separate unfinished owners.
"""
from __future__ import annotations

import ast
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_agent_namespace_store import VALUES
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions

ROOT = Path(__file__).resolve().parents[1]
MAGIC = int.from_bytes(b'HIANOB01', 'little')
BAD = 0xfffffffd

OBJECTS = r'''
def namespace_objects(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) < 512:
        return 4294967293
    if get(w, 8) == 3 or get(w, 8) == 4:
        return emit(o, w, 4294967293)
    if length(o) < 192:
        return poison(w, 1)
    if get(w, 0) == 0:
        at = 0
        while at < 512:
            if byte(w, at) != 0:
                poison(w, 2)
                return emit(o, w, 4294967293)
            at = at + 1
        put(w, 0, OBJECT_MAGIC)
        put(w, 8, 1)
        put(w, 40, 1)
        put(w, 48, 512)
    if valid_state(w) == 0 or arena_valid(w) == 0:
        poison(w, 2)
        return emit(o, w, 4294967293)
    if frame(s, w) == 0:
        poison(w, 3)
        return emit(o, w, 4294967293)
    copy_input(w, s, 128, 0, 128)
    fill_range(w, 256, 256, 0)
    status = dispatch(s, o, w)
    if status == 4294967293:
        if get(w, 8) != 3:
            poison(w, 4)
    elif status != 1:
        put(w, 32, read64(s, 32))
        if get(w, 56) != 0:
            put(w, 64, read64(s, 48))
        if get(w, 8) != 4:
            put(w, 8, 1)
    return emit(o, w, status)

def poison(w:mutbuf, reason:u64) -> u64:
    put(w, 8, 3)
    put(w, 120, reason)
    return 4294967293

def valid_state(w:mutbuf) -> u64:
    if get(w, 0) != OBJECT_MAGIC or (get(w, 8) != 1 and get(w, 8) != 2):
        return 0
    if get(w, 40) == 0 or get(w, 48) < 512 or get(w, 48) > length(w) or (get(w, 48) & 7) != 0:
        return 0
    if get(w, 56) != 0 and get(w, 56) != get(w, 72):
        return 0
    if get(w, 56) == 0 and get(w, 64) != 0:
        return 0
    if get(w, 88) != 0 or get(w, 96) != 0 or get(w, 104) != 0 or get(w, 112) != 0 or get(w, 120) != 0:
        return 0
    if get(w, 32) != 0 and get(w, 16) == 0 and get(w, 24) == 0:
        return 0
    return 1

def frame(s:readbuf, w:mutbuf) -> u64:
    if length(s) < 128 or read64(s, 0) != OBJECT_MAGIC:
        return 0
    command = read64(s, 8)
    if command < 1 or command > 18 or read64(s, 112) != length(s) - 128 or read64(s, 120) != 0:
        return 0
    if read64(s, 16) == 0 and read64(s, 24) == 0:
        return 0
    if get(w, 32) == 18446744073709551615 or read64(s, 32) != get(w, 32) + 1:
        return 0
    if get(w, 32) != 0 or get(w, 8) == 2:
        if read64(s, 16) != get(w, 16) or read64(s, 24) != get(w, 24):
            return 0
    else:
        put(w, 16, read64(s, 16))
        put(w, 24, read64(s, 24))
    if command == 2:
        if read64(s, 56) == 0:
            return 0
    elif read64(s, 56) != 0 or read64(s, 112) != 0:
        return 0
    if command == 1:
        if get(w, 56) != 0 or read64(s, 40) <= get(w, 72) or read64(s, 48) != 0:
            return 0
    else:
        if read64(s, 40) != get(w, 56):
            return 0
        if get(w, 56) == 0:
            if read64(s, 48) != 0:
                return 0
        elif read64(s, 48) < get(w, 64):
            return 0
    if get(w, 8) == 2:
        at = 0
        while at < 128:
            if read64(s, at) != get(w, 128 + at):
                return 0
            at = at + 8
    return 1

def zero_args(s:readbuf, start:u64) -> u64:
    at = start
    while at < 112:
        if read64(s, at) != 0:
            return 0
        at = at + 8
    return 1

def aligned(n:u64) -> u64:
    return (n + 7) & 18446744073709551608

def node_shape(w:mutbuf, at:u64) -> u64:
    span = get(w, at)
    kind = get(w, at + 8)
    flags = get(w, at + 32)
    if kind < 1 or kind > 7 or flags > 3 or flags == 1:
        return 0
    if (flags & 1) != 0 and kind != 4 and kind != 5 and kind != 7:
        return 0
    if kind == 1:
        cls = get(w, at + 40)
        size = get(w, at + 48)
        if cls > 4 or size > 18446744073709551544 or span != 64 + aligned(size) or get(w, at + 56) != 0:
            return 0
        if cls == 0 and size != 0:
            return 0
        if (cls == 1 or cls == 2) and size != 8:
            return 0
    elif kind == 2:
        width = get(w, at + 40)
        if width > 2305843009213693943 or span != 64 + width * 8 or get(w, at + 48) != 0 or get(w, at + 56) != 0:
            return 0
    elif kind == 3:
        if span != 96 or get(w, at + 80) != 0 or get(w, at + 88) != 0:
            return 0
        count = get(w, at + 72)
        if count == 0:
            if get(w, at + 56) != 0 or get(w, at + 64) != 0:
                return 0
        elif get(w, at + 56) == 0 or get(w, at + 64) == 0:
            return 0
    elif kind == 4:
        if span != 72:
            return 0
        if (get(w, at + 48) == 0) != (get(w, at + 40) == 0):
            return 0
    elif kind == 5:
        if span != 72:
            return 0
    elif kind == 6:
        if span != 64 or get(w, at + 40) == 0 or get(w, at + 56) != 0:
            return 0
        if get(w, at + 48) != 0 and get(w, at + 48) <= get(w, at + 16):
            return 0
    else:
        if span != 64 or get(w, at + 40) == 0:
            return 0
        if (get(w, at + 56) == 0) != (get(w, at + 48) == 0):
            return 0
    return 1

def arena_valid(w:mutbuf) -> u64:
    at = 512
    previous = 0
    while at < get(w, 48):
        if get(w, 48) - at < 64:
            return 0
        span = get(w, at)
        identity = get(w, at + 16)
        if span < 64 or (span & 7) != 0 or span > get(w, 48) - at:
            return 0
        if identity <= previous or identity >= get(w, 40) or get(w, at + 24) > get(w, 72):
            return 0
        if node_shape(w, at) == 0:
            return 0
        previous = identity
        at = at + span
    return choose(at == get(w, 48), 1, 0)

def find(w:mutbuf, identity:u64, kind:u64) -> u64:
    if identity == 0:
        return 0
    at = 512
    while at < get(w, 48):
        if get(w, at + 16) == identity:
            if (get(w, at + 32) & 2) == 0 or (kind != 0 and get(w, at + 8) != kind):
                return 0
            return at
        at = at + get(w, at)
    return 0

def vector_cell(w:mutbuf, identity:u64, column:u64) -> u64:
    vector = find(w, identity, 2)
    if vector == 0 or column >= get(w, vector + 40):
        return 0
    return find(w, get(w, vector + 64 + column * 8), 1)

def compact(w:mutbuf) -> u64:
    source = 512
    target = 512
    count = 0
    end = get(w, 48)
    while source < end:
        span = get(w, source)
        if (get(w, source + 32) & 2) != 0:
            if target != source:
                move_workspace(w, target, source, span)
            target = target + span
            count = count + 1
        source = source + span
    fill_range(w, target, end - target, 0)
    put(w, 48, target)
    return count

def reserve(w:mutbuf, bytes:u64, nodes:u64) -> u64:
    if nodes > 18446744073709551615 - get(w, 40):
        return poison(w, 5)
    if bytes > 18446744073709551615 - get(w, 48):
        return poison(w, 5)
    if get(w, 48) + bytes > length(w):
        compact(w)
    if bytes > 18446744073709551615 - get(w, 48):
        return poison(w, 5)
    if get(w, 48) + bytes > length(w):
        put(w, 8, 2)
        put(w, 288, get(w, 48) + bytes)
        put(w, 296, 192)
        return 1
    return 0

def new_node(w:mutbuf, kind:u64, span:u64) -> u64:
    at = get(w, 48)
    fill_range(w, at, span, 0)
    put(w, at, span)
    put(w, at + 8, kind)
    put(w, at + 16, get(w, 40))
    put(w, at + 24, get(w, 56))
    put(w, at + 32, 2)
    put(w, 40, get(w, 40) + 1)
    put(w, 48, at + span)
    return at

def results(w:mutbuf, a:u64, b:u64, c:u64, d:u64) -> u64:
    put(w, 256, a)
    put(w, 264, b)
    put(w, 272, c)
    put(w, 280, d)
    return 0

def dispatch(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    command = read64(s, 8)
    if command >= 2 and command <= 11 and command != 5 and get(w, 56) == 0:
        return poison(w, 6)
    if command == 1:
        return begin_scope(s, w)
    if command == 2:
        return import_vector(s, w)
    if command == 3:
        return null_vector(s, w)
    if command == 4:
        return constant(s, w)
    if command == 5:
        return field(s, w)
    if command == 6:
        return replace(s, w)
    if command == 7:
        return builder(s, w)
    if command == 8:
        return append(s, w)
    if command == 9:
        return finish(s, w)
    if command == 10:
        return error_result(s, w)
    if command == 11:
        return clean_scope(s, w)
    if command == 12:
        return describe(s, o, w)
    if command == 13:
        return cell_read(s, o, w)
    if command == 14:
        return cursor(s, w)
    if command == 15:
        return next_result(s, w)
    if command == 16:
        return drop(s, w)
    if command == 17:
        return close(s, w)
    if zero_args(s, 64) == 0:
        return poison(w, 7)
    if collect(w) == 4294967293:
        return 4294967293
    return results(w, compact(w), 0, 0, 0)

def begin_scope(s:readbuf, w:mutbuf) -> u64:
    if zero_args(s, 72) == 0 or read64(s, 64) <= get(w, 80):
        return poison(w, 7)
    put(w, 56, read64(s, 40))
    put(w, 64, 0)
    put(w, 72, read64(s, 40))
    put(w, 80, read64(s, 64))
    return results(w, get(w, 56), 0, 0, 0)

def effective_kind(s:readbuf, at:u64) -> u64:
    kind = read64(s, at)
    if kind == 2:
        bits = read64(s, at + 16)
        if ((bits >> 52) & 2047) == 2047 and (bits & 4503599627370495) != 0:
            return 0
    return kind

def import_plan(s:readbuf, w:mutbuf) -> u64:
    if zero_args(s, 64) == 0 or length(s) < 136:
        return poison(w, 7)
    count = read64(s, 128)
    if count > (length(s) - 136) >> 4 or count > 2305843009213693943:
        return poison(w, 8)
    needed = 64 + count * 8
    at = 136
    index = 0
    while index < count:
        if length(s) - at < 16:
            return poison(w, 8)
        kind = read64(s, at)
        size = read64(s, at + 8)
        if kind > 4 or size > length(s) - at - 16:
            return poison(w, 8)
        if kind == 0 and size != 0:
            return poison(w, 8)
        if (kind == 1 or kind == 2) and size != 8:
            return poison(w, 8)
        stored = choose(effective_kind(s, at) == 0, 0, size)
        if stored > 18446744073709551544 or 64 + aligned(stored) > 18446744073709551615 - needed:
            return poison(w, 5)
        needed = needed + 64 + aligned(stored)
        at = at + 16 + size
        index = index + 1
    if at != length(s):
        return poison(w, 8)
    return needed

def import_vector(s:readbuf, w:mutbuf) -> u64:
    needed = import_plan(s, w)
    if get(w, 8) == 3:
        return 4294967293
    count = read64(s, 128)
    status = reserve(w, needed, count + 1)
    if status != 0:
        return status
    first = get(w, 40)
    at = 136
    index = 0
    while index < count:
        kind = effective_kind(s, at)
        size = choose(kind == 0, 0, read64(s, at + 8))
        node = new_node(w, 1, 64 + aligned(size))
        put(w, node + 40, kind)
        put(w, node + 48, size)
        copy_input(w, s, node + 64, at + 16, size)
        at = at + 16 + read64(s, at + 8)
        index = index + 1
    vector = new_node(w, 2, 64 + count * 8)
    put(w, vector + 40, count)
    index = 0
    while index < count:
        put(w, vector + 64 + index * 8, first + index)
        index = index + 1
    return results(w, get(w, vector + 16), count, 0, 0)

def null_vector(s:readbuf, w:mutbuf) -> u64:
    width = read64(s, 64)
    if zero_args(s, 72) == 0 or width > 2305843009213693935:
        return poison(w, 7)
    status = reserve(w, 128 + width * 8, 2)
    if status != 0:
        return status
    cell = new_node(w, 1, 64)
    vector = new_node(w, 2, 64 + width * 8)
    put(w, vector + 40, width)
    index = 0
    while index < width:
        put(w, vector + 64 + index * 8, get(w, cell + 16))
        index = index + 1
    return results(w, get(w, vector + 16), width, 0, 0)

def constant(s:readbuf, w:mutbuf) -> u64:
    selector = read64(s, 64)
    if selector > 5 or zero_args(s, 80) == 0 or (selector != 5 and read64(s, 72) != 0):
        return poison(w, 7)
    size = 8
    if selector == 0:
        size = 0
    elif selector == 3:
        size = 1
    elif selector == 4:
        size = 9
    status = reserve(w, 136 + aligned(size), 2)
    if status != 0:
        return status
    cell = new_node(w, 1, 64 + aligned(size))
    put(w, cell + 40, choose(selector == 0, 0, choose(selector == 3 or selector == 4, 3, 1)))
    put(w, cell + 48, size)
    if selector == 2:
        put(w, cell + 64, 1)
    elif selector == 3:
        store(w, cell + 64, 48)
    elif selector == 4:
        put(w, cell + 64, COMPLETE_WORD)
        store(w, cell + 72, 100)
    elif selector == 5:
        put(w, cell + 64, read64(s, 72))
    vector = new_node(w, 2, 72)
    put(w, vector + 40, 1)
    put(w, vector + 64, get(w, cell + 16))
    return results(w, get(w, vector + 16), 1, 0, 0)

def field(s:readbuf, w:mutbuf) -> u64:
    if zero_args(s, 80) == 0:
        return poison(w, 7)
    cell = vector_cell(w, read64(s, 64), read64(s, 72))
    if cell == 0:
        return poison(w, 9)
    return results(w, get(w, cell + 16), get(w, cell + 40), get(w, cell + 48), 0)

def replace(s:readbuf, w:mutbuf) -> u64:
    if zero_args(s, 88) == 0:
        return poison(w, 7)
    source = find(w, read64(s, 64), 2)
    cell = find(w, read64(s, 80), 1)
    if source == 0 or cell == 0 or read64(s, 72) >= get(w, source + 40):
        return poison(w, 9)
    width = get(w, source + 40)
    index = 0
    while index < width:
        if vector_cell(w, read64(s, 64), index) == 0:
            return poison(w, 9)
        index = index + 1
    status = reserve(w, 64 + width * 8, 1)
    if status != 0:
        return status
    source = find(w, read64(s, 64), 2)
    target = new_node(w, 2, 64 + width * 8)
    put(w, target + 40, width)
    move_workspace(w, target + 64, source + 64, width * 8)
    put(w, target + 64 + read64(s, 72) * 8, read64(s, 80))
    return results(w, get(w, target + 16), width, 0, 0)

def builder(s:readbuf, w:mutbuf) -> u64:
    if zero_args(s, 80) == 0:
        return poison(w, 7)
    status = reserve(w, 96, 1)
    if status != 0:
        return status
    node = new_node(w, 3, 96)
    put(w, node + 40, read64(s, 64))
    put(w, node + 48, read64(s, 72))
    return results(w, get(w, node + 16), 0, 0, 0)

def append_plan(s:readbuf, w:mutbuf) -> u64:
    if zero_args(s, 88) == 0:
        return poison(w, 7)
    builder = find(w, read64(s, 64), 3)
    vector = find(w, read64(s, 72), 2)
    if builder == 0 or vector == 0 or get(w, builder + 24) != get(w, 56) or get(w, builder + 48) != read64(s, 80):
        return poison(w, 9)
    if get(w, builder + 72) == 18446744073709551615:
        return poison(w, 5)
    if get(w, builder + 72) != 0:
        last = find(w, get(w, builder + 64), 6)
        if last == 0 or get(w, last + 48) != 0:
            return poison(w, 9)
    width = get(w, vector + 40)
    selected = 0
    index = 0
    while index < width and index < 64:
        if (read64(s, 80) & (1 << index)) != 0:
            if vector_cell(w, read64(s, 72), index) == 0:
                return poison(w, 9)
            selected = selected + 1
        index = index + 1
    return selected

def append(s:readbuf, w:mutbuf) -> u64:
    selected = append_plan(s, w)
    if get(w, 8) == 3:
        return 4294967293
    status = reserve(w, 128 + selected * 8, 2)
    if status != 0:
        return status
    builder = find(w, read64(s, 64), 3)
    source = find(w, read64(s, 72), 2)
    vector = new_node(w, 2, 64 + selected * 8)
    put(w, vector + 40, selected)
    index = 0
    target = 0
    while index < get(w, source + 40) and index < 64:
        if (read64(s, 80) & (1 << index)) != 0:
            put(w, vector + 64 + target * 8, get(w, source + 64 + index * 8))
            target = target + 1
        index = index + 1
    link = new_node(w, 6, 64)
    put(w, link + 40, get(w, vector + 16))
    if get(w, builder + 72) == 0:
        put(w, builder + 56, get(w, link + 16))
    else:
        last = find(w, get(w, builder + 64), 6)
        put(w, last + 48, get(w, link + 16))
    put(w, builder + 64, get(w, link + 16))
    put(w, builder + 72, get(w, builder + 72) + 1)
    return results(w, read64(s, 64), get(w, builder + 72), 0, 0)

def finish(s:readbuf, w:mutbuf) -> u64:
    if zero_args(s, 88) == 0:
        return poison(w, 7)
    builder = find(w, read64(s, 64), 3)
    if builder == 0 or get(w, builder + 24) != get(w, 56):
        return poison(w, 9)
    status = reserve(w, 72, 1)
    if status != 0:
        return status
    builder = find(w, read64(s, 64), 3)
    node = new_node(w, 4, 72)
    put(w, node + 32, 3)
    put(w, node + 40, get(w, builder + 56))
    put(w, node + 48, get(w, builder + 72))
    put(w, node + 56, read64(s, 72))
    put(w, node + 64, read64(s, 80))
    return results(w, get(w, node + 16), get(w, node + 48), read64(s, 72), read64(s, 80))

def error_result(s:readbuf, w:mutbuf) -> u64:
    if zero_args(s, 96) == 0:
        return poison(w, 7)
    status = reserve(w, 72, 1)
    if status != 0:
        return status
    node = new_node(w, 5, 72)
    put(w, node + 32, 3)
    put(w, node + 40, read64(s, 64))
    put(w, node + 48, read64(s, 72))
    put(w, node + 56, read64(s, 80))
    put(w, node + 64, read64(s, 88))
    return results(w, get(w, node + 16), 0, 0, 0)

def clean_scope(s:readbuf, w:mutbuf) -> u64:
    if zero_args(s, 88) == 0 or read64(s, 72) != get(w, 56) or read64(s, 80) == 18446744073709551615 or read64(s, 48) != read64(s, 80) + 1:
        return poison(w, 7)
    node = find(w, read64(s, 64), 0)
    if node == 0 or (get(w, node + 8) != 4 and get(w, node + 8) != 5) or get(w, node + 24) != get(w, 56) or get(w, node + 32) != 3:
        return poison(w, 9)
    at = 512
    while at < get(w, 48):
        if get(w, at + 24) == get(w, 56) and get(w, at + 16) != read64(s, 64) and get(w, at + 8) != 7:
            put(w, at + 32, get(w, at + 32) & 2)
        at = at + get(w, at)
    put(w, 56, 0)
    put(w, 64, 0)
    return collect(w)

def describe(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    if zero_args(s, 72) == 0:
        return poison(w, 7)
    node = find(w, read64(s, 64), 0)
    if node == 0:
        return poison(w, 9)
    kind = get(w, node + 8)
    if (kind == 4 or kind == 5 or kind == 7) and get(w, node + 32) != 3:
        return poison(w, 9)
    if kind == 4:
        return results(w, kind, get(w, node + 48), get(w, node + 56), get(w, node + 64))
    if kind == 5:
        if length(o) < 200:
            put(w, 8, 2)
            put(w, 288, get(w, 48))
            put(w, 296, 200)
            return 1
        put(w, 304, 8)
        put(w, 320, node + 64)
        return results(w, kind, get(w, node + 40), get(w, node + 48), get(w, node + 56))
    return results(w, kind, get(w, node + 40), get(w, node + 48), get(w, node + 56))

def cell_read(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    if zero_args(s, 80) == 0:
        return poison(w, 7)
    cell = find(w, read64(s, 64), 1)
    if cell == 0 or read64(s, 72) > get(w, cell + 48):
        return poison(w, 9)
    offset = read64(s, 72)
    remain = get(w, cell + 48) - offset
    if remain != 0 and length(o) == 192:
        put(w, 8, 2)
        put(w, 288, get(w, 48))
        put(w, 296, 193)
        return 1
    count = choose(remain < length(o) - 192, remain, length(o) - 192)
    results(w, get(w, cell + 40), get(w, cell + 48), offset, offset + count)
    put(w, 304, count)
    put(w, 320, cell + 64 + offset)
    return choose(count == remain, 0, 2)

def cursor(s:readbuf, w:mutbuf) -> u64:
    if zero_args(s, 72) == 0:
        return poison(w, 7)
    result = find(w, read64(s, 64), 4)
    if result == 0 or get(w, result + 32) != 3:
        return poison(w, 9)
    status = reserve(w, 64, 1)
    if status != 0:
        return status
    result = find(w, read64(s, 64), 4)
    node = new_node(w, 7, 64)
    put(w, node + 32, 3)
    put(w, node + 40, read64(s, 64))
    put(w, node + 48, get(w, result + 40))
    put(w, node + 56, get(w, result + 48))
    return results(w, get(w, node + 16), get(w, node + 56), 0, 0)

def next_result(s:readbuf, w:mutbuf) -> u64:
    if zero_args(s, 72) == 0:
        return poison(w, 7)
    cursor = find(w, read64(s, 64), 7)
    if cursor == 0 or get(w, cursor + 32) != 3 or find(w, get(w, cursor + 40), 4) == 0:
        return poison(w, 9)
    if get(w, cursor + 56) == 0:
        put(w, cursor + 32, 2)
        if collect(w) == 4294967293:
            return 4294967293
        return 3
    link = find(w, get(w, cursor + 48), 6)
    if link == 0:
        return poison(w, 9)
    vector = find(w, get(w, link + 40), 2)
    if vector == 0:
        return poison(w, 9)
    if get(w, cursor + 56) > 1 and find(w, get(w, link + 48), 6) == 0:
        return poison(w, 9)
    put(w, cursor + 56, get(w, cursor + 56) - 1)
    put(w, cursor + 48, choose(get(w, cursor + 56) == 0, 0, get(w, link + 48)))
    return results(w, get(w, vector + 16), get(w, vector + 40), get(w, cursor + 56), 0)

def drop(s:readbuf, w:mutbuf) -> u64:
    if zero_args(s, 72) == 0:
        return poison(w, 7)
    node = find(w, read64(s, 64), 0)
    if node == 0 or get(w, node + 32) != 3:
        return poison(w, 9)
    put(w, node + 32, 2)
    return collect(w)

def close(s:readbuf, w:mutbuf) -> u64:
    if zero_args(s, 64) == 0:
        return poison(w, 7)
    fill_range(w, 512, get(w, 48) - 512, 0)
    put(w, 48, 512)
    put(w, 56, 0)
    put(w, 64, 0)
    put(w, 8, 4)
    return 0

def mark(w:mutbuf, identity:u64, kind:u64) -> u64:
    node = find(w, identity, kind)
    if node == 0:
        poison(w, 10)
        return 0
    if (get(w, node + 32) & 4) != 0:
        return 0
    put(w, node + 32, get(w, node + 32) | 4)
    return 1

def mark_sequence(w:mutbuf, first:u64, count:u64) -> u64:
    identity = first
    index = 0
    changed = 0
    while index < count:
        link = find(w, identity, 6)
        if link == 0:
            poison(w, 10)
            return 0
        changed = changed + mark(w, identity, 6)
        changed = changed + mark(w, get(w, link + 40), 2)
        if get(w, 8) == 3:
            return 0
        identity = get(w, link + 48)
        index = index + 1
    return changed

def mark_children(w:mutbuf, node:u64) -> u64:
    kind = get(w, node + 8)
    changed = 0
    if kind == 2:
        index = 0
        while index < get(w, node + 40):
            changed = changed + mark(w, get(w, node + 64 + index * 8), 1)
            if get(w, 8) == 3:
                return 0
            index = index + 1
    elif kind == 3:
        changed = mark_sequence(w, get(w, node + 56), get(w, node + 72))
    elif kind == 4:
        changed = mark_sequence(w, get(w, node + 40), get(w, node + 48))
    elif kind == 7:
        changed = mark(w, get(w, node + 40), 4)
    return changed

def collect(w:mutbuf) -> u64:
    at = 512
    while at < get(w, 48):
        flags = get(w, at + 32)
        if (flags & 2) != 0:
            if (flags & 1) != 0 or (get(w, 56) != 0 and get(w, at + 24) == get(w, 56)):
                put(w, at + 32, flags | 4)
        at = at + get(w, at)
    changed = 1
    while changed != 0:
        changed = 0
        at = 512
        while at < get(w, 48):
            if (get(w, at + 32) & 4) != 0:
                changed = changed + mark_children(w, at)
                if get(w, 8) == 3:
                    return 4294967293
            at = at + get(w, at)
    at = 512
    while at < get(w, 48):
        if (get(w, at + 32) & 4) != 0:
            put(w, at + 32, get(w, at + 32) & 3)
        else:
            put(w, at + 32, 0)
        at = at + get(w, at)
    return 0

def emit(o:mutbuf, w:mutbuf, status:u64) -> u64:
    if length(o) < 192:
        return 4294967293
    fill_range(o, 0, length(o), 0)
    put(o, 0, OBJECT_MAGIC)
    put(o, 8, status)
    put(o, 16, get(w, 16))
    put(o, 24, get(w, 24))
    put(o, 32, get(w, 160))
    put(o, 40, get(w, 136))
    put(o, 48, get(w, 168))
    put(o, 56, get(w, 176))
    if status != 4294967293:
        put(o, 64, get(w, 256))
        put(o, 72, get(w, 264))
        put(o, 80, get(w, 272))
        put(o, 88, get(w, 280))
        put(o, 96, get(w, 288))
        put(o, 104, get(w, 296))
        put(o, 112, get(w, 304))
    put(o, 120, get(w, 120))
    put(o, 128, get(w, 184))
    put(o, 136, get(w, 56))
    put(o, 144, get(w, 48))
    put(o, 152, get(w, 40))
    put(o, 160, 1)
    if status != 4294967293 and get(w, 304) != 0:
        copy_workspace(o, w, 192, get(w, 320), get(w, 304))
    return status
'''


class ObjectBuilder(Builder):
    """Use existing checked bulk operations; keep the base builder unchanged."""
    def expr(self, expression):
        if isinstance(expression, ast.Call) and isinstance(expression.func, ast.Name):
            name = expression.func.id
            if name in ('copy_input', 'copy_workspace', 'move_workspace'):
                values = [self.expr(arg) for arg in expression.args]
                if name == 'move_workspace':
                    assert len(values) == 4 and values[0][1] == 'mutbuf'
                    return self.op('buffer.move_within', values[:1] + [self.cast(v, 'usize') for v in values[1:]])
                assert len(values) == 5 and values[0][1] == 'mutbuf'
                if name == 'copy_workspace':
                    assert values[1][1] == 'mutbuf'
                    loan = self.op('borrow.read', [values[1]], 'readbuf')
                    self.op('buffer.copy_range', [values[0], loan] + [self.cast(v, 'usize') for v in values[2:]])
                    return self.op('loan.end', [loan])
                assert values[1][1] == 'readbuf'
                return self.op('buffer.copy_range', values[:2] + [self.cast(v, 'usize') for v in values[2:]])
        return super().expr(expression)


def source_program():
    return (OBJECTS.replace('OBJECT_MAGIC', str(MAGIC))
            .replace('COMPLETE_WORD', str(int.from_bytes(b'complete', 'little')))
            + VALUES[VALUES.index('\ndef read64('):])


def document():
    nodes = ast.parse(source_program()).body
    names = {node.name: 'f' + str(i) for i, node in enumerate(nodes)}
    if len(names) != len(nodes):
        raise ValueError('duplicate namespace objects HIA symbol')
    signatures = {node.name: ([a.annotation.id for a in node.args.args], node.returns.id) for node in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = ObjectBuilder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({'name': names[node.name], 'params': [builder.param(v) for v in builder.params],
                          'returns': [builder.returns], 'effects': ['read', 'write', 'trap'],
                          'entry': 'b0', 'blocks': builder.blocks})
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8', 'module': 'agent_namespace_objects', 'functions': functions})


def main():
    path = ROOT / 'examples/hia_bootstrap/agent_namespace_objects.hiaasm'
    path.write_text(render_assembly(document()))
    print(path.name, path.stat().st_size)


if __name__ == '__main__':
    main()

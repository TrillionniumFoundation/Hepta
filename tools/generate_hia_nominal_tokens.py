"""Author a retained, typed ObjectToken renderer; the image parses all payloads.

The host authoring DSL is lowered to checked HIA assembly. Runtime graph
admission, wire offsets, keys, references, sizes and serialization are HIA-owned.
"""
from __future__ import annotations

import ast
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_composite_functions import COMMON
from tools.generate_hia_json_canonical import SOURCE as CANONICAL_SOURCE
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions

MAGIC = int.from_bytes(b'HIANTK01', 'little')
REPLY = int.from_bytes(b'HIANTR01', 'little')
STATE = int.from_bytes(b'HIANTS01', 'little')
CONSTANTS = {'MAGIC': MAGIC, 'REPLY': REPLY, 'STATE': STATE,
             'N': (1 << 64) - 1, 'LIMIT': (1 << 63) - 1, 'HANDLES': 1 << 63}

# Workspace header (512 bytes): identity/poison/cursor/source/index at 0..48;
# output cursor at 56 (shared with the qualified JSON escaping helpers);
# hash table base/capacity/mapping length/key chain/count at 64..96;
# retained cursor/key chain/key count at 112..128; handle chain at 136;
# stream magic/action/serial/slots/request/sequence at 152..192;
# root/current/done/final/token count/active at 200..240;
# required workspace/output at 248/256; source parsing flag/cursor at 264/272;
# serialization stack at 288; decimal powers at 320..479.
# Nodes are 128 bytes: kind/data/length/head/tail/next/parent/remaining-or-value,
# pending-key/canonical-size/wire-end/hash-next/hash/global-key-next/depth/role.
# Kind 7 is a typed reference, resolved only to an admitted immutable node.

SOURCE = r'''
def nominal_tokens(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(o) < 64 or length(w) < 512:
        return 4294967293
    if get(w, 0) == STATE and get(w, 8) != 0:
        return reply(o, w, 3)
    if length(s) < 64 or word(s, 0) != MAGIC or word(s, 56) != length(s) - 64:
        return reject(o, w)
    operation = word(s, 8)
    if operation == 1:
        if get(w, 0) != 0:
            return reject(o, w)
        return begin_source(s, o, w)
    if get(w, 0) != STATE or get(w, 240) != 1:
        return reject(o, w)
    if operation == 4:
        if length(s) != 64 or get(w, 224) != 1:
            return reject(o, w)
        put(w, 16, get(w, 112))
        put(w, 88, get(w, 120))
        put(w, 96, get(w, 128))
        put(w, 80, 0)
        stream_identity(s, w)
        return reply(o, w, 0)
    if word(s, 24) != 0 or word(s, 32) != 0 or word(s, 40) != 0 or word(s, 48) != 0:
        return reject(o, w)
    if operation == 5:
        return seal_root(s, o, w)
    if word(s, 16) != 0:
        return reject(o, w)
    if operation == 2:
        return feed_frame(s, o, w)
    if operation == 3 and length(s) == 64:
        return canonical(o, w)
    return reject(o, w)

def poison(w:mutbuf) -> u64:
    put(w, 0, STATE)
    put(w, 8, 1)
    return 0

def reject(o:mutbuf, w:mutbuf) -> u32:
    poison(w)
    return reply(o, w, 3)

def reply(o:mutbuf, w:mutbuf, status:u64) -> u32:
    put(o, 0, REPLY)
    put(o, 8, status)
    put(o, 16, get(w, 224))
    put(o, 24, get(w, 192))
    put(o, 32, get(w, 248))
    put(o, 40, get(w, 256))
    put(o, 48, get(w, 232))
    kind = N
    if get(w, 8) == 0 and get(w, 200) != 0:
        kind = get(w, resolve(w, get(w, 200)))
        if kind == 3:
            kind = 2
    put(o, 56, kind)
    return 64

def plus(w:mutbuf, a:u64, b:u64) -> u64:
    if a > LIMIT or b > LIMIT - a:
        poison(w)
        return 0
    return a + b

def increment(w:mutbuf, value:u64) -> u64:
    if value == N:
        poison(w)
        return 0
    return value + 1

def allocate(w:mutbuf, size:u64) -> u64:
    at = get(w, 16)
    rounded = (size + 7) & 18446744073709551608
    if size > LIMIT - 7 or at > get(w, 64) or rounded > get(w, 64) - at:
        poison(w)
        return 512
    put(w, 16, at + rounded)
    return at

def new_node(w:mutbuf, kind:u64) -> u64:
    node = allocate(w, 128)
    i = 0
    while i < 128:
        put(w, node + i, 0)
        i = i + 8
    put(w, node, kind)
    put(w, node + 112, 1)
    return node

def resolve(w:mutbuf, node:u64) -> u64:
    while get(w, node) == 7:
        node = get(w, node + 8)
    return node

def table_capacity(count:u64) -> u64:
    capacity = 16
    while capacity < count and capacity < 576460752303423488:
        capacity = capacity * 2
    return capacity * 2

def reserve(w:mutbuf, extra:u64, keys:u64) -> u64:
    if keys > 576460752303423488:
        poison(w)
        return 3
    capacity = table_capacity(keys)
    required = plus(w, plus(w, get(w, 16), extra), capacity * 8)
    if get(w, 8) != 0:
        return 3
    put(w, 248, required)
    if length(w) < required:
        return 1
    if get(w, 80) != length(w) or get(w, 72) != capacity:
        put(w, 64, length(w) - capacity * 8)
        put(w, 72, capacity)
        put(w, 80, length(w))
        rehash(w)
    return 0

def rehash(w:mutbuf) -> u64:
    i = 0
    while i < get(w, 72):
        put(w, get(w, 64) + i * 8, 0)
        i = i + 1
    node = get(w, 88)
    while node != 0:
        at = get(w, 64) + (get(w, node + 96) & (get(w, 72) - 1)) * 8
        put(w, node + 88, get(w, at))
        put(w, at, node)
        node = get(w, node + 104)
    return 0

def string_hash(w:mutbuf, node:u64, parent:u64) -> u64:
    node = resolve(w, node)
    value = 14695981039346656037 ^ parent
    at = get(w, node + 8)
    size = get(w, node + 16)
    i = 0
    while i < size:
        value = (value ^ byte(w, at + i)) * 1099511628211
        i = i + 1
    return value

def string_equal(w:mutbuf, a:u64, b:u64) -> u64:
    a = resolve(w, a)
    b = resolve(w, b)
    size = get(w, a + 16)
    if size != get(w, b + 16):
        return 0
    i = 0
    while i < size:
        if byte(w, get(w, a + 8) + i) != byte(w, get(w, b + 8) + i):
            return 0
        i = i + 1
    return 1

def insert_key(w:mutbuf, key:u64, parent:u64) -> u64:
    value = string_hash(w, key, parent)
    at = get(w, 64) + (value & (get(w, 72) - 1)) * 8
    node = get(w, at)
    while node != 0:
        if get(w, node + 48) == parent and get(w, node + 96) == value:
            if string_equal(w, node, key) == 1:
                poison(w)
                return 0
        node = get(w, node + 88)
    put(w, key + 88, get(w, at))
    put(w, key + 96, value)
    put(w, at, key)
    put(w, key + 104, get(w, 88))
    put(w, 88, key)
    put(w, 96, get(w, 96) + 1)
    return 1

def link_child(w:mutbuf, parent:u64, node:u64) -> u64:
    previous = get(w, parent + 32)
    if previous == 0:
        put(w, parent + 24, node)
    else:
        put(w, previous + 40, node)
    put(w, parent + 32, node)
    return 0

def attach(w:mutbuf, node:u64) -> u64:
    parent = get(w, 208)
    put(w, node + 48, parent)
    if parent == 0:
        if get(w, 200) != 0:
            poison(w)
            return 0
        put(w, 200, node)
        return 1
    if get(w, parent + 56) == 0:
        poison(w)
        return 0
    if get(w, parent) == 5:
        if get(w, parent + 56) < get(w, parent + 16):
            put(w, parent + 72, plus(w, get(w, parent + 72), 1))
        put(w, parent + 56, get(w, parent + 56) - 1)
        link_child(w, parent, node)
    else:
        if get(w, parent + 64) == 0:
            if get(w, resolve(w, node)) != 4:
                poison(w)
                return 0
            if insert_key(w, node, parent) == 0:
                return 0
            if get(w, parent + 56) < get(w, parent + 16):
                put(w, parent + 72, plus(w, get(w, parent + 72), 1))
            put(w, parent + 72, plus(w, get(w, parent + 72), 1))
            put(w, parent + 64, node)
            put(w, node + 120, 1)
            link_child(w, parent, node)
        else:
            put(w, get(w, parent + 64) + 56, node)
            put(w, parent + 64, 0)
            put(w, parent + 56, get(w, parent + 56) - 1)
    return 1

def finish(w:mutbuf, node:u64) -> u64:
    going = True
    while going and get(w, 8) == 0:
        kind = get(w, node)
        if get(w, 264) == 1 and (kind == 5 or kind == 6):
            if get(w, node + 80) != get(w, 272):
                poison(w)
                return 0
        parent = get(w, node + 48)
        if parent == 0:
            put(w, 208, 0)
            put(w, 216, 1)
            going = False
        else:
            put(w, parent + 72, plus(w, get(w, parent + 72), get(w, node + 72)))
            depth = plus(w, get(w, node + 112), 1)
            if depth > get(w, parent + 112):
                put(w, parent + 112, depth)
            put(w, 208, parent)
            if get(w, parent + 56) == 0 and get(w, parent + 64) == 0:
                node = parent
            else:
                going = False
    return 0

def accept_node(w:mutbuf, node:u64) -> u64:
    if attach(w, node) == 0:
        return 0
    kind = get(w, node)
    if (kind == 5 or kind == 6) and get(w, node + 56) != 0:
        put(w, 208, node)
    else:
        finish(w, node)
    return 0

def valid_utf8(w:mutbuf, at:u64, size:u64) -> u64:
    i = 0
    while i < size:
        first = byte(w, at + i)
        need = 0
        low = 128
        high = 191
        if first >= 128:
            if first >= 194 and first <= 223:
                need = 1
            elif first >= 224 and first <= 239:
                need = 2
                if first == 224:
                    low = 160
                if first == 237:
                    high = 159
            elif first >= 240 and first <= 244:
                need = 3
                if first == 240:
                    low = 144
                if first == 244:
                    high = 143
            else:
                return 0
        if need > size - i - 1:
            return 0
        j = 1
        while j <= need:
            value = byte(w, at + i + j)
            if value < low or value > high:
                return 0
            low = 128
            high = 191
            j = j + 1
        i = i + need + 1
    return 1

def string_size(w:mutbuf, at:u64, size:u64) -> u64:
    result = 2
    i = 0
    while i < size:
        ch = byte(w, at + i)
        amount = 1
        if ch == 34 or ch == 92:
            amount = 2
        if ch < 32:
            amount = 6
            if ch == 8 or ch == 9 or ch == 10 or ch == 12 or ch == 13:
                amount = 2
        result = plus(w, result, amount)
        i = i + 1
    return result

def decimal_valid(w:mutbuf, at:u64, size:u64) -> u64:
    if size == 0:
        return 0
    i = 0
    if byte(w, at) == 45:
        if size == 1:
            return 0
        i = 1
    if byte(w, at + i) == 48:
        return choose(size == 1, 1, 0)
    if byte(w, at + i) < 49 or byte(w, at + i) > 57:
        return 0
    while i < size:
        if byte(w, at + i) < 48 or byte(w, at + i) > 57:
            return 0
        i = i + 1
    return 1

def scalar_source(w:mutbuf, node:u64, at:u64, size:u64) -> u64:
    kind = get(w, node)
    put(w, node + 8, at)
    put(w, node + 16, size)
    if kind == 0:
        if size != 0:
            return poison(w)
        put(w, node + 72, 4)
    elif kind == 1:
        if size != 1 or byte(w, at) > 1:
            return poison(w)
        put(w, node + 8, byte(w, at))
        put(w, node + 72, choose(byte(w, at) == 1, 4, 5))
    elif kind == 2:
        if decimal_valid(w, at, size) == 0:
            return poison(w)
        put(w, node + 72, size)
    elif kind == 4:
        if valid_utf8(w, at, size) == 0:
            return poison(w)
        put(w, node + 72, string_size(w, at, size))
    else:
        return poison(w)
    return 0

def wire_count(s:readbuf) -> u64:
    at = 64
    count = 0
    while at < length(s):
        if length(s) - at < 16:
            return N
        size = word(s, at + 8)
        if size > length(s) - at - 16:
            return N
        kind = word(s, at)
        if kind == 5 or kind == 6:
            if size < 8:
                return N
            at = at + 24
        else:
            at = at + 16 + size
        count = count + 1
    return count

def source_node(w:mutbuf, at:u64) -> u64:
    base = get(w, 24)
    kind = get(w, base + at)
    size = get(w, base + at + 8)
    end = at + 16 + size
    parent = get(w, 208)
    if parent != 0:
        if end > get(w, parent + 80):
            poison(w)
            return end
    node = new_node(w, kind)
    index = get(w, 40) + get(w, 48) * 16
    put(w, index, at)
    put(w, index + 8, node)
    put(w, 48, get(w, 48) + 1)
    if kind == 5 or kind == 6:
        count = get(w, base + at + 16)
        if count > ((size - 8) >> 4):
            poison(w)
            return end
        if kind == 6 and count > ((size - 8) >> 5):
            poison(w)
            return end
        put(w, node + 16, count)
        put(w, node + 56, count)
        put(w, node + 72, 2)
        put(w, node + 80, end)
        end = at + 24
    else:
        scalar_source(w, node, base + at + 16, size)
    put(w, 272, end)
    if get(w, 8) == 0:
        accept_node(w, node)
    return end

def begin_source(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    count = wire_count(s)
    if count == 0 or count == N or count > 36028797018963967 or length(s) > LIMIT - 512:
        return reject(o, w)
    index = 512 + ((length(s) - 64 + 7) & 18446744073709551608)
    required = plus(w, plus(w, index, count * 144), table_capacity(count) * 8)
    put(w, 248, required)
    if get(w, 8) != 0:
        return reject(o, w)
    if length(w) < required:
        return reply(o, w, 1)
    i = 0
    while i < 512:
        put(w, i, 0)
        i = i + 8
    put(w, 0, STATE)
    put(w, 24, 512)
    put(w, 32, length(s) - 64)
    put(w, 40, index)
    put(w, 16, index + count * 16)
    reserve(w, count * 128, count)
    i = 64
    while i < length(s):
        store(w, 512 + i - 64, byte(s, i))
        i = i + 1
    i = 0
    value = 1
    while i < 20:
        put(w, 320 + i * 8, value)
        if i < 19:
            value = value * 10
        i = i + 1
    put(w, 264, 1)
    i = 0
    while i < get(w, 32) and get(w, 8) == 0:
        i = source_node(w, i)
    if get(w, 8) != 0 or get(w, 216) != 1 or get(w, 208) != 0 or get(w, 48) != count:
        return reject(o, w)
    put(w, 112, get(w, 16))
    put(w, 120, get(w, 88))
    put(w, 128, get(w, 96))
    stream_identity(s, w)
    return reply(o, w, 0)

def stream_identity(s:readbuf, w:mutbuf) -> u64:
    i = 0
    while i < 5:
        put(w, 152 + i * 8, word(s, 16 + i * 8))
        i = i + 1
    put(w, 192, 0)
    put(w, 200, 0)
    put(w, 208, 0)
    put(w, 216, 0)
    put(w, 224, 0)
    put(w, 232, 0)
    put(w, 240, 1)
    put(w, 248, 0)
    put(w, 256, 0)
    put(w, 264, 0)
    return 0

def lookup(w:mutbuf, identifier:u64) -> u64:
    if identifier >= HANDLES:
        node = get(w, 136)
        while node != 0:
            if get(w, node) == identifier:
                return get(w, node + 8)
            node = get(w, node + 16)
        return 0
    lo = 0
    hi = get(w, 48)
    while lo < hi:
        mid = lo + ((hi - lo) >> 1)
        at = get(w, 40) + mid * 16
        actual = get(w, at)
        if actual == identifier:
            return get(w, at + 8)
        if actual < identifier:
            lo = mid + 1
        else:
            hi = mid
    return 0

def token_count(s:readbuf) -> u64:
    at = 128
    count = 0
    while at < length(s):
        if length(s) - at < 16:
            return N
        kind = word(s, at)
        size = word(s, at + 8)
        at = at + 16
        if kind == 1:
            if size > length(s) - at:
                return N
            at = at + size
        count = count + 1
    return count

def unsigned_size(w:mutbuf, value:u64) -> u64:
    size = 1
    while size < 20 and value >= get(w, 320 + size * 8):
        size = size + 1
    return size

def token_node(s:readbuf, w:mutbuf, at:u64) -> u64:
    kind = word(s, at)
    value = word(s, at + 8)
    next = at + 16
    node = new_node(w, kind)
    if kind == 0:
        target = lookup(w, value)
        if target == 0:
            poison(w)
            return next
        target = resolve(w, target)
        put(w, node, 7)
        put(w, node + 8, target)
        put(w, node + 72, get(w, target + 72))
        put(w, node + 112, get(w, target + 112))
    elif kind == 1:
        data = allocate(w, value)
        i = 0
        while i < value:
            store(w, data + i, byte(s, next + i))
            i = i + 1
        put(w, node, 4)
        scalar_source(w, node, data, value)
        next = next + value
    elif kind == 2:
        put(w, node, 3)
        put(w, node + 8, value)
        put(w, node + 72, unsigned_size(w, value))
    elif kind == 3:
        if value > 1:
            poison(w)
            return next
        put(w, node, 1)
        put(w, node + 8, value)
        put(w, node + 72, choose(value == 1, 4, 5))
    elif kind == 4:
        if value != 0:
            poison(w)
            return next
        put(w, node, 0)
        put(w, node + 72, 4)
    elif kind == 5 or kind == 6:
        put(w, node + 16, value)
        put(w, node + 56, value)
        put(w, node + 72, 2)
    else:
        poison(w)
        return next
    if get(w, 8) == 0:
        accept_node(w, node)
    return next

def frame_identity(s:readbuf, w:mutbuf) -> u64:
    if length(s) < 128 or get(w, 224) != 0:
        return 0
    if word(s, 64) != get(w, 152) or word(s, 72) != get(w, 160):
        return 0
    if word(s, 80) != get(w, 192) or word(s, 88) > 1:
        return 0
    if word(s, 96) != get(w, 168) or word(s, 104) != get(w, 176):
        return 0
    if word(s, 112) != get(w, 184) or word(s, 120) != length(s) - 128:
        return 0
    return 1

def feed_frame(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if frame_identity(s, w) == 0:
        return reject(o, w)
    count = token_count(s)
    if count == N or count > 36028797018963967:
        return reject(o, w)
    result = reserve(w, plus(w, count * 136, length(s) - 128), plus(w, get(w, 96), count))
    if result != 0:
        return reply(o, w, result)
    at = 128
    while at < length(s) and get(w, 8) == 0:
        at = token_node(s, w, at)
        put(w, 232, increment(w, get(w, 232)))
    if get(w, 8) != 0:
        return reject(o, w)
    if word(s, 88) == 1:
        if get(w, 216) != 1 or get(w, 208) != 0:
            return reject(o, w)
        put(w, 224, 1)
    put(w, 192, increment(w, get(w, 192)))
    if get(w, 8) != 0:
        return reject(o, w)
    return reply(o, w, 0)

def seal_root(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    handle = word(s, 16)
    if length(s) != 64 or get(w, 224) != 1 or handle < HANDLES:
        return reject(o, w)
    node = resolve(w, get(w, 200))
    if get(w, node) != 6 or lookup(w, handle) != 0:
        return reject(o, w)
    result = reserve(w, 24, get(w, 96))
    if result != 0:
        return reply(o, w, result)
    record = allocate(w, 24)
    put(w, record, handle)
    put(w, record + 8, node)
    put(w, record + 16, get(w, 136))
    put(w, 136, record)
    put(w, 112, get(w, 16))
    put(w, 120, get(w, 88))
    put(w, 128, get(w, 96))
    return reply(o, w, 0)

def key_less(w:mutbuf, a:u64, b:u64) -> u64:
    a = resolve(w, a)
    b = resolve(w, b)
    aa = get(w, a + 8)
    bb = get(w, b + 8)
    na = get(w, a + 16)
    nb = get(w, b + 16)
    i = 0
    while i < na and i < nb:
        x = byte(w, aa + i)
        y = byte(w, bb + i)
        if x < y:
            return 1
        if x > y:
            return 0
        i = i + 1
    return choose(na <= nb, 1, 0)

def sort_object(w:mutbuf, node:u64) -> u64:
    if get(w, node + 120) != 0:
        return 0
    size = get(w, node + 16)
    head = get(w, node + 24)
    width = 1
    while width < size:
        p = head
        head = 0
        tail = 0
        while p != 0:
            q = p
            left = 0
            while left < width and q != 0:
                q = get(w, q + 40)
                left = left + 1
            right = width
            element = 0
            while left > 0 or (right > 0 and q != 0):
                take_left = False
                if left > 0:
                    if right == 0 or q == 0:
                        take_left = True
                    else:
                        if key_less(w, p, q) == 1:
                            take_left = True
                if take_left:
                    element = p
                    p = get(w, p + 40)
                    left = left - 1
                else:
                    element = q
                    q = get(w, q + 40)
                    right = right - 1
                if tail == 0:
                    head = element
                else:
                    put(w, tail + 40, element)
                tail = element
            p = q
        put(w, tail + 40, 0)
        width = width * 2
    put(w, node + 24, head)
    put(w, node + 120, 1)
    return 0

def append_literal(o:mutbuf, w:mutbuf, value:u64, size:u64) -> u64:
    i = 0
    while i < size:
        append_byte(o, w, (value >> (i * 8)) & 255)
        i = i + 1
    return 0

def append_unsigned(o:mutbuf, w:mutbuf, value:u64) -> u64:
    size = unsigned_size(w, value)
    while size > 0:
        power = get(w, 320 + (size - 1) * 8)
        digit = 0
        while value >= power:
            value = value - power
            digit = digit + 1
        append_byte(o, w, 48 + digit)
        size = size - 1
    return 0

def write_scalar(o:mutbuf, w:mutbuf, node:u64) -> u64:
    kind = get(w, node)
    if kind == 0:
        append_literal(o, w, 1819047278, 4)
    elif kind == 1:
        if get(w, node + 8) == 0:
            append_literal(o, w, 435728179558, 5)
        else:
            append_literal(o, w, 1702195828, 4)
    elif kind == 2:
        i = 0
        while i < get(w, node + 16):
            append_byte(o, w, byte(w, get(w, node + 8) + i))
            i = i + 1
    elif kind == 3:
        append_unsigned(o, w, get(w, node + 8))
    elif kind == 4:
        append_string(o, w, get(w, node + 8), get(w, node + 16))
    else:
        poison(w)
    return 0

def render_push(w:mutbuf, depth:u64, node:u64) -> u64:
    at = get(w, 288) + depth * 32
    put(w, at, resolve(w, node))
    put(w, at + 8, 0)
    put(w, at + 16, 0)
    put(w, at + 24, 0)
    return depth + 1

def render_step(o:mutbuf, w:mutbuf, depth:u64) -> u64:
    frame = get(w, 288) + (depth - 1) * 32
    node = get(w, frame)
    kind = get(w, node)
    if get(w, frame + 8) == 0:
        if kind < 5:
            write_scalar(o, w, node)
            return depth - 1
        if kind == 6:
            sort_object(w, node)
        append_byte(o, w, choose(kind == 5, 91, 123))
        put(w, frame + 8, 1)
        put(w, frame + 16, get(w, node + 24))
    item = get(w, frame + 16)
    if item == 0:
        append_byte(o, w, choose(kind == 5, 93, 125))
        return depth - 1
    if get(w, frame + 24) != 0:
        append_byte(o, w, 44)
    put(w, frame + 24, 1)
    put(w, frame + 16, get(w, item + 40))
    if kind == 6:
        key = resolve(w, item)
        append_string(o, w, get(w, key + 8), get(w, key + 16))
        append_byte(o, w, 58)
        item = get(w, item + 56)
    return render_push(w, depth, item)

def canonical(o:mutbuf, w:mutbuf) -> u32:
    if get(w, 224) != 1 or get(w, 216) != 1:
        return reject(o, w)
    root = resolve(w, get(w, 200))
    size = plus(w, get(w, root + 72), 64)
    if get(w, root + 112) > 288230376151711743 or get(w, 8) != 0:
        return reject(o, w)
    result = reserve(w, get(w, root + 112) * 32, get(w, 96))
    if result != 0:
        return reply(o, w, result)
    put(w, 256, size)
    if length(o) < size:
        return reply(o, w, 2)
    put(w, 288, get(w, 16))
    put(w, 56, 64)
    depth = render_push(w, 0, root)
    while depth != 0 and get(w, 8) == 0:
        depth = render_step(o, w, depth)
    if get(w, 8) != 0 or get(w, 56) != size:
        return reject(o, w)
    return reply(o, w, 0)
'''


def source_program():
    helpers = [node for node in ast.parse(COMMON).body if node.name in {'word', 'put', 'get'}]
    helpers += [node for node in ast.parse(CANONICAL_SOURCE).body
                if node.name in {'append_byte', 'append_string', 'hex_digit'}]
    nodes = ast.parse(SOURCE).body + helpers

    class Constants(ast.NodeTransformer):
        def visit_Name(self, node):
            if isinstance(node.ctx, ast.Load) and node.id in CONSTANTS:
                return ast.copy_location(ast.Constant(CONSTANTS[node.id]), node)
            return node

    module = Constants().visit(ast.Module(body=nodes, type_ignores=[]))
    return ast.unparse(ast.fix_missing_locations(module))


def document():
    nodes = ast.parse(source_program()).body
    names = {node.name: 'f' + str(i) for i, node in enumerate(nodes)}
    signatures = {node.name: ([a.annotation.id for a in node.args.args], node.returns.id) for node in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = Builder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({'name': names[node.name], 'params': [builder.param(v) for v in builder.params],
                          'returns': [builder.returns], 'effects': ['read', 'write', 'trap'],
                          'entry': 'b0', 'blocks': builder.blocks})
    program = compact_authoring_cfg({'schema': 'hepta.hia.program.v8', 'module': 'nominal_tokens',
                                    'functions': functions})
    for function in program['functions']:
        assert len(function['params']) <= 16, function['name']
        for block in function['blocks']:
            assert len(block['params']) <= 16, (function['name'], block['id'], len(block['params']))
    return program


def main():
    path = Path(__file__).resolve().parents[1] / 'examples/hia_bootstrap/nominal_tokens.hepta'
    path.write_text(render_assembly(document()))
    print(path.name, path.stat().st_size)


if __name__ == '__main__':
    main()

"""Author the bounded raw HIA JSON and exact-kind nominal packet codec.

The image reuses the current HIA JSON decoder and performs the complete packet
walk itself. Python authoring does not appear on the image's execution path.
"""
from __future__ import annotations

import ast
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_json_decode import source_program as decoder_source
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions


CONSTANTS = {
    'REQUEST_MAGIC': int.from_bytes(b'HIANJQ01', 'little'),
    'REPLY_MAGIC': int.from_bytes(b'HIANJP01', 'little'),
    'RENDER_REQUEST': int.from_bytes(b'HIAJTQ01', 'little'),
    'RENDER_REPLY': int.from_bytes(b'HIAJTP01', 'little'),
    'RENDER_PACKET_LIMIT': 32 * 1024 * 1024,
    'RENDER_JSON_LIMIT': (8 * 1024 * 1024) + 128,
    'RENDER_STACK': 128 + 131 * 32,
    'RENDER_NODES': 1048576,
    'ARENA_MAGIC': 5208772604367785521,
    'NONE': (1 << 64) - 1,
    'MAX_BYTES': 8 * 1024 * 1024,
    'MAX_NODES': 262144,
    'MAX_DEPTH': 128,
    'BAD_JSON': 0xffffffff,
    'BAD_BUDGET': 0xfffffffe,
    'BAD_ABI': 0xfffffffd,
    'BAD_DUPLICATE': 0xfffffffc,
    'BAD_BYTES': 0xfffffffb,
    'BAD_INTEGER': 0xfffffffa,
    'BAD_INTERNAL': 0xfffffff9,
}


SOURCE = r'''
def nominal_json(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) >= 64 and get(w, 0) == RENDER_REQUEST:
        return njs_render(s, o, w)
    if length(s) > MAX_BYTES:
        return BAD_BYTES
    if length(w) < 128 or length(o) < 128:
        return BAD_ABI
    if get(w, 0) != REQUEST_MAGIC:
        return BAD_ABI
    digits = get(w, 8)
    mode = get(w, 16)
    legacy = get(w, 24)
    if (digits != 0 and digits < 640) or mode > 1 or legacy > 1:
        return BAD_ABI
    if mode == 0 and legacy != 0:
        return BAD_ABI
    if get(w, 32) != 0 or get(w, 40) != 0 or get(w, 48) != 0 or get(w, 56) != 0:
        return BAD_ABI
    # This is an allocation bound, never an extra structural-node charge.
    bound = ((length(s) + 1) >> 1) + 1
    if bound > MAX_NODES:
        bound = MAX_NODES
    arena_bound = 64 + bound * 56 + length(s)
    if arena_bound < 128 + (MAX_DEPTH + 1) * 32:
        arena_bound = 128 + (MAX_DEPTH + 1) * 32
    packet_bound = bound * 40 + length(s) + 41
    if length(w) < arena_bound + bound * 8 or length(o) < packet_bound:
        return BAD_ABI
    # bytes.decode('utf-8') precedes syntax/budget/key checks in decode_json.
    # A late invalid UTF-8 byte must win over an earlier duplicate or budget.
    if njs_utf8(s, 0, length(s)) == 0:
        return BAD_JSON
    put(o, 48, MAX_NODES)
    put(o, 56, MAX_DEPTH)
    result = widen(decode_json(s, w, o))
    if result >= BAD_DUPLICATE:
        return result
    if result < 64 or result > length(w):
        return BAD_INTERNAL
    count = get(w, 8)
    base = get(w, 16)
    if get(w, 0) != ARENA_MAGIC or count < 1 or count > bound or base != 64 + count * 56:
        return BAD_INTERNAL
    if get(w, 24) != result or get(w, 32) != result or get(w, 40) != length(s):
        return BAD_INTERNAL
    if get(w, 48) != 1 or get(w, 56) != 0 or result < base:
        return BAD_INTERNAL
    if count * 8 > length(w) - result:
        return BAD_INTERNAL
    lengths = result
    status = njs_validate(s, w, count, base, result, digits)
    if status != 0:
        return status
    total = njs_lengths(s, w, count, packet_bound, lengths)
    if total == BAD_INTERNAL:
        return BAD_INTERNAL
    if mode == 1:
        total = total + 41
    if total > length(o):
        return BAD_ABI
    cursor = 0
    if mode == 1:
        put(o, 0, 5)
        put(o, 8, total - 16)
        put(o, 16, 2)
        cursor = 24
    cursor = njs_emit(s, o, w, count, lengths, cursor)
    if mode == 1:
        put(o, cursor, 1)
        put(o, cursor + 8, 1)
        store(o, cursor + 16, legacy)
        cursor = cursor + 17
    if cursor != total:
        return BAD_INTERNAL
    # Publish only fixed control metadata after the complete packet. The caller
    # binds its requested scalar policy without parsing a payload node.
    put(w, 0, REPLY_MAGIC)
    put(w, 8, total)
    put(w, 16, digits)
    put(w, 24, mode)
    put(w, 32, legacy)
    put(w, 40, length(s))
    put(w, 48, count)
    put(w, 56, 1)
    return total

def njs_validate(s:readbuf, w:mutbuf, count:u64, base:u64, result:u64, digits:u64) -> u64:
    # First visit the scalar leaves in source order, after the complete syntax
    # preflight. This retains the reference integer conversion failure order.
    node = 0
    while node < count:
        record = 64 + node * 56
        kind = get(w, record)
        parent = get(w, record + 8)
        sibling = get(w, record + 16)
        start = get(w, record + 24)
        size = get(w, record + 32)
        key = get(w, record + 40)
        key_size = get(w, record + 48)
        if kind > 6:
            return BAD_INTERNAL
        if node == 0:
            if parent != NONE or sibling != NONE:
                return BAD_INTERNAL
        else:
            if parent >= node:
                return BAD_INTERNAL
        if sibling != NONE:
            if sibling <= node or sibling >= count:
                return BAD_INTERNAL
        if parent != NONE and get(w, 64 + parent * 56) == 6:
            if key < base or key > result or key_size > result - key:
                return BAD_INTERNAL
        else:
            if key != 0 or key_size != 0:
                return BAD_INTERNAL
        if kind == 4:
            if start < base or start > result or size > result - start:
                return BAD_INTERNAL
        if kind == 3:
            if start > length(s) or size < 1 or size > length(s) - start:
                return BAD_INTERNAL
            decimal_digits = size
            if byte(s, start) == 45:
                decimal_digits = decimal_digits - 1
            if digits != 0 and decimal_digits > digits:
                return BAD_INTEGER
        node = node + 1
    return 0

def njs_lengths(s:readbuf, w:mutbuf, count:u64, packet_bound:u64, lengths:u64) -> u64:
    # Every child follows its parent in the decoder's preorder arena. Compute
    # complete subtree lengths backwards before emitting any packet bytes.
    edges = 0
    node = count
    while node != 0:
        node = node - 1
        record = 64 + node * 56
        kind = get(w, record)
        start = get(w, record + 24)
        size = get(w, record + 32)
        total = 16
        if kind == 1 or kind == 2:
            total = 17
        if kind == 3 or kind == 4:
            total = total + size
            if kind == 3 and size == 2 and byte(s, start) == 45 and byte(s, start + 1) == 48:
                total = 17
        if kind == 5 or kind == 6:
            total = 24
            child = start
            index = 0
            if size > count:
                return BAD_INTERNAL
            while index < size:
                if child <= node or child >= count:
                    return BAD_INTERNAL
                child_record = 64 + child * 56
                if get(w, child_record + 8) != node:
                    return BAD_INTERNAL
                total = total + get(w, lengths + child * 8)
                if kind == 6:
                    total = total + 16 + get(w, child_record + 48)
                child = get(w, child_record + 16)
                index = index + 1
            if child != NONE:
                return BAD_INTERNAL
            edges = edges + size
        if total > packet_bound:
            return BAD_INTERNAL
        put(w, lengths + node * 8, total)
    if edges != count - 1:
        return BAD_INTERNAL
    return get(w, lengths)

def njs_emit(s:readbuf, o:mutbuf, w:mutbuf, count:u64, lengths:u64, cursor:u64) -> u64:
    node = 0
    while node < count:
        record = 64 + node * 56
        kind = get(w, record)
        parent = get(w, record + 8)
        start = get(w, record + 24)
        size = get(w, record + 32)
        if parent != NONE and get(w, 64 + parent * 56) == 6:
            key = get(w, record + 40)
            key_size = get(w, record + 48)
            put(o, cursor, 4)
            put(o, cursor + 8, key_size)
            njs_copy_arena(w, o, key, cursor + 16, key_size)
            cursor = cursor + 16 + key_size
        wire_kind = kind
        if kind == 1 or kind == 2:
            wire_kind = 1
        if kind == 3:
            wire_kind = 2
        payload = get(w, lengths + node * 8) - 16
        put(o, cursor, wire_kind)
        put(o, cursor + 8, payload)
        cursor = cursor + 16
        if kind == 5 or kind == 6:
            put(o, cursor, size)
            cursor = cursor + 8
        else:
            if kind == 1 or kind == 2:
                store(o, cursor, kind - 1)
            if kind == 3:
                if size == 2 and byte(s, start) == 45 and byte(s, start + 1) == 48:
                    store(o, cursor, 48)
                else:
                    njs_copy_raw(s, o, start, cursor, size)
            if kind == 4:
                njs_copy_arena(w, o, start, cursor, size)
            cursor = cursor + payload
        node = node + 1
    return cursor

def njs_copy_raw(s:readbuf, o:mutbuf, source:u64, destination:u64, size:u64) -> u64:
    index = 0
    while index < size:
        store(o, destination + index, byte(s, source + index))
        index = index + 1
    return 0

def njs_copy_arena(w:mutbuf, o:mutbuf, source:u64, destination:u64, size:u64) -> u64:
    index = 0
    while index < size:
        store(o, destination + index, byte(w, source + index))
        index = index + 1
    return 0

def njs_utf8(s:readbuf, index:u64, stop:u64) -> u64:
    while index < stop:
        first = byte(s, index)
        width = 1
        if first >= 128:
            width = 0
            if first >= 194 and first <= 223:
                width = 2
            if first >= 224 and first <= 239:
                width = 3
            if first >= 240 and first <= 244:
                width = 4
            if width == 0 or width > stop - index:
                return 0
            second = byte(s, index + 1)
            if second < 128 or second > 191:
                return 0
            if first == 224 and second < 160:
                return 0
            if first == 237 and second > 159:
                return 0
            if first == 240 and second < 144:
                return 0
            if first == 244 and second > 143:
                return 0
            offset = 2
            while offset < width:
                value = byte(s, index + offset)
                if value < 128 or value > 191:
                    return 0
                offset = offset + 1
        index = index + width
    return 1

def njs_render(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) < RENDER_STACK:
        return BAD_ABI
    offset = 8
    while offset < 64:
        if get(w, offset) != 0:
            return BAD_ABI
        offset = offset + 8
    if length(s) > RENDER_PACKET_LIMIT:
        return BAD_BYTES
    capacity = length(o)
    if capacity > RENDER_JSON_LIMIT:
        capacity = RENDER_JSON_LIMIT
    # Each frame holds its packet end, remaining children, container kind and
    # original child count. The root frame owns exactly one complete value.
    put(w, 128, length(s))
    put(w, 136, 1)
    put(w, 144, 0)
    put(w, 152, 1)
    position = 0
    cursor = 0
    depth = 0
    nodes = 0
    while True:
        frame = 128 + depth * 32
        stop = get(w, frame)
        left = get(w, frame + 8)
        flavor = get(w, frame + 16)
        if left == 0:
            if position != stop:
                return BAD_JSON
            if depth == 0:
                put(w, 0, RENDER_REPLY)
                put(w, 8, cursor)
                put(w, 16, length(s))
                put(w, 24, nodes)
                put(w, 56, 1)
                return cursor
            if cursor == capacity:
                return BAD_BUDGET
            store(o, cursor, choose(flavor == 5, 93, 125))
            cursor = cursor + 1
            depth = depth - 1
        else:
            if position > stop or stop - position < 16:
                return BAD_JSON
            size = njs_word(s, position + 8)
            start = position + 16
            if size > stop - start:
                return BAD_JSON
            kind = njs_word(s, position)
            nodes = nodes + 1
            if nodes > RENDER_NODES:
                return BAD_BUDGET
            # A map alternates string-key and value nodes, including in the
            # traversal budget. Delimiters follow remaining-count parity.
            if flavor == 6 and (left & 1) == 0 and kind != 4:
                return BAD_JSON
            cursor = njs_delimiter(o, cursor, capacity, flavor, left, get(w, frame + 24))
            if cursor == BAD_BUDGET:
                return BAD_BUDGET
            put(w, frame + 8, left - 1)
            position = start + size
            if kind == 5 or kind == 6:
                if size < 8:
                    return BAD_JSON
                if depth == 130 or cursor == capacity:
                    return BAD_BUDGET
                count = njs_word(s, start)
                if count > RENDER_NODES:
                    return BAD_BUDGET
                children = count * choose(kind == 5, 1, 2)
                if children > ((size - 8) >> 4):
                    return BAD_JSON
                depth = depth + 1
                frame = 128 + depth * 32
                put(w, frame, position)
                put(w, frame + 8, children)
                put(w, frame + 16, kind)
                put(w, frame + 24, children)
                store(o, cursor, choose(kind == 5, 91, 123))
                cursor = cursor + 1
                position = start + 8
            else:
                cursor = njs_render_leaf(s, o, start, size, kind, cursor, capacity)
                if cursor >= BAD_BUDGET:
                    return cursor
    return BAD_INTERNAL

def njs_word(s:readbuf, start:u64) -> u64:
    index = 0
    value = 0
    while index < 8:
        value = value | (byte(s, start + index) << (index * 8))
        index = index + 1
    return value

def njs_delimiter(o:mutbuf, cursor:u64, capacity:u64, flavor:u64, left:u64, first:u64) -> u64:
    if flavor == 0 or left == first:
        return cursor
    if cursor == capacity:
        return BAD_BUDGET
    store(o, cursor, choose(flavor == 6 and (left & 1) != 0, 58, 44))
    return cursor + 1

def njs_render_leaf(s:readbuf, o:mutbuf, start:u64, size:u64, kind:u64, cursor:u64, capacity:u64) -> u64:
    if kind == 4:
        return njs_quote(s, o, start, start + size, cursor, capacity)
    if kind == 2:
        if njs_decimal(s, start, start + size) == 0:
            return BAD_JSON
        if size > capacity - cursor:
            return BAD_BUDGET
        njs_copy_raw(s, o, start, cursor, size)
        return cursor + size
    if kind == 0 and size == 0:
        return njs_keyword(o, cursor, capacity, 1819047278, 4)
    if kind == 1 and size == 1:
        flag = byte(s, start)
        if flag == 0:
            return njs_keyword(o, cursor, capacity, 435728179558, 5)
        if flag == 1:
            return njs_keyword(o, cursor, capacity, 1702195828, 4)
    return BAD_JSON

# The decoder and constructor packet transport both write canonical decimal.
def njs_decimal(s:readbuf, start:u64, stop:u64) -> u64:
    if start == stop:
        return 0
    cursor = start
    if byte(s, cursor) == 45:
        cursor = cursor + 1
        if cursor == stop or byte(s, cursor) == 48:
            return 0
    if byte(s, cursor) == 48 and stop - cursor != 1:
        return 0
    while cursor < stop:
        digit = byte(s, cursor)
        if digit < 48 or digit > 57:
            return 0
        cursor = cursor + 1
    return 1

def njs_keyword(o:mutbuf, cursor:u64, capacity:u64, packed:u64, size:u64) -> u64:
    if size > capacity - cursor:
        return BAD_BUDGET
    index = 0
    while index < size:
        store(o, cursor + index, (packed >> (index * 8)) & 255)
        index = index + 1
    return cursor + size

def njs_quote(s:readbuf, o:mutbuf, start:u64, stop:u64, cursor:u64, capacity:u64) -> u64:
    if njs_utf8(s, start, stop) == 0:
        return BAD_JSON
    if capacity - cursor < 2:
        return BAD_BUDGET
    store(o, cursor, 34)
    cursor = cursor + 1
    index = start
    while index < stop:
        value = byte(s, index)
        cursor = njs_quote_byte(o, cursor, capacity - 1, value)
        if cursor == BAD_BUDGET:
            return BAD_BUDGET
        index = index + 1
    store(o, cursor, 34)
    return cursor + 1

def njs_quote_byte(o:mutbuf, at:u64, stop:u64, value:u64) -> u64:
    if value == 34 or value == 92:
        if stop - at < 2:
            return BAD_BUDGET
        store(o, at, 92)
        store(o, at + 1, value)
        return at + 2
    if value < 32:
        if stop - at < 2:
            return BAD_BUDGET
        return njs_quote_control(o, at, stop, value)
    if at == stop:
        return BAD_BUDGET
    store(o, at, value)
    return at + 1

def njs_quote_control(o:mutbuf, at:u64, stop:u64, value:u64) -> u64:
    short = 0
    if value == 8:
        short = 98
    if value == 9:
        short = 116
    if value == 10:
        short = 110
    if value == 12:
        short = 102
    if value == 13:
        short = 114
    if short != 0:
        store(o, at, 92)
        store(o, at + 1, short)
        return at + 2
    if stop - at < 6:
        return BAD_BUDGET
    store(o, at, 92)
    store(o, at + 1, 117)
    store(o, at + 2, 48)
    store(o, at + 3, 48)
    store(o, at + 4, 48 + (value >> 4))
    low = value & 15
    store(o, at + 5, low + choose(low < 10, 48, 87))
    return at + 6
'''


def source_program():
    nodes = ast.parse(SOURCE + decoder_source()).body

    class Constants(ast.NodeTransformer):
        def visit_Name(self, node):
            if isinstance(node.ctx, ast.Load) and node.id in CONSTANTS:
                return ast.copy_location(ast.Constant(CONSTANTS[node.id]), node)
            return node

    return [Constants().visit(node) for node in nodes]


def document():
    nodes = source_program()
    names = {node.name: 'f' + str(i) for i, node in enumerate(nodes)}
    signatures = {node.name: ([arg.annotation.id for arg in node.args.args], node.returns.id)
                  for node in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = Builder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({'name': names[node.name],
                          'params': [builder.param(value) for value in builder.params],
                          'returns': [builder.returns], 'effects': ['read', 'write', 'trap'],
                          'entry': 'b0', 'blocks': builder.blocks})
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8',
                                  'module': 'nominal_json', 'functions': functions})


def main():
    path = Path(__file__).resolve().parents[1] / 'examples/hia_bootstrap/nominal_json.hepta'
    path.write_text(render_assembly(document()))
    print(path.name, path.stat().st_size)


if __name__ == '__main__':
    main()

"""Author selected SQLite B-tree cell layout decisions in HIA.

This parser reads one complete page and selects one cell. It is not a whole
page/tree integrity check or a pager. No SQL, disk I/O or overflow-page read is
performed. The bounded domain and rejection policies are in the adjacent ABI.
"""
from __future__ import annotations

import ast
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions

SOURCE_PATH = 'examples/hia_bootstrap/sqlite_btree_cell.hiaasm'
MAGIC = int.from_bytes(b'HIABTC01', 'little')
SOURCE = r'''
def sqlite_btree_cell(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) != 64:
        return 4294967293
    if control_word(w, 0) != CELL_MAGIC or control_word(w, 8) != 1 or control_word(w, 56) != 0:
        return 4294967293
    size = control_word(w, 16)
    reserved = control_word(w, 24)
    page = control_word(w, 32)
    pages = control_word(w, 48)
    if size < 512 or size > 65536 or (size & (size - 1)) != 0 or length(s) != size:
        return 4294967293
    if reserved > 255 or size - reserved < 480 or length(o) > 128:
        return 4294967293
    if page == 0 or pages == 0 or pages > 4294967294 or page > pages:
        return 4294967293
    if page == 1:
        if database_header(s, size, reserved, pages) == 0:
            return 4294967291
    return page_cell(s, o, w)

def database_header(s:readbuf, size:u64, reserved:u64, pages:u64) -> u64:
    if read_be(s, 0, 8) != DB_MAGIC0 or read_be(s, 8, 8) != DB_MAGIC1:
        return 0
    encoded = read_be(s, 16, 2)
    if encoded == 1:
        encoded = 65536
    if encoded != size or byte(s, 20) != reserved:
        return 0
    if byte(s, 18) < 1 or byte(s, 18) > 2 or byte(s, 19) < 1 or byte(s, 19) > 2:
        return 0
    if byte(s, 21) != 64 or byte(s, 22) != 32 or byte(s, 23) != 32:
        return 0
    schema = read_be(s, 44, 4)
    encoding = read_be(s, 56, 4)
    if schema < 1 or schema > 4 or encoding < 1 or encoding > 3:
        return 0
    if read_be(s, 24, 4) == read_be(s, 92, 4) and read_be(s, 28, 4) != 0:
        if read_be(s, 28, 4) != pages:
            return 0
    index = 72
    while index < 92:
        if byte(s, index) != 0:
            return 0
        index = index + 1
    return 1

def page_cell(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    header = 0
    if control_word(w, 32) == 1:
        header = 100
    kind = byte(s, header)
    if kind != 2 and kind != 5 and kind != 10 and kind != 13:
        return 4294967291
    if header == 100 and kind != 5 and kind != 13:
        return 4294967291
    usable = length(s) - control_word(w, 24)
    count = read_be(s, header + 3, 2)
    content = read_be(s, header + 5, 2)
    if content == 0:
        content = 65536
    pointer = header + 8
    if kind == 2 or kind == 5:
        pointer = pointer + 4
        right = read_be(s, header + 8, 4)
        if right == 0 or right > control_word(w, 48) or right == control_word(w, 32):
            return 4294967291
    if content > usable or pointer + count * 2 > content or byte(s, header + 7) > 60:
        return 4294967291
    free = read_be(s, header + 1, 2)
    if free != 0:
        if free < content or free > usable - 4:
            return 4294967291
    index = control_word(w, 40)
    if index >= count:
        return 4294967289
    offset = read_be(s, pointer + index * 2, 2)
    if offset < content or offset > usable - 4:
        return 4294967291
    return decode_cell(s, o, w, kind, usable, count, offset)

def decode_cell(s:readbuf, o:mutbuf, w:mutbuf, kind:u64, usable:u64, count:u64, offset:u64) -> u32:
    cursor = offset
    child = 0
    if kind == 2 or kind == 5:
        child = read_be(s, cursor, 4)
        if child == 0 or child > control_word(w, 48) or child == control_word(w, 32):
            return 4294967291
        cursor = cursor + 4
    payload = 0
    if kind != 5:
        width = varint_size(s, cursor, usable)
        if width == 0:
            return 4294967294
        # SQLite's inline payload reader is a 32-bit contract; this API
        # explicitly refuses the ambiguous 6..9-byte nonminimal encoding.
        if width > 5:
            return 4294967291
        payload = varint_value(s, cursor, width)
        if payload > 2147483647:
            return 4294967290
        cursor = cursor + width
    key = payload
    if kind == 5 or kind == 13:
        width = varint_size(s, cursor, usable)
        if width == 0:
            return 4294967294
        key = varint_value(s, cursor, width)
        cursor = cursor + width
    local = 0
    payload_offset = 0
    overflow = 0
    overflow_offset = 0
    overflow_pages = 0
    overflow_last = 0
    end = cursor
    if kind != 5:
        payload_offset = cursor
        maximum = divide32((usable - 12) * 64, 255) - 23
        if kind == 13:
            maximum = usable - 35
        local = payload
        if payload > maximum:
            minimum = divide32((usable - 12) * 32, 255) - 23
            remainder = payload - minimum
            remainder = remainder - divide32(remainder, usable - 4) * (usable - 4)
            local = minimum + remainder
            if local > maximum:
                local = minimum
        if local > usable - cursor:
            return 4294967294
        end = cursor + local
        if payload > local:
            if usable - end < 4:
                return 4294967294
            overflow_offset = end
            overflow = read_be(s, end, 4)
            if overflow == 0 or overflow > control_word(w, 48) or overflow == control_word(w, 32):
                return 4294967291
            end = end + 4
            remaining = payload - local
            overflow_pages = divide32(remaining + usable - 5, usable - 4)
            overflow_last = remaining - (overflow_pages - 1) * (usable - 4)
        if end - offset < 4:
            end = offset + 4
    if end > usable:
        return 4294967294
    if length(o) < 128:
        return 4294967292
    # No output byte is written until all selected-cell checks complete.
    write_word(o, 0, control_word(w, 32))
    write_word(o, 8, kind)
    write_word(o, 16, usable)
    write_word(o, 24, count)
    write_word(o, 32, control_word(w, 40))
    write_word(o, 40, offset)
    write_word(o, 48, end - offset)
    write_word(o, 56, payload_offset)
    write_word(o, 64, payload)
    write_word(o, 72, local)
    write_word(o, 80, child)
    write_word(o, 88, key)
    write_word(o, 96, overflow)
    write_word(o, 104, overflow_offset)
    write_word(o, 112, overflow_pages)
    write_word(o, 120, overflow_last)
    return 128

def divide32(value:u64, divisor:u64) -> u64:
    quotient = 0
    remainder = 0
    bits = 32
    while bits > 0:
        bits = bits - 1
        remainder = (remainder << 1) | ((value >> bits) & 1)
        if remainder >= divisor:
            remainder = remainder - divisor
            quotient = quotient | (1 << bits)
    return quotient

def varint_size(s:readbuf, offset:u64, end:u64) -> u64:
    count = 0
    while count < 8:
        if offset + count >= end:
            return 0
        part = byte(s, offset + count)
        count = count + 1
        if part < 128:
            return count
    if offset + 8 >= end:
        return 0
    return 9

def varint_value(s:readbuf, offset:u64, count:u64) -> u64:
    value = 0
    index = 0
    while index < count:
        if index == 8:
            value = (value << 8) | byte(s, offset + index)
        else:
            value = (value << 7) | (byte(s, offset + index) & 127)
        index = index + 1
    return value

def read_be(s:readbuf, offset:u64, count:u64) -> u64:
    value = 0
    index = 0
    while index < count:
        value = (value << 8) | byte(s, offset + index)
        index = index + 1
    return value

def control_word(w:mutbuf, offset:u64) -> u64:
    value = 0
    index = 0
    while index < 8:
        value = value | (byte(w, offset + index) << (index * 8))
        index = index + 1
    return value

def write_word(o:mutbuf, offset:u64, value:u64) -> u64:
    index = 0
    while index < 8:
        store(o, offset + index, (value >> (index * 8)) & 255)
        index = index + 1
    return 0
'''


def source():
    return (SOURCE.replace('CELL_MAGIC', str(MAGIC))
            .replace('DB_MAGIC0', str(int.from_bytes(b'SQLite f', 'big')))
            .replace('DB_MAGIC1', str(int.from_bytes(b'ormat 3\0', 'big'))))

def document():
    nodes = ast.parse(source()).body
    names = {node.name: 'f' + str(index) for index, node in enumerate(nodes)}
    signatures = {node.name: ([argument.annotation.id for argument in node.args.args],
                              node.returns.id) for node in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = Builder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({'name': names[node.name],
                          'params': [builder.param(value) for value in builder.params],
                          'returns': [builder.returns],
                          'effects': ['read', 'write', 'trap'],
                          'entry': 'b0', 'blocks': builder.blocks})
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8',
                                  'module': 'sqlite_btree_cell', 'functions': functions})


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path)
    arguments = parser.parse_args()
    destination = arguments.output
    mode = 'x'
    if destination is None:
        destination = Path(__file__).resolve().parents[1] / SOURCE_PATH
        mode = 'w'
    with destination.open(mode, encoding='utf-8', newline='\n') as stream:
        stream.write(render_assembly(document()))
    print(destination.name, destination.stat().st_size)


if __name__ == '__main__':
    main()

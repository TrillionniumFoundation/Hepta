"""Author SQLite's complete 64-bit, one-to-nine-byte varint codec in HIA.

The executable uses no Python/C SQLite codec. The upstream original functions
remain independent qualification oracles. This is a byte-codec migration, not
a SQL engine, pager, transaction, filesystem or durability implementation.
"""
from __future__ import annotations

import ast
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions

SOURCE_PATH = 'examples/hia_bootstrap/sqlite_varint.hiaasm'
MAGIC = int.from_bytes(b'HIASVR01', 'little')
DECODE = 1
ENCODE = 2
REFUSE_PROTOCOL = 0xfffffffd
REFUSE_TRUNCATED = 0xfffffffe
REFUSE_CAPACITY = 0xfffffffc

SOURCE = r'''
def sqlite_varint(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    # The sixteen-byte control is an immutable command, not continuation state.
    # A successful invocation returns the original consumed/written length.
    if length(w) != 16:
        return 4294967293
    if control_word(w, 0) != VARINT_MAGIC:
        return 4294967293
    operation = control_word(w, 8)
    if operation == 1:
        if length(s) > 9 or length(o) != 8:
            return 4294967293
        return decode_varint(s, o)
    if operation == 2:
        if length(s) != 8 or length(o) > 9:
            return 4294967293
        return encode_varint(s, o)
    return 4294967293

def decode_varint(s:readbuf, o:mutbuf) -> u32:
    value = 0
    index = 0
    while index < 8:
        if index >= length(s):
            return 4294967294
        part = byte(s, index)
        value = (value << 7) | (part & 127)
        index = index + 1
        if part < 128:
            write_word(o, value)
            return index
    if length(s) < 9:
        return 4294967294
    # SQLite's ninth byte contributes all eight bits, even if bit 7 is set.
    # The accumulated prefix has exactly 56 bits; this shift does not lose any.
    value = (value << 8) | byte(s, 8)
    write_word(o, value)
    return 9

def encode_varint(s:readbuf, o:mutbuf) -> u32:
    value = input_word(s)
    if value >= 72057594037927936:
        if length(o) < 9:
            return 4294967292
        # Preserve the original nine-byte branch's write order: byte 8 first,
        # then bytes 7 through 0. No byte outside that exact prefix is written.
        store(o, 8, value & 255)
        value = value >> 8
        index = 8
        while index > 0:
            index = index - 1
            store(o, index, (value & 127) | 128)
            value = value >> 7
        return 9
    count = 1
    remaining = value
    while remaining > 127:
        remaining = remaining >> 7
        count = count + 1
    if length(o) < count:
        return 4294967292
    index = 0
    while index < count:
        shift = (count - 1 - index) * 7
        part = (value >> shift) & 127
        if index + 1 < count:
            part = part | 128
        store(o, index, part)
        index = index + 1
    return count

def input_word(s:readbuf) -> u64:
    value = 0
    index = 0
    while index < 8:
        value = value | (byte(s, index) << (index * 8))
        index = index + 1
    return value

def control_word(w:mutbuf, offset:u64) -> u64:
    value = 0
    index = 0
    while index < 8:
        value = value | (byte(w, offset + index) << (index * 8))
        index = index + 1
    return value

def write_word(o:mutbuf, value:u64) -> u64:
    index = 0
    while index < 8:
        store(o, index, (value >> (index * 8)) & 255)
        index = index + 1
    return 0
'''


def source():
    return SOURCE.replace('VARINT_MAGIC', str(MAGIC))


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
                                  'module': 'sqlite_varint', 'functions': functions})


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

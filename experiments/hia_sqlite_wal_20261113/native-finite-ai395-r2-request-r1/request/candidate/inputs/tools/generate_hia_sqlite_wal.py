"""Author the SQLite WAL checksum, header and frame byte kernels in HIA.

This module authors HIA/Core source. The emitted functions perform all checksum
arithmetic and format decisions. They do not open a database or acquire a lock.
An accepted frame is not, by itself, a committed or recoverable transaction.
"""
from __future__ import annotations

import ast
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions

SOURCE_PATH = 'examples/hia_bootstrap/sqlite_wal.hiaasm'
MAGIC = int.from_bytes(b'HIASWL01', 'little')
CHECKSUM, HEADER, FRAME = 1, 2, 3
REFUSE_PROTOCOL = 0xfffffffd
REFUSE_FORMAT = 0xfffffffc
REFUSE_CHECKSUM = 0xfffffffb
REFUSE_SALT = 0xfffffffa
REFUSE_VERSION = 0xfffffff9

SOURCE = r'''
def sqlite_wal(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) != 64:
        return 4294967293
    if control_word(w, 0) != WAL_COMMAND_MAGIC:
        return 4294967293
    operation = control_word(w, 8)
    order = control_word(w, 16)
    seed0 = control_word(w, 24)
    seed1 = control_word(w, 32)
    page_size = control_word(w, 40)
    salt0 = control_word(w, 48)
    salt1 = control_word(w, 56)
    if operation == 1:
        if length(o) != 8 or length(s) < 8 or length(s) > 65536:
            return 4294967293
        if (length(s) & 7) != 0 or order > 1:
            return 4294967293
        if seed0 > 4294967295 or seed1 > 4294967295:
            return 4294967293
        if page_size != 0 or salt0 != 0 or salt1 != 0:
            return 4294967293
        pair = checksum_region(s, 0, length(s), order, seed0, seed1)
        write_u32(o, 0, pair & 4294967295)
        write_u32(o, 4, pair >> 32)
        return 8
    if operation == 2:
        if length(s) != 32 or length(o) != 32:
            return 4294967293
        if order != 0 or seed0 != 0 or seed1 != 0:
            return 4294967293
        if page_size != 0 or salt0 != 0 or salt1 != 0:
            return 4294967293
        return check_header(s, o)
    if operation == 3:
        if length(o) != 16 or order > 1:
            return 4294967293
        if seed0 > 4294967295 or seed1 > 4294967295:
            return 4294967293
        if salt0 > 4294967295 or salt1 > 4294967295:
            return 4294967293
        if page_size < 512 or page_size > 65536:
            return 4294967293
        if (page_size & (page_size - 1)) != 0:
            return 4294967293
        if length(s) != page_size + 24:
            return 4294967293
        if word(s, 8, 1) != salt0 or word(s, 12, 1) != salt1:
            return 4294967290
        page_number = word(s, 0, 1)
        if page_number == 0:
            return 4294967292
        pair = checksum_region(s, 0, 8, order, seed0, seed1)
        pair = checksum_region(s, 24, page_size, order, pair & 4294967295, pair >> 32)
        if (pair & 4294967295) != word(s, 16, 1) or (pair >> 32) != word(s, 20, 1):
            return 4294967291
        write_u32(o, 0, pair & 4294967295)
        write_u32(o, 4, pair >> 32)
        write_u32(o, 8, page_number)
        write_u32(o, 12, word(s, 4, 1))
        return 16
    return 4294967293

def check_header(s:readbuf, o:mutbuf) -> u32:
    magic = word(s, 0, 1)
    page_size = word(s, 8, 1)
    if (magic & 4294967294) != 931071618:
        return 4294967292
    if page_size < 512 or page_size > 65536:
        return 4294967292
    if (page_size & (page_size - 1)) != 0:
        return 4294967292
    order = magic & 1
    pair = checksum_region(s, 0, 24, order, 0, 0)
    if (pair & 4294967295) != word(s, 24, 1) or (pair >> 32) != word(s, 28, 1):
        return 4294967291
    version = word(s, 4, 1)
    if version != 3007000:
        return 4294967289
    write_u32(o, 0, pair & 4294967295)
    write_u32(o, 4, pair >> 32)
    write_u32(o, 8, page_size)
    write_u32(o, 12, word(s, 12, 1))
    write_u32(o, 16, word(s, 16, 1))
    write_u32(o, 20, word(s, 20, 1))
    write_u32(o, 24, order)
    write_u32(o, 28, version)
    return 32

def checksum_region(s:readbuf, offset:u64, count:u64, order:u64, s0:u64, s1:u64) -> u64:
    index = 0
    while index < count:
        # Mask each update to the original unsigned 32-bit arithmetic.
        s0 = (s0 + word(s, offset + index, order) + s1) & 4294967295
        s1 = (s1 + word(s, offset + index + 4, order) + s0) & 4294967295
        index = index + 8
    return s0 | (s1 << 32)

def word(s:readbuf, offset:u64, order:u64) -> u64:
    result = 0
    index = 0
    while index < 4:
        if order == 1:
            result = (result << 8) | byte(s, offset + index)
        else:
            result = result | (byte(s, offset + index) << (index * 8))
        index = index + 1
    return result

def control_word(w:mutbuf, offset:u64) -> u64:
    value = 0
    index = 0
    while index < 8:
        value = value | (byte(w, offset + index) << (index * 8))
        index = index + 1
    return value

def write_u32(o:mutbuf, offset:u64, value:u64) -> u64:
    index = 0
    while index < 4:
        store(o, offset + index, (value >> (index * 8)) & 255)
        index = index + 1
    return 0
'''


def source():
    return SOURCE.replace('WAL_COMMAND_MAGIC', str(MAGIC))


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
                                  'module': 'sqlite_wal', 'functions': functions})


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

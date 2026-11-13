"""Author SQLite page-one geometry and ordered retry decisions in HIA.

The complete lockBtree bodies retained from SQLite 3.46.0 and 3.53.2 are
byte-identical. This core preserves their byte-admission order, including WAL
and page-size rereads. External locking, page acquisition, WAL opening and
pager page-size changes are requests to the caller, not simulated effects.
"""
from __future__ import annotations

import ast
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions

SOURCE_PATH = "examples/hia_bootstrap/sqlite_database_header.hiaasm"
COMMAND_MAGIC = int.from_bytes(b"HIADBH01", "little")
REPLY_MAGIC = int.from_bytes(b"HIADBR01", "little")
REFUSE_PROTOCOL = 0xfffffffd
ACCEPT, OPEN_WAL_AND_REREAD, RESIZE_AND_REREAD, FORMAT_ERROR = 1, 2, 3, 4

SOURCE = r'''
def sqlite_database_header(s:readbuf, o:mutbuf, c:readbuf) -> u32:
    if length(s) != 100 or length(o) != 256 or length(c) != 128:
        return 4294967293
    if protocol_ok(c) == 0:
        return 4294967293
    initialize(c, o)
    npage = header_word(s, 28)
    if npage == 0 or header_word(s, 24) != header_word(s, 92):
        npage = control_word(c, 32)
    if (control_word(c, 40) & 1) != 0:
        npage = 0
    if npage == 0:
        return finish(o, 0)
    return nonempty(s, c, o, npage)

def protocol_ok(c:readbuf) -> u64:
    if control_word(c, 0) != HEADER_COMMAND_MAGIC or control_word(c, 8) != 1:
        return 0
    page = control_word(c, 16)
    usable = control_word(c, 24)
    if page < 512 or page > 65536 or (page & (page - 1)) != 0:
        return 0
    if usable > page or page - usable > 255:
        return 0
    if control_word(c, 32) > 4294967295 or control_word(c, 40) > 63:
        return 0
    if control_word(c, 48) > 1:
        return 0
    offset = 56
    while offset < 128:
        if control_word(c, offset) != 0:
            return 0
        offset = offset + 8
    return 1

def initialize(c:readbuf, o:mutbuf) -> u64:
    offset = 0
    while offset < 256:
        store(o, offset, 0)
        offset = offset + 1
    write_word(o, 0, HEADER_REPLY_MAGIC)
    write_word(o, 24, (control_word(c, 40) >> 3) & 1)
    write_word(o, 32, control_word(c, 16))
    write_word(o, 40, control_word(c, 24))
    write_word(o, 56, (control_word(c, 40) >> 4) & 1)
    write_word(o, 64, (control_word(c, 40) >> 5) & 1)
    return 0

def nonempty(s:readbuf, c:readbuf, o:mutbuf, npage:u64) -> u32:
    if header_word(s, 0) != 1397836905 or header_word(s, 4) != 1952784486 or header_word(s, 8) != 1869770081 or header_word(s, 12) != 1948267264:
        return failure(o, 26)
    if byte(s, 18) > 2:
        write_word(o, 24, 1)
    if byte(s, 19) > 2:
        return failure(o, 26)
    if byte(s, 19) == 2 and (control_word(c, 40) & 4) == 0:
        write_word(o, 72, 2)
        if control_word(c, 48) == 0:
            write_word(o, 8, 2)
            return 256
    else:
        write_word(o, 72, 1)
    if byte(s, 21) != 64 or byte(s, 22) != 32 or byte(s, 23) != 32:
        return failure(o, 26)
    page = (byte(s, 16) << 8) | (byte(s, 17) << 16)
    if page <= 256 or page > 65536 or ((page - 1) & page) != 0:
        return failure(o, 26)
    usable = page - byte(s, 20)
    if page != control_word(c, 16):
        write_word(o, 32, page)
        write_word(o, 40, usable)
        write_word(o, 80, 1)
        write_word(o, 8, 3)
        return 256
    if npage > control_word(c, 32):
        if (control_word(c, 40) & 2) == 0:
            return failure(o, 11)
        npage = control_word(c, 32)
    if usable < 480:
        return failure(o, 26)
    write_word(o, 32, page)
    write_word(o, 40, usable)
    write_word(o, 80, 1)
    if header_word(s, 52) != 0:
        write_word(o, 56, 1)
    else:
        write_word(o, 56, 0)
    if header_word(s, 64) != 0:
        write_word(o, 64, 1)
    else:
        write_word(o, 64, 0)
    return finish(o, npage)

def finish(o:mutbuf, npage:u64) -> u32:
    usable = output_word(o, 40)
    max_local = divide32((usable - 12) * 64, 255) - 23
    min_local = divide32((usable - 12) * 32, 255) - 23
    write_word(o, 8, 1)
    write_word(o, 48, npage)
    write_word(o, 88, max_local)
    write_word(o, 96, min_local)
    write_word(o, 104, usable - 35)
    write_word(o, 112, min_local)
    if max_local > 127:
        write_word(o, 120, 127)
    else:
        write_word(o, 120, max_local)
    return 256

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

def failure(o:mutbuf, rc:u64) -> u32:
    write_word(o, 8, 4)
    write_word(o, 16, rc)
    return 256

def write_word(o:mutbuf, offset:u64, value:u64) -> u64:
    index = 0
    while index < 8:
        store(o, offset + index, (value >> (8 * index)) & 255)
        index = index + 1
    return 0

def control_word(c:readbuf, offset:u64) -> u64:
    value = 0
    index = 0
    while index < 8:
        value = value | (byte(c, offset + index) << (8 * index))
        index = index + 1
    return value

def output_word(o:mutbuf, offset:u64) -> u64:
    value = 0
    index = 0
    while index < 8:
        value = value | (byte(o, offset + index) << (8 * index))
        index = index + 1
    return value

def header_word(s:readbuf, offset:u64) -> u64:
    value = 0
    index = 0
    while index < 4:
        value = (value << 8) | byte(s, offset + index)
        index = index + 1
    return value
'''


def source():
    return (SOURCE.replace("HEADER_COMMAND_MAGIC", str(COMMAND_MAGIC))
            .replace("HEADER_REPLY_MAGIC", str(REPLY_MAGIC)))


def document():
    nodes = ast.parse(source()).body
    names = {node.name: "f" + str(index) for index, node in enumerate(nodes)}
    signatures = {node.name: ([argument.annotation.id for argument in node.args.args],
                              node.returns.id) for node in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = Builder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({"name": names[node.name],
                          "params": [builder.param(value) for value in builder.params],
                          "returns": [builder.returns],
                          "effects": ["read", "write", "trap"],
                          "entry": "b0", "blocks": builder.blocks})
    return compact_authoring_cfg({"schema": "hepta.hia.program.v8",
                                  "module": "sqlite_database_header", "functions": functions})


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args()
    destination = arguments.output
    mode = "x"
    if destination is None:
        destination = Path(__file__).resolve().parents[1] / SOURCE_PATH
        mode = "w"
    with destination.open(mode, encoding="utf-8", newline="\n") as stream:
        stream.write(render_assembly(document()))
    print(destination.name, destination.stat().st_size)


if __name__ == "__main__":
    main()

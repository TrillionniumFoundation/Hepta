"""Author the streaming SQLite WAL committed-snapshot and page-location core.

No database file, lock, WAL index, Python SQLite API or default AgentStore hook is
used here. A snapshot is a validated byte-prefix description; the caller must
hold the external read/recovery locks and keep the database/WAL generation stable.
The fixed state never stores an entire WAL, database or per-page frame map.
"""
from __future__ import annotations

import ast
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions

SOURCE_PATH = "examples/hia_bootstrap/sqlite_wal_snapshot.hiaasm"
COMMAND_MAGIC = int.from_bytes(b"HIASWS01", "little")
STATE_MAGIC = int.from_bytes(b"HIASWT01", "little")
REPLY_MAGIC = int.from_bytes(b"HIASWR01", "little")
START, HEADER, FRAME, LOOKUP, FINISH = 1, 2, 3, 4, 5
REFUSE_PROTOCOL = 0xfffffffd
REFUSE_VERSION = 0xfffffff9
REFUSE_SNAPSHOT = 0xfffffff8

# checksum_region, word and control_word below are verbatim from the retained
# 7eb498e3 WAL author. Their arithmetic and byte-observation order are unchanged.
SOURCE = r'''
def sqlite_wal_snapshot(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(o) != 128 or length(w) != 256 or length(s) < 16:
        return 4294967293
    if input_word(s, 0) != SNAPSHOT_COMMAND_MAGIC:
        return 4294967293
    operation = input_word(s, 8)
    if operation == 1:
        return start_scan(s, o, w)
    if control_word(w, 0) != SNAPSHOT_STATE_MAGIC:
        return 4294967293
    if operation == 2:
        return consume_header(s, o, w)
    if operation == 3:
        return consume_frame(s, o, w)
    if operation == 4:
        return start_lookup(s, o, w)
    if operation == 5:
        return finish(s, o, w)
    return 4294967293

def start_scan(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) != 40:
        return 4294967293
    wal_bytes = input_word(s, 16)
    base_pages = input_word(s, 24)
    base_size = input_word(s, 32)
    if wal_bytes > 9223372036854775807 or base_pages > 4294967295:
        return 4294967293
    if base_size < 512 or base_size > 65536:
        return 4294967293
    if (base_size & (base_size - 1)) != 0:
        return 4294967293
    index = 0
    while index < 256:
        if byte(w, index) != 0:
            return 4294967293
        index = index + 1
    write_word(w, 0, SNAPSHOT_STATE_MAGIC)
    write_word(w, 8, 1)
    write_word(w, 16, 1)
    write_word(w, 24, wal_bytes)
    write_word(w, 32, base_pages)
    write_word(w, 120, 32)
    write_word(w, 136, base_pages)
    write_word(w, 216, base_size)
    if wal_bytes <= 32:
        write_word(w, 8, 3)
        write_word(w, 168, 1)
    return reply(o, w)

def consume_header(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) != 48 or control_word(w, 8) != 1:
        return 4294967293
    mode = control_word(w, 16)
    if mode != 1 and mode != 2:
        return 4294967293
    magic = word(s, 16, 1)
    page_size = word(s, 24, 1)
    if mode == 2:
        if magic != 931071618 + control_word(w, 48):
            return 4294967288
        if word(s, 20, 1) != 3007000 or page_size != control_word(w, 40):
            return 4294967288
        if word(s, 28, 1) != control_word(w, 72):
            return 4294967288
        if word(s, 32, 1) != control_word(w, 56) or word(s, 36, 1) != control_word(w, 64):
            return 4294967288
        if word(s, 40, 1) != control_word(w, 80) or word(s, 44, 1) != control_word(w, 88):
            return 4294967288
    if (magic & 4294967294) != 931071618:
        return stop_scan(o, w, 3)
    if page_size < 512 or page_size > 65536:
        return stop_scan(o, w, 3)
    if (page_size & (page_size - 1)) != 0:
        return stop_scan(o, w, 3)
    order = magic & 1
    pair = checksum_region(s, 16, 24, order, 0, 0)
    if (pair & 4294967295) != word(s, 40, 1) or (pair >> 32) != word(s, 44, 1):
        if mode == 2:
            return 4294967288
        return stop_scan(o, w, 4)
    if word(s, 20, 1) != 3007000:
        return 4294967289
    if mode == 1:
        write_word(w, 40, page_size)
        write_word(w, 48, order)
        write_word(w, 56, word(s, 32, 1))
        write_word(w, 64, word(s, 36, 1))
        write_word(w, 72, word(s, 28, 1))
        write_word(w, 80, pair & 4294967295)
        write_word(w, 88, pair >> 32)
    write_word(w, 96, pair & 4294967295)
    write_word(w, 104, pair >> 32)
    write_word(w, 8, 2)
    if mode == 1:
        if control_word(w, 24) - 32 < page_size + 24:
            write_word(w, 8, 3)
            write_word(w, 168, 2)
    return reply(o, w)

def consume_frame(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if control_word(w, 8) != 2:
        return 4294967293
    mode = control_word(w, 16)
    if mode != 1 and mode != 2:
        return 4294967293
    page_size = control_word(w, 40)
    if page_size < 512 or page_size > 65536:
        return 4294967293
    if (page_size & (page_size - 1)) != 0 or control_word(w, 48) > 1:
        return 4294967293
    if control_word(w, 56) > 4294967295 or control_word(w, 64) > 4294967295:
        return 4294967293
    if control_word(w, 96) > 4294967295 or control_word(w, 104) > 4294967295:
        return 4294967293
    extent = control_word(w, 24)
    offset = control_word(w, 120)
    if extent > 9223372036854775807 or offset < 32 or offset > extent:
        return 4294967293
    if extent - offset < page_size + 24 or control_word(w, 112) >= 9223372036854775807:
        return 4294967293
    if length(s) != page_size + 40:
        return 4294967293
    if word(s, 24, 1) != control_word(w, 56) or word(s, 28, 1) != control_word(w, 64):
        if mode == 2:
            return 4294967288
        return stop_scan(o, w, 5)
    page_number = word(s, 16, 1)
    if page_number == 0:
        if mode == 2:
            return 4294967288
        return stop_scan(o, w, 6)
    before0 = control_word(w, 96)
    before1 = control_word(w, 104)
    order = control_word(w, 48)
    pair = checksum_region(s, 16, 8, order, before0, before1)
    pair = checksum_region(s, 40, page_size, order, pair & 4294967295, pair >> 32)
    after0 = pair & 4294967295
    after1 = pair >> 32
    if after0 != word(s, 32, 1) or after1 != word(s, 36, 1):
        if mode == 2:
            return 4294967288
        return stop_scan(o, w, 7)
    frame_number = control_word(w, 112) + 1
    frame_offset = control_word(w, 120)
    next_offset = frame_offset + page_size + 24
    database_pages = word(s, 20, 1)
    if mode == 2:
        if frame_number > control_word(w, 128):
            return 4294967288
        if frame_number == control_word(w, 128):
            if next_offset != control_word(w, 160) or database_pages != control_word(w, 136):
                return 4294967288
            if after0 != control_word(w, 144) or after1 != control_word(w, 152):
                return 4294967288
    write_word(w, 96, after0)
    write_word(w, 104, after1)
    write_word(w, 112, frame_number)
    write_word(w, 120, next_offset)
    if mode == 1:
        if database_pages != 0:
            write_word(w, 128, frame_number)
            write_word(w, 136, database_pages)
            write_word(w, 144, after0)
            write_word(w, 152, after1)
            write_word(w, 160, next_offset)
        remaining = control_word(w, 24) - next_offset
        if remaining < page_size + 24:
            write_word(w, 8, 3)
            write_word(w, 168, 0)
            if remaining != 0:
                write_word(w, 168, 2)
    else:
        if page_number == control_word(w, 176):
            write_word(w, 184, frame_number)
            write_word(w, 192, frame_offset)
            write_word(w, 200, after0)
            write_word(w, 208, after1)
            write_word(w, 232, before0)
            write_word(w, 240, before1)
            write_word(w, 224, 2)
        if frame_number == control_word(w, 128):
            write_word(w, 8, 3)
    return reply(o, w)

def start_lookup(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) != 24 or control_word(w, 8) != 4 or control_word(w, 16) != 1:
        return 4294967293
    page_number = input_word(s, 16)
    if page_number == 0 or page_number > 4294967295:
        return 4294967293
    write_word(w, 16, 2)
    write_word(w, 8, 1)
    write_word(w, 96, control_word(w, 80))
    write_word(w, 104, control_word(w, 88))
    write_word(w, 112, 0)
    write_word(w, 120, 32)
    write_word(w, 176, page_number)
    write_word(w, 224, 1)
    if page_number > control_word(w, 136):
        write_word(w, 224, 0)
        write_word(w, 8, 3)
    else:
        if control_word(w, 128) == 0:
            write_word(w, 8, 3)
    return reply(o, w)

def finish(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) != 16 or control_word(w, 8) != 3:
        return 4294967293
    mode = control_word(w, 16)
    if mode == 1:
        write_word(w, 8, 4)
        return reply(o, w)
    if mode == 2:
        write_word(w, 8, 5)
        return reply(o, w)
    return 4294967293

def stop_scan(o:mutbuf, w:mutbuf, reason:u64) -> u32:
    if control_word(w, 16) != 1:
        return 4294967288
    write_word(w, 8, 3)
    write_word(w, 168, reason)
    return reply(o, w)

def reply(o:mutbuf, w:mutbuf) -> u32:
    index = 0
    while index < 128:
        store(o, index, 0)
        index = index + 1
    phase = control_word(w, 8)
    mode = control_word(w, 16)
    action = 3
    offset = 0
    count = 0
    frame_number = control_word(w, 112)
    page_size = control_word(w, 40)
    if phase != 2:
        if control_word(w, 128) == 0:
            page_size = control_word(w, 216)
    if phase == 1:
        action = 1
        offset = 0
        count = 32
        frame_number = 0
    if phase == 2:
        action = 2
        offset = control_word(w, 120)
        count = control_word(w, 40) + 24
        frame_number = frame_number + 1
    if phase == 3:
        if mode == 2:
            action = 4
    if phase == 4:
        action = 5
    if phase == 5:
        action = 6
        location = control_word(w, 224)
        offset = 0
        frame_number = 0
        if location == 1:
            offset = (control_word(w, 176) - 1) * page_size
            count = page_size
        if location == 2:
            offset = control_word(w, 192) + 24
            count = page_size
            frame_number = control_word(w, 184)
            write_word(o, 96, control_word(w, 232))
            write_word(o, 104, control_word(w, 240))
            write_word(o, 112, control_word(w, 200))
            write_word(o, 120, control_word(w, 208))
    write_word(o, 0, SNAPSHOT_REPLY_MAGIC)
    write_word(o, 8, action)
    write_word(o, 16, offset)
    write_word(o, 24, count)
    write_word(o, 32, frame_number)
    write_word(o, 40, page_size)
    write_word(o, 48, control_word(w, 136))
    write_word(o, 56, control_word(w, 128))
    write_word(o, 64, control_word(w, 160))
    write_word(o, 72, control_word(w, 168))
    write_word(o, 80, control_word(w, 176))
    write_word(o, 88, control_word(w, 224))
    return 128

def write_word(w:mutbuf, offset:u64, value:u64) -> u64:
    index = 0
    while index < 8:
        store(w, offset + index, (value >> (index * 8)) & 255)
        index = index + 1
    return 0

def input_word(s:readbuf, offset:u64) -> u64:
    value = 0
    index = 0
    while index < 8:
        value = value | (byte(s, offset + index) << (index * 8))
        index = index + 1
    return value

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
'''


def source():
    return (SOURCE.replace("SNAPSHOT_COMMAND_MAGIC", str(COMMAND_MAGIC))
            .replace("SNAPSHOT_STATE_MAGIC", str(STATE_MAGIC))
            .replace("SNAPSHOT_REPLY_MAGIC", str(REPLY_MAGIC)))


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
                                  "module": "sqlite_wal_snapshot", "functions": functions})


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

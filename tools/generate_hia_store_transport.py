"""Author HIA's native Store command and response protocol."""
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'examples/hia_bootstrap/agent_store_transport.hepta'

WIRE = {
    'BUILD_COMMAND': b'HIASTCM1',
    'READ_ACK': b'HIASTAK1',
    'READ_ROW': b'HIASTRW1',
    'READ_EVENT': b'HIASTEV1',
    'READ_VALUES': b'HIASTVL1',
    'READ_TRANSACTION': b'HIASTTX1',
    'COMMAND': b'HIATCM01',
    'ACK': b'HIATXR01',
    'ROW': b'HIAQRF01',
    'VALUES': b'HIAROW01',
    'WAL_TRANSACTION': b'HIAWTA01',
    'WAL_ANCHOR': b'HIAWAK01',
}

POLICY = '''
def store_transport(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 8:
        return 0
    role = read_word(s, 0)
    if role == BUILD_COMMAND:
        if length(s) != 40 or length(o) != 48 or read_word(s, 8) == 0:
            return 0
        write_word(o, 0, COMMAND)
        write_word(o, 8, 1)
        copy_fields(s, o, 8, 16, 32)
        return 48
    if role == READ_ACK:
        if length(s) != 104 or length(o) != 48:
            return 0
        if read_word(s, 24) != ACK or read_word(s, 32) != 1:
            return 0
        if read_word(s, 40) != read_word(s, 8) or read_word(s, 48) != read_word(s, 16):
            return 0
        copy_fields(s, o, 56, 0, 48)
        return 48
    if role == READ_ROW:
        if length(s) != 88 or length(o) != 56:
            return 0
        if read_word(s, 24) != ROW or read_word(s, 40) != read_word(s, 8):
            return 0
        if read_word(s, 64) > read_word(s, 16) or read_word(s, 80) != 0:
            return 0
        copy_fields(s, o, 32, 0, 56)
        return 56
    if role == READ_EVENT:
        if length(o) != 16 or length(s) < 104:
            return 0
        return store_query_event(s, o)
    if role == READ_VALUES:
        if length(o) != 16 or length(s) < 32:
            return 0
        return store_values(s, o)
    if role == READ_TRANSACTION:
        if length(o) != 16 or (length(s) != 48 and length(s) != 304):
            return 0
        return store_transaction(s, o)
    return 0

def store_query_event(s:readbuf, o:mutbuf) -> u64:
    kind = read_word(s, 8)
    size = read_word(s, 32)
    active = read_word(s, 40)
    if active > 1 or read_word(s, 80) > 1:
        return 0
    if kind == 4 and active == 0 and size == 416 and length(s) == 520:
        return query_summary(s, o)
    if length(s) != 104:
        return 0
    if kind == 1 and active == 0 and size == 128 and read_word(s, 24) == 0:
        return event_result(o, 1, 0)
    if active == 1 and read_word(s, 16) == read_word(s, 48) and read_word(s, 24) == read_word(s, 56):
        if kind == 2:
            used = read_word(s, 56)
            limit = read_word(s, 64)
            if size == 0 or used > limit or size > limit - used:
                return event_result(o, 101, 0)
            return event_result(o, 2, 0)
        if kind == 3 and size == 0:
            if read_word(s, 80) != 0 and read_word(s, 72) != 0:
                return event_result(o, 102, 0)
            return event_result(o, 3, 0)
    return event_result(o, 104, 0)

def query_summary(s:readbuf, o:mutbuf) -> u64:
    if read_word(s, 488) != read_word(s, 88) or read_word(s, 496) != read_word(s, 96) or read_word(s, 512) != read_word(s, 72):
        return event_result(o, 103, 0)
    return event_result(o, 4, read_word(s, 504))

def store_values(s:readbuf, o:mutbuf) -> u64:
    extent = read_word(s, 24)
    if extent < 32:
        return event_result(o, 2, 0)
    if length(s) < 64 or read_word(s, 32) != VALUES or read_word(s, 40) != 1:
        return event_result(o, 3, 0)
    if read_word(s, 16) != read_word(s, 48):
        return event_result(o, 3, 0)
    count = read_word(s, 56)
    directory = length(s) - 64
    if count != read_word(s, 8) or count > directory:
        return event_result(o, 3, 0)
    if directory != count * 24 or extent < directory + 32:
        return event_result(o, 3, 0)
    offset = directory + 32
    index = 0
    while index < count:
        cell = 64 + index * 24
        kind = read_word(s, cell)
        size = read_word(s, cell + 16)
        if read_word(s, cell + 8) != offset or size > extent - offset:
            return event_result(o, 4, index)
        if kind > 4 or (kind == 0 and size != 0) or ((kind == 1 or kind == 2) and size != 8):
            return event_result(o, 5, index)
        offset = offset + size
        index = index + 1
    if offset != extent:
        return event_result(o, 6, count)
    return event_result(o, 1, count)

def store_transaction(s:readbuf, o:mutbuf) -> u64:
    kind = read_word(s, 8)
    status = read_word(s, 16)
    count = read_word(s, 24)
    previous = read_word(s, 32)
    generation = read_word(s, 40)
    receipt = length(s) == 304
    if kind == 0 or kind == 21:
        if receipt or status != 0 or (kind == 21 and generation < previous):
            return event_result(o, 2, 0)
        return event_result(o, 1, generation)
    if kind != 2 and kind != 3:
        return 0
    advance = kind == 2 and count != 0
    if status != 0 or generation < previous or receipt != advance:
        return event_result(o, 3, 0)
    if advance:
        if generation - previous != 1:
            return event_result(o, 3, 0)
        if read_word(s, 48) != WAL_TRANSACTION or read_word(s, 176) != WAL_ANCHOR:
            return event_result(o, 4, 0)
        if read_word(s, 184) != 1 or read_word(s, 192) != generation:
            return event_result(o, 4, 0)
    elif generation != previous:
        return event_result(o, 3, 0)
    return event_result(o, 1, generation)

def event_result(o:mutbuf, decision:u64, total:u64) -> u64:
    write_word(o, 0, decision)
    write_word(o, 8, total)
    return 16

def read_word(s:readbuf, at:u64) -> u64:
    count = 0
    value = 0
    while count < 8:
        value = value | (byte(s, at + count) << (count * 8))
        count = count + 1
    return value

def write_word(o:mutbuf, at:u64, value:u64) -> u64:
    count = 0
    while count < 8:
        store(o, at + count, (value >> (count * 8)) & 255)
        count = count + 1
    return 0

def copy_fields(s:readbuf, o:mutbuf, start:u64, end:u64, extent:u64) -> u64:
    index = 0
    while index < extent:
        store(o, end + index, byte(s, start + index))
        index = index + 1
    return 0
'''


def source_program():
    import re

    return re.sub(r'\b(' + '|'.join(WIRE) + r')\b',
        lambda name: str(int.from_bytes(WIRE[name.group()], 'little')), POLICY)


if __name__ == '__main__':
    program = document(source_program(), module='agent_store_transport')
    SOURCE.write_text(render_assembly(program))

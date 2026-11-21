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
    'BUILD_PARAMETERS': b'HIASTPA1',
    'UNIQUE_START': b'HIASTUR1',
    'UNIQUE_REQUEST': b'HIASTUP1',
    'UNIQUE_CONSUME': b'HIASTUC1',
    'COMMAND': b'HIATCM01',
    'ACK': b'HIATXR01',
    'ROW': b'HIAQRF01',
    'VALUES': b'HIAROW01',
    'WAL_TRANSACTION': b'HIAWTA01',
    'WAL_ANCHOR': b'HIAWAK01',
    'QUERY_PARAMETERS': b'HIAQPA01',
    'INSERT_PARAMETERS': b'HIAINS01',
    'UPDATE_PARAMETERS': b'HIAUPB01',
}

POLICY = '''
def store_transport(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 8:
        return 0
    role = read_word(s, 0)
    if role == UNIQUE_START or role == UNIQUE_REQUEST or role == UNIQUE_CONSUME:
        return unique_stream(s, o, w, role)
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
    if role == BUILD_PARAMETERS:
        if length(s) < 40:
            return 0
        return store_parameters(s, o)
    return 0

# All three indexed read methods share this immutable transaction envelope.
# Mode 0 borrows an already-open transaction. Mode 1 owns BEGIN and ROLLBACK.
# Mode 2 owns ROLLBACK after readiness of a freshly connected Store.
def request_unique(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    if length(w) != 2304 or length(s) < 105 or read_state(w, 0) != 0:
        return 0
    request = read_word(s, 8)
    plan = read_word(s, 16)
    mode = read_word(s, 24)
    generation = read_word(s, 32)
    size = read_word(s, 40)
    if request > 18446744073709551612 or mode > 2 or size != length(s) - 48:
        return 0
    if plan != 2 and plan != 3 and plan != 6:
        return 0
    cap = choose(plan == 2, 192, choose(plan == 3, 208, 2048))
    if size > 56 + cap or read_word(s, 48) != QUERY_PARAMETERS:
        return 0
    if read_word(s, 56) != 1 or read_word(s, 64) != 1 or read_word(s, 72) != size:
        return 0
    if read_word(s, 80) != 3 or read_word(s, 88) != 56 or read_word(s, 96) != size - 56:
        return 0
    configure_unique(w, request, plan)
    write_word(w, 112, mode)
    write_word(w, 120, generation)
    write_word(w, 128, size)
    write_word(w, 136, 1)
    copy_fields(s, w, 48, 192, size)
    if mode == 1:
        return send_unique(o, w, 21, 0, 0, 6)
    return issue_unique_query(o, w)

def configure_unique(w:mutbuf, request:u64, plan:u64) -> u64:
    write_word(w, 8, request)
    write_word(w, 16, plan)
    write_word(w, 24, choose(plan == 6, 6, 1))
    write_word(w, 32, choose(plan == 6, 15, 63))
    return write_word(w, 40, choose(plan == 6, 512, 1000000032))

def issue_unique_query(o:mutbuf, w:mutbuf) -> u64:
    return send_unique(o, w, 27, read_state(w, 16) + 3, read_state(w, 128), 1)

def send_unique(o:mutbuf, w:mutbuf, kind:u64, target:u64, extent:u64, phase:u64) -> u64:
    request = read_state(w, 8) + 1
    write_word(w, 8, request)
    write_word(w, 0, phase)
    write_word(o, 0, 4)
    write_word(o, 8, 48 + extent)
    write_word(o, 16, 8)
    write_word(o, 32, COMMAND)
    write_word(o, 40, 1)
    write_word(o, 48, request)
    write_word(o, 56, kind)
    write_word(o, 64, target)
    write_word(o, 72, extent)
    at = 0
    while at < extent:
        store(o, 80 + at, byte(w, 192 + at))
        at = at + 1
    return 80 + extent

def unique_transaction(s:readbuf, o:mutbuf, w:mutbuf, phase:u64) -> u64:
    if length(w) != 2304:
        return 0
    if phase == 6 or phase == 8:
        if length(s) != 16 or read_word(s, 8) != ACK:
            return 0
        return stream_read(o, w, phase + 1, 72)
    if length(s) != 80 or read_word(s, 8) != 1 or read_word(s, 16) != read_state(w, 8):
        return 0
    if read_word(s, 32) != 0:
        return 0
    generation = read_word(s, 48)
    if phase == 7:
        if read_word(s, 24) != 21 or generation < read_state(w, 120):
            return 0
        write_word(w, 120, generation)
        return issue_unique_query(o, w)
    if phase != 9 or read_word(s, 24) != 3 or generation != read_state(w, 120):
        return 0
    return finish_unique(o, w)

def finish_unique(o:mutbuf, w:mutbuf) -> u64:
    write_word(w, 0, 5)
    write_word(o, 0, 5)
    write_word(o, 8, read_state(w, 48))
    write_word(o, 16, read_state(w, 80))
    write_word(o, 32, read_state(w, 8))
    write_word(o, 40, read_state(w, 120))
    return 48

# A durable indexed read is exactly one authenticated summary and final
# acknowledgement around at most one row. The transport only delivers the
# requested byte extents and copies accepted fragments to its private sink.
def unique_stream(s:readbuf, o:mutbuf, w:mutbuf, role:u64) -> u64:
    if (length(w) != 128 and length(w) != 2304) or length(o) < 8160:
        return 0
    write_word(o, 16, 0)
    write_word(o, 24, 0)
    if role == UNIQUE_REQUEST:
        return request_unique(s, o, w)
    if role == UNIQUE_START:
        if length(s) != 24 or read_state(w, 0) != 0:
            return 0
        request = read_word(s, 8)
        plan = read_word(s, 16)
        if request == 0 or (plan != 2 and plan != 3 and plan != 6):
            return 0
        configure_unique(w, request, plan)
        return stream_read(o, w, 1, 8)
    phase = read_state(w, 0)
    if phase >= 6:
        return unique_transaction(s, o, w, phase)
    if phase == 1 and length(s) == 16:
        magic = read_word(s, 8)
        if magic == ACK and read_state(w, 56) == 1:
            return stream_read(o, w, 4, 72)
        if magic == ROW and read_state(w, 56) == 0:
            return stream_read(o, w, 2, 56)
    elif phase == 2 and length(s) == 64:
        return stream_header(s, o, w)
    elif phase == 3:
        return stream_payload(s, o, w)
    elif phase == 4 and length(s) == 80:
        if read_word(s, 8) != 1 or read_word(s, 16) != read_state(w, 8):
            return 0
        if read_word(s, 24) != 27 or read_word(s, 32) != 0:
            return 0
        if length(w) == 2304 and read_state(w, 136) == 1:
            if read_state(w, 112) == 0:
                return finish_unique(o, w)
            return send_unique(o, w, 3, 0, 0, 8)
        write_word(w, 0, 5)
        write_word(o, 0, 3)
        write_word(o, 8, read_state(w, 48))
        write_word(o, 16, read_state(w, 80))
        return 32
    return 0

def stream_header(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    kind = read_word(s, 8)
    table = read_word(s, 16)
    identity = read_word(s, 24)
    offset = read_word(s, 32)
    extent = read_word(s, 40)
    active = read_state(w, 64)
    used = read_state(w, 48)
    if table != read_state(w, 24) or extent > 8128 or read_word(s, 56) != 0:
        return 0
    if kind == 1 and active == 0 and extent == 128 and offset == 0:
        write_word(w, 96, identity)
    elif kind == 4:
        if active != 0 or extent != 416:
            return 0
    else:
        if active != 1 or identity != read_state(w, 72) or offset != used:
            return 0
        if kind == 3 and extent == 0 and read_state(w, 80) == 0:
            write_word(w, 64, 0)
            write_word(w, 80, 1)
            return stream_read(o, w, 1, 8)
        if kind != 2 or extent == 0 or extent > read_state(w, 40) - used:
            return 0
    write_word(w, 88, kind)
    write_word(w, 104, extent)
    return stream_read(o, w, 3, extent)

def stream_payload(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    extent = read_state(w, 104)
    if length(s) != 8 + extent:
        return 0
    kind = read_state(w, 88)
    if kind == 1:
        if read_state(w, 80) != 0:
            return 0
        write_word(w, 64, 1)
        write_word(w, 72, read_state(w, 96))
    elif kind == 2:
        used = read_state(w, 48)
        write_word(w, 0, 1)
        write_word(w, 48, used + extent)
        write_word(o, 0, 2)
        write_word(o, 8, extent)
        write_word(o, 16, used)
        copy_fields(s, o, 8, 32, extent)
        return 32 + extent
    elif kind == 4:
        if read_word(s, 392) != read_state(w, 16) or read_word(s, 400) != read_state(w, 32):
            return 0
        if read_word(s, 416) != read_state(w, 80):
            return 0
        write_word(w, 56, 1)
    else:
        return 0
    return stream_read(o, w, 1, 8)

def stream_read(o:mutbuf, w:mutbuf, phase:u64, extent:u64) -> u64:
    write_word(w, 0, phase)
    write_word(o, 0, 1)
    write_word(o, 8, extent)
    return 32

def read_state(w:mutbuf, at:u64) -> u64:
    count = 0
    value = 0
    while count < 8:
        value = value | (byte(w, at + count) << (count * 8))
        count = count + 1
    return value

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

def store_parameters(s:readbuf, o:mutbuf) -> u64:
    form = read_word(s, 8)
    count = read_word(s, 24)
    limit = read_word(s, 32)
    fields = length(s) - 40
    if count > fields or fields != count * 16:
        return 0
    header = 40
    if form == QUERY_PARAMETERS:
        header = 32
    elif form != INSERT_PARAMETERS and form != UPDATE_PARAMETERS:
        return 0
    directory_end = header + count * 24
    if length(o) != directory_end or directory_end > limit:
        return 0
    offset = directory_end
    index = 0
    while index < count:
        cell = 40 + index * 16
        target = header + index * 24
        kind = read_word(s, cell)
        size = read_word(s, cell + 8)
        if size > limit - offset:
            return 0
        if kind > 4 or (kind == 0 and size != 0) or ((kind == 1 or kind == 2) and size != 8):
            return 0
        write_word(o, target, kind)
        write_word(o, target + 8, offset)
        write_word(o, target + 16, size)
        offset = offset + size
        index = index + 1
    write_word(o, 0, form)
    write_word(o, 8, 1)
    if header == 32:
        write_word(o, 16, count)
        write_word(o, 24, offset)
    else:
        write_word(o, 16, read_word(s, 16))
        write_word(o, 24, 0)
        write_word(o, 32, count)
    return directory_end

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

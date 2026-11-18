"""Author the HIA controller for projecting a retained Agent snapshot."""
from pathlib import Path
import re

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_sqlite_agent_catalog import POLICY as CATALOG


POLICY = '''
def project(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 568 or length(w) < DENSE + length(s) or length(o) < 64:
        return 64
    state = get(w, STATE)
    if state == 0:
        return begin(s, w)
    if get(w, STATUS) != 0:
        return 65
    if state == CATALOG_OPEN:
        return start_walk(w, 1)
    if state == WALK_OPEN:
        return table_page(s, w, get(w, ROOT))
    if state == PAGE_READ:
        return walk_page(w)
    if state == WALK_PAGE:
        if get(w, TABLE) == 0:
            put(w, CAT_COUNT, get(w, WALK_RESULT + 24))
            put(w, CAT_CURSOR, 0)
            return next_catalog_row(s, w)
        return plan_page(w)
    if state == ROW_READ:
        return describe_row(w)
    if state == ROW_LAYOUT:
        return typed_row(w)
    if state == CATALOG_ROW:
        return next_catalog_row(s, w)
    if state == CATALOG_END:
        return start_plan(w)
    if state == PLAN_INITIAL or state == PLAN_PAGE:
        return advance(s, o, w)
    if state == ROW_PROJECTION:
        return plan_row(w)
    if state == PLAN_ROW:
        if append_row(o, w) != 0:
            return 66
        return advance(s, o, w)
    return 64

def begin(s:readbuf, w:mutbuf) -> u32:
    if uint(s, 0) != SNAPSHOT or uint(s, 8) == 0 or uint(s, 56) != SQLITE:
        return 64
    pages = uint(s, 16)
    size = uint(s, 24)
    if size < 512 or size > 65536 or (size & (size - 1)) != 0:
        return 64
    if pages < 12 or pages > 524288 or length(s) != 56 + pages * size:
        return 64
    header_size = byte(s, 72) * 256 + byte(s, 73)
    if size == 65536:
        if header_size != 1:
            return 64
    elif header_size != size:
        return 64
    if byte(s, 74) != 2 or byte(s, 75) != 2:
        return 64
    put(w, SIZE, size)
    put(w, PAGES, pages)
    put(w, TX, uint(s, 8))
    put(w, ID, uint(s, 32))
    put(w, ID + 8, uint(s, 40))
    put(w, ID + 16, uint(s, 48))
    put(w, CURSOR, 64)
    copy_source(s, w, 56, DENSE + 16, pages * size)
    # Only the private dense lookup copy has rollback-format mode bytes.
    store(w, DENSE + 34, 1)
    store(w, DENSE + 35, 1)
    put(w, Q, CATALOG_REQUEST)
    put(w, Q + 8, 1)
    put(w, Q + 16, pages)
    put(w, Q + 24, 1)
    return dispatch(w, CATALOG_OPEN, CATALOG, Q, 32, R, 112, CAT_WS, 1024)

def start_walk(w:mutbuf, root:u64) -> u32:
    put(w, ROOT, root)
    put(w, WALK_WS, 0)
    prefix(w, Q, WALK_REQUEST, 1)
    put(w, Q + 40, get(w, PAGES))
    put(w, Q + 48, root)
    return dispatch(w, WALK_OPEN, WALK, Q, 56, WALK_RESULT, LIST, WALK_WS, walk_space(w))

def table_page(s:readbuf, w:mutbuf, page:u64) -> u32:
    size = get(w, SIZE)
    if page < 1 or page > get(w, PAGES):
        return 65
    put(w, PAGE, page)
    put(w, Q, page | (HSP2 << 32))
    put(w, Q + 8, 0)
    copy_source(s, w, 56, Q + 16, size)
    put(w, Q + 16 + size, get(w, PAGES))
    if page == 1:
        put(w, Q + 24 + size, 0)
        return dispatch(w, PAGE_READ, LOOKUP, Q, 32 + size, R, LIST, ROW_WS, 72)
    put(w, Q + 24 + size, 1)
    put(w, Q + 32 + size, page)
    copy_source(s, w, 56 + (page - 1) * size, Q + 40 + size, size)
    return dispatch(w, PAGE_READ, LOOKUP, Q, 40 + size * 2, R, LIST, ROW_WS, 72)

def walk_page(w:mutbuf) -> u32:
    count = get(w, R + 16)
    if get(w, R) != BTREE or count > 32769:
        return 65
    prefix(w, Q, WALK_REQUEST, 2)
    move(w, R, Q + 40, 32 + count * 8)
    return dispatch(w, WALK_PAGE, WALK, Q, 72 + count * 8, WALK_RESULT, LIST, WALK_WS, walk_space(w))

def walk_space(w:mutbuf) -> u64:
    count = get(w, PAGES)
    return 81 + (count >> 3) + count * 8

def next_catalog_row(s:readbuf, w:mutbuf) -> u32:
    count = get(w, CAT_COUNT)
    cursor = get(w, CAT_CURSOR)
    if get(w, WALK_RESULT) != WALK_REPLY or count > 32769:
        return 65
    if cursor < count:
        put(w, CAT_CURSOR, cursor + 1)
        return lookup_row(w, get(w, WALK_RESULT + 32 + cursor * 8))
    next_page = get(w, WALK_RESULT + 16)
    if next_page != 0:
        return table_page(s, w, next_page)
    put(w, Q, CATALOG_REQUEST)
    put(w, Q + 8, 3)
    return dispatch(w, CATALOG_END, CATALOG, Q, 16, R, 112, CAT_WS, 1024)

def lookup_row(w:mutbuf, row:u64) -> u32:
    put(w, ROW, row)
    put(w, DENSE, get(w, ROOT))
    put(w, DENSE + 8, row)
    extent = 16 + get(w, SIZE) * get(w, PAGES)
    return dispatch(w, ROW_READ, LOOKUP, DENSE, extent, HOLD, REGION, ROW_WS, 72)

def describe_row(w:mutbuf) -> u32:
    size = get(w, HOLD + 8)
    if get(w, HOLD) != ROW_REPLY or size == 0 or size > REGION - 32 or get(w, HOLD + 16) != 1:
        return 65
    if get(w, HOLD + 24) != get(w, PAGE):
        return 65
    put(w, LOOKUP_SIZE, size)
    if get(w, TABLE) == 11:
        return plan_row(w)
    return dispatch(w, ROW_LAYOUT, RECORD, HOLD + 32, size, R, 256, REC_WS, 16)

def typed_row(w:mutbuf) -> u32:
    count = get(w, R + 8)
    size = get(w, LOOKUP_SIZE)
    if get(w, R) != RECORD_REPLY or count == 0 or count > 7 or get(w, R + 16) != size:
        return 65
    extent = 32 + count * 32
    table = get(w, TABLE)
    if size > REGION - 40 - extent:
        return 66
    if table == 0:
        if count != 5:
            return 65
        put(w, Q, CATALOG_REQUEST)
        put(w, Q + 8, 2)
        put(w, Q + 16, get(w, ROW))
        put(w, Q + 24, extent)
        move(w, R, Q + 32, extent)
        move(w, HOLD + 32, Q + 32 + extent, size)
        return dispatch(w, CATALOG_ROW, CATALOG, Q, 32 + extent + size, R, 112, CAT_WS, 1024)
    put(w, Q, IMPORT_REQUEST)
    put(w, Q + 8, table)
    put(w, Q + 16, get(w, ROW))
    put(w, Q + 24, 1)
    put(w, Q + 32, extent)
    move(w, R, Q + 40, extent)
    move(w, HOLD + 32, Q + 40 + extent, size)
    return dispatch(w, ROW_PROJECTION, IMPORT, Q, 40 + extent + size, HOLD, REGION, 0, 0)

def start_plan(w:mutbuf) -> u32:
    prefix(w, Q, PLAN_REQUEST, 1)
    put(w, Q + 40, get(w, PAGES))
    put(w, Q + 48, get(w, TX))
    move(w, R, Q + 56, 112)
    return dispatch(w, PLAN_INITIAL, PLAN, Q, 168, R, 96, PLAN_WS, PLAN_SPACE)

def plan_page(w:mutbuf) -> u32:
    count = get(w, WALK_RESULT + 24)
    if get(w, WALK_RESULT) != WALK_REPLY or count > 32769:
        return 65
    prefix(w, Q, PLAN_REQUEST, 2)
    put(w, Q + 40, get(w, TABLE))
    move(w, WALK_RESULT, Q + 48, 32 + count * 8)
    return dispatch(w, PLAN_PAGE, PLAN, Q, 80 + count * 8, R, 96, PLAN_WS, PLAN_SPACE)

def plan_row(w:mutbuf) -> u32:
    table = get(w, TABLE)
    extent = 32 + get(w, LOOKUP_SIZE)
    if table < 11:
        count = get(w, HOLD + 24)
        if get(w, HOLD) != ROW_REPLY or count < 1 or count > 7 or get(w, HOLD + 16) != table:
            return 65
        last = HOLD + 32 + (count - 1) * 24
        begin = get(w, last + 8)
        size = get(w, last + 16)
        if begin > REGION or size > REGION - begin:
            return 65
        extent = begin + size
    if extent > REGION - 120:
        return 66
    prefix(w, Q, PLAN_REQUEST, 3)
    put(w, Q + 40, table)
    put(w, Q + 48, get(w, PAGE))
    put(w, Q + 56, get(w, ROW))
    move(w, HOLD, Q + 64, extent)
    return dispatch(w, PLAN_ROW, PLAN, Q, 64 + extent, R, 120 + extent, PLAN_WS, PLAN_SPACE)

def append_row(o:mutbuf, w:mutbuf) -> u64:
    size = get(w, R + 112)
    cursor = get(w, CURSOR)
    if get(w, R + 96) != get(w, TABLE) or get(w, R + 104) != get(w, ROW):
        return 1
    if size > REGION - 120 or cursor + 24 + size > length(o):
        return 1
    move_to_output(o, w, R + 96, cursor, 24 + size)
    put(w, CURSOR, cursor + 24 + size)
    if get(w, TABLE) == 11:
        put(w, SEQUENCE, 24 + size)
    return 0

def advance(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if get(w, R) != PLAN_REPLY:
        return 65
    action = get(w, R + 8)
    table = get(w, R + 16)
    if table < 1 or table > 11:
        return 65
    put(w, TABLE, table)
    if action == 1:
        return start_walk(w, get(w, R + 24))
    if action == 2:
        return table_page(s, w, get(w, R + 32))
    if action == 3:
        if get(w, PAGE) != get(w, R + 32):
            return 65
        return lookup_row(w, get(w, R + 40))
    if action != 4 or get(w, R + 64) != BATCH:
        return 65
    size = get(w, CURSOR)
    seq = get(w, SEQUENCE)
    emit(o, 0, PROJECTION)
    emit(o, 8, size - 32 - seq)
    emit(o, 16, seq)
    emit(o, 24, get(w, R + 48))
    move_to_output(o, w, R + 64, 32, 32)
    put(w, INPUT_N, size)
    return 0

def prefix(w:mutbuf, at:u64, tag:u64, phase:u64) -> u64:
    put(w, at, tag)
    put(w, at + 8, phase)
    put(w, at + 16, get(w, ID))
    put(w, at + 24, get(w, ID + 8))
    return put(w, at + 32, get(w, ID + 16))

def dispatch(w:mutbuf, state:u64, role:u32, src:u64, count:u64, dst:u64, cap:u64, scratch:u64, extent:u64) -> u32:
    put(w, STATE, state)
    put(w, INPUT, src)
    put(w, INPUT_N, count)
    put(w, OUTPUT, dst)
    put(w, OUTPUT_N, cap)
    put(w, SCRATCH, scratch)
    put(w, SCRATCH_N, extent)
    return role

def copy_source(s:readbuf, w:mutbuf, src:u64, dst:u64, size:u64) -> u64:
    i = 0
    while i < size:
        store(w, dst + i, byte(s, src + i))
        i = i + 1
    return 0

def move(w:mutbuf, src:u64, dst:u64, size:u64) -> u64:
    i = 0
    while i < size:
        store(w, dst + i, byte(w, src + i))
        i = i + 1
    return 0

def move_to_output(o:mutbuf, w:mutbuf, src:u64, dst:u64, size:u64) -> u64:
    i = 0
    while i < size:
        store(o, dst + i, byte(w, src + i))
        i = i + 1
    return 0
'''

CONSTANTS = {
    'SNAPSHOT': b'HIASMIG1', 'SQLITE': b'SQLite f', 'CATALOG_REQUEST': b'HIASCAT1',
    'HSP2': b'HSP2', 'ROW_REPLY': b'HIAROW01', 'WALK_REQUEST': b'HIASTW01',
    'WALK_REPLY': b'HIASWA01', 'BTREE': b'HIABTW01', 'PLAN_REQUEST': b'HIASMP01',
    'PLAN_REPLY': b'HIASMR01', 'RECORD_REPLY': b'HIASREC1', 'BATCH': b'HIASQB01',
    'IMPORT_REQUEST': b'HIASQI01', 'PROJECTION': b'HIASPRO1',
    'STATUS': 0, 'STATE': 8, 'INPUT': 16, 'INPUT_N': 24, 'OUTPUT': 32, 'OUTPUT_N': 40,
    'SCRATCH': 48, 'SCRATCH_N': 56, 'SIZE': 64, 'PAGES': 72, 'TX': 80, 'ID': 88,
    'TABLE': 112, 'ROOT': 120, 'PAGE': 128, 'ROW': 136, 'CURSOR': 144, 'SEQUENCE': 152,
    'CAT_COUNT': 160, 'CAT_CURSOR': 168, 'LOOKUP_SIZE': 176,
    'CAT_WS': 1024, 'ROW_WS': 2048, 'REC_WS': 2176, 'PLAN_WS': 4096,
    'PLAN_SPACE': 208 + 8 * 32769, 'WALK_WS': 270336, 'WALK_RESULT': 5 << 20,
    'LIST': 32 + 8 * 32769, 'REGION': 64 << 20,
    'Q': 6 << 20, 'R': 70 << 20, 'HOLD': 134 << 20, 'DENSE': 198 << 20,
    'CATALOG': 1, 'WALK': 2, 'LOOKUP': 3, 'RECORD': 4, 'IMPORT': 5, 'PLAN': 6,
    'CATALOG_OPEN': 1, 'WALK_OPEN': 2, 'PAGE_READ': 3, 'WALK_PAGE': 4,
    'ROW_READ': 5, 'ROW_LAYOUT': 6, 'CATALOG_ROW': 7, 'CATALOG_END': 8,
    'PLAN_INITIAL': 9, 'PLAN_PAGE': 10, 'ROW_PROJECTION': 11, 'PLAN_ROW': 12,
}


def source_program():
    def replace(match):
        name = match[0]
        value = CONSTANTS.get(name, name)
        return str(int.from_bytes(value, 'little') if isinstance(value, bytes) else value)

    helpers = CATALOG[CATALOG.index('\ndef uint('):]
    return re.sub(r'\b[A-Z][A-Z0-9_]*\b', replace, POLICY) + helpers


def main():
    source = Path(__file__).resolve().parents[1] / 'examples/hia_bootstrap/sqlite_migration_projection.hepta'
    source.write_text(render_assembly(document(source_program(), 'sqlite_migration_projection')))


if __name__ == '__main__':
    main()

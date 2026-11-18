"""Author the native Agent SQLite migration continuation.

The retained Pager and per-table walker are trusted peers. The plan binds their
observations to one snapshot and emits ordered, retryable import frames. Only a
completed plan issues the batch header; pending frames are not a commit receipt.
"""
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_sqlite_agent_catalog import POLICY as CATALOG, SCHEMA


POLICY = '''
def plan(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 40 or uint(s, 0) != PLAN:
        return 1
    if length(w) < 208:
        return 3
    phase = uint(s, 8)
    if phase == 1:
        return begin(s, o, w)
    if get(w, 0) != 1 or uint(s, 16) != get(w, 96) or uint(s, 24) != get(w, 104) or uint(s, 32) != get(w, 112):
        return 1
    if phase == 2:
        return accept_page(s, o, w)
    if phase == 3:
        return accept_row(s, o, w)
    return 1

def begin(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) != 168 or get(w, 0) != 0 or uint(s, 56) != CATALOG_OK or uint(s, 64) != 1 or uint(s, 72) != TABLES:
        return 1
    pages = uint(s, 40)
    transaction = uint(s, 48)
    if pages <= TABLES or pages > 4294967294 or transaction == 0:
        return 1
    i = 0
    while i < TABLES:
        root = uint(s, 80 + i * 8)
        if root < 2 or root > pages:
            return 1
        j = 0
        while j < i:
            if root == uint(s, 80 + j * 8):
                return 1
            j = j + 1
        i = i + 1
    if length(o) < 96:
        return 2
    i = 0
    while i < 96:
        put(w, i, 0)
        i = i + 8
    i = 0
    while i < 24:
        store(w, 96 + i, byte(s, 16 + i))
        i = i + 1
    i = 0
    while i < TABLES:
        put(w, 120 + i * 8, uint(s, 80 + i * 8))
        i = i + 1
    put(w, 0, 1)
    put(w, 8, pages)
    put(w, 16, transaction)
    return start_table(o, w, 1)

def accept_page(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 80 or uint(s, 40) != get(w, 24) or get(w, 48) != 0:
        return 1
    page = get(w, 32)
    next_page = uint(s, 64)
    count = uint(s, 72)
    if uint(s, 48) != WALK or uint(s, 56) != page or next_page == page or next_page > get(w, 8) or count > 32769 or length(s) != 80 + count * 8:
        return 1
    if get(w, 24) == TABLES and (count > 1 or (count == 1 and get(w, 80) != 0)):
        return 4
    if count > ((length(w) - 208) >> 3):
        return 3
    if length(o) < 96:
        return 2
    put(w, 40, next_page)
    if count == 0:
        return follow_page(o, w)
    i = 0
    while i < count * 8:
        store(w, 208 + i, byte(s, 80 + i))
        i = i + 1
    put(w, 48, count)
    put(w, 56, 0)
    return reply(o, w, 3, get(w, 208))

def accept_row(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    slots = get(w, 48)
    cursor = get(w, 56)
    if length(s) < 96 or slots == 0 or cursor >= slots:
        return 1
    table = get(w, 24)
    key = get(w, 208 + cursor * 8)
    if uint(s, 40) != table or uint(s, 48) != get(w, 32) or uint(s, 56) != key or uint(s, 64) != ROW:
        return 1
    extent = length(s) - 64
    if table == TABLES:
        # Retain the raw sqlite_sequence record, tagged by the retained lookup.
        if extent <= 32 or uint(s, 72) != extent - 32 or uint(s, 80) != 1 or uint(s, 88) != get(w, 32):
            return 4
    else:
        columns = uint(s, 88)
        if uint(s, 72) != 1 or uint(s, 80) != table or columns != width(table) or extent < 32 + columns * 24:
            return 4
    if length(o) < 120 + extent:
        return 2
    put(o, 96, table)
    put(o, 104, key)
    put(o, 112, extent)
    i = 0
    while i < extent:
        store(o, 120 + i, byte(s, 64 + i))
        i = i + 1
    if table == TABLES:
        put(w, 80, 1)
    else:
        put(w, 64, get(w, 64) + 1)
        if table == 5 and key <= 9223372036854775807 and key > get(w, 72):
            put(w, 72, key)
    cursor = cursor + 1
    if cursor < slots:
        put(w, 56, cursor)
        return reply(o, w, 3, get(w, 208 + cursor * 8))
    put(w, 48, 0)
    put(w, 56, 0)
    return follow_page(o, w)

def follow_page(o:mutbuf, w:mutbuf) -> u32:
    page = get(w, 40)
    if page != 0:
        put(w, 32, page)
        return reply(o, w, 2, 0)
    table = get(w, 24)
    if table == TABLES:
        put(w, 0, 2)
        put(w, 32, 0)
        return reply(o, w, 4, 0)
    return start_table(o, w, table + 1)

def start_table(o:mutbuf, w:mutbuf, table:u64) -> u32:
    put(w, 24, table)
    put(w, 32, get(w, 120 + (table - 1) * 8))
    return reply(o, w, 1, 0)

def reply(o:mutbuf, w:mutbuf, action:u64, key:u64) -> u32:
    table = get(w, 24)
    put(o, 0, REPLY)
    put(o, 8, action)
    put(o, 16, table)
    put(o, 24, get(w, 120 + (table - 1) * 8))
    put(o, 32, get(w, 32))
    put(o, 40, key)
    put(o, 48, get(w, 72))
    put(o, 56, get(w, 80))
    put(o, 64, 0)
    put(o, 72, 0)
    put(o, 80, 0)
    put(o, 88, 0)
    if action == 4:
        put(o, 64, BATCH)
        put(o, 72, 1)
        put(o, 80, get(w, 16))
        put(o, 88, get(w, 64))
    return 0

def width(table:u64) -> u64:
WIDTHS
    return 0
'''


def source_program():
    policy = POLICY
    words = {'PLAN': b'HIASMP01', 'REPLY': b'HIASMR01', 'CATALOG_OK': b'HIASCOK1',
             'WALK': b'HIASWA01', 'ROW': b'HIAROW01', 'BATCH': b'HIASQB01'}
    for name, word in words.items():
        policy = policy.replace(name, str(int.from_bytes(word, 'little')))
    policy = policy.replace('TABLES', str(len(SCHEMA)))
    widths = [len(ddl.split(',primary key(')[0].split(','))
              for _, ddl, _ in SCHEMA[:-1]]
    policy = policy.replace('WIDTHS', '\n'.join(
        f'    if table == {i}:\n        return {columns}'
        for i, columns in enumerate(widths, 1)))
    helpers = CATALOG[CATALOG.index('\ndef uint('):CATALOG.index('\ndef emit(')]
    return policy + helpers


def main():
    path = Path(__file__).resolve().parents[1] / 'examples/hia_bootstrap/sqlite_migration_plan.hepta'
    path.write_text(render_assembly(document(source_program(), 'sqlite_migration_plan')))


if __name__ == '__main__':
    main()

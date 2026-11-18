"""Author the stateful HIA table walk used with retained SQLite pages."""
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_sqlite_agent_catalog import POLICY as CATALOG


POLICY = '''
def walk(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 40 or uint(s, 0) != REQUEST:
        return 1
    if length(w) < 80:
        return 3
    phase = uint(s, 8)
    if phase == 1:
        return begin(s, o, w)
    if phase != 2 or get(w, 0) != 1 or length(s) < 72:
        return 1
    if uint(s, 16) != get(w, 48) or uint(s, 24) != get(w, 56) or uint(s, 32) != get(w, 64):
        return 1
    count = uint(s, 56)
    if uint(s, 40) != PAGE or count > 32769 or length(s) != 72 + count * 8:
        return 1
    pages = get(w, 8)
    extent = get(w, 16)
    pending = get(w, 24)
    if pages < 1 or pages > 4294967294 or extent != (pages >> 3) + 1:
        return 1
    stack = 80 + extent
    if stack > length(w) or pending == 0 or pending > ((length(w) - stack) >> 3):
        return 1
    depth = pending - 1
    page = uint(s, 64)
    if page != get(w, stack + depth * 8):
        return 1
    kind = uint(s, 48)
    if kind == 5:
        return branch_page(s, o, w, stack, depth, page, count)
    if kind == 13:
        return leaf_page(s, o, w, stack, depth, page, count)
    return corrupt(w)

def begin(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) != 56 or get(w, 0) != 0:
        return 1
    pages = uint(s, 40)
    root = uint(s, 48)
    if pages < 1 or pages > 4294967294 or root < 1 or root > pages:
        return 1
    extent = (pages >> 3) + 1
    if length(w) < 88 + extent:
        return 3
    if length(o) < 32:
        return 2
    at = 0
    while at < extent:
        store(w, 80 + at, 0)
        at = at + 1
    first = mark(w, root, pages)
    if first == 0:
        return corrupt(w)
    put(w, 0, 1)
    put(w, 8, pages)
    put(w, 16, extent)
    put(w, 24, 1)
    put(w, 32, 0)
    put(w, 40, 0)
    put(w, 48, uint(s, 16))
    put(w, 56, uint(s, 24))
    put(w, 64, uint(s, 32))
    put(w, 80 + extent, root)
    reply(o, 0, root, 0)
    return 0

def branch_page(s:readbuf, o:mutbuf, w:mutbuf, stack:u64, depth:u64, page:u64, count:u64) -> u32:
    if count == 0:
        return corrupt(w)
    if count > ((length(w) - stack) >> 3) - depth:
        return 3
    if length(o) < 32:
        return 2
    pages = get(w, 8)
    pending = depth
    remaining = count
    # Push in reverse so the leftmost child is next, with other siblings retained.
    while remaining != 0:
        remaining = remaining - 1
        child = uint(s, 72 + remaining * 8)
        if mark(w, child, pages) == 0:
            return corrupt(w)
        put(w, stack + pending * 8, child)
        pending = pending + 1
    put(w, 24, pending)
    reply(o, page, get(w, stack + (pending - 1) * 8), 0)
    return 0

def leaf_page(s:readbuf, o:mutbuf, w:mutbuf, stack:u64, depth:u64, page:u64, count:u64) -> u32:
    if length(o) < 32 + count * 8:
        return 2
    previous = get(w, 32)
    seen = get(w, 40)
    i = 0
    while i < count:
        ordered = uint(s, 72 + i * 8) ^ 9223372036854775808
        if seen == 1 and ordered <= previous:
            return corrupt(w)
        previous = ordered
        seen = 1
        i = i + 1
    next_page = 0
    if depth == 0:
        put(w, 0, 2)
    else:
        next_page = get(w, stack + (depth - 1) * 8)
    put(w, 24, depth)
    put(w, 32, previous)
    put(w, 40, seen)
    reply(o, page, next_page, count)
    i = 0
    while i < count * 8:
        store(o, 32 + i, byte(s, 72 + i))
        i = i + 1
    return 0

def mark(w:mutbuf, page:u64, pages:u64) -> u64:
    if page < 1 or page > pages:
        return 0
    at = 80 + (page >> 3)
    mask = 1 << (page & 7)
    old = byte(w, at)
    if (old & mask) != 0:
        return 0
    store(w, at, old | mask)
    return 1

def corrupt(w:mutbuf) -> u32:
    put(w, 0, 3)
    return 4

def reply(o:mutbuf, page:u64, next_page:u64, count:u64) -> u64:
    put(o, 0, REPLY)
    put(o, 8, page)
    put(o, 16, next_page)
    return put(o, 24, count)
'''


def source_program():
    policy = POLICY
    for name, word in (('REQUEST', b'HIASTW01'), ('REPLY', b'HIASWA01'), ('PAGE', b'HIABTW01')):
        policy = policy.replace(name, str(int.from_bytes(word, 'little')))
    helpers = CATALOG[CATALOG.index('\ndef uint('):CATALOG.index('\ndef emit(')]
    return policy + helpers


def main():
    path = Path(__file__).resolve().parents[1] / 'examples/hia_bootstrap/sqlite_table_walk.hepta'
    path.write_text(render_assembly(document(source_program(), 'sqlite_table_walk')))


if __name__ == '__main__':
    main()

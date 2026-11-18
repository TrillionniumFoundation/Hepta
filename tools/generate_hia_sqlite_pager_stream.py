"""Render the HIA migration stream policy for the retained SQLite Pager."""
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_sqlite_agent_catalog import POLICY as CATALOG


POLICY = '''
def stream(p:readbuf, event:mutbuf, out:mutbuf) -> u32:
    if length(p) != 147456 or length(event) != 128 or length(out) != 72:
        return 65
    if uint(p, 8) != 200 or uint(p, 32) != 0 or uint(p, 73736) != 0:
        return 65
    mode = uint(p, 3904)
    locks = uint(p, 104)
    wal_locked = mode == 1 and (locks & 32) != 0
    main_locked = mode == 2 and (locks & 128) != 0
    if wal_locked == False and main_locked == False:
        return 65
    next_page = get(out, 64)
    if next_page == 0:
        return begin(p, event, out)
    if uint(p, 288) != get(out, 40) or uint(p, 296) != get(out, 48) or uint(p, 304) != get(out, 56):
        return 65
    if next_page > get(out, 24):
        put(out, 64, 0)
        return 0
    at = 0
    while at < 128:
        put(event, at, 0)
        at = at + 8
    put(event, 0, EVENT)
    put(event, 8, 2)
    put(event, 16, uint(p, 16))
    put(event, 24, 3)
    put(event, 64, next_page)
    put(out, 64, next_page + 1)
    return 2

def begin(p:readbuf, event:mutbuf, out:mutbuf) -> u32:
    if get(event, 0) != EVENT or get(event, 8) != 2 or get(event, 16) != uint(p, 16):
        return 65
    if get(event, 24) != 9 or get(event, 64) == 0:
        return 65
    at = 32
    while at < 128:
        if at != 64 and get(event, at) != 0:
            return 65
        at = at + 8
    size = uint(p, 128)
    pages = uint(p, 136)
    if size < 512 or size > 65536 or (size & (size - 1)) != 0:
        return 65
    if pages < 12 or pages > 524288 or pages * size > 268435456:
        return 65
    put(out, 0, 56 + pages * size)
    put(out, 8, MIGRATION)
    put(out, 16, get(event, 64))
    put(out, 24, pages)
    put(out, 32, size)
    put(out, 40, uint(p, 288))
    put(out, 48, uint(p, 296))
    put(out, 56, uint(p, 304))
    put(out, 64, 1)
    return 1
'''


def source_program():
    policy = POLICY.replace('EVENT', str(int.from_bytes(b'HIAPGEV2', 'little')))
    policy = policy.replace('MIGRATION', str(int.from_bytes(b'HIASMIG1', 'little')))
    return policy + CATALOG[CATALOG.index('\ndef uint('):]


def main():
    source = Path(__file__).resolve().parents[1] / 'examples/hia_bootstrap/sqlite_pager_stream.hepta'
    source.write_text(render_assembly(document(source_program(), 'sqlite_pager_stream')))


if __name__ == '__main__':
    main()

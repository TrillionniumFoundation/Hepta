"""Render the HIA controller for staging a projected legacy Agent database."""
from pathlib import Path
import re

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_sqlite_agent_catalog import POLICY as CATALOG


POLICY = '''
def stage(p:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(p) < 64 or length(w) != 8192 or length(o) < 56:
        return 64
    state = get(w, STATE)
    if state == 0:
        return begin(p, o, w)
    if state == 3:
        status = get(w, STATUS)
        if status == 4:
            put(w, SEQUENCE, 0)
        elif status != 0:
            return 65
        return publish(o, w)
    if get(w, STATUS) != 0:
        return 65
    if state == 1:
        if get(o, 32) != PROPOSAL:
            return 65
        put(w, IN_AT, 32)
        put(w, IN_SIZE, get(w, PROPOSAL_N))
        put(w, OUT_AT, 32 + get(w, PROPOSAL_N))
        put(w, OUT_SIZE, get(w, INVENTORY_N))
        put(w, STATE, 2)
        return 2
    if state == 2:
        at = 32 + get(w, PROPOSAL_N)
        if get(o, at) != INVENTORY or get(o, at + 8) != 1:
            return 65
        if get(o, at + 16) * 64 + 24 != get(w, INVENTORY_N):
            return 65
        return cost(p, o, w)
    return 64

def begin(p:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if uint(p, 0) != PROJECTION or uint(p, 32) != BATCH or uint(p, 40) != 1 or uint(p, 48) != 1:
        return 64
    batch = uint(p, 8)
    tail = uint(p, 16)
    rows = uint(p, 56)
    if batch < 32 or batch > length(p) - 32 or tail != length(p) - 32 - batch:
        return 64
    if rows > ((batch - 32) >> 5):
        return 64
    at = 64
    artifacts = 0
    while at < 32 + batch:
        if 32 + batch - at < 24:
            return 64
        size = uint(p, at + 16)
        if size < 32 or size > 32 + batch - at - 24:
            return 64
        if uint(p, at) == 1:
            artifacts = artifacts + 1
        at = at + 24 + size
    inventory = 24 + artifacts * 64
    put(w, INVENTORY_N, inventory)
    if rows == 0:
        if batch != 32:
            return 64
        put(o, 32, INVENTORY)
        put(o, 40, 1)
        put(o, 48, 0)
        return cost(p, o, w)
    proposal = batch + 8 * rows
    if 32 + proposal + inventory > length(o):
        return 66
    put(w, PROPOSAL_N, proposal)
    put(w, IN_AT, 32)
    put(w, IN_SIZE, batch)
    put(w, OUT_AT, 32)
    put(w, OUT_SIZE, proposal)
    put(w, STATE, 1)
    return 1

def cost(p:readbuf, o:mutbuf, w:mutbuf) -> u32:
    size = uint(p, 16)
    if size == 0:
        return publish(o, w)
    sequence_at = 32 + uint(p, 8)
    if size < 57 or size > 184 or uint(p, sequence_at) != 11:
        return 65
    raw = size - 56
    if uint(p, sequence_at + 16) != size - 24 or uint(p, sequence_at + 24) != ROW:
        return 65
    if uint(p, sequence_at + 32) != raw or uint(p, sequence_at + 40) != 1:
        return 65
    dest = 32 + get(w, PROPOSAL_N) + get(w, INVENTORY_N)
    if dest + 656 > length(o):
        return 66
    tx = 1
    if get(w, PROPOSAL_N) != 0:
        tx = 2
    put(w, 128, COST)
    put(w, 136, 1)
    put(w, 144, tx)
    put(w, 152, uint(p, 24))
    i = 0
    while i < raw:
        store(w, 160 + i, byte(p, sequence_at + 56 + i))
        i = i + 1
    put(w, IN_AT, 128)
    put(w, IN_SIZE, 32 + raw)
    put(w, OUT_AT, dest)
    put(w, OUT_SIZE, 656)
    put(w, SEQUENCE, 656)
    put(w, STATE, 3)
    return 3

def publish(o:mutbuf, w:mutbuf) -> u32:
    proposal = get(w, PROPOSAL_N)
    inventory = get(w, INVENTORY_N)
    sequence = get(w, SEQUENCE)
    put(o, 0, STAGING)
    put(o, 8, proposal)
    put(o, 16, inventory)
    put(o, 24, sequence)
    put(w, IN_SIZE, 32 + proposal + inventory + sequence)
    return 0
'''


CONSTANTS = {
    'PROJECTION': b'HIASPRO1', 'BATCH': b'HIASQB01', 'PROPOSAL': b'HIATXB01',
    'INVENTORY': b'HIAFID01', 'ROW': b'HIAROW01', 'COST': b'HIASQH01',
    'STAGING': b'HIASTAG1', 'STATUS': 0, 'STATE': 8, 'IN_AT': 16, 'IN_SIZE': 24,
    'OUT_AT': 32, 'OUT_SIZE': 40, 'PROPOSAL_N': 48, 'INVENTORY_N': 56, 'SEQUENCE': 64,
}


def source_program():
    def replace(match):
        value = CONSTANTS[match[0]]
        return str(int.from_bytes(value, 'little') if isinstance(value, bytes) else value)

    helpers = CATALOG[CATALOG.index('\ndef uint('):]
    return re.sub(r'\b[A-Z][A-Z0-9_]*\b', replace, POLICY) + helpers


def main():
    source = Path(__file__).resolve().parents[1] / 'examples/hia_bootstrap/sqlite_migration_stage.hepta'
    source.write_text(render_assembly(document(source_program(), 'sqlite_migration_stage')))


if __name__ == '__main__':
    main()

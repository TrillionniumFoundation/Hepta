"""Render the HIA effect scheduler for a prepared Agent Store migration."""
from pathlib import Path
import re

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_sqlite_agent_catalog import POLICY as CATALOG


POLICY = '''
def migrate(p:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(p) < 56 or length(o) < 56 or length(w) != 48:
        return 64
    phase = get(w, PHASE)
    if phase != 0 and get(w, STATUS) != 0:
        return 65
    if phase == 0:
        return admit(p, w)
    if phase == CHECK_TARGET:
        if uint(p, 8) == 0:
            return write_sequence(p, w)
        put(w, ADDRESS, 32)
        put(w, SIZE, uint(p, 8))
        put(w, PHASE, CHECK_INVENTORY)
        return CHECK_INVENTORY
    if phase == CHECK_INVENTORY:
        size = uint(p, 16)
        if size > length(o) - 32:
            return 64
        i = 0
        source = 32 + uint(p, 8)
        while i < size:
            if byte(p, source + i) != byte(o, 32 + i):
                return 65
            i = i + 1
        return next_artifact(p, w)
    if phase == COPY_ARTIFACT:
        return next_artifact(p, w)
    if phase == WRITE_PROPOSAL:
        return write_sequence(p, w)
    if phase != WRITE_SEQUENCE and phase != COMPLETE:
        return 64
    put(o, 0, DURABLE)
    put(o, 8, get(w, CURSOR))
    put(o, 16, get(w, GENERATION))
    put(o, 24, 1)
    return 0

def admit(p:readbuf, w:mutbuf) -> u32:
    proposal = uint(p, 8)
    inventory = uint(p, 16)
    sequence = uint(p, 24)
    if uint(p, 0) != STAGING or proposal > length(p) - 32:
        return 64
    if inventory < 24 or inventory > length(p) - 32 - proposal:
        return 64
    if sequence != length(p) - 32 - proposal - inventory or (sequence != 0 and sequence != 656):
        return 64
    at = 32 + proposal
    if uint(p, at) != INVENTORY or uint(p, at + 8) != 1:
        return 64
    count = uint(p, at + 16)
    if inventory & 63 != 24 or count != ((inventory - 24) >> 6):
        return 64
    tx = 1
    if proposal != 0:
        if proposal < 32 or uint(p, 32) != PROPOSAL or uint(p, 40) != 1 or uint(p, 48) != 1:
            return 64
        tx = 2
    elif count != 0:
        return 64
    if sequence != 0:
        at = at + inventory
        if uint(p, at) != WAL or uint(p, at + 8) != 96 or uint(p, at + 16) != tx:
            return 64
    put(w, PHASE, CHECK_TARGET)
    return CHECK_TARGET

def next_artifact(p:readbuf, w:mutbuf) -> u32:
    proposal = uint(p, 8)
    cursor = get(w, CURSOR)
    if cursor < ((uint(p, 16) - 24) >> 6):
        put(w, ADDRESS, 56 + proposal + cursor * 64)
        put(w, SIZE, 64)
        put(w, CURSOR, cursor + 1)
        put(w, PHASE, COPY_ARTIFACT)
        return COPY_ARTIFACT
    put(w, ADDRESS, 32)
    put(w, SIZE, proposal)
    put(w, GENERATION, 1)
    put(w, PHASE, WRITE_PROPOSAL)
    return WRITE_PROPOSAL

def write_sequence(p:readbuf, w:mutbuf) -> u32:
    size = uint(p, 24)
    if size == 0:
        put(w, PHASE, COMPLETE)
        return COMPLETE
    put(w, ADDRESS, 32 + uint(p, 8) + uint(p, 16))
    put(w, SIZE, size)
    put(w, GENERATION, 1 + get(w, GENERATION))
    put(w, PHASE, WRITE_SEQUENCE)
    return WRITE_SEQUENCE
'''


CONSTANTS = {
    'STAGING': b'HIASTAG1', 'INVENTORY': b'HIAFID01', 'PROPOSAL': b'HIATXB01',
    'WAL': b'HIAWAL01', 'DURABLE': b'HIASDUR1', 'STATUS': 0, 'PHASE': 8,
    'ADDRESS': 16, 'SIZE': 24, 'CURSOR': 32, 'GENERATION': 40,
    'CHECK_INVENTORY': 1, 'COPY_ARTIFACT': 2, 'WRITE_PROPOSAL': 3,
    'WRITE_SEQUENCE': 4, 'COMPLETE': 5, 'CHECK_TARGET': 6,
}


def source_program():
    def replace(match):
        value = CONSTANTS[match[0]]
        return str(int.from_bytes(value, 'little') if isinstance(value, bytes) else value)

    helpers = CATALOG[CATALOG.index('\ndef uint('):]
    return re.sub(r'\b[A-Z][A-Z0-9_]*\b', replace, POLICY) + helpers


def main():
    source = Path(__file__).resolve().parents[1] / 'examples/hia_bootstrap/sqlite_migration_publish.hepta'
    source.write_text(render_assembly(document(source_program(), 'sqlite_migration_publish')))


if __name__ == '__main__':
    main()

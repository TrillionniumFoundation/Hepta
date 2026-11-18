"""Render the native HIA lock, stage, publish and release coordinator."""
from pathlib import Path
import re

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_sqlite_agent_catalog import POLICY as CATALOG


POLICY = '''
def migrate(i:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(i) != 1312 or length(o) != 128 or length(w) != 64:
        return 64
    phase = get(w, PHASE)
    if phase == 0:
        profile = uint(i, 8)
        mode = uint(i, 0)
        if (profile != 34600 and profile != 35302) or (mode != 1 and mode != 2):
            return 64
        command(o, 1, profile, mode)
        return advance(w, OPEN)
    if get(w, STATUS) != 0:
        return 65
    if phase == OPEN:
        return start_export(i, o, w)
    if phase == EXPORT:
        return capture(i, w)
    if phase == CAPTURE:
        return advance(w, PROJECT)
    if phase == PROJECT:
        if uint(i, RESULT) != STAGED:
            return 65
        proposal = uint(i, RESULT + 8)
        inventory = uint(i, RESULT + 16)
        extension = uint(i, RESULT + 24)
        if inventory < 24 or (inventory & 63) != 24 or (extension != 0 and extension != 656):
            return 65
        put(w, ARTIFACTS, (inventory - 24) >> 6)
        generation = 0
        if proposal != 0:
            generation = generation + 1
        if extension != 0:
            generation = generation + 1
        put(w, GENERATION, generation)
        return advance(w, INITIALIZE)
    if phase == INITIALIZE:
        return advance(w, PUBLISH)
    if phase == PUBLISH:
        if uint(i, RESULT) != DURABLE or uint(i, RESULT + 8) != get(w, ARTIFACTS):
            return 65
        if uint(i, RESULT + 16) != get(w, GENERATION) or uint(i, RESULT + 24) != 1:
            return 65
        command(o, 4, 0, 0)
        return advance(w, CLOSE)
    if phase != CLOSE or reply(i, 130) == 0:
        return 65
    put(o, 0, DURABLE)
    put(o, 8, get(w, ARTIFACTS))
    put(o, 16, get(w, GENERATION))
    put(o, 24, 1)
    return 0

def start_export(i:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if reply(i, 128) == 0:
        return 65
    mode = uint(i, 0)
    holds = uint(i, REPLY + 64)
    if (mode == 1 and (holds & 32) == 0) or (mode == 2 and (holds & 128) == 0):
        return 65
    size = uint(i, REPLY + 72)
    count = uint(i, REPLY + 80)
    if size < 512 or size > 65536 or (size & (size - 1)) != 0:
        return 65
    if count < 12 or count > 524288 or count * size > 268435456:
        return 65
    put(w, COUNT, count)
    put(w, SIZE, size)
    put(w, PAGE_BYTES, count * size)
    command(o, 9, 1, 0)
    return advance(w, EXPORT)

def capture(i:readbuf, w:mutbuf) -> u32:
    if uint(i, SNAPSHOT) != 56 + get(w, PAGE_BYTES) or uint(i, SNAPSHOT + 8) != SNAPSHOT_TAG:
        return 65
    if uint(i, SNAPSHOT + 16) != 1 or uint(i, SNAPSHOT + 24) != get(w, COUNT) or uint(i, SNAPSHOT + 32) != get(w, SIZE):
        return 65
    at = 0
    while at < 24:
        if uint(i, SNAPSHOT + 40 + at) != uint(i, STATE_ID + at):
            return 65
        at = at + 8
    return advance(w, CAPTURE)

def reply(i:readbuf, kind:u64) -> u64:
    if uint(i, REPLY) != REPLY_TAG or uint(i, REPLY + 8) != 2 or uint(i, REPLY + 16) != NONCE:
        return 0
    if uint(i, REPLY + 24) != kind or uint(i, REPLY + 32) != 0 or uint(i, REPLY + 40) != 0:
        return 0
    return 1

def command(o:mutbuf, kind:u64, argument:u64, mode:u64) -> u64:
    at = 0
    while at < 128:
        put(o, at, 0)
        at = at + 8
    put(o, 0, EVENT_TAG)
    put(o, 8, 2)
    put(o, 16, NONCE)
    put(o, 24, kind)
    put(o, 64, argument)
    put(o, 72, mode)
    return 0

def advance(w:mutbuf, phase:u32) -> u32:
    put(w, PHASE, phase)
    return phase
'''


CONSTANTS = {
    'EVENT_TAG': b'HIAPGEV2', 'REPLY_TAG': b'HIAPGOT2', 'SNAPSHOT_TAG': b'HIASMIG1',
    'STAGED': b'HIASTAG1', 'DURABLE': b'HIASDUR1', 'NONCE': 0x4849414D49475231,
    'REPLY': 64, 'STATE_ID': 480, 'SNAPSHOT': 1216, 'RESULT': 1280,
    'STATUS': 0, 'PHASE': 8, 'COUNT': 16, 'SIZE': 24, 'PAGE_BYTES': 32,
    'ARTIFACTS': 40, 'GENERATION': 48, 'OPEN': 1, 'EXPORT': 2, 'CAPTURE': 3,
    'PROJECT': 4, 'INITIALIZE': 5, 'PUBLISH': 6, 'CLOSE': 7,
}


def source_program():
    def replace(match):
        value = CONSTANTS[match[0]]
        return str(int.from_bytes(value, 'little') if isinstance(value, bytes) else value)

    helpers = CATALOG[CATALOG.index('\ndef uint('):]
    return re.sub(r'\b[A-Z][A-Z0-9_]*\b', replace, POLICY) + helpers


def main():
    source = Path(__file__).resolve().parents[1] / 'examples/hia_bootstrap/sqlite_migrate.hepta'
    source.write_text(render_assembly(document(source_program(), 'sqlite_migrate')))


if __name__ == '__main__':
    main()

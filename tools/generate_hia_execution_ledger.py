"""Render the compact HIA policy for the VM's exact execution ledger."""

from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document

MAGIC = b'HIAELO01'
SOURCE = r'''
def observe(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) != 216 or word(s, 0) != MAGIC:
        return 255
    status = word(s, 8)
    if status < 1 or status > 3:
        return 1
    if word(s, 16) > 1 or word(s, 24) > 1:
        return 2
    flags = word(s, 72)
    if flags > 15:
        return 255
    if (flags & 1) != 0:
        return 3
    if (flags & 2) != 0:
        return 4
    if (flags & 4) != 0:
        return 5
    if (flags & 8) != 0 or word(s, 48) < 1 or word(s, 48) > 10000000 or word(s, 56) > 1073741824:
        return 6
    outcome = resources(s)
    if outcome != 0:
        return outcome
    return outcome_code(s, status)

def resources(s:readbuf) -> u64:
    allocated = word(s, 80)
    freed = word(s, 88)
    created = word(s, 104)
    dropped = word(s, 112)
    live = word(s, 120)
    if freed > allocated or allocated > word(s, 96) or allocated > created or freed > dropped or dropped > created or live != created - dropped:
        return 7
    payload = word(s, 128)
    nonempty = allocated - freed
    if nonempty > live or nonempty > payload or (nonempty == 0 and payload != 0):
        return 8
    started = word(s, 144)
    ended = word(s, 152)
    loans = word(s, 160)
    if ended > started or loans != started - ended:
        return 9
    if live == 0 and word(s, 32) == 0 and loans != 0:
        return 10
    peak = word(s, 136)
    if payload > peak or peak > word(s, 56):
        return 11
    if word(s, 16) == 1:
        return chains(s, live)
    return 0

def chains(s:readbuf, live:u64) -> u64:
    created = word(s, 168)
    consumed = word(s, 176)
    nodes = word(s, 192)
    dropped = word(s, 200)
    remaining = word(s, 208)
    if consumed > created or word(s, 184) != created - consumed or dropped > nodes or remaining != nodes - dropped:
        return 12
    if remaining > (live >> 1):
        return 13
    return 0

def outcome_code(s:readbuf, status:u64) -> u64:
    error = word(s, 64)
    if status == 1:
        if error != 0:
            return 14
        if word(s, 120) != 0 or word(s, 160) != 0:
            return 15
        if word(s, 16) == 1 and (word(s, 184) != 0 or word(s, 208) != 0):
            return 15
    if status == 2 and (error < 1 or error > 5):
        return 16
    if status == 3 and (error < 6 or error > 9 or (error == 9 and word(s, 24) == 0)):
        return 16
    ticks = word(s, 40)
    limit = word(s, 48)
    if status == 3 and error == 6:
        if ticks != limit + 1:
            return 17
    elif ticks < 1 or ticks > limit:
        return 17
    return 0

def word(s:readbuf, offset:u64) -> u64:
    value = 0
    i = 0
    while i < 8:
        value = value | (byte(s, offset + i) << (i * 8))
        i = i + 1
    return value
'''


def render():
    return render_assembly(document(SOURCE.replace('MAGIC', str(int.from_bytes(MAGIC, 'little'))),
                                    'execution_ledger'))


if __name__ == '__main__':
    target = Path(__file__).resolve().parents[1] / 'examples/hia_bootstrap/execution_ledger.hepta'
    target.write_text(render())

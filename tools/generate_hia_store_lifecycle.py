"""Author the current AgentStore construction/close continuation in HIA.

The integer program owns the complete branch, short circuit, loop and cleanup
order.  Object/Path/SQLite operations are fixed foreign ports.  In particular,
the protected construction region starts immediately after connect returns.
"""
from __future__ import annotations

import ast
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if __package__ in (None, ''):
    sys.path.insert(0, str(ROOT))

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions

REQUEST_MAGIC = int.from_bytes(b'HIASLRQ1', 'little')
RESULT_MAGIC = int.from_bytes(b'HIASLRS1', 'little')
STATE_MAGIC = int.from_bytes(b'HIASLST1', 'little')
SOURCE_NAME = 'examples/hia_bootstrap/store_lifecycle.hepta'
STATE_BYTES = 128
OUTPUT_BYTES = 80

# State: magic/version/mode/port/sequence/phase/identity[2]/suffix/depth/seal.
# Phase: 1 issued, 2 claimed, 3 pop handled exception, 4 returned,
#        5 propagate active exception, 6 unconfirmed protocol.
SOURCE = r'''
def lifecycle(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) != 80 or length(o) < 80 or length(w) != 128:
        return 4294967293
    if read_word(s, 0) != @REQUEST_MAGIC@ or read_word(s, 64) != 0 or read_word(s, 72) != 0:
        return 4294967293
    event = read_word(s, 8)
    if event == 0:
        return initialize(s, o, w)
    if valid_state(w) == 0:
        return 4294967293
    if read_word(s, 40) != get(w, 2) or read_word(s, 48) != get(w, 6) or read_word(s, 56) != get(w, 7):
        return refuse(o, w)
    if read_word(s, 16) != get(w, 4) or read_word(s, 24) != get(w, 3):
        return refuse(o, w)
    if event == 1:
        if get(w, 5) != 1 or read_word(s, 32) != 0:
            return refuse(o, w)
        set(w, 5, 2)
        seal(w)
        return answer(o, w, 0)
    if event == 2:
        if get(w, 5) != 2:
            return refuse(o, w)
        observation = read_word(s, 32)
        if is_predicate(get(w, 3)) == 1:
            if observation > 1:
                return refuse(o, w)
        else:
            if observation != 0:
                return refuse(o, w)
        return succeeded(o, w, observation)
    if event == 3:
        if get(w, 5) != 2 or read_word(s, 32) != 0:
            return refuse(o, w)
        return failed(o, w)
    if event == 4:
        if get(w, 5) != 3 or get(w, 9) != 2 or read_word(s, 32) != 0:
            return refuse(o, w)
        set(w, 9, 1)
        return advance(o, w, 0, 5)
    return refuse(o, w)

def initialize(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    mode = read_word(s, 40)
    if (mode != 1 and mode != 2) or read_word(s, 16) != 0 or read_word(s, 24) != 0 or read_word(s, 32) != 0:
        return 4294967293
    if read_word(s, 48) == 0 and read_word(s, 56) == 0:
        return 4294967293
    i = 0
    while i < 128:
        if byte(w, i) != 0:
            return 4294967293
        i = i + 1
    set(w, 0, @STATE_MAGIC@)
    set(w, 1, 1)
    set(w, 2, mode)
    set(w, 3, 1)
    if mode == 2:
        set(w, 3, 70)
    set(w, 4, 1)
    set(w, 5, 1)
    set(w, 6, read_word(s, 48))
    set(w, 7, read_word(s, 56))
    seal(w)
    return answer(o, w, 0)

def succeeded(o:mutbuf, w:mutbuf, observed:u64) -> u32:
    port = get(w, 3)
    next_port = port + 1
    if port == 4:
        if observed == 1:
            next_port = 60
    elif port == 7 or port == 8:
        if observed == 1:
            next_port = 61
    elif port == 11:
        if observed == 1:
            next_port = 62
    elif port == 13:
        if observed == 0:
            next_port = 63
    elif port == 14 or port == 15:
        if observed == 1:
            next_port = 63
    elif port == 17:
        if observed == 1:
            next_port = 19
    elif port == 18:
        if observed == 0:
            next_port = 23
    elif port == 20:
        if observed == 0:
            next_port = 64
    elif port == 21 or port == 22:
        if observed == 1:
            next_port = 64
    elif port == 27:
        if observed == 0:
            next_port = 65
    elif port == 35:
        if observed == 0:
            next_port = 44
    elif port == 39:
        if observed == 0:
            next_port = 66
    elif port == 40 or port == 41:
        if observed == 1:
            next_port = 66
    elif port == 42:
        if get(w, 8) == 0:
            set(w, 8, 1)
            next_port = 38
    elif port == 44 or port == 71:
        return advance(o, w, 0, 4)
    elif port == 60:
        next_port = 5
    elif port == 61:
        next_port = 9
    elif port == 62:
        next_port = 12
    elif port == 63:
        next_port = 16
    elif port == 64:
        next_port = 23
    elif port == 65:
        next_port = 28
    elif port == 66:
        next_port = 42
    elif port == 80:
        return advance(o, w, 0, 5)
    elif port == 81:
        return advance(o, w, 82, 3)
    return advance(o, w, next_port, 1)

def failed(o:mutbuf, w:mutbuf) -> u32:
    port = get(w, 3)
    if port == 80 and get(w, 9) == 1:
        set(w, 9, 2)
        return advance(o, w, 81, 1)
    if port == 81 and get(w, 9) == 2:
        set(w, 9, 3)
        return advance(o, w, 0, 5)
    if get(w, 9) != 0:
        return refuse(o, w)
    set(w, 9, 1)
    if get(w, 2) == 1:
        if (port >= 24 and port <= 44) or port == 65 or port == 66:
            return advance(o, w, 80, 1)
    return advance(o, w, 0, 5)

def is_predicate(port:u64) -> u64:
    if port == 4 or port == 7 or port == 8 or port == 11 or port == 13 or port == 14 or port == 15:
        return 1
    if port == 17 or port == 18 or port == 20 or port == 21 or port == 22 or port == 27 or port == 35:
        return 1
    if port == 39 or port == 40 or port == 41:
        return 1
    return 0

def valid_state(w:mutbuf) -> u64:
    if get(w, 0) != @STATE_MAGIC@ or get(w, 1) != 1 or (get(w, 2) != 1 and get(w, 2) != 2):
        return 0
    if get(w, 4) == 0 or get(w, 4) > 128 or get(w, 5) == 0 or get(w, 5) > 6:
        return 0
    if get(w, 8) > 1 or get(w, 9) > 3 or get(w, 11) != 0 or get(w, 12) != 0 or get(w, 13) != 0 or get(w, 14) != 0 or get(w, 15) != 0:
        return 0
    if checksum(w) != get(w, 10):
        return 0
    port = get(w, 3)
    if get(w, 5) == 1 or get(w, 5) == 2:
        if (port >= 1 and port <= 44) or (port >= 60 and port <= 66) or port == 70 or port == 71 or port == 80 or port == 81:
            return 1
        return 0
    if get(w, 5) == 3:
        if port == 82 and get(w, 9) == 2:
            return 1
        return 0
    if port != 0:
        return 0
    return 1

def advance(o:mutbuf, w:mutbuf, port:u64, phase:u64) -> u32:
    set(w, 3, port)
    set(w, 4, get(w, 4) + 1)
    set(w, 5, phase)
    seal(w)
    return answer(o, w, 0)

def refuse(o:mutbuf, w:mutbuf) -> u32:
    set(w, 3, 0)
    set(w, 5, 6)
    seal(w)
    return answer(o, w, 1)

def answer(o:mutbuf, w:mutbuf, status:u64) -> u32:
    set(o, 0, @RESULT_MAGIC@)
    set(o, 1, status)
    set(o, 2, get(w, 3))
    set(o, 3, get(w, 4))
    set(o, 4, get(w, 5))
    set(o, 5, get(w, 2))
    set(o, 6, get(w, 8))
    set(o, 7, get(w, 9))
    set(o, 8, get(w, 6))
    set(o, 9, get(w, 7))
    return 80

def checksum(w:mutbuf) -> u64:
    value = 1469598103934665603
    i = 0
    while i < 16:
        if i != 10:
            value = ((value << 7) | (value >> 57)) ^ get(w, i)
        i = i + 1
    return value

def seal(w:mutbuf) -> u64:
    value = checksum(w)
    set(w, 10, value)
    return value

def read_word(s:readbuf, index:u64) -> u64:
    value = 0
    i = 0
    while i < 8:
        value = value | (byte(s, index + i) << (i * 8))
        i = i + 1
    return value

def get(w:mutbuf, index:u64) -> u64:
    value = 0
    i = 0
    while i < 8:
        value = value | (byte(w, index * 8 + i) << (i * 8))
        i = i + 1
    return value

def set(w:mutbuf, index:u64, value:u64) -> u64:
    i = 0
    while i < 8:
        store(w, index * 8 + i, value >> (i * 8))
        i = i + 1
    return value
'''


def source_program():
    value = SOURCE
    for name in ('REQUEST_MAGIC', 'RESULT_MAGIC', 'STATE_MAGIC'):
        value = value.replace('@' + name + '@', str(globals()[name]))
    return value


def document():
    nodes = ast.parse(source_program()).body
    names = {node.name: 'f' + str(i) for i, node in enumerate(nodes)}
    signatures = {node.name: ([arg.annotation.id for arg in node.args.args], node.returns.id)
                  for node in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = Builder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({'name': names[node.name], 'params': [builder.param(v) for v in builder.params],
            'returns': [builder.returns], 'effects': ['read', 'write', 'trap'],
            'entry': 'b0', 'blocks': builder.blocks})
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8',
                                  'module': 'store_lifecycle', 'functions': functions})


if __name__ == '__main__':
    path = ROOT / SOURCE_NAME
    path.write_text(render_assembly(document()))
    print(path.name, path.stat().st_size)

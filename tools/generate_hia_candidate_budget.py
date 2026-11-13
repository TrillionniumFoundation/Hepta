"""Author the ordinary candidate-attempt budget owner in HIA.

SQLite supplies bounded observations and performs fixed effects.  HIA admits
the original count, owns the next count and requires exact write/readback and
commit acknowledgements before a candidate may run.
"""
from __future__ import annotations

import ast
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ''}:
    sys.path.insert(0, str(ROOT))

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions

REQUEST_MAGIC = int.from_bytes(b'HIACBRQ1', 'little')
RESULT_MAGIC = int.from_bytes(b'HIACBRS1', 'little')
STATE_MAGIC = int.from_bytes(b'HIACBST1', 'little')
STATE_BYTES = 384
OUTPUT_BYTES = 272
SOURCE_PATH = 'examples/hia_bootstrap/candidate_budget.hepta'

SOURCE = r'''
def candidate_budget(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 96 or length(s) > 288 or length(o) < 272 or length(w) != 384:
        return 4294967293
    if read_word(s, 0) != @REQUEST_MAGIC@ or read_word(s, 88) != 0:
        return 4294967293
    event = read_word(s, 8)
    if event == 0:
        return initialize(s, o, w)
    if valid_state(w) == 0:
        return 4294967293
    if read_word(s, 48) != get(w, 4) or read_word(s, 56) != get(w, 5) or read_word(s, 64) != get(w, 6) or read_word(s, 72) != get(w, 7):
        return refuse(o, w, 2)
    if get(w, 2) >= 6 or read_word(s, 16) != get(w, 3):
        return refuse(o, w, 2)
    if event == 2:
        return observe_row(s, o, w)
    if length(s) != 96 or read_word(s, 32) != 0 or read_word(s, 40) != 0 or read_word(s, 80) != 0:
        return refuse(o, w, 1)
    if event == 1:
        if get(w, 2) != 1 or read_word(s, 24) != 1:
            return refuse(o, w, 2)
        set(w, 2, 2)
        return advance(o, w, 2)
    if event == 3:
        if get(w, 2) != 3 or read_word(s, 24) != 1:
            return refuse(o, w, 2)
        set(w, 2, 4)
        return advance(o, w, 2)
    if event == 4:
        if get(w, 2) != 5 or read_word(s, 24) != 1:
            return refuse(o, w, 4)
        set(w, 2, 6)
        return advance(o, w, 0)
    return refuse(o, w, 1)

def initialize(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    maximum = read_word(s, 24)
    size = read_word(s, 80)
    if maximum == 0 or maximum > 4096 or size == 0 or size > 192 or length(s) != 96 + size:
        return 4294967293
    if read_word(s, 16) != 0 or read_word(s, 32) != 0 or read_word(s, 40) != 0:
        return 4294967293
    if (read_word(s, 48) == 0 and read_word(s, 56) == 0) or (read_word(s, 64) == 0 and read_word(s, 72) == 0):
        return 4294967293
    i = 0
    while i < 384:
        if byte(w, i) != 0:
            return 4294967293
        i = i + 1
    set(w, 0, @STATE_MAGIC@)
    set(w, 1, 1)
    set(w, 2, 1)
    set(w, 3, 1)
    set(w, 4, read_word(s, 48))
    set(w, 5, read_word(s, 56))
    set(w, 6, read_word(s, 64))
    set(w, 7, read_word(s, 72))
    set(w, 8, maximum)
    set(w, 11, size)
    set(w, 12, 1)
    i = 0
    while i < size:
        store(w, 128 + i, byte(s, 96 + i))
        i = i + 1
    seal(w)
    return answer(o, w, 0)

def observe_row(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if get(w, 2) != 2 and get(w, 2) != 4:
        return refuse(o, w, 2)
    found = read_word(s, 24)
    kind = read_word(s, 32)
    value = read_word(s, 40)
    size = read_word(s, 80)
    if found > 1 or size > 192 or length(s) != 96 + size:
        return refuse(o, w, 1)
    if found == 0:
        if kind != 0 or value != 0 or size != 0:
            return refuse(o, w, 1)
        if get(w, 2) == 2:
            return refuse(o, w, 3)
        return refuse(o, w, 2)
    if kind != 0 or value >= 9223372036854775808:
        return refuse(o, w, 1)
    if size != get(w, 11):
        return refuse(o, w, 2)
    i = 0
    while i < size:
        if byte(s, 96 + i) != byte(w, 128 + i):
            return refuse(o, w, 2)
        i = i + 1
    if get(w, 2) == 2:
        if value >= get(w, 8):
            return refuse(o, w, 3)
        set(w, 9, value)
        set(w, 10, value + 1)
        set(w, 2, 3)
        return advance(o, w, 3)
    if value != get(w, 10):
        return refuse(o, w, 2)
    set(w, 2, 5)
    return advance(o, w, 4)

def valid_state(w:mutbuf) -> u64:
    if get(w, 0) != @STATE_MAGIC@ or get(w, 1) != 1 or get(w, 2) == 0 or get(w, 2) > 7:
        return 0
    if get(w, 3) == 0 or get(w, 3) > 7 or get(w, 8) == 0 or get(w, 8) > 4096:
        return 0
    if get(w, 11) == 0 or get(w, 11) > 192 or get(w, 12) > 4:
        return 0
    if checksum(w) != get(w, 13):
        return 0
    return 1

def refuse(o:mutbuf, w:mutbuf, status:u64) -> u32:
    set(w, 2, 7)
    set(w, 12, 0)
    seal(w)
    return answer(o, w, status)

def advance(o:mutbuf, w:mutbuf, action:u64) -> u32:
    set(w, 3, get(w, 3) + 1)
    set(w, 12, action)
    seal(w)
    return answer(o, w, 0)

def answer(o:mutbuf, w:mutbuf, status:u64) -> u32:
    set(o, 0, @RESULT_MAGIC@)
    set(o, 1, status)
    set(o, 2, get(w, 12))
    set(o, 3, get(w, 3))
    set(o, 4, get(w, 2))
    set(o, 5, get(w, 8))
    set(o, 6, get(w, 9))
    set(o, 7, get(w, 10))
    set(o, 8, get(w, 11))
    set(o, 9, 0)
    i = 0
    while i < get(w, 11):
        store(o, 80 + i, byte(w, 128 + i))
        i = i + 1
    return 80 + get(w, 11)

def checksum(w:mutbuf) -> u64:
    value = 1469598103934665603
    i = 0
    while i < 48:
        if i != 13:
            value = ((value << 7) | (value >> 57)) ^ get(w, i)
        i = i + 1
    return value

def seal(w:mutbuf) -> u64:
    value = checksum(w)
    set(w, 13, value)
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
    signatures = {n.name: ([a.annotation.id for a in n.args.args], n.returns.id) for n in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = Builder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({'name': names[node.name], 'params': [builder.param(v) for v in builder.params],
            'returns': [builder.returns], 'effects': ['read', 'write', 'trap'],
            'entry': 'b0', 'blocks': builder.blocks})
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8', 'module': 'candidate_budget', 'functions': functions})


def main():
    path = ROOT / SOURCE_PATH
    path.write_text(render_assembly(document()))
    print(path.name, path.stat().st_size)


if __name__ == '__main__':
    main()

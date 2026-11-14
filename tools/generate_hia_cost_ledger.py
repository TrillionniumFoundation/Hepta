"""Author the complete read-only cost-ledger continuation and signed sum in HIA.

SQLite, JSON and CPython object conversion/allocation are fixed foreign ports.
The program owns the retained row cut, order, two scans, equality, exact signed
addition, unknown external costs and successful/exceptional terminal policy.
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
REQUEST_MAGIC = int.from_bytes(b'HIACLRQ1', 'little')
RESULT_MAGIC = int.from_bytes(b'HIACLRS1', 'little')
STATE_MAGIC = int.from_bytes(b'HIACLST1', 'little')
SOURCE_NAME = 'examples/hia_bootstrap/cost_ledger.hepta'
SOURCE = r'''
def cost_ledger(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 16 or read_word(s, 0) != @REQUEST_MAGIC@:
        return 4294967293
    event = read_word(s, 8)
    if event == 10:
        return add(s, o)
    if event == 11:
        return equal(s, o)
    if length(s) != 80 or length(o) != 80 or length(w) != 128:
        return 4294967293
    if read_word(s, 64) != 0 or read_word(s, 72) != 0:
        return 4294967293
    if event == 0:
        return initialize(s, o, w)
    if valid(w) == 0:
        return 4294967293
    if read_word(s, 16) != get(w, 4) or read_word(s, 24) != get(w, 3):
        return refuse(o, w)
    if read_word(s, 40) != 0 or read_word(s, 48) != get(w, 6) or read_word(s, 56) != get(w, 7):
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
        return succeeded(o, w, read_word(s, 32))
    if event == 3:
        if get(w, 5) != 2 or read_word(s, 32) != 0:
            return refuse(o, w)
        return advance(o, w, 0, 5)
    return refuse(o, w)

def initialize(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if read_word(s, 16) != 0 or read_word(s, 24) != 0 or read_word(s, 32) != 0 or read_word(s, 40) != 0:
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
    set(w, 3, 1)
    set(w, 4, 1)
    set(w, 5, 1)
    set(w, 6, read_word(s, 48))
    set(w, 7, read_word(s, 56))
    seal(w)
    return answer(o, w, 0)

def succeeded(o:mutbuf, w:mutbuf, observed:u64) -> u32:
    port = get(w, 3)
    if port == 1:
        if observed > 10001:
            return refuse(o, w)
        set(w, 12, observed)
        if observed > 10000:
            set(w, 12, 10000)
            set(w, 13, 1)
        return advance(o, w, 2, 1)
    if port == 6 or port == 11 or port == 14:
        if observed > 1:
            return refuse(o, w)
    elif port != 7:
        if observed != 0:
            return refuse(o, w)
    next_port = port + 1
    if port == 2:
        set(w, 8, 0)
        if get(w, 12) == 0:
            next_port = 4
    elif port == 3:
        set(w, 8, get(w, 8) + 1)
        if get(w, 8) < get(w, 12):
            next_port = 3
    elif port == 6:
        if observed == 1:
            next_port = 10
    elif port == 7:
        set(w, 14, observed)
        set(w, 8, 0)
        if observed == 0:
            next_port = 9
    elif port == 8:
        set(w, 8, get(w, 8) + 1)
        if get(w, 8) < get(w, 14):
            next_port = 8
    elif port == 9:
        next_port = 10
    elif port == 10:
        set(w, 8, 0)
        set(w, 9, 0)
        if get(w, 12) == 0:
            next_port = 15
    elif port == 11 or port == 14:
        if observed == 1:
            next_port = 12
        else:
            return next_row(o, w)
    elif port == 13:
        return next_row(o, w)
    elif port == 15:
        return advance(o, w, 0, 4)
    return advance(o, w, next_port, 1)

def next_row(o:mutbuf, w:mutbuf) -> u32:
    set(w, 8, get(w, 8) + 1)
    if get(w, 8) < get(w, 12):
        if get(w, 9) == 0:
            return advance(o, w, 11, 1)
        return advance(o, w, 14, 1)
    if get(w, 9) == 0:
        set(w, 9, 1)
        set(w, 8, 0)
        return advance(o, w, 14, 1)
    return advance(o, w, 15, 1)

def valid(w:mutbuf) -> u64:
    if get(w, 0) != @STATE_MAGIC@ or get(w, 1) != 1 or get(w, 2) != 0:
        return 0
    if get(w, 4) == 0 or get(w, 5) == 0 or get(w, 5) > 6:
        return 0
    if get(w, 9) > 1 or get(w, 12) > 10000 or get(w, 13) > 1 or get(w, 11) != 0 or get(w, 15) != 0:
        return 0
    if checksum(w) != get(w, 10):
        return 0
    port = get(w, 3)
    if get(w, 5) == 1 or get(w, 5) == 2:
        if port < 1 or port > 15:
            return 0
        if port == 3 or port == 11 or port == 12 or port == 13 or port == 14:
            if get(w, 8) >= get(w, 12):
                return 0
        if port == 8 and get(w, 8) >= get(w, 14):
            return 0
        return 1
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
    set(o, 5, get(w, 8))
    set(o, 6, get(w, 9))
    set(o, 7, get(w, 13))
    set(o, 8, get(w, 6))
    set(o, 9, get(w, 7))
    return 80

def add(s:readbuf, o:mutbuf) -> u32:
    if length(s) < 34:
        return 4294967293
    a = read_word(s, 16)
    b = read_word(s, 24)
    if a == 0 or b == 0 or a > length(s) - 32 or b != length(s) - 32 - a:
        return 4294967293
    width = a
    if b > width:
        width = b
    if width > length(o) or length(o) - width < 17:
        return 4294967293
    sign_a = 0
    sign_b = 0
    if byte(s, 31 + a) >= 128:
        sign_a = 255
    if byte(s, 31 + a + b) >= 128:
        sign_b = 255
    i = 0
    carry = 0
    while i <= width:
        x = sign_a
        y = sign_b
        if i < a:
            x = byte(s, 32 + i)
        if i < b:
            y = byte(s, 32 + a + i)
        total = x + y + carry
        store(o, 16 + i, total)
        carry = total >> 8
        i = i + 1
    size = width + 1
    trimming = 1
    while size > 1 and trimming == 1:
        top = byte(o, 15 + size)
        below = byte(o, 14 + size)
        if (top == 0 and below < 128) or (top == 255 and below >= 128):
            size = size - 1
        else:
            trimming = 0
    set(o, 0, @RESULT_MAGIC@)
    set(o, 1, size)
    return 16

def equal(s:readbuf, o:mutbuf) -> u32:
    if length(s) < 34 or length(o) != 16:
        return 4294967293
    a = read_word(s, 16)
    b = read_word(s, 24)
    if a == 0 or b == 0 or a > length(s) - 32 or b != length(s) - 32 - a:
        return 4294967293
    same = 0
    if a == b:
        same = 1
        i = 0
        while i < a:
            if byte(s, 32 + i) != byte(s, 32 + a + i):
                same = 0
            i = i + 1
    set(o, 0, @RESULT_MAGIC@)
    set(o, 1, same)
    return 16

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
                                  'module': 'cost_ledger', 'functions': functions})


if __name__ == '__main__':
    path = ROOT / SOURCE_NAME
    path.write_text(render_assembly(document()))
    print(path.name, path.stat().st_size)

"""Author retained generation/lease state, independent of foreign resources."""
from __future__ import annotations
import ast
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ''}:
    sys.path.insert(0, str(ROOT))
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions

REQUEST_MAGIC = int.from_bytes(b'HIAGRQ01', 'little')
STATE_MAGIC = int.from_bytes(b'HIAGST01', 'little')
LEASE_MAGIC = int.from_bytes(b'HIAGLS01', 'little')
SOURCE = r'''
def generation_retention(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) != 64 or length(o) != 64 or length(w) < 65:
        return 4294967293
    if read_word(s, 0) != @REQUEST_MAGIC@ or read_word(s, 48) != 0 or read_word(s, 56) != 0:
        return 4294967293
    event = read_word(s, 8)
    a = read_word(s, 16)
    b = read_word(s, 24)
    token_a = read_word(s, 32)
    token_b = read_word(s, 40)
    if (a == 0 and b == 0) or event > 6:
        return 4294967293
    if event == 0:
        if all_zero(w) == 0 or token_a != 0 or token_b != 0:
            return 4294967292
        set_word(w, 0, @STATE_MAGIC@)
        set_word(w, 1, a)
        set_word(w, 2, b)
        seal_state(w)
        return 0
    if valid_state(w) == 0:
        return 4294967292
    if get_word(w, 1) != a or get_word(w, 2) != b:
        return 4294967291
    if event == 1:
        return acquire(o, w, token_a, token_b)
    if event == 2:
        return close_lease(o, w, token_a, token_b)
    if event == 6:
        if valid_lease(o, w, token_a, token_b) == 0:
            return 4294967291
        return narrow(get_word(o, 5))
    if event == 3:
        if token_a != 0 or token_b != 0:
            return 4294967293
        set_word(w, 3, get_word(w, 3) | 1)
        seal_state(w)
        return 0
    if event == 4:
        return claim(w, token_a, token_b)
    if token_a != 0 or token_b != 0:
        return 4294967293
    flags = get_word(w, 3)
    if get_word(w, 4) == 0:
        flags = flags | 4
        if (flags & 1) != 0:
            flags = flags | 8
            if (flags & 2) == 0:
                flags = flags | 16
    return narrow(flags)

def acquire(o:mutbuf, w:mutbuf, a:u64, b:u64) -> u32:
    if (a == 0 and b == 0) or all_zero(o) == 0:
        return 4294967291
    if get_word(w, 3) != 0:
        return 4294967290
    n = get_word(w, 4)
    # No state or lease byte is touched before this capacity decision.
    i = 0
    carry = 1
    while i < n and carry != 0:
        if byte(w, 64 + i) != 255:
            carry = 0
        i = i + 1
    if carry != 0 and n == length(w) - 64:
        return 4294967288
    i = 0
    carry = 1
    while i < n and carry != 0:
        value = byte(w, 64 + i)
        if value == 255:
            store(w, 64 + i, 0)
        else:
            store(w, 64 + i, value + 1)
            carry = 0
        i = i + 1
    if carry != 0:
        store(w, 64 + n, 1)
        n = n + 1
    set_word(w, 4, n)
    set_word(o, 0, @LEASE_MAGIC@)
    set_word(o, 1, get_word(w, 1))
    set_word(o, 2, get_word(w, 2))
    set_word(o, 3, a)
    set_word(o, 4, b)
    set_word(o, 5, 1)
    seal_lease(o)
    seal_state(w)
    return 0

def close_lease(o:mutbuf, w:mutbuf, a:u64, b:u64) -> u32:
    if valid_lease(o, w, a, b) == 0:
        return 4294967291
    if get_word(o, 5) == 2:
        return 1
    n = get_word(w, 4)
    if n == 0 or (get_word(w, 3) & 2) != 0:
        return 4294967287
    i = 0
    borrow = 1
    while i < n and borrow != 0:
        value = byte(w, 64 + i)
        if value == 0:
            store(w, 64 + i, 255)
        else:
            store(w, 64 + i, value - 1)
            borrow = 0
        i = i + 1
    while n > 0 and byte(w, 64 + n - 1) == 0:
        n = n - 1
    set_word(w, 4, n)
    set_word(o, 5, 2)
    seal_lease(o)
    seal_state(w)
    return 0

def claim(w:mutbuf, a:u64, b:u64) -> u32:
    if a == 0 and b == 0:
        return 4294967291
    if (get_word(w, 3) & 1) == 0 or get_word(w, 4) != 0:
        return 4294967290
    if (get_word(w, 3) & 2) != 0:
        if get_word(w, 6) != a or get_word(w, 7) != b:
            return 4294967291
        return 1
    set_word(w, 3, 3)
    set_word(w, 6, a)
    set_word(w, 7, b)
    seal_state(w)
    return 0

def valid_state(w:mutbuf) -> u64:
    if get_word(w, 0) != @STATE_MAGIC@ or get_word(w, 3) > 3:
        return 0
    n = get_word(w, 4)
    if n > length(w) - 64:
        return 0
    if n != 0 and byte(w, 64 + n - 1) == 0:
        return 0
    i = 64 + n
    while i < length(w):
        if byte(w, i) != 0:
            return 0
        i = i + 1
    flags = get_word(w, 3)
    if (flags & 2) != 0:
        if flags != 3 or n != 0 or (get_word(w, 6) == 0 and get_word(w, 7) == 0):
            return 0
    elif get_word(w, 6) != 0 or get_word(w, 7) != 0:
        return 0
    if checksum(w, 64 + n, 40) != get_word(w, 5):
        return 0
    return 1

def valid_lease(o:mutbuf, w:mutbuf, a:u64, b:u64) -> u64:
    if get_word(o, 0) != @LEASE_MAGIC@ or get_word(o, 7) != 0:
        return 0
    if get_word(o, 1) != get_word(w, 1) or get_word(o, 2) != get_word(w, 2):
        return 0
    if (a == 0 and b == 0) or get_word(o, 3) != a or get_word(o, 4) != b:
        return 0
    if get_word(o, 5) < 1 or get_word(o, 5) > 2:
        return 0
    if checksum(o, 64, 48) != get_word(o, 6):
        return 0
    return 1

def checksum(w:mutbuf, size:u64, skip:u64) -> u64:
    value = 1469598103934665603
    i = 0
    while i < size:
        if i < skip or i >= skip + 8:
            value = (value ^ byte(w, i)) * 1099511628211
        i = i + 1
    return value

def seal_state(w:mutbuf) -> u64:
    return set_word(w, 5, checksum(w, 64 + get_word(w, 4), 40))

def seal_lease(o:mutbuf) -> u64:
    return set_word(o, 6, checksum(o, 64, 48))

def all_zero(w:mutbuf) -> u64:
    i = 0
    while i < length(w):
        if byte(w, i) != 0:
            return 0
        i = i + 1
    return 1

def get_word(w:mutbuf, index:u64) -> u64:
    value = 0
    i = 0
    while i < 8:
        value = value | (byte(w, index * 8 + i) << (i * 8))
        i = i + 1
    return value

def read_word(s:readbuf, at:u64) -> u64:
    value = 0
    i = 0
    while i < 8:
        value = value | (byte(s, at + i) << (i * 8))
        i = i + 1
    return value

def set_word(w:mutbuf, index:u64, value:u64) -> u64:
    i = 0
    while i < 8:
        store(w, index * 8 + i, value >> (i * 8))
        i = i + 1
    return value

def narrow(value:u64) -> u32:
    return value
'''


def source_program():
    value = SOURCE
    for name, number in {'REQUEST_MAGIC': REQUEST_MAGIC, 'STATE_MAGIC': STATE_MAGIC,
                         'LEASE_MAGIC': LEASE_MAGIC}.items():
        value = value.replace('@' + name + '@', str(number))
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
        functions.append({'name': names[node.name], 'params': [builder.param(p) for p in builder.params],
            'returns': [builder.returns], 'effects': ['read', 'write', 'trap'],
            'entry': 'b0', 'blocks': builder.blocks})
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8',
        'module': 'generation_retention', 'functions': functions})


if __name__ == '__main__':
    path = ROOT / 'examples/hia_bootstrap/generation_retention.hepta'
    path.write_text(render_assembly(document()))
    print(path.name, path.stat().st_size)

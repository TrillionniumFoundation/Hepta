"""Author the explicit HIA fresh checkout-source admission owner.

The runtime never imports this generator. Path union, ordering, deduplication,
read claims, SHA-256 and complete-map decisions are all emitted as HIA.
The canonical asset is byte-identical to the frozen revision-three prototype.
"""
from __future__ import annotations
import argparse
import ast
from hashlib import sha256
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ''}:
    sys.path.insert(0, str(ROOT))
SOURCE = ROOT / 'examples/hia_bootstrap/source_admission.hepta'
FROZEN_HIA_SHA256 = 'e7e0bdf576dd721c36d98a2b1855bcd34a2ab480094c322a3629ddc26de192f6'

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions
from tools.generate_hia_sha256 import INITIAL, ROUND, BODY as SHA_BODY


class _SourceAdmissionBuilder(Builder):
    """Preserve the frozen revision-three operation stream for this owner."""

    def op(self,op,args,t=None,**attrs):
        out=[] if t is None else [self.value(t)]
        self.block['ops'].append({'op':op,'args':[a[0] for a in args],'out':[self.param(x) for x in out],'attrs':attrs})
        return out[0] if out else None


POLICY = r'''
def entry(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(o) < 48 or length(s) < 8:
        return 4294967281
    fill_range(o, 0, length(o), 0)
    op = read_word(s, 0)
    if op == 0:
        return initialize(s, o, w)
    if length(s) < 24 or valid_state(w) == 0:
        return refuse(o, 16)
    if read_word(s, 8) != get(w, 24):
        return refuse(o, 16)
    if op == 4:
        if length(s) != 24:
            return refuse(o, 16)
        receipt(o, 0, 3, get(w, 24), get(w, 32), get(w, 16), get(w, 56))
        return 0
    if read_word(s, 16) != get(w, 32):
        return refuse(o, 16)
    if op == 1:
        return next_file(s, o, w)
    if op == 2:
        return accept_bytes(s, o, w)
    if op == 3:
        if length(s) != 32 or get(w, 16) != 2:
            return refuse(o, 16)
        put(w, 16, 5)
        put(w, 104, read_word(s, 24))
        seal(w)
        receipt(o, 4, 4, get(w, 24), get(w, 32), get(w, 96), get(w, 104))
        return 4
    return refuse(o, 16)

def initialize(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 32 or read_word(s, 8) == 0:
        return refuse(o, 16)
    declared = read_word(s, 16)
    dynamic = read_word(s, 24)
    count = declared + dynamic
    if count < declared or count > ((length(s) - 32) >> 4):
        return refuse(o, 16)
    if count > 192153584101141146:
        return refuse(o, 16)
    base = 1536 + count * 96
    extent = base + length(s)
    if base < 1536 or extent < base:
        return refuse(o, 16)
    at = 32
    i = 0
    while i < count:
        if at > length(s) or length(s) - at < 16:
            return refuse(o, 16)
        if read_word(s, at) != i:
            return refuse(o, 16)
        size = read_word(s, at + 8)
        at = at + 16
        if size > length(s) - at:
            return refuse(o, 16)
        at = at + size
        i = i + 1
    if at != length(s):
        return refuse(o, 16)
    i = 0
    while i < length(w):
        if byte(w, i) != 0:
            return refuse(o, 16)
        i = i + 1
    if length(w) < extent:
        receipt(o, 1, 5, read_word(s, 8), 0, count, extent)
        return 1
    fill_range(w, 0, length(w), 0)
    put(w, 0, 3548931266558574920)
    put(w, 8, 1)
    put(w, 16, 1)
    put(w, 24, read_word(s, 8))
    put(w, 40, count)
    put(w, 64, extent)
    put(w, 72, base)
    put(w, 80, length(s))
    i = 0
    while i < length(s):
        store(w, base + i, byte(s, i))
        i = i + 1
    at = 32
    i = 0
    while i < count:
        size = read_word(s, at + 8)
        record = 1536 + i * 96
        put(w, record, base + at + 16)
        put(w, record + 8, size)
        put(w, record + 16, i)
        at = at + 16 + size
        i = i + 1
    sort_records(w, count)
    unique = 0
    i = 0
    while i < count:
        admit = 1
        if unique > 0:
            if compare_names(w, 1536 + (unique - 1) * 96, 1536 + i * 96) == 0:
                admit = 0
        if admit == 1:
            copy_record(w, 1536 + unique * 96, 1536 + i * 96)
            unique = unique + 1
        i = i + 1
    put(w, 48, unique)
    seal(w)
    receipt(o, 0, 0, get(w, 24), 0, unique, extent)
    return 0

def next_file(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) != 24 or get(w, 16) != 1:
        return refuse(o, 16)
    cursor = get(w, 56)
    count = get(w, 48)
    if cursor < count:
        if get(w, 32) == 18446744073709551615:
            return refuse(o, 16)
        record = 1536 + cursor * 96
        if get(w, record + 88) != 0:
            return refuse(o, 16)
        put(w, 32, get(w, 32) + 1)
        put(w, 96, get(w, record + 16))
        put(w, 16, 2)
        seal(w)
        receipt(o, 0, 1, get(w, 24), get(w, 32), get(w, 96), get(w, record + 8))
        return 0
    if count > 256204778801521549:
        return refuse(o, 16)
    required = 48 + count * 72
    if length(o) < required:
        receipt(o, 1, 6, get(w, 24), get(w, 32), count, required)
        return 1
    i = 0
    while i < count:
        if get(w, 1536 + i * 96 + 88) != 1:
            return refuse(o, 16)
        i = i + 1
    i = 0
    while i < count:
        record = 1536 + i * 96
        destination = 48 + i * 72
        put(o, destination, get(w, record + 16))
        j = 0
        while j < 64:
            store(o, destination + 8 + j, byte(w, record + 24 + j))
            j = j + 1
        i = i + 1
    put(w, 16, 4)
    seal(w)
    receipt(o, 0, 2, get(w, 24), get(w, 32), count, required)
    return 0

def accept_bytes(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 32 or get(w, 16) != 2:
        return refuse(o, 16)
    size = read_word(s, 24)
    if size != length(s) - 32:
        return refuse(o, 16)
    record = 1536 + get(w, 56) * 96
    if get(w, 56) >= get(w, 48) or get(w, record + 88) != 0:
        return refuse(o, 16)
    put(w, 16, 3)
    sha_file(s, 32, size, w, record + 24)
    put(w, record + 88, 1)
    put(w, 56, get(w, 56) + 1)
    put(w, 16, 1)
    seal(w)
    receipt(o, 0, 0, get(w, 24), get(w, 32), get(w, 56), get(w, 64))
    return 0

def valid_state(w:mutbuf) -> u64:
    if length(w) < 1536:
        return 0
    if get(w, 0) != 3548931266558574920 or get(w, 8) != 1 or get(w, 24) == 0:
        return 0
    extent = get(w, 64)
    count = get(w, 40)
    if extent < 1568 or extent > length(w) or count > ((extent - 1536) >> 4):
        return 0
    if count > 192153584101141146:
        return 0
    base = 1536 + count * 96
    if base > extent or get(w, 72) != base or get(w, 80) != extent - base:
        return 0
    if get(w, 80) < 32 or get(w, 48) > count or get(w, 56) > get(w, 48):
        return 0
    if get(w, 16) < 1 or get(w, 16) > 5 or get(w, 16) == 3:
        return 0
    if get(w, 16) == 2 and get(w, 56) >= get(w, 48):
        return 0
    if checksum(w) != get(w, 120):
        return 0
    i = 0
    while i < get(w, 48):
        record = 1536 + i * 96
        offset = get(w, record)
        size = get(w, record + 8)
        if offset < base or offset > extent or size > extent - offset:
            return 0
        if get(w, record + 16) >= count or get(w, record + 88) > 1:
            return 0
        i = i + 1
    return 1

def checksum(w:mutbuf) -> u64:
    h = 14695981039346656037
    i = 0
    extent = get(w, 64)
    while i < 120:
        h = (h ^ byte(w, i + 0)) * 1099511628211
        h = (h ^ byte(w, i + 1)) * 1099511628211
        h = (h ^ byte(w, i + 2)) * 1099511628211
        h = (h ^ byte(w, i + 3)) * 1099511628211
        h = (h ^ byte(w, i + 4)) * 1099511628211
        h = (h ^ byte(w, i + 5)) * 1099511628211
        h = (h ^ byte(w, i + 6)) * 1099511628211
        h = (h ^ byte(w, i + 7)) * 1099511628211
        i = i + 8
    i = 128
    while i <= extent - 8:
        h = (h ^ byte(w, i + 0)) * 1099511628211
        h = (h ^ byte(w, i + 1)) * 1099511628211
        h = (h ^ byte(w, i + 2)) * 1099511628211
        h = (h ^ byte(w, i + 3)) * 1099511628211
        h = (h ^ byte(w, i + 4)) * 1099511628211
        h = (h ^ byte(w, i + 5)) * 1099511628211
        h = (h ^ byte(w, i + 6)) * 1099511628211
        h = (h ^ byte(w, i + 7)) * 1099511628211
        i = i + 8
    while i < extent:
        h = (h ^ byte(w, i)) * 1099511628211
        i = i + 1
    return h

def seal(w:mutbuf) -> u64:
    put(w, 120, checksum(w))
    return 0

def receipt(o:mutbuf, status:u64, action:u64, nonce:u64, sequence:u64, value:u64, required:u64) -> u64:
    put(o, 0, status)
    put(o, 8, action)
    put(o, 16, nonce)
    put(o, 24, sequence)
    put(o, 32, value)
    put(o, 40, required)
    return status

def refuse(o:mutbuf, status:u64) -> u32:
    put(o, 0, status)
    return status

def compare_names(w:mutbuf, left:u64, right:u64) -> u64:
    a = get(w, left)
    b = get(w, right)
    an = get(w, left + 8)
    bn = get(w, right + 8)
    i = 0
    while i < an and i < bn:
        x = byte(w, a + i)
        y = byte(w, b + i)
        if x < y:
            return 1
        if x > y:
            return 2
        i = i + 1
    if an < bn:
        return 1
    if an > bn:
        return 2
    return 0

def greater(w:mutbuf, left:u64, right:u64) -> u64:
    relation = compare_names(w, left, right)
    if relation == 2:
        return 1
    if relation == 0 and get(w, left + 16) > get(w, right + 16):
        return 1
    return 0

def copy_record(w:mutbuf, destination:u64, source:u64) -> u64:
    if destination != source:
        i = 0
        while i < 96:
            store(w, destination + i, byte(w, source + i))
            i = i + 1
    return 0

def swap_records(w:mutbuf, left:u64, right:u64) -> u64:
    i = 0
    while i < 96:
        value = byte(w, left + i)
        store(w, left + i, byte(w, right + i))
        store(w, right + i, value)
        i = i + 1
    return 0

def sift(w:mutbuf, root:u64, count:u64) -> u64:
    active = 1
    while active == 1 and root < (count >> 1):
        child = root * 2 + 1
        if child + 1 < count:
            if greater(w, 1536 + (child + 1) * 96, 1536 + child * 96) == 1:
                child = child + 1
        if greater(w, 1536 + child * 96, 1536 + root * 96) == 1:
            swap_records(w, 1536 + root * 96, 1536 + child * 96)
            root = child
        else:
            active = 0
    return 0

def sort_records(w:mutbuf, count:u64) -> u64:
    start = count >> 1
    while start > 0:
        start = start - 1
        sift(w, start, count)
    end = count
    while end > 1:
        end = end - 1
        swap_records(w, 1536, 1536 + end * 96)
        sift(w, 0, end)
    return 0

def read_word(s:readbuf, at:u64) -> u64:
    return (byte(s, at + 0) << 0) | (byte(s, at + 1) << 8) | (byte(s, at + 2) << 16) | (byte(s, at + 3) << 24) | (byte(s, at + 4) << 32) | (byte(s, at + 5) << 40) | (byte(s, at + 6) << 48) | (byte(s, at + 7) << 56)

def get(w:mutbuf, at:u64) -> u64:
    return (byte(w, at + 0) << 0) | (byte(w, at + 1) << 8) | (byte(w, at + 2) << 16) | (byte(w, at + 3) << 24) | (byte(w, at + 4) << 32) | (byte(w, at + 5) << 40) | (byte(w, at + 6) << 48) | (byte(w, at + 7) << 56)

def put(w:mutbuf, at:u64, value:u64) -> u64:
    store(w, at + 0, (value >> 0) & 255)
    store(w, at + 1, (value >> 8) & 255)
    store(w, at + 2, (value >> 16) & 255)
    store(w, at + 3, (value >> 24) & 255)
    store(w, at + 4, (value >> 32) & 255)
    store(w, at + 5, (value >> 40) & 255)
    store(w, at + 6, (value >> 48) & 255)
    store(w, at + 7, (value >> 56) & 255)
    return 0
'''


def sha_source():
    source = 'def sha_file(s:readbuf, start:u64, count:u64, w:mutbuf, destination:u64) -> u64:\n'
    for i, value in enumerate(ROUND):
        source += f'    sha_put(w, {i*8}, {value})\n'
    for i, value in enumerate(INITIAL):
        source += f'    sha_put(w, {1024+i*8}, {value})\n'
    fragment = '        while i < 16:\n            value = 0\n            j = 0\n            while j < 4:\n                value = (value << 8) | padded_byte(s, block + i * 4 + j, padded)\n                j = j + 1\n            put(w, 512 + i * 8, value)\n            i = i + 1\n'
    replacement = '        if block <= count and count - block >= 64:\n            while i < 16:\n                at = start + block + i * 4\n                value = (byte(s, at) << 24) | (byte(s, at + 1) << 16) | (byte(s, at + 2) << 8) | byte(s, at + 3)\n                put(w, 512 + i * 8, value)\n                i = i + 1\n        else:\n            while i < 16:\n                value = 0\n                j = 0\n                while j < 4:\n                    value = (value << 8) | padded_byte(s, block + i * 4 + j, padded)\n                    j = j + 1\n                put(w, 512 + i * 8, value)\n                i = i + 1\n'
    assert SHA_BODY.count(fragment) == 1
    body = SHA_BODY.replace(fragment, replacement).replace('length(s)', 'count')
    body = body.replace('padded_byte(s, block + i * 4 + j, padded)',
                        'sha_padded_byte(s, start, count, block + i * 4 + j, padded)')
    body = body.replace('get(', 'sha_get(').replace('put(', 'sha_put(').replace('rotate(', 'sha_rotate(')
    source += body
    for i, name in enumerate('abcdefgh'):
        source += f'        sha_put(w, {1024+i*8}, (sha_get(w, {1024+i*8}) + {name}) & 4294967295)\n'
    source += '''        block = block + 64
    i = 0
    while i < 8:
        value = sha_get(w, 1024 + i * 8)
        j = 0
        while j < 8:
            nibble = (value >> ((7 - j) * 4)) & 15
            character = nibble + 48
            if nibble > 9:
                character = nibble + 87
            store(w, destination + i * 8 + j, character)
            j = j + 1
        i = i + 1
    return 0

def sha_padded_byte(s:readbuf, start:u64, count:u64, index:u64, total:u64) -> u64:
    if index < count:
        return byte(s, start + index)
    if index == count:
        return 128
    if index < total - 8:
        return 0
    return (((count & 2305843009213693951) << 3) >> ((total - 1 - index) * 8)) & 255

def sha_rotate(value:u64, shift:u64) -> u64:
    return (value >> shift) | ((value << (32 - shift)) & 4294967295)

def sha_get(w:mutbuf, index:u64) -> u64:
    at = 256 + index
    return byte(w, at) | (byte(w, at + 1) << 8) | (byte(w, at + 2) << 16) | (byte(w, at + 3) << 24)

def sha_put(w:mutbuf, index:u64, value:u64) -> u64:
    at = 256 + index
    store(w, at + 0, (value >> 0) & 255)
    store(w, at + 1, (value >> 8) & 255)
    store(w, at + 2, (value >> 16) & 255)
    store(w, at + 3, (value >> 24) & 255)
    store(w, at + 4, 0)
    store(w, at + 5, 0)
    store(w, at + 6, 0)
    store(w, at + 7, 0)
    return 0
'''
    return source


def source_program():
    return POLICY + sha_source()


def document():
    nodes = ast.parse(source_program()).body
    names = {node.name: 'f'+str(i) for i, node in enumerate(nodes)}
    signatures = {node.name: ([a.annotation.id for a in node.args.args], node.returns.id) for node in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = _SourceAdmissionBuilder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({'name': names[node.name], 'params': [builder.param(v) for v in builder.params],
                          'returns': [builder.returns], 'effects': ['read', 'write', 'trap'],
                          'entry': 'b0', 'blocks': builder.blocks})
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8', 'module': 'checkout_source_admission',
                                  'functions': functions})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    doc = document()
    raw = render_assembly(doc).encode()
    functions = doc['functions']
    blocks = [b for f in functions for b in f['blocks']]
    info = {'functions': len(functions), 'blocks': len(blocks),
            'ops': sum(len(b['ops']) for b in blocks),
            'max_block_params': max(len(b['params']) for b in blocks),
            'assembly_bytes': len(raw), 'sha256': sha256(raw).hexdigest()}
    if not (info['functions'] <= 128 and info['blocks'] <= 1536
            and info['ops'] <= 8192 and info['max_block_params'] <= 16
            and len(raw) <= 1 << 20):
        raise ValueError('source-admission authoring exceeds the original compiler profile')
    if info['sha256'] != FROZEN_HIA_SHA256:
        raise ValueError('canonical HIA differs from the retained revision-three source')
    if args.check:
        if SOURCE.read_bytes() != raw:
            raise ValueError('checked-in source-admission HIA is not generated from this owner')
    else:
        SOURCE.write_bytes(raw)
    print(json.dumps(info, sort_keys=True))


if __name__ == '__main__':
    main()

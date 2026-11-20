"""Generate HIA's complete finite patch impact and call-graph owner.

Inputs are detached, freshly verified function facts. Canonical function and
signature bytes are transported unchanged. This code owns comparisons, sorted
identities, edge construction/deduplication and both-graph transitive closure.
It does not replace Core verification, patching or receipt authentication.
"""
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document

ROOT = Path(__file__).resolve().parents[1]
REQUEST_MAGIC = int.from_bytes(b'HIAPIM01', 'little')
RESULT_MAGIC = int.from_bytes(b'HIAPIR01', 'little')

POLICY = '''def impact(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 32 or length(w) < 64:
        return 1
    put(w, 0, 0)
    put(w, 8, 0)
    magic = number(s, w)
    phase = number(s, w)
    old = number(s, w)
    count = number(s, w)
    if magic != REQUEST_MAGIC or phase > 1:
        return 1
    if old == 0 or old > 1024 or count == 0 or count > 1024:
        return 2
    stride = (count + 7) >> 3
    newbase = 64 + old * 40
    oldorder = newbase + count * 40
    neworder = oldorder + old * 8
    queue = neworder + count * 8
    flags = queue + count * 8
    matrix = flags + count * 8
    area = count * stride
    if length(w) != matrix + area * 2 or length(o) != 16 + count * 16 + area * 2:
        return 1
    if records(s, w, 64, old, phase) != 0:
        return 1
    if records(s, w, newbase, count, phase) != 0 or get(w, 0) != length(s):
        return 1
    if order(s, w, 64, oldorder, old) != 0:
        return 1
    if order(s, w, newbase, neworder, count) != 0:
        return 1
    if changes(s, w, old, newbase, neworder, count, flags) != 0:
        return 3
    i = 0
    while i < area * 2:
        store(w, matrix + i, 0)
        i = i + 1
    if phase != 0:
        if edges(s, w, 64, oldorder, old, newbase, neworder, count, matrix, stride) != 0:
            return 4
        if edges(s, w, newbase, neworder, count, newbase, neworder, count, matrix + area, stride) != 0:
            return 4
        closure(w, count, stride, flags, queue, matrix, area)
    put(o, 0, RESULT_MAGIC)
    put(o, 8, count)
    i = 0
    while i < count:
        put(o, 16 + i * 16, get(w, neworder + i * 8))
        put(o, 24 + i * 16, get(w, flags + i * 8))
        i = i + 1
    i = 0
    while i < area * 2:
        store(o, 16 + count * 16 + i, byte(w, matrix + i))
        i = i + 1
    return 0

def changes(s:readbuf, w:mutbuf, old:u64, newbase:u64, neworder:u64, count:u64, flags:u64) -> u64:
    i = 0
    while i < count:
        put(w, flags + i * 8, 3)
        i = i + 1
    i = 0
    while i < old:
        prior = 64 + i * 40
        index = locate(s, w, newbase, neworder, count, get(w, prior))
        if index == count:
            return 3
        current = newbase + get(w, neworder + index * 8) * 40
        changed = 0
        if compare(s, get(w, prior + 8), get(w, current + 8)) != 0:
            changed = changed | 1
        if compare(s, get(w, prior + 16), get(w, current + 16)) != 0:
            changed = changed | 2
        put(w, flags + index * 8, changed)
        i = i + 1
    return 0

def records(s:readbuf, w:mutbuf, base:u64, count:u64, phase:u64) -> u64:
    i = 0
    while i < count:
        put(w, base + i * 40, text(s, w))
        put(w, base + i * 40 + 8, text(s, w))
        put(w, base + i * 40 + 16, text(s, w))
        put(w, base + i * 40 + 24, get(w, 0))
        n = number(s, w)
        if get(w, 8) != 0 or n > (length(s) - get(w, 0)) >> 4:
            return 1
        if phase == 0 and n != 0:
            return 1
        j = 0
        while j < n:
            text(s, w)
            text(s, w)
            j = j + 1
        if get(w, 8) != 0:
            return 1
        put(w, base + i * 40 + 32, get(w, 0))
        i = i + 1
    return 0

def order(s:readbuf, w:mutbuf, base:u64, index:u64, count:u64) -> u64:
    i = 0
    while i < count:
        j = i
        moving = 1
        while j > 0 and moving != 0:
            prior = get(w, index + (j - 1) * 8)
            relation = compare(s, get(w, base + i * 40), get(w, base + prior * 40))
            if relation == 0:
                return 1
            if relation == 2:
                moving = 0
            else:
                put(w, index + j * 8, prior)
                j = j - 1
        put(w, index + j * 8, i)
        i = i + 1
    return 0

def locate(s:readbuf, w:mutbuf, base:u64, orderbase:u64, count:u64, name:u64) -> u64:
    left = 0
    right = count
    while left < right:
        middle = left + ((right - left) >> 1)
        item = get(w, orderbase + middle * 8)
        relation = compare(s, name, get(w, base + item * 40))
        if relation == 0:
            return middle
        if relation == 1:
            right = middle
        else:
            left = middle + 1
    return count

def edges(s:readbuf, w:mutbuf, base:u64, orderbase:u64, count:u64, newbase:u64, neworder:u64, total:u64, matrix:u64, stride:u64) -> u64:
    i = 0
    while i < count:
        record = base + i * 40
        caller = locate(s, w, newbase, neworder, total, get(w, record))
        if caller == total:
            return 1
        put(w, 0, get(w, record + 24))
        n = number(s, w)
        j = 0
        while j < n:
            opcode = text(s, w)
            name = text(s, w)
            if is_call(s, opcode) != 0:
                if locate(s, w, base, orderbase, count, name) == count:
                    return 1
                callee = locate(s, w, newbase, neworder, total, name)
                if callee == total:
                    return 1
                position = matrix + caller * stride + (callee >> 3)
                store(w, position, byte(w, position) | (1 << (callee & 7)))
            j = j + 1
        if get(w, 8) != 0 or get(w, 0) != get(w, record + 32):
            return 1
        i = i + 1
    return 0

def closure(w:mutbuf, count:u64, stride:u64, flags:u64, queue:u64, matrix:u64, area:u64) -> u64:
    read = 0
    write = 0
    i = 0
    while i < count:
        value = get(w, flags + i * 8)
        if (value & 1) != 0:
            put(w, flags + i * 8, value | 4)
            put(w, queue + write * 8, i)
            write = write + 1
        i = i + 1
    while read < write:
        callee = get(w, queue + read * 8)
        read = read + 1
        caller = 0
        while caller < count:
            value = get(w, flags + caller * 8)
            position = matrix + caller * stride + (callee >> 3)
            incoming = byte(w, position) | byte(w, position + area)
            if (value & 4) == 0 and (incoming & (1 << (callee & 7))) != 0:
                put(w, flags + caller * 8, value | 4)
                put(w, queue + write * 8, caller)
                write = write + 1
            caller = caller + 1
    return 0

def is_call(s:readbuf, at:u64) -> u64:
    if uint(s, at) != 4:
        return 0
    if byte(s, at + 8) == 99 and byte(s, at + 9) == 97 and byte(s, at + 10) == 108 and byte(s, at + 11) == 108:
        return 1
    return 0

def compare(s:readbuf, a:u64, b:u64) -> u64:
    an = uint(s, a)
    bn = uint(s, b)
    i = 0
    while i < an and i < bn:
        av = byte(s, a + 8 + i)
        bv = byte(s, b + 8 + i)
        if av < bv:
            return 1
        if av > bv:
            return 2
        i = i + 1
    if an < bn:
        return 1
    if an > bn:
        return 2
    return 0

def text(s:readbuf, w:mutbuf) -> u64:
    start = get(w, 0)
    size = number(s, w)
    if get(w, 8) != 0 or size > length(s) - get(w, 0):
        put(w, 8, 1)
        return 0
    put(w, 0, get(w, 0) + size)
    return start

def number(s:readbuf, w:mutbuf) -> u64:
    at = get(w, 0)
    if at > length(s) or length(s) - at < 8:
        put(w, 8, 1)
        return 0
    put(w, 0, at + 8)
    return uint(s, at)

def uint(s:readbuf, at:u64) -> u64:
    value = 0
    i = 0
    while i < 8:
        value = value | (byte(s, at + i) << (i * 8))
        i = i + 1
    return value

def get(w:mutbuf, at:u64) -> u64:
    value = 0
    i = 0
    while i < 8:
        value = value | (byte(w, at + i) << (i * 8))
        i = i + 1
    return value

def put(w:mutbuf, at:u64, value:u64) -> u64:
    i = 0
    while i < 8:
        store(w, at + i, value & 255)
        value = value >> 8
        i = i + 1
    return 0
'''


def source():
    return POLICY.replace('REQUEST_MAGIC', str(REQUEST_MAGIC)).replace('RESULT_MAGIC', str(RESULT_MAGIC))


def main():
    path = ROOT / 'examples/hia_bootstrap/patch_impact.hepta'
    path.write_text(render_assembly(document(source(), 'patch_impact')))
    print(path.name, path.stat().st_size)


if __name__ == '__main__':
    main()

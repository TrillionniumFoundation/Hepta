"""Generate the extra finite scalar native-lifecycle profile in HIA.

The input carries already verified Core facts, with their original strings and
ordering. This owner decides the additional runtime profile and complete CFG
acyclicity; it neither verifies Core nor grants scalar-totality proof authority.
"""
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document

ROOT = Path(__file__).resolve().parents[1]
REQUEST_MAGIC = int.from_bytes(b'HIASCP01', 'little')
RESULT_MAGIC = int.from_bytes(b'HIASCR01', 'little')

POLICY = '''def profile(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) != 8192 or length(o) != 144 or length(s) < 64:
        return 16
    put(w, 0, 0)
    put(w, 8, 0)
    if number(s, w) != REQUEST_MAGIC:
        return 16
    structured = number(s, w)
    total = number(s, w)
    explicit = number(s, w)
    count = number(s, w)
    exports = number(s, w)
    phase = number(s, w)
    schema = text(s, w)
    if structured > 1 or total > 1 or explicit > 1 or phase > 1 or get(w, 8) != 0:
        return 16
    if structured != 0 or qualified_schema(s, schema) == 0:
        return 1
    if count == 0 or count > 16:
        return 2
    if explicit != 0 and exports != count:
        return 3
    if explicit == 0 and exports != 0:
        return 16
    if phase == 0:
        if get(w, 0) != length(s):
            return 16
        return 17
    i = 0
    while i < exports:
        put(w, 128 + i * 8, text(s, w))
        i = i + 1
    i = 0
    while i < count:
        end = frame(s, w)
        begin = get(w, 0)
        name = text(s, w)
        if get(w, 8) != 0 or get(w, 0) > end:
            return 16
        put(w, 256 + i * 32, begin)
        put(w, 264 + i * 32, end)
        put(w, 272 + i * 32, name)
        put(w, 0, end)
        i = i + 1
    if get(w, 8) != 0 or get(w, 0) != length(s):
        return 16
    i = 0
    while i < count:
        if explicit != 0:
            j = 0
            found = 0
            while j < exports:
                if equal(s, get(w, 272 + i * 32), get(w, 128 + j * 8)) != 0:
                    found = 1
                j = j + 1
            if found == 0:
                return 3
        elif implicit_scalar(s, w, i) == 0:
            return 3
        i = i + 1
    i = 0
    while i < count:
        status = signature(s, w, i, total)
        if status != 0:
            return status
        status = blocks(s, w, i, total)
        if status != 0:
            return status
        i = i + 1
    if get(w, 8) != 0:
        return 16
    order(s, w, count)
    put(o, 0, RESULT_MAGIC)
    put(o, 8, count)
    i = 0
    while i < count:
        put(o, 16 + i * 8, get(w, 6144 + i * 8))
        i = i + 1
    return 0

def implicit_scalar(s:readbuf, w:mutbuf, index:u64) -> u64:
    put(w, 0, get(w, 256 + index * 32))
    text(s, w)
    n = items(s, w)
    i = 0
    while i < n:
        if scalar(s, text(s, w)) == 0:
            return 0
        i = i + 1
    n = items(s, w)
    i = 0
    while i < n:
        if scalar(s, text(s, w)) == 0:
            return 0
        i = i + 1
    return 1

def signature(s:readbuf, w:mutbuf, index:u64, total:u64) -> u64:
    put(w, 0, get(w, 256 + index * 32))
    text(s, w)
    n = items(s, w)
    bad = 0
    if n > 16:
        bad = 1
    i = 0
    while i < n:
        kind = scalar(s, text(s, w))
        if kind == 0 or kind == 12:
            bad = 1
        i = i + 1
    n = items(s, w)
    if n != 1:
        bad = 1
    i = 0
    while i < n:
        kind = scalar(s, text(s, w))
        if kind == 0 or kind == 12:
            bad = 1
        i = i + 1
    n = items(s, w)
    i = 0
    while i < n:
        effect = text(s, w)
        if total == 0 or trap_word(s, effect) == 0:
            bad = 1
        i = i + 1
    if get(w, 8) != 0:
        return 16
    if bad != 0:
        return 4
    put(w, 280 + index * 32, get(w, 0))
    return 0

def blocks(s:readbuf, w:mutbuf, function:u64, total:u64) -> u64:
    put(w, 0, get(w, 280 + function * 32))
    count = number(s, w)
    if count > 64:
        return 5
    if count == 0:
        return 16
    operations = 0
    i = 0
    while i < count:
        end = frame(s, w)
        put(w, 1024 + i * 64, get(w, 0))
        put(w, 1032 + i * 64, end)
        put(w, 1040 + i * 64, text(s, w))
        put(w, 1048 + i * 64, get(w, 0))
        n = items(s, w)
        j = 0
        while j < n:
            text(s, w)
            j = j + 1
        put(w, 1056 + i * 64, get(w, 0))
        n = number(s, w)
        if n > 2048 - operations:
            return 5
        operations = operations + n
        j = 0
        while j < n:
            put(w, 0, frame(s, w))
            j = j + 1
        put(w, 1064 + i * 64, get(w, 0))
        if get(w, 8) != 0 or get(w, 0) > end:
            return 16
        put(w, 0, end)
        i = i + 1
    if get(w, 8) != 0 or get(w, 0) != get(w, 264 + function * 32):
        return 16
    i = 0
    while i < count:
        status = block_policy(s, w, i, count, total)
        if status != 0:
            return status
        i = i + 1
    return acyclic(w, count)

def block_policy(s:readbuf, w:mutbuf, index:u64, count:u64, total:u64) -> u64:
    put(w, 0, get(w, 1048 + index * 64))
    n = items(s, w)
    i = 0
    while i < n:
        kind = scalar(s, text(s, w))
        if kind == 0 or kind == 12:
            return 6
        i = i + 1
    put(w, 0, get(w, 1056 + index * 64))
    n = number(s, w)
    i = 0
    while i < n:
        end = frame(s, w)
        status = operation(s, w, total)
        if status != 0:
            return status
        if get(w, 8) != 0 or get(w, 0) != end:
            return 16
        i = i + 1
    if get(w, 0) != get(w, 1064 + index * 64):
        return 16
    status = terminal(s, w, index, count, total)
    if status != 0:
        return status
    if get(w, 8) != 0 or get(w, 0) != get(w, 1032 + index * 64):
        return 16
    return 0

def operation(s:readbuf, w:mutbuf, total:u64) -> u64:
    kind = opcode(s, text(s, w))
    n = items(s, w)
    bad = 0
    first = 0
    i = 0
    while i < n:
        value = scalar(s, text(s, w))
        if i == 0:
            first = value
        if value == 0 or value == 12:
            bad = 1
        i = i + 1
    mode_kind = number(s, w)
    mode = text(s, w)
    allowed = 0
    if kind == 1 or kind == 2:
        allowed = 1
    if total != 0 and kind == 3 and (first == 3 or first == 5):
        allowed = 1
    if allowed == 0 or bad != 0:
        return 7
    if kind == 2 and (mode_kind != 1 or wrap_word(s, mode) == 0):
        return 7
    return 0

def terminal(s:readbuf, w:mutbuf, index:u64, count:u64, total:u64) -> u64:
    kind = termcode(s, text(s, w))
    direct = text(s, w)
    yes = text(s, w)
    no = text(s, w)
    first = 0
    second = 0
    if kind == 1 or (kind == 4 and total != 0):
        first = 0
    elif kind == 2:
        first = target(s, w, direct, count)
        if first == 0:
            return 16
    elif kind == 3:
        first = target(s, w, yes, count)
        second = target(s, w, no, count)
        if first == 0 or second == 0:
            return 16
    else:
        return 8
    put(w, 1072 + index * 64, first)
    put(w, 1080 + index * 64, second)
    return 0

def target(s:readbuf, w:mutbuf, name:u64, count:u64) -> u64:
    i = 0
    while i < count:
        if equal(s, name, get(w, 1040 + i * 64)) != 0:
            return i + 1
        i = i + 1
    return 0

def acyclic(w:mutbuf, count:u64) -> u64:
    i = 0
    while i < count:
        put(w, 5120 + i * 8, 0)
        i = i + 1
    i = 0
    while i < count:
        j = 0
        while j < 2:
            next = get(w, 1072 + i * 64 + j * 8)
            if next != 0:
                put(w, 5120 + (next - 1) * 8, get(w, 5120 + (next - 1) * 8) + 1)
            j = j + 1
        i = i + 1
    ready = 0
    i = 0
    while i < count:
        if get(w, 5120 + i * 8) == 0:
            put(w, 5632 + ready * 8, i)
            ready = ready + 1
        i = i + 1
    visited = 0
    while ready != 0:
        ready = ready - 1
        index = get(w, 5632 + ready * 8)
        visited = visited + 1
        j = 0
        while j < 2:
            next = get(w, 1072 + index * 64 + j * 8)
            if next != 0:
                incoming = get(w, 5120 + (next - 1) * 8) - 1
                put(w, 5120 + (next - 1) * 8, incoming)
                if incoming == 0:
                    put(w, 5632 + ready * 8, next - 1)
                    ready = ready + 1
            j = j + 1
    if visited != count:
        return 9
    return 0

def order(s:readbuf, w:mutbuf, count:u64) -> u64:
    i = 0
    while i < count:
        j = i
        moving = 1
        while j > 0 and moving != 0:
            previous = get(w, 6144 + (j - 1) * 8)
            if less(s, get(w, 272 + i * 32), get(w, 272 + previous * 32)) == 0:
                moving = 0
            else:
                put(w, 6144 + j * 8, previous)
                j = j - 1
        put(w, 6144 + j * 8, i)
        i = i + 1
    return 0

def equal(s:readbuf, a:u64, b:u64) -> u64:
    n = chunk(s, a, 8)
    if n != chunk(s, b, 8):
        return 0
    i = 0
    while i < n:
        if byte(s, a + 8 + i) != byte(s, b + 8 + i):
            return 0
        i = i + 1
    return 1

def less(s:readbuf, a:u64, b:u64) -> u64:
    n = chunk(s, a, 8)
    m = chunk(s, b, 8)
    i = 0
    while i < n and i < m:
        x = byte(s, a + 8 + i)
        y = byte(s, b + 8 + i)
        if x < y:
            return 1
        if x > y:
            return 0
        i = i + 1
    if n < m:
        return 1
    return 0

def number(s:readbuf, w:mutbuf) -> u64:
    at = get(w, 0)
    if at > length(s) or length(s) - at < 8:
        put(w, 8, 1)
        return 0
    put(w, 0, at + 8)
    return chunk(s, at, 8)

def text(s:readbuf, w:mutbuf) -> u64:
    at = get(w, 0)
    end = frame(s, w)
    put(w, 0, end)
    if get(w, 8) != 0:
        return 0
    return at

def items(s:readbuf, w:mutbuf) -> u64:
    count = number(s, w)
    at = get(w, 0)
    if at > length(s) or count > ((length(s) - at) >> 3):
        put(w, 8, 1)
        return 0
    return count

def frame(s:readbuf, w:mutbuf) -> u64:
    size = number(s, w)
    at = get(w, 0)
    if at > length(s) or size > length(s) - at:
        put(w, 8, 1)
        return at
    return at + size

def chunk(s:readbuf, at:u64, count:u64) -> u64:
    value = 0
    i = 0
    while i < count:
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
        store(w, at + i, (value >> (i * 8)) & 255)
        i = i + 1
    return 0
'''


def classifier(name, rows):
    result = f'def {name}(s:readbuf, at:u64) -> u64:\n    size = chunk(s, at, 8)\n'
    for word, code in rows:
        raw = word.encode('ascii')
        predicates = [f'size == {len(raw)}']
        for offset in range(0, len(raw), 8):
            part = raw[offset:offset + 8]
            predicates.append(f'chunk(s, at + {8 + offset}, {len(part)}) == {int.from_bytes(part, "little")}')
        result += '    if ' + ' and '.join(predicates) + f':\n        return {code}\n'
    return result + '    return 0\n'


def source():
    native = ('bool', 'i8', 'u8', 'i16', 'u16', 'i32', 'u32', 'i64', 'u64', 'isize', 'usize', 'unit')
    ordinary = ('const', 'select', 'int.add.wrap', 'int.sub.wrap', 'int.mul.wrap',
                'bit.and', 'bit.or', 'bit.xor', 'bit.not', 'bool.not', 'bool.and', 'bool.or',
                'compare.eq', 'compare.ne', 'compare.lt', 'compare.le', 'compare.gt', 'compare.ge')
    extra = classifier('scalar', tuple(zip(native, range(1, 13))))
    extra += classifier('opcode', [(word, 1) for word in ordinary] + [('int.cast', 2), ('int.div.checked', 3), ('int.rem.checked', 3)])
    extra += classifier('termcode', [('ret', 1), ('jump', 2), ('branch', 3), ('trap', 4)])
    extra += classifier('qualified_schema', [('hepta.hia.program.v' + str(i), 1) for i in range(1, 8)])
    extra += classifier('trap_word', [('trap', 1)])
    extra += classifier('wrap_word', [('wrap', 1)])
    return POLICY.replace('REQUEST_MAGIC', str(REQUEST_MAGIC)).replace('RESULT_MAGIC', str(RESULT_MAGIC)) + extra


def main():
    path = ROOT / 'examples/hia_bootstrap/scalar_profile.hepta'
    path.write_text(render_assembly(document(source(), 'scalar_profile')))
    print(path.name, path.stat().st_size)


if __name__ == '__main__':
    main()

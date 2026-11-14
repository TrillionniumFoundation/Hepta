"""Exact finite DAG, profile and arbitrary-width resource arithmetic in HIA."""
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from hepta.hia_static_budget import _V8_BYTE_TYPES, _V8_BYTE_OPS, _V8_CHAIN_OPS
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_patch_impact import POLICY as IMPACT_POLICY

ROOT = Path(__file__).resolve().parents[1]
REQUEST_MAGIC = int.from_bytes(b'HIASBG01', 'little')
RESULT_MAGIC = int.from_bytes(b'HIASBR01', 'little')

POLICY = '''def budget(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 16 or length(w) < 128:
        return 1
    put(w, 0, 0)
    put(w, 8, 0)
    magic = number(s, w)
    mode = number(s, w)
    if magic != REQUEST_MAGIC or mode > 4:
        return 1
    if mode == 3:
        return profile(s, o, w)
    if mode == 4:
        return limits(s, o, w)
    count = number(s, w)
    children = number(s, w)
    width = number(s, w)
    entry = text(s, w)
    if count > 4096 or children > 1024 or width == 0 or width > 4096:
        return 1
    if mode != 1 and (children != 0 or width != 8):
        return 1
    put(w, 24, mode)
    put(w, 32, count)
    put(w, 40, children)
    put(w, 48, width)
    put(w, 56, entry)
    at = 128 + children * 40
    put(w, 64, at)
    at = at + count * 40
    put(w, 72, at)
    at = at + children * 8
    put(w, 80, at)
    at = at + count * 8
    put(w, 88, at)
    at = at + count * 8
    put(w, 96, at)
    at = at + count * 8
    put(w, 104, at)
    at = at + count * ((count + 7) >> 3)
    put(w, 112, at)
    put(w, 120, width * 2 + 8)
    if length(w) != at + count * (width * 2 + 8):
        return 1
    expected = 16 + count * 8
    if mode == 1:
        expected = 24 + width * 2
    if length(o) != expected:
        return 1
    if parse(s, w, 128, children, get(w, 64), count, width, mode) != 0:
        return 1
    if order(s, w, 128, get(w, 72), children) != 0:
        return 1
    if order(s, w, get(w, 64), get(w, 80), count) != 0:
        return 2
    put(w, 16, 0)
    if mode != 1:
        if key_admission(s, w, entry, get(w, 64), get(w, 80), count) != 0:
            if get(w, 16) == 3:
                return 3
            return 1
    if graph(s, w, get(w, 64), get(w, 80), count, get(w, 88), get(w, 96), get(w, 104), (count + 7) >> 3) != 0:
        if get(w, 16) == 3:
            return 3
        if get(w, 16) == 6:
            return 6
        return 2
    return calculate(s, o, w)

def calculate(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    mode = get(w, 24)
    count = get(w, 32)
    width = get(w, 48)
    values = get(w, 112)
    metric = get(w, 120)
    i = 0
    while i < count * metric:
        store(w, values + i, 0)
        i = i + 1
    if mode == 0:
        i = 0
        while i < count:
            put(o, 16 + i * 8, get(w, get(w, 96) + i * 8))
            i = i + 1
        put(o, 0, RESULT_MAGIC)
        put(o, 8, count)
        return 0
    i = count
    while i > 0:
        i = i - 1
        node = get(w, get(w, 96) + i * 8)
        dest = values + node * metric
        if mode == 1:
            if block(s, w, get(w, 64) + node * 40, 128, get(w, 72), get(w, 40), dest, width) != 0:
                return 5
        else:
            put(w, dest + width * 2, 1)
        if propagate(w, node) != 0:
            return 5
    if mode == 2:
        i = 0
        while i < count:
            put(o, 16 + i * 8, get(w, values + i * metric + width * 2))
            i = i + 1
        put(o, 0, RESULT_MAGIC)
        put(o, 8, count)
        return 0
    selected = locate(s, w, get(w, 64), get(w, 80), count, get(w, 56))
    if selected == count:
        return 3
    at = values + get(w, get(w, 80) + selected * 8) * metric
    if add_small(w, at + width, 1, width) != 0:
        return 5
    i = 0
    while i < width * 2:
        store(o, 24 + i, byte(w, at + i))
        i = i + 1
    put(o, 0, RESULT_MAGIC)
    put(o, 8, width)
    put(o, 16, get(w, at + width * 2))
    return 0

def propagate(w:mutbuf, node:u64) -> u64:
    mode = get(w, 24)
    count = get(w, 32)
    width = get(w, 48)
    metric = get(w, 120)
    dest = get(w, 112) + node * metric
    matrix = get(w, 104)
    stride = (count + 7) >> 3
    bestalloc = count
    bestticks = count
    depth = get(w, dest + width * 2)
    j = 0
    while j < count:
        if edge(w, matrix, stride, node, j) != 0:
            other = get(w, 112) + j * metric
            if mode == 1:
                if bestalloc == count or bigger(w, other, get(w, 112) + bestalloc * metric, width) != 0:
                    bestalloc = j
                if bestticks == count or bigger(w, other + width, get(w, 112) + bestticks * metric + width, width) != 0:
                    bestticks = j
            extra = get(w, other + width * 2)
            if mode == 2:
                extra = extra + 1
            if extra > depth:
                depth = extra
        j = j + 1
    put(w, dest + width * 2, depth)
    if bestalloc != count:
        if add_state(w, dest, get(w, 112) + bestalloc * metric, width) != 0:
            return 5
    if bestticks != count:
        if add_state(w, dest + width, get(w, 112) + bestticks * metric + width, width) != 0:
            return 5
    return 0

def parse(s:readbuf, w:mutbuf, childbase:u64, children:u64, nodebase:u64, count:u64, width:u64, mode:u64) -> u64:
    i = 0
    while i < children:
        at = childbase + i * 40
        put(w, at, text(s, w))
        a = text(s, w)
        b = text(s, w)
        d = number(s, w)
        if get(w, 8) != 0 or uint(s, a) > width or uint(s, b) > width or d == 0 or d > 1024:
            return 1
        put(w, at + 8, a)
        put(w, at + 16, b)
        put(w, at + 24, d)
        i = i + 1
    i = 0
    while i < count:
        at = nodebase + i * 40
        put(w, at, text(s, w))
        put(w, at + 8, get(w, 0))
        n = number(s, w)
        if get(w, 8) != 0 or n > (length(s) - get(w, 0)) >> 3:
            return 1
        j = 0
        while j < n:
            text(s, w)
            j = j + 1
        put(w, at + 16, get(w, 0))
        n = number(s, w)
        if get(w, 8) != 0:
            return 1
        if mode == 1 and n > (length(s) - get(w, 0)) >> 4:
            return 1
        put(w, at + 32, 0)
        if mode != 1:
            if n > 1:
                return 1
            put(w, at + 32, n)
        else:
            j = 0
            while j < n:
                text(s, w)
                text(s, w)
                j = j + 1
        if get(w, 8) != 0:
            return 1
        put(w, at + 24, get(w, 0))
        i = i + 1
    if get(w, 8) != 0 or get(w, 0) != length(s):
        return 1
    return 0

def key_admission(s:readbuf, w:mutbuf, entry:u64, base:u64, sorted:u64, count:u64) -> u64:
    end = entry + 8 + uint(s, entry)
    put(w, 0, entry + 8)
    original = number(s, w)
    n = number(s, w)
    if get(w, 8) != 0 or get(w, 0) > end or n > (end - get(w, 0)) >> 3:
        return 1
    i = 0
    while i < n:
        name = text(s, w)
        if get(w, 8) != 0 or get(w, 0) > end:
            return 1
        if locate(s, w, base, sorted, count, name) == count:
            put(w, 16, 3)
            return 3
        i = i + 1
    if get(w, 0) != end:
        return 1
    if original != count:
        put(w, 16, 7)
    return 0

def graph(s:readbuf, w:mutbuf, base:u64, sorted:u64, count:u64, degree:u64, queue:u64, matrix:u64, stride:u64) -> u64:
    i = 0
    while i < count * stride:
        store(w, matrix + i, 0)
        i = i + 1
    i = 0
    while i < count:
        put(w, degree + i * 8, 0)
        i = i + 1
    i = 0
    while i < count:
        put(w, 0, get(w, base + i * 40 + 8))
        n = number(s, w)
        j = 0
        while j < n:
            target = locate(s, w, base, sorted, count, text(s, w))
            if target == count:
                put(w, 16, 3)
                return 3
            target = get(w, sorted + target * 8)
            if edge(w, matrix, stride, i, target) == 0:
                pos = matrix + i * stride + (target >> 3)
                store(w, pos, byte(w, pos) | (1 << (target & 7)))
                put(w, degree + target * 8, get(w, degree + target * 8) + 1)
            j = j + 1
        i = i + 1
    write = 0
    i = 0
    while i < count:
        node = get(w, sorted + i * 8)
        if get(w, degree + node * 8) == 0:
            put(w, queue + write * 8, node)
            write = write + 1
        i = i + 1
    read = 0
    while read < write:
        node = get(w, queue + read * 8)
        read = read + 1
        if get(w, base + node * 40 + 32) != 0:
            put(w, 0, node)
            put(w, 16, 6)
            return 6
        i = 0
        while i < count:
            target = get(w, sorted + i * 8)
            if edge(w, matrix, stride, node, target) != 0:
                d = get(w, degree + target * 8) - 1
                put(w, degree + target * 8, d)
                if d == 0:
                    put(w, queue + write * 8, target)
                    write = write + 1
            i = i + 1
    if write != count or get(w, 16) == 7:
        put(w, 16, 2)
        return 2
    return 0

def block(s:readbuf, w:mutbuf, record:u64, childbase:u64, childorder:u64, children:u64, dest:u64, width:u64) -> u64:
    depth = 1
    put(w, 0, get(w, record + 16))
    n = number(s, w)
    if add_small(w, dest + width, n + 1, width) != 0:
        return 5
    i = 0
    alloc = 0
    while i < n:
        op = text(s, w)
        callee = text(s, w)
        if is_alloc(s, op) != 0:
            alloc = alloc + 1
        if is_call(s, op) != 0:
            child = locate(s, w, childbase, childorder, children, callee)
            if child == children:
                return 4
            at = childbase + get(w, childorder + child * 8) * 40
            if add_source(s, w, dest, get(w, at + 8), width) != 0:
                return 5
            if add_source(s, w, dest + width, get(w, at + 16), width) != 0:
                return 5
            d = get(w, at + 24) + 1
            if d > depth:
                depth = d
        i = i + 1
    if add_small(w, dest, alloc, width) != 0:
        return 5
    put(w, dest + width * 2, depth)
    return 0

def edge(w:mutbuf, base:u64, stride:u64, source:u64, target:u64) -> u64:
    return byte(w, base + source * stride + (target >> 3)) & (1 << (target & 7))

def bigger(w:mutbuf, left:u64, right:u64, width:u64) -> u64:
    i = width
    while i > 0:
        i = i - 1
        a = byte(w, left + i)
        b = byte(w, right + i)
        if a > b:
            return 1
        if a < b:
            return 0
    return 0

def add_small(w:mutbuf, dest:u64, value:u64, width:u64) -> u64:
    i = 0
    while i < width:
        total = byte(w, dest + i) + (value & 255)
        store(w, dest + i, total & 255)
        value = (value >> 8) + (total >> 8)
        i = i + 1
    return value

def add_source(s:readbuf, w:mutbuf, dest:u64, source:u64, width:u64) -> u64:
    count = uint(s, source)
    carry = 0
    i = 0
    while i < width:
        value = 0
        if i < count:
            value = byte(s, source + 8 + i)
        total = byte(w, dest + i) + value + carry
        store(w, dest + i, total & 255)
        carry = total >> 8
        i = i + 1
    return carry

def add_state(w:mutbuf, dest:u64, source:u64, width:u64) -> u64:
    carry = 0
    i = 0
    while i < width:
        total = byte(w, dest + i) + byte(w, source + i) + carry
        store(w, dest + i, total & 255)
        carry = total >> 8
        i = i + 1
    return carry

def limits(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(o) != 32 or length(w) != 128:
        return 1
    fields = number(s, w)
    count = number(s, w)
    if get(w, 8) != 0 or fields == 0 or fields > 4 or count > 1024:
        return 1
    i = 0
    while i < fields:
        at = text(s, w)
        if get(w, 8) != 0:
            return 1
        put(w, 32 + i * 8, at)
        i = i + 1
    offender = count
    field = 0
    i = 0
    while i < count:
        j = 0
        while j < fields:
            value = text(s, w)
            if get(w, 8) != 0 or uint(s, value) == 0:
                return 1
            if offender == count and greater_source(s, value, get(w, 32 + j * 8)) != 0:
                offender = i
                field = j
            j = j + 1
        i = i + 1
    if get(w, 0) != length(s):
        return 1
    put(o, 0, RESULT_MAGIC)
    put(o, 8, count)
    put(o, 16, offender)
    put(o, 24, field)
    return 0

def greater_source(s:readbuf, left:u64, right:u64) -> u64:
    a = uint(s, left)
    b = uint(s, right)
    if b == 0:
        return 0
    if a > b:
        return 1
    if a < b:
        return 0
    i = a
    while i > 0:
        i = i - 1
        x = byte(s, left + 8 + i)
        y = byte(s, right + 8 + i)
        if x > y:
            return 1
        if x < y:
            return 0
    return 0

def profile(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(o) != 32 or length(w) != 128:
        return 1
    expected = text(s, w)
    actual = text(s, w)
    allow = number(s, w)
    count = number(s, w)
    if get(w, 8) != 0 or allow > 1 or count > 1024:
        return 1
    reason = 0
    offender = 0
    if compare(s, expected, actual) != 0:
        reason = 1
    i = 0
    while i < count:
        blocks = number(s, w)
        if get(w, 8) != 0 or blocks > 4096:
            return 1
        j = 0
        while j < blocks:
            term = text(s, w)
            if get(w, 8) != 0:
                return 1
            if reason == 0 and listed(s, term, 0, 0) == 0:
                reason = 2
                offender = i
            n = number(s, w)
            if get(w, 8) != 0 or n > (length(s) - get(w, 0)) >> 3:
                return 1
            k = 0
            while k < n:
                op = text(s, w)
                if get(w, 8) != 0:
                    return 1
                if reason == 0 and listed(s, op, 1, allow) == 0:
                    reason = 3
                    offender = i
                k = k + 1
            j = j + 1
        n = number(s, w)
        if get(w, 8) != 0 or n > (length(s) - get(w, 0)) >> 3:
            return 1
        j = 0
        while j < n:
            typ = text(s, w)
            if get(w, 8) != 0:
                return 1
            if reason == 0 and listed(s, typ, 2, allow) == 0:
                reason = 4
                offender = i
            j = j + 1
        i = i + 1
    if get(w, 0) != length(s):
        return 1
    put(o, 0, RESULT_MAGIC)
    put(o, 8, count)
    put(o, 16, reason)
    put(o, 24, offender)
    return 0
'''


def constant_lookup(words):
    def branch(lo, hi, depth):
        space = '    ' * depth
        if hi - lo == 1:
            return [f'{space}return {words[lo]}']
        mid = (lo + hi) // 2
        return ([f'{space}if index < {mid}:'] + branch(lo, mid, depth + 1)
                + [f'{space}else:'] + branch(mid, hi, depth + 1))
    return '\n'.join(['def profile_word(index:u64) -> u64:',
        f'    if index >= {len(words)}:', '        return 0', *branch(0, len(words), 1)]) + '\n'


def profile_tables():
    groups = [('ret', 'trap', 'jump', 'branch'), sorted(_V8_BYTE_OPS), sorted(_V8_BYTE_TYPES),
              sorted(_V8_CHAIN_OPS), ['chain']]
    words, bounds = [], []
    for group in groups:
        begin = len(words)
        for token in group:
            raw = token.encode('ascii')
            words.append(len(raw))
            words.extend(int.from_bytes(raw[i:i+8].ljust(8, b'\0'), 'little') for i in range(0, len(raw), 8))
        bounds.append((begin, len(words)))
    code = ['def listed(s:readbuf, at:u64, kind:u64, allow:u64) -> u64:',
            f'    begin = {bounds[0][0]}', f'    end = {bounds[0][1]}']
    for kind in (1, 2):
        code += [f'    if kind == {kind}:', f'        begin = {bounds[kind][0]}', f'        end = {bounds[kind][1]}']
    code += ['    if in_table(s, at, begin, end) != 0:', '        return 1', '    if allow != 0:']
    for kind in (1, 2):
        lo, hi = bounds[kind + 2]
        code += [f'        if kind == {kind}:', f'            return in_table(s, at, {lo}, {hi})']
    code += ['    return 0', '', '''def in_table(s:readbuf, at:u64, begin:u64, end:u64) -> u64:
    length = uint(s, at)
    i = begin
    while i < end:
        size = profile_word(i)
        if size == length:
            j = 0
            equal = 1
            while j < size and equal != 0:
                value = (profile_word(i + 1 + (j >> 3)) >> ((j & 7) * 8)) & 255
                if byte(s, at + 8 + j) != value:
                    equal = 0
                j = j + 1
            if equal != 0:
                return 1
        i = i + 1 + ((size + 7) >> 3)
    return 0
''', constant_lookup(words)]
    return '\n'.join(code)


def predicate(name, tokens):
    rows = [f'def {name}(s:readbuf, at:u64) -> u64:']
    for token in tokens:
        raw = token.encode('ascii')
        condition = ' and '.join([f'uint(s, at) == {len(raw)}',
            *(f'byte(s, at + {8 + i}) == {value}' for i, value in enumerate(raw))])
        rows += [f'    if {condition}:', '        return 1']
    return '\n'.join([*rows, '    return 0', ''])


def source():
    helpers = IMPACT_POLICY[IMPACT_POLICY.index('def order'):IMPACT_POLICY.index('def edges')]
    helpers += IMPACT_POLICY[IMPACT_POLICY.index('def compare'):]
    return (POLICY.replace('REQUEST_MAGIC', str(REQUEST_MAGIC)).replace('RESULT_MAGIC', str(RESULT_MAGIC))
            + '\n' + helpers + '\n' + predicate('is_call', ('call',))
            + '\n' + predicate('is_alloc', ('buffer.new', 'buffer.try_new', 'owner.drop'))
            + '\n' + profile_tables())


def main():
    path = ROOT / 'examples/hia_bootstrap/static_budget.hepta'
    path.write_text(render_assembly(document(source(), 'static_budget')))
    print(path.name, path.stat().st_size)


if __name__ == '__main__':
    main()

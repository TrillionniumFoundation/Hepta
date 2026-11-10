"""Author the HIA SSA/CFG editing-view algorithm, not a semantic verifier.

No Python graph algorithm runs in the selected application. The normalized
packet contains facts from the already verified immutable HIA Core function.
The HIA application validates packet ownership, computes the original FIFO
monotone data/control-flow closure and closes all shown instruction inputs.
"""
from __future__ import annotations
import ast
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions

MAGIC = int.from_bytes(b'HIASLC01', 'little')
RESULT_MAGIC = int.from_bytes(b'HIASLR01', 'little')
MAX_BYTES = 8 << 20
NONE = (1 << 64) - 1


def source_program():
    return r'''
def slice(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if valid(s) == 0:
        return 4294967295
    nb = uint(s, 8)
    no = uint(s, 16)
    nv = uint(s, 24)
    source = uint(s, 48)
    selected = uint(s, 56)
    required = 64 + 8 * (nb + nv + no)
    scratch = required + nb * 8
    if length(o) < required or length(w) < scratch:
        return 4294967294
    i = 0
    while i < scratch:
        store(w, i, 0)
        i = i + 1
    put(w, 24, 1)
    put(w, 32, source)
    set_op(s, w, selected, 3)
    start = op(s, selected, 3)
    count = op(s, selected, 4)
    i = 0
    while i < count:
        set_flow(s, w, start + i, 1)
        i = i + 1
    scan(s, w, source, selected + 1)
    close(s, w, source)
    if visible(s, w, source) > 256:
        return 4294967290
    status = propagate(s, w, source)
    if status != 0:
        return status
    while get(w, 16) != 0:
        head = get(w, 0)
        b = get(w, required + head * 8)
        head = head + 1
        if head == nb:
            head = 0
        put(w, 0, head)
        put(w, 16, get(w, 16) - 1)
        set_block(w, b, block_flag(w, b) & 7)
        scan(s, w, b, block(s, b, 2))
        status = propagate(s, w, b)
        if status != 0:
            return status
    total = visible(s, w, source)
    b = 0
    while b < nb:
        if b != source and (block_flag(w, b) & 1) != 0:
            if (block_flag(w, b) & 2) != 0:
                i = block(s, b, 2)
                end = i + block(s, b, 3)
                while i < end:
                    if op_flag(s, w, i) == 0:
                        set_op(s, w, i, 2)
                    i = i + 1
            close(s, w, b)
            total = total + visible(s, w, b)
            if total > 256:
                return 4294967290
        b = b + 1
    # Publish only after the complete graph and every refusal condition pass.
    put(o, 0, RESULT_MAGIC)
    put(o, 8, nb)
    put(o, 16, no)
    put(o, 24, nv)
    put(o, 32, source)
    put(o, 40, selected)
    put(o, 48, total)
    put(o, 56, 0)
    b = 0
    while b < nb:
        flag = block_flag(w, b) & 3
        if b == source:
            flag = 0
        if flag != 0 and block(s, b, 4) == 2:
            if (flow(s, w, block(s, b, 5)) & 1) != 0:
                flag = flag | 4
        put(o, 64 + b * 8, flag)
        b = b + 1
    i = 0
    while i < nv:
        put(o, 64 + nb * 8 + i * 8, flow(s, w, i))
        i = i + 1
    i = 0
    while i < no:
        put(o, 64 + (nb + nv) * 8 + i * 8, op_flag(s, w, i))
        i = i + 1
    return required

def valid(s:readbuf) -> u64:
    if length(s) < 64 or length(s) > 8388608 or uint(s, 0) != MAGIC:
        return 0
    nb = uint(s, 8)
    no = uint(s, 16)
    nv = uint(s, 24)
    ne = uint(s, 32)
    nl = uint(s, 40)
    if nb == 0 or nb > 131072 or no == 0 or no > 209715 or nv == 0 or nv > 524288:
        return 0
    if ne > 262144 or nl > 1048576 or uint(s, 48) >= nb or uint(s, 56) >= no:
        return 0
    if 64 + nb * 64 + no * 40 + nv * 16 + ne * 32 + nl * 8 != length(s):
        return 0
    if op(s, uint(s, 56), 0) != uint(s, 48) or op(s, uint(s, 56), 4) == 0:
        return 0
    i = 0
    previous = 0
    while i < ne:
        origin = edge(s, i, 0)
        if origin >= nb or origin < previous:
            return 0
        previous = origin
        i = i + 1
    b = 0
    while b < nb:
        if valid_block(s, b) == 0 or valid_terminator(s, b) == 0:
            return 0
        b = b + 1
    return 1

def valid_block(s:readbuf, b:u64) -> u64:
    vi = block(s, b, 0)
    oi = block(s, b, 2)
    if vi > uint(s, 24) or block(s, b, 1) > uint(s, 24) - vi:
        return 0
    if oi > uint(s, 16) or block(s, b, 3) > uint(s, 16) - oi:
        return 0
    if b == 0:
        if vi != 0 or oi != 0:
            return 0
    else:
        if oi != block(s, b - 1, 2) + block(s, b - 1, 3):
            return 0
        if vi != block_end(s, b - 1):
            return 0
    end = vi + block(s, b, 1)
    while vi < end:
        if value(s, vi, 0) != b or value(s, vi, 1) != NONE:
            return 0
        vi = vi + 1
    end = oi + block(s, b, 3)
    while oi < end:
        if op(s, oi, 0) != b or op(s, oi, 3) != vi or op(s, oi, 4) > uint(s, 24) - vi:
            return 0
        if valid_args(s, op(s, oi, 1), op(s, oi, 2), b, vi) == 0:
            return 0
        stop = vi + op(s, oi, 4)
        while vi < stop:
            if value(s, vi, 0) != b or value(s, vi, 1) != oi:
                return 0
            vi = vi + 1
        oi = oi + 1
    if b + 1 == uint(s, 8):
        if vi != uint(s, 24) or oi != uint(s, 16):
            return 0
    return 1

def block_end(s:readbuf, b:u64) -> u64:
    if block(s, b, 3) == 0:
        return block(s, b, 0) + block(s, b, 1)
    last = block(s, b, 2) + block(s, b, 3) - 1
    return op(s, last, 3) + op(s, last, 4)

def valid_args(s:readbuf, start:u64, count:u64, b:u64, bound:u64) -> u64:
    if start > uint(s, 40) or count > uint(s, 40) - start:
        return 0
    i = 0
    while i < count:
        v = link(s, start + i)
        if v >= bound or value(s, v, 0) != b:
            return 0
        i = i + 1
    return 1

def valid_terminator(s:readbuf, b:u64) -> u64:
    term = block(s, b, 4)
    ts = block(s, b, 6)
    tn = block(s, b, 7)
    if term > 3 or valid_args(s, ts, tn, b, block_end(s, b)) == 0:
        return 0
    offset = 0
    if term == 2:
        if tn == 0 or block(s, b, 5) != link(s, ts):
            return 0
        offset = 1
    elif block(s, b, 5) != NONE:
        return 0
    count = 0
    i = 0
    while i < uint(s, 32):
        if edge(s, i, 0) == b:
            if valid_edge(s, b, i, offset) == 0:
                return 0
            offset = offset + edge(s, i, 3)
            count = count + 1
        i = i + 1
    expected = 0
    if term == 1:
        expected = 1
    if term == 2:
        expected = 2
    if count != expected:
        return 0
    if (term == 1 or term == 2 or term == 3) and offset != tn:
        return 0
    return 1

def valid_edge(s:readbuf, b:u64, i:u64, offset:u64) -> u64:
    dest = edge(s, i, 1)
    start = edge(s, i, 2)
    count = edge(s, i, 3)
    if dest >= uint(s, 8) or offset > block(s, b, 7):
        return 0
    if count != block(s, dest, 1) or count > block(s, b, 7) - offset:
        return 0
    if valid_args(s, start, count, b, block_end(s, b)) == 0:
        return 0
    j = 0
    while j < count:
        if link(s, start + j) != link(s, block(s, b, 6) + offset + j):
            return 0
        j = j + 1
    return 1

def scan(s:readbuf, w:mutbuf, b:u64, start:u64) -> u64:
    end = block(s, b, 2) + block(s, b, 3)
    while start < end:
        j = 0
        affected = 0
        while j < op(s, start, 2):
            if (flow(s, w, link(s, op(s, start, 1) + j)) & 1) != 0:
                affected = 1
            j = j + 1
        if affected != 0:
            set_op(s, w, start, 1)
            j = 0
            while j < op(s, start, 4):
                v = op(s, start, 3) + j
                set_flow(s, w, v, flow(s, w, v) | 1)
                j = j + 1
        start = start + 1
    return 0

def propagate(s:readbuf, w:mutbuf, b:u64) -> u64:
    nb = uint(s, 8)
    controls = block_flag(w, b) & 2
    if block(s, b, 4) == 2:
        if (flow(s, w, block(s, b, 5)) & 1) != 0:
            controls = 2
    i = 0
    while i < uint(s, 32):
        if edge(s, i, 0) == b:
            d = edge(s, i, 1)
            start = edge(s, i, 2)
            count = edge(s, i, 3)
            any_flow = 0
            j = 0
            while j < count:
                if (flow(s, w, link(s, start + j)) & 1) != 0:
                    any_flow = 1
                j = j + 1
            if any_flow != 0 or controls != 0:
                if d == get(w, 32):
                    return 4294967292
                flag = block_flag(w, d)
                if (flag & 1) == 0:
                    put(w, 24, get(w, 24) + 1)
                    if get(w, 24) > 64:
                        return 4294967291
                    flag = flag | 1
                fresh = 0
                if controls != 0 and (flag & 2) == 0:
                    fresh = 1
                    flag = flag | 2
                j = 0
                while j < count:
                    if (flow(s, w, link(s, start + j)) & 1) != 0:
                        v = block(s, d, 0) + j
                        if (flow(s, w, v) & 2) == 0:
                            fresh = 1
                            set_flow(s, w, v, flow(s, w, v) | 3)
                    j = j + 1
                if fresh != 0 and (flag & 8) == 0:
                    tail = get(w, 8)
                    base = 64 + 8 * (nb + uint(s, 16) + uint(s, 24))
                    put(w, base + tail * 8, d)
                    tail = tail + 1
                    if tail == nb:
                        tail = 0
                    put(w, 8, tail)
                    put(w, 16, get(w, 16) + 1)
                    flag = flag | 8
                set_block(w, d, flag)
        i = i + 1
    return 0

def close(s:readbuf, w:mutbuf, b:u64) -> u64:
    changed = 1
    while changed != 0:
        changed = 0
        j = 0
        while j < block(s, b, 7):
            v = link(s, block(s, b, 6) + j)
            changed = changed | need(s, w, v)
            j = j + 1
        i = block(s, b, 2)
        end = i + block(s, b, 3)
        while i < end:
            if op_flag(s, w, i) != 0:
                j = 0
                while j < op(s, i, 2):
                    v = link(s, op(s, i, 1) + j)
                    changed = changed | need(s, w, v)
                    j = j + 1
            i = i + 1
    return 0

def need(s:readbuf, w:mutbuf, v:u64) -> u64:
    producer = value(s, v, 1)
    if producer != NONE:
        if op_flag(s, w, producer) == 0:
            set_op(s, w, producer, 2)
            return 1
    return 0

def visible(s:readbuf, w:mutbuf, b:u64) -> u64:
    i = block(s, b, 2)
    end = i + block(s, b, 3)
    count = 0
    while i < end:
        if op_flag(s, w, i) != 0:
            count = count + 1
        i = i + 1
    return count

def block(s:readbuf, b:u64, field:u64) -> u64:
    return uint(s, 64 + b * 64 + field * 8)

def op(s:readbuf, i:u64, field:u64) -> u64:
    return uint(s, 64 + uint(s, 8) * 64 + i * 40 + field * 8)

def value(s:readbuf, i:u64, field:u64) -> u64:
    return uint(s, 64 + uint(s, 8) * 64 + uint(s, 16) * 40 + i * 16 + field * 8)

def edge(s:readbuf, i:u64, field:u64) -> u64:
    return uint(s, 64 + uint(s, 8) * 64 + uint(s, 16) * 40 + uint(s, 24) * 16 + i * 32 + field * 8)

def link(s:readbuf, i:u64) -> u64:
    return uint(s, 64 + uint(s, 8) * 64 + uint(s, 16) * 40 + uint(s, 24) * 16 + uint(s, 32) * 32 + i * 8)

def block_flag(w:mutbuf, b:u64) -> u64:
    return get(w, 64 + b * 8)

def set_block(w:mutbuf, b:u64, x:u64) -> u64:
    return put(w, 64 + b * 8, x)

def flow(s:readbuf, w:mutbuf, v:u64) -> u64:
    return get(w, 64 + uint(s, 8) * 8 + v * 8)

def set_flow(s:readbuf, w:mutbuf, v:u64, x:u64) -> u64:
    return put(w, 64 + uint(s, 8) * 8 + v * 8, x)

def op_flag(s:readbuf, w:mutbuf, i:u64) -> u64:
    return get(w, 64 + (uint(s, 8) + uint(s, 24)) * 8 + i * 8)

def set_op(s:readbuf, w:mutbuf, i:u64, x:u64) -> u64:
    return put(w, 64 + (uint(s, 8) + uint(s, 24)) * 8 + i * 8, x)

def uint(s:readbuf, at:u64) -> u64:
    result = 0
    i = 0
    while i < 8:
        result = result | (byte(s, at + i) << (i * 8))
        i = i + 1
    return result

def get(w:mutbuf, at:u64) -> u64:
    result = 0
    i = 0
    while i < 8:
        result = result | (byte(w, at + i) << (i * 8))
        i = i + 1
    return result

def put(w:mutbuf, at:u64, x:u64) -> u64:
    i = 0
    while i < 8:
        store(w, at + i, x & 255)
        x = x >> 8
        i = i + 1
    return 0
'''.replace('RESULT_MAGIC', str(RESULT_MAGIC)).replace('MAGIC', str(MAGIC)).replace('NONE', str(NONE))


def document():
    nodes = ast.parse(source_program()).body
    names = {node.name: 'f'+str(i) for i, node in enumerate(nodes)}
    signatures = {node.name: ([a.annotation.id for a in node.args.args], node.returns.id) for node in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = Builder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({'name': names[node.name], 'params': [builder.param(v) for v in builder.params],
            'returns': [builder.returns], 'effects': ['read', 'write', 'trap'],
            'entry': 'b0', 'blocks': builder.blocks})
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8',
        'module': 'agent_slice', 'functions': functions})


def main():
    path = Path(__file__).resolve().parents[1]/'examples/hia_bootstrap/agent_slice.hiaasm'
    path.write_text(render_assembly(document()))
    print(path.name, path.stat().st_size)


if __name__ == '__main__': main()

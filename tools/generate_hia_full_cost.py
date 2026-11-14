"""Author exact finite full-cost arithmetic and ordered decisions in HIA.

The selected runtime consumes the retained .hepta source's native image. JSON,
identity and field admission remain with the ordinary full-cost caller.
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

REQUEST_MAGIC = int.from_bytes(b'HIAFCP01', 'little')
RESULT_MAGIC = int.from_bytes(b'HIAFCR01', 'little')
SOURCE = r'''
def full_cost(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 16 or length(o) != 80 or length(w) != 0:
        return 3
    if word(s, 0) != @REQUEST_MAGIC@:
        return 3
    mode = word(s, 8)
    if mode == 1:
        return arm(s, o)
    if mode == 2:
        return decide(s, o)
    return 3

def arm(s:readbuf, o:mutbuf) -> u32:
    if length(s) < 112:
        return 3
    n = word(s, 16)
    if n < 8 or n > 128 or length(s) != 112 + n * 40:
        return 3
    total = 0
    i = 0
    while i < 11:
        cost = word(s, 24 + i * 8)
        if cost > 100000000000000000:
            return 3
        total = bounded_add(total, cost)
        i = i + 1
    rss = 0
    p99 = 0
    i = 0
    while i < n:
        at = 112 + i * 40
        j = 0
        while j < 3:
            cost = word(s, at + j * 8)
            if cost > 100000000000000000 or (j == 0 and cost == 0):
                return 3
            total = bounded_add(total, cost)
            j = j + 1
        observed = word(s, at + 24)
        if observed == 0 or observed > 281474976710656:
            return 3
        if observed > rss:
            rss = observed
        observed = word(s, at + 32)
        if observed == 0 or observed > 100000000000000000:
            return 3
        if observed > p99:
            p99 = observed
        i = i + 1
    begin(o, 1)
    if total > 100000000000000000:
        put(o, 2, 1)
    put(o, 3, total)
    put(o, 4, rss)
    put(o, 5, p99)
    return 80

def bounded_add(total:u64, cost:u64) -> u64:
    if total > 100000000000000000:
        return 100000000000000001
    if cost > 100000000000000000 - total:
        return 100000000000000001
    return total + cost

def decide(s:readbuf, o:mutbuf) -> u32:
    if length(s) != 136:
        return 3
    i = 0
    while i < 4:
        total = word(s, 16 + i * 8)
        if total < 8 or total > 100000000000000000:
            return 3
        if word(s, 64 + i * 8) > 16:
            return 3
        i = i + 1
    if word(s, 48) == 0 or word(s, 48) > 281474976710656:
        return 3
    if word(s, 56) == 0 or word(s, 56) > 100000000000000000:
        return 3
    if word(s, 96) < 1 or word(s, 96) > 4:
        return 3
    if word(s, 104) < 1 or word(s, 104) > 100000000000000000:
        return 3
    if word(s, 112) < 1 or word(s, 112) > 1000000:
        return 3
    if word(s, 120) < 1 or word(s, 120) > 281474976710656:
        return 3
    if word(s, 128) < 1 or word(s, 128) > 100000000000000000:
        return 3
    begin(o, 2)
    chosen = 0
    i = 1
    while i < 3:
        if word(s, 16 + i * 8) < word(s, 16 + chosen * 8):
            chosen = i
        i = i + 1
    baseline = word(s, 16 + chosen * 8)
    ndu = word(s, 40)
    put(o, 3, chosen)
    put(o, 4, baseline)
    sign = 0
    if ndu > baseline:
        sign = 1
        saving = ndu - baseline
    else:
        saving = baseline - ndu
    put(o, 5, sign)
    put(o, 6, saving)
    ppm(o, saving, baseline, sign)
    reasons(s, o)
    return 80

def reasons(s:readbuf, o:mutbuf) -> u64:
    mask = 0
    i = 0
    while i < 4:
        if word(s, 64 + i * 8) != 0:
            mask = mask | 1
        i = i + 1
    if word(s, 96) != 1:
        mask = mask | 2
    if get(o, 5) != 0 or get(o, 6) < word(s, 104):
        mask = mask | 4
    if get(o, 5) != 0 or (get(o, 8) == 0 and get(o, 7) < word(s, 112)):
        mask = mask | 8
    if word(s, 48) > word(s, 120):
        mask = mask | 16
    if word(s, 56) > word(s, 128):
        mask = mask | 32
    put(o, 9, mask)
    return 0

def ppm(o:mutbuf, magnitude:u64, divisor:u64, negative:u64) -> u64:
    # A 57-bit admitted magnitude times 1e6 needs up to 77 bits. Keep both
    # limbs and divide all 128 bits; no narrowing, float or changed ratio.
    bottom = (magnitude & 4294967295) * 1000000
    upper = (magnitude >> 32) * 1000000 + (bottom >> 32)
    low = (bottom & 4294967295) | (upper << 32)
    high = upper >> 32
    quotient_low = 0
    quotient_high = 0
    remainder = 0
    remaining = 128
    while remaining != 0:
        remaining = remaining - 1
        if remaining >= 64:
            digit = (high >> (remaining - 64)) & 1
        else:
            digit = (low >> remaining) & 1
        remainder = (remainder << 1) | digit
        if remainder >= divisor:
            remainder = remainder - divisor
            if remaining >= 64:
                quotient_high = quotient_high | (1 << (remaining - 64))
            else:
                quotient_low = quotient_low | (1 << remaining)
    # Python's signed // rounds down, so a negative nonintegral ratio needs
    # the magnitude rounded up before the sign is restored by transport.
    if negative != 0 and remainder != 0:
        quotient_low = quotient_low + 1
        if quotient_low == 0:
            quotient_high = quotient_high + 1
    put(o, 7, quotient_low)
    put(o, 8, quotient_high)
    return 0

def begin(o:mutbuf, mode:u64) -> u64:
    i = 0
    while i < 80:
        store(o, i, 0)
        i = i + 1
    put(o, 0, @RESULT_MAGIC@)
    put(o, 1, mode)
    return 0

def word(s:readbuf, at:u64) -> u64:
    value = 0
    i = 0
    while i < 8:
        value = value | (byte(s, at + i) << (i * 8))
        i = i + 1
    return value

def get(o:mutbuf, index:u64) -> u64:
    value = 0
    i = 0
    while i < 8:
        value = value | (byte(o, index * 8 + i) << (i * 8))
        i = i + 1
    return value

def put(o:mutbuf, index:u64, value:u64) -> u64:
    i = 0
    while i < 8:
        store(o, index * 8 + i, value >> (i * 8))
        i = i + 1
    return 0
'''


def source():
    return SOURCE.replace('@REQUEST_MAGIC@', str(REQUEST_MAGIC)).replace('@RESULT_MAGIC@', str(RESULT_MAGIC))


def document():
    nodes = ast.parse(source()).body
    names = {node.name: 'f' + str(i) for i, node in enumerate(nodes)}
    signatures = {node.name: ([a.annotation.id for a in node.args.args], node.returns.id) for node in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = Builder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({'name': names[node.name], 'params': [builder.param(value) for value in builder.params],
            'returns': [builder.returns], 'effects': ['read', 'write', 'trap'],
            'entry': 'b0', 'blocks': builder.blocks})
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8', 'module': 'full_cost', 'functions': functions})


if __name__ == '__main__':
    path = ROOT / 'examples/hia_bootstrap/full_cost.hepta'
    path.write_text(render_assembly(document()))
    print(path.name, path.stat().st_size)

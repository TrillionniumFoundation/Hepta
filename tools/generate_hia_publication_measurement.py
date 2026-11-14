"""Author the finite publication measurement decision in HIA.

This authoring program does not run in the selected publication path. HIA owns
all medians, deviations, exact projections and ordered admission reasons.
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

REQUEST_MAGIC = int.from_bytes(b'HIAPME01', 'little')
RESULT_MAGIC = int.from_bytes(b'HIAPMR01', 'little')
OUTPUT_BYTES = 176
STATE_BYTES = 2048
SOURCE = r'''
def publication_measurement(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 448 or length(o) != 176 or length(w) != 2048:
        return 4294967293
    i = 0
    while i < 176:
        store(o, i, 0)
        i = i + 1
    set_word(o, 0, @RESULT_MAGIC@)
    if read_word(s, 0) != @REQUEST_MAGIC@:
        return refused(o, 2)
    n = read_word(s, 8)
    count = read_word(s, 16)
    horizon = read_word(s, 24)
    search = read_word(s, 32)
    maximum = read_word(s, 40)
    sign = read_word(s, 48)
    prepare_size = read_word(s, 56)
    if n < 15 or n > 63 or n % 2 != 1 or length(s) < 208 + n * 16:
        return refused(o, 2)
    if count < 1 or count > 64000000 or horizon < 1 or horizon > 1000000000000:
        return refused(o, 2)
    if search > 3600000000000 or maximum < 1 or maximum > 3600000000000:
        return refused(o, 2)
    if sign > 1 or read_word(s, 64) != 0 or read_word(s, 72) != 0:
        return refused(o, 2)
    if prepare_size != length(s) - (208 + n * 16):
        return refused(o, 2)
    if prepare_size == 0 and sign != 0:
        return refused(o, 2)
    if prepare_size != 0 and byte(s, length(s) - 1) == 0:
        return refused(o, 2)
    changed = 0
    i = 0
    while i < 128:
        value = byte(s, 80 + i)
        if (value < 48 or value > 57) and (value < 97 or value > 102):
            return refused(o, 2)
        if i < 64 and value != byte(s, 144 + i):
            changed = 1
        i = i + 1
    i = 0
    while i < n:
        baseline = read_word(s, 208 + i * 16)
        candidate = read_word(s, 216 + i * 16)
        if baseline < 1 or baseline > 60000000000 or candidate < 1 or candidate > 60000000000:
            return refused(o, 2)
        set_word(w, i, baseline)
        set_word(w, 64 + i, candidate)
        set_word(w, 128 + i, 60000000000 + baseline - candidate)
        i = i + 1
    med_b = median(w, 0, n)
    med_c = median(w, 64, n)
    shifted_saving = median(w, 128, n)
    mad_b = deviation(w, 0, n, med_b)
    mad_c = deviation(w, 64, n, med_c)
    saving_mad = deviation(w, 128, n, shifted_saving)
    saving = shifted_saving - 60000000000
    set_word(o, 3, n)
    set_word(o, 4, med_b)
    set_word(o, 5, med_c)
    set_word(o, 6, mad_b)
    set_word(o, 7, mad_c)
    set_word(o, 8, saving)
    set_word(o, 9, saving_mad)
    set_word(o, 18, changed)
    set_word(o, 19, count)
    set_word(o, 20, horizon)
    reasons = 0
    if changed == 0:
        reasons = reasons | 1
    if mad_b * 1000000 > 50000 * med_b:
        reasons = reasons | 2
    if mad_c * 1000000 > 50000 * med_c:
        reasons = reasons | 4
    if shifted_saving <= 60000000000 or saving * 1000000 < 20000 * med_b:
        reasons = reasons | 8
    if shifted_saving <= 60000000000 or saving <= 3 * saving_mad:
        reasons = reasons | 16
    if prepare_size > 10:
        return refused(o, 1)
    read_prepare(s, o, 208 + n * 16, prepare_size, sign)
    signed_plus(o, 10, get_word(o, 10), get_word(o, 11), get_word(o, 12), search)
    signed_plus(o, 13, get_word(o, 10), get_word(o, 11), get_word(o, 12), 2000000000)
    charged_sign = get_word(o, 13)
    charged_low = get_word(o, 14)
    charged_high = get_word(o, 15)
    if charged_sign == 0 and (charged_high != 0 or charged_low > maximum):
        reasons = reasons | 32
    project(w, med_b, horizon, count)
    projected_b = get_word(w, 0)
    if get_word(w, 1) != 0 or projected_b < 1 or projected_b > 1000000000000000000:
        return refused(o, 1)
    set_word(o, 16, projected_b)
    project(w, med_c, horizon, count)
    projected_low = get_word(w, 0)
    projected_high = get_word(w, 1)
    if charged_sign == 0:
        total_low = projected_low + charged_low
        total_high = projected_high + charged_high
        if total_low < projected_low:
            total_high = total_high + 1
    else:
        if projected_high < charged_high or (projected_high == charged_high and projected_low < charged_low):
            return refused(o, 1)
        total_low = projected_low - charged_low
        total_high = projected_high - charged_high
        if projected_low < charged_low:
            total_high = total_high - 1
    if total_high != 0 or total_low < 1 or total_low > 1000000000000000000:
        return refused(o, 1)
    set_word(o, 17, total_low)
    if total_low >= projected_b:
        reasons = reasons | 64
    set_word(o, 2, reasons)
    if reasons == 0:
        set_word(o, 21, 1)
    return 176

def read_prepare(s:readbuf, o:mutbuf, start:u64, size:u64, sign:u64) -> u64:
    low = 0
    high = 0
    i = 0
    while i < size:
        value = byte(s, start + i)
        if i < 8:
            low = low | (value << (i * 8))
        else:
            high = high | (value << ((i - 8) * 8))
        i = i + 1
    set_word(o, 10, sign)
    set_word(o, 11, low)
    set_word(o, 12, high)
    return 0

def median(w:mutbuf, start:u64, n:u64) -> u64:
    i = 1
    while i < n:
        value = get_word(w, start + i)
        j = i
        moving = 1
        while j > 0 and moving != 0:
            previous = get_word(w, start + j - 1)
            if previous <= value:
                moving = 0
            else:
                set_word(w, start + j, previous)
                j = j - 1
        set_word(w, start + j, value)
        i = i + 1
    return get_word(w, start + n // 2)

def deviation(w:mutbuf, start:u64, n:u64, mid:u64) -> u64:
    i = 0
    while i < n:
        value = get_word(w, start + i)
        if value >= mid:
            delta = value - mid
        else:
            delta = mid - value
        set_word(w, 192 + i, delta)
        i = i + 1
    return median(w, 192, n)

def signed_plus(o:mutbuf, start:u64, sign:u64, low:u64, high:u64, delta:u64) -> u64:
    if sign == 0:
        result = low + delta
        if result < low:
            high = high + 1
        low = result
    elif high == 0 and low <= delta:
        sign = 0
        low = delta - low
    else:
        if low < delta:
            high = high - 1
        low = low - delta
    set_word(o, start, sign)
    set_word(o, start + 1, low)
    set_word(o, start + 2, high)
    return 0

def project(w:mutbuf, a:u64, b:u64, count:u64) -> u64:
    a0 = a & 4294967295
    a1 = a >> 32
    b0 = b & 4294967295
    b1 = b >> 32
    p0 = a0 * b0
    p1 = a1 * b0 + a0 * b1 + (p0 >> 32)
    low = (p0 & 4294967295) | (p1 << 32)
    high = a1 * b1 + (p1 >> 32)
    q_high = high // count
    remainder = high % count
    middle = (remainder << 32) | (low >> 32)
    q_middle = middle // count
    remainder = middle % count
    bottom = (remainder << 32) | (low & 4294967295)
    q_bottom = bottom // count
    remainder = bottom % count
    q_low = (q_middle << 32) | q_bottom
    if remainder != 0:
        q_low = q_low + 1
        if q_low == 0:
            q_high = q_high + 1
    set_word(w, 0, q_low)
    set_word(w, 1, q_high)
    return 0

def refused(o:mutbuf, code:u64) -> u32:
    set_word(o, 1, code)
    return 176

def get_word(w:mutbuf, index:u64) -> u64:
    value = 0
    count = 0
    while count < 8:
        value = value | (byte(w, index * 8 + count) << (count * 8))
        count = count + 1
    return value

def read_word(s:readbuf, index:u64) -> u64:
    value = 0
    count = 0
    while count < 8:
        value = value | (byte(s, index + count) << (count * 8))
        count = count + 1
    return value

def set_word(w:mutbuf, index:u64, value:u64) -> u64:
    count = 0
    while count < 8:
        store(w, index * 8 + count, value >> (count * 8))
        count = count + 1
    return value
'''


def source_program():
    return SOURCE.replace('@REQUEST_MAGIC@', str(REQUEST_MAGIC)).replace('@RESULT_MAGIC@', str(RESULT_MAGIC))


class MeasurementBuilder(Builder):
    def expr(self, value):
        if isinstance(value, ast.BinOp) and isinstance(value.op, (ast.Mod, ast.FloorDiv)):
            left, right = self.expr(value.left), self.expr(value.right)
            return self.op('int.rem.checked' if isinstance(value.op, ast.Mod) else 'int.div.checked',
                           [left, right], left[1])
        return super().expr(value)


def document():
    nodes = ast.parse(source_program()).body
    names = {node.name: 'f' + str(i) for i, node in enumerate(nodes)}
    signatures = {node.name: ([a.annotation.id for a in node.args.args], node.returns.id)
                  for node in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = MeasurementBuilder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({'name': names[node.name],
            'params': [builder.param(value) for value in builder.params],
            'returns': [builder.returns], 'effects': ['read', 'write', 'trap'],
            'entry': 'b0', 'blocks': builder.blocks})
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8',
        'module': 'publication_measurement', 'functions': functions})


def main():
    path = ROOT / 'examples/hia_bootstrap/publication_measurement.hepta'
    path.write_text(render_assembly(document()))
    print(path.name, path.stat().st_size)


if __name__ == '__main__':
    main()

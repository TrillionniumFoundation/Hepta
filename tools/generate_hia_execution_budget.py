"""Author the bounded HIA execution-budget transaction and run state owner.

SQLite supplies raw rows and effect acknowledgements. HIA owns every admitted
row transition, remaining-time decision, run claim and decimal cost addition.
The generator is authoring infrastructure, never a production policy fallback.
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

REQUEST_MAGIC = int.from_bytes(b'HIAEBRQ1', 'little')
STATE_MAGIC = int.from_bytes(b'HIAEBST1', 'little')
RESULT_MAGIC = int.from_bytes(b'HIAEBRS1', 'little')
STATE_BYTES = 13568
MAX_DECIMAL = 4300

SOURCE = r'''
def budget_main(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 128 or length(s) > 4700 or length(o) < 13312 or length(w) != 13568:
        return 4294967293
    if read_word(s, 0) != @REQUEST_MAGIC@:
        return 4294967293
    if read_word(s, 72) != 0 or read_word(s, 80) != 0 or read_word(s, 88) != 0:
        return invalid(o, 1)
    event = read_word(s, 8)
    if event == 0:
        return initialize(s, o, w)
    if valid_state(w) == 0:
        return invalid(o, 2)
    if read_word(s, 96) != get(w, 5) or read_word(s, 104) != get(w, 6) or read_word(s, 112) != get(w, 22) or read_word(s, 120) != get(w, 23):
        return invalid(o, 2)
    if event == 90:
        if length(s) != 128:
            return invalid(o, 1)
        return answer(o, w, get(w, 19), 0)
    if get(w, 3) == 9 or get(w, 3) == 8 or read_word(s, 16) != get(w, 4):
        return refuse(o, w, 5)
    if get(w, 4) == 18446744073709551615:
        return refuse(o, w, 6)
    if event == 2:
        return row_transition(s, o, w)
    if length(s) != 128 and event != 6:
        return refuse(o, w, 1)
    if event == 1:
        if get(w, 3) != 1 or read_word(s, 32) != 1:
            return refuse(o, w, 5)
        set(w, 3, 2)
        return advance(o, w, 2)
    if event == 3:
        if get(w, 3) != 3 or read_word(s, 32) != 1:
            return refuse(o, w, 5)
        set(w, 3, 4)
        return advance(o, w, 2)
    if event == 4:
        if get(w, 3) != 5 or read_word(s, 32) != 1:
            return refuse(o, w, 7)
        if get(w, 2) == 1 and get(w, 24) == 0:
            set(w, 3, 7)
        else:
            set(w, 3, 8)
        return advance(o, w, 0)
    if event == 5 or event == 6 or event == 10:
        return run_transition(s, o, w, event)
    return refuse(o, w, 1)

def initialize(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    kind = read_word(s, 32)
    maximum = read_word(s, 40)
    started = read_word(s, 48)
    context_size = read_word(s, 56)
    owner_size = read_word(s, 64)
    if kind > 2 or context_size == 0 or context_size > 192 or owner_size > 64 or length(s) != 128 + context_size + owner_size:
        return invalid(o, 1)
    if kind == 1:
        if maximum == 0 or maximum > 3600000 or owner_size != 64 or hexadecimal(s, 128 + context_size, owner_size) == 0:
            return invalid(o, 1)
    elif maximum != 0 or started != 0 or owner_size != 0:
        return invalid(o, 1)
    if read_word(s, 96) == 0 and read_word(s, 104) == 0:
        return invalid(o, 1)
    if read_word(s, 112) == 0 and read_word(s, 120) == 0:
        return invalid(o, 1)
    i = 0
    while i < 13568:
        if byte(w, i) != 0:
            return invalid(o, 2)
        i = i + 1
    set(w, 0, @STATE_MAGIC@)
    set(w, 1, 1)
    set(w, 2, kind)
    set(w, 3, 1)
    set(w, 4, 1)
    set(w, 5, read_word(s, 96))
    set(w, 6, read_word(s, 104))
    set(w, 7, context_size)
    set(w, 8, owner_size)
    set(w, 10, 1)
    set(w, 12, maximum)
    set(w, 13, started)
    set(w, 22, read_word(s, 112))
    set(w, 23, read_word(s, 120))
    copy_input(s, 128, w, 256, context_size)
    copy_input(s, 128 + context_size, w, 448, owner_size)
    store(w, 4824, 48)
    action = 1
    if kind == 2:
        set(w, 3, 2)
        action = 2
    if kind == 0:
        set(w, 9, 1)
        store(w, 512, 48)
    set(w, 18, action)
    seal(w)
    return answer(o, w, 0, action)

def row_transition(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if get(w, 3) != 2 and get(w, 3) != 4:
        return refuse(o, w, 5)
    found = read_word(s, 32)
    held = read_word(s, 40)
    context_size = read_word(s, 48)
    used_size = read_word(s, 56)
    owner_size = read_word(s, 64)
    if found > 1 or held > 1 or context_size > 192 or used_size > 4300 or owner_size > 64:
        return refuse(o, w, 1)
    if length(s) != 128 + context_size + used_size + owner_size:
        return refuse(o, w, 1)
    if found == 0:
        if held != 0 or context_size != 0 or used_size != 0 or owner_size != 0:
            return refuse(o, w, 1)
        if get(w, 3) == 4 or get(w, 24) != 0:
            return refuse(o, w, 5)
        if get(w, 2) == 0:
            set(w, 3, 3)
            return advance(o, w, 3)
        if get(w, 2) == 2:
            set(w, 3, 8)
            return advance(o, w, 0)
        return refuse(o, w, 3)
    if context_size != get(w, 7) or same_input(s, 128, w, 256, context_size) == 0:
        return refuse(o, w, 5)
    if held == 0 and owner_size != 0:
        return refuse(o, w, 1)
    used_start = 128 + context_size
    owner_start = used_start + used_size
    set(w, 21, 1)
    if get(w, 3) == 4:
        return verify_row(s, o, w, held, used_start, used_size, owner_start, owner_size)
    if get(w, 24) != 0:
        if held != 1 or owner_size != get(w, 8) or same_input(s, owner_start, w, 448, owner_size) == 0 or used_size != get(w, 9) or same_input(s, used_start, w, 512, used_size) == 0:
            return refuse(o, w, 5)
        set(w, 3, 3)
        return advance(o, w, 5)
    if get(w, 2) == 0:
        return refuse(o, w, 8)
    if get(w, 2) == 1 and held != 0:
        return refuse(o, w, 4)
    if canonical(s, used_start, used_size) == 0:
        return refuse(o, w, 1)
    copy_input(s, used_start, w, 512, used_size)
    set(w, 9, used_size)
    if get(w, 2) == 2:
        copy_input(s, owner_start, w, 448, owner_size)
        set(w, 8, owner_size)
        set(w, 20, held)
        set(w, 3, 8)
        return advance(o, w, 0)
    remaining = budget_remaining(w, used_size)
    set(w, 16, remaining)
    set(w, 25, remaining)
    set(w, 20, 1)
    set(w, 3, 3)
    return advance(o, w, 4)

def verify_row(s:readbuf, o:mutbuf, w:mutbuf, held:u64, used_start:u64, used_size:u64, owner_start:u64, owner_size:u64) -> u32:
    expected_held = 0
    expected_owner_size = 0
    expected_used_size = get(w, 9)
    expected_used_start = 512
    if get(w, 2) == 1 and get(w, 24) == 0:
        expected_held = 1
        expected_owner_size = get(w, 8)
    if get(w, 24) != 0:
        expected_used_size = get(w, 11)
        expected_used_start = 9136
    if held != expected_held or owner_size != expected_owner_size or used_size != expected_used_size or same_input(s, used_start, w, expected_used_start, used_size) == 0:
        return refuse(o, w, 5)
    if expected_held != 0 and same_input(s, owner_start, w, 448, owner_size) == 0:
        return refuse(o, w, 5)
    set(w, 3, 5)
    return advance(o, w, 6)

def run_transition(s:readbuf, o:mutbuf, w:mutbuf, event:u64) -> u32:
    if get(w, 2) != 1 or get(w, 3) != 7:
        return refuse(o, w, 5)
    if event == 5:
        now = read_word(s, 24)
        total = read_word(s, 32)
        if get(w, 14) != 0 or now < get(w, 13) or total > 86400000 or get(w, 15) == 18446744073709551615:
            return refuse(o, w, 5)
        elapsed = divide_million(now - get(w, 13))
        remaining = 0
        if elapsed < get(w, 25):
            remaining = get(w, 25) - elapsed
        if total < remaining:
            remaining = total
        set(w, 16, remaining)
        set(w, 14, get(w, 4) + 1)
        set(w, 15, get(w, 15) + 1)
        return advance(o, w, 7)
    if event == 6:
        size = read_word(s, 40)
        if get(w, 14) == 0 or read_word(s, 16) != get(w, 14):
            return refuse(o, w, 5)
        if read_word(s, 32) != 1:
            return refuse(o, w, 7)
        if length(s) != 128 + size or canonical(s, 128, size) == 0:
            return refuse(o, w, 1)
        copy_input(s, 128, w, 9136, size)
        new_size = add_decimal(w, 4824, get(w, 10), 9136, size, 9136)
        if new_size == 0:
            return refuse(o, w, 6)
        copy_state(w, 9136, 4824, new_size)
        set(w, 10, new_size)
        set(w, 14, 0)
        return advance(o, w, 0)
    if event == 10:
        if get(w, 14) != 0:
            return refuse(o, w, 7)
        new_size = add_decimal(w, 512, get(w, 9), 4824, get(w, 10), 9136)
        if new_size == 0:
            return refuse(o, w, 6)
        set(w, 11, new_size)
        set(w, 24, 1)
        set(w, 3, 1)
        return advance(o, w, 1)
    return refuse(o, w, 1)

def budget_remaining(w:mutbuf, size:u64) -> u64:
    if size > 13:
        return 0
    value = 0
    i = 0
    while i < size:
        value = value * 10 + byte(w, 512 + i) - 48
        i = i + 1
    used_ms = divide_million(value)
    if used_ms >= get(w, 12):
        return 0
    return get(w, 12) - used_ms

def add_decimal(w:mutbuf, left:u64, left_size:u64, right:u64, right_size:u64, target:u64) -> u64:
    width = left_size
    if right_size > width:
        width = right_size
    carry = 0
    i = 0
    while i < width:
        digit = carry
        if i < left_size:
            digit = digit + byte(w, left + left_size - 1 - i) - 48
        if i < right_size:
            digit = digit + byte(w, right + right_size - 1 - i) - 48
        carry = 0
        if digit >= 10:
            carry = 1
            digit = digit - 10
        store(w, target + width - i, 48 + digit)
        i = i + 1
    store(w, target, 48 + carry)
    if carry != 0:
        if width == 4300:
            return 0
        return width + 1
    i = 0
    while i < width:
        store(w, target + i, byte(w, target + 1 + i))
        i = i + 1
    return width

def divide_million(value:u64) -> u64:
    quotient = 0
    remainder = 0
    bit = 64
    while bit != 0:
        bit = bit - 1
        remainder = remainder * 2 + ((value >> bit) & 1)
        if remainder >= 1000000:
            remainder = remainder - 1000000
            quotient = quotient | (1 << bit)
    return quotient

def canonical(s:readbuf, start:u64, size:u64) -> u64:
    if size == 0 or size > 4300:
        return 0
    if size > 1 and byte(s, start) == 48:
        return 0
    i = 0
    while i < size:
        ch = byte(s, start + i)
        if ch < 48 or ch > 57:
            return 0
        i = i + 1
    return 1

def hexadecimal(s:readbuf, start:u64, size:u64) -> u64:
    i = 0
    while i < size:
        ch = byte(s, start + i)
        if (ch < 48 or ch > 57) and (ch < 97 or ch > 102):
            return 0
        i = i + 1
    return 1

def valid_state(w:mutbuf) -> u64:
    if get(w, 0) != @STATE_MAGIC@ or get(w, 1) != 1 or get(w, 2) > 2 or get(w, 3) == 0 or get(w, 3) > 9 or get(w, 4) == 0:
        return 0
    if get(w, 7) == 0 or get(w, 7) > 192 or get(w, 8) > 64 or get(w, 9) > 4300 or get(w, 10) == 0 or get(w, 10) > 4300 or get(w, 11) > 4300:
        return 0
    if get(w, 12) > 3600000 or get(w, 16) > 86400000 or get(w, 18) > 7 or get(w, 19) > 8 or get(w, 20) > 1 or get(w, 21) > 1 or get(w, 24) > 1 or get(w, 25) > 3600000:
        return 0
    i = 26
    while i < 32:
        if get(w, i) != 0:
            return 0
        i = i + 1
    if get(w, 17) != checksum(w):
        return 0
    return 1

def refuse(o:mutbuf, w:mutbuf, status:u64) -> u32:
    set(w, 3, 9)
    set(w, 19, status)
    set(w, 18, 0)
    seal(w)
    return answer(o, w, status, 0)

def advance(o:mutbuf, w:mutbuf, action:u64) -> u32:
    set(w, 4, get(w, 4) + 1)
    set(w, 18, action)
    seal(w)
    return answer(o, w, 0, action)

def invalid(o:mutbuf, status:u64) -> u32:
    i = 0
    while i < 16:
        set(o, i, 0)
        i = i + 1
    set(o, 0, @RESULT_MAGIC@)
    set(o, 1, status)
    return 128

def answer(o:mutbuf, w:mutbuf, status:u64, action:u64) -> u32:
    set(o, 0, @RESULT_MAGIC@)
    set(o, 1, status)
    set(o, 2, action)
    set(o, 3, get(w, 4))
    set(o, 4, get(w, 16))
    set(o, 5, get(w, 3))
    set(o, 6, get(w, 4))
    set(o, 7, get(w, 2))
    set(o, 8, get(w, 7))
    set(o, 9, get(w, 9))
    set(o, 10, get(w, 8))
    set(o, 11, get(w, 11))
    set(o, 12, get(w, 10))
    set(o, 13, get(w, 20))
    set(o, 14, get(w, 21))
    set(o, 15, 0)
    at = 128
    copy_output(w, 256, o, at, get(w, 7))
    at = at + get(w, 7)
    copy_output(w, 512, o, at, get(w, 9))
    at = at + get(w, 9)
    copy_output(w, 448, o, at, get(w, 8))
    at = at + get(w, 8)
    copy_output(w, 9136, o, at, get(w, 11))
    at = at + get(w, 11)
    copy_output(w, 4824, o, at, get(w, 10))
    at = at + get(w, 10)
    return at

def same_input(s:readbuf, start:u64, w:mutbuf, target:u64, size:u64) -> u64:
    i = 0
    while i < size:
        if byte(s, start + i) != byte(w, target + i):
            return 0
        i = i + 1
    return 1

def copy_input(s:readbuf, start:u64, w:mutbuf, target:u64, size:u64) -> u64:
    i = 0
    while i < size:
        store(w, target + i, byte(s, start + i))
        i = i + 1
    return size

def copy_output(w:mutbuf, start:u64, o:mutbuf, target:u64, size:u64) -> u64:
    i = 0
    while i < size:
        store(o, target + i, byte(w, start + i))
        i = i + 1
    return size

def copy_state(w:mutbuf, start:u64, target:u64, size:u64) -> u64:
    i = 0
    while i < size:
        store(w, target + i, byte(w, start + i))
        i = i + 1
    return size

def checksum(w:mutbuf) -> u64:
    value = 1469598103934665603
    i = 0
    while i < 1696:
        if i != 17:
            value = ((value << 7) | (value >> 57)) ^ get(w, i)
        i = i + 1
    return value

def seal(w:mutbuf) -> u64:
    value = checksum(w)
    set(w, 17, value)
    return value

def get(w:mutbuf, index:u64) -> u64:
    value = 0
    value = value | (byte(w, index * 8 + 0) << 0)
    value = value | (byte(w, index * 8 + 1) << 8)
    value = value | (byte(w, index * 8 + 2) << 16)
    value = value | (byte(w, index * 8 + 3) << 24)
    value = value | (byte(w, index * 8 + 4) << 32)
    value = value | (byte(w, index * 8 + 5) << 40)
    value = value | (byte(w, index * 8 + 6) << 48)
    value = value | (byte(w, index * 8 + 7) << 56)
    return value

def read_word(s:readbuf, index:u64) -> u64:
    value = 0
    value = value | (byte(s, index + 0) << 0)
    value = value | (byte(s, index + 1) << 8)
    value = value | (byte(s, index + 2) << 16)
    value = value | (byte(s, index + 3) << 24)
    value = value | (byte(s, index + 4) << 32)
    value = value | (byte(s, index + 5) << 40)
    value = value | (byte(s, index + 6) << 48)
    value = value | (byte(s, index + 7) << 56)
    return value

def set(w:mutbuf, index:u64, value:u64) -> u64:
    store(w, index * 8 + 0, value >> 0)
    store(w, index * 8 + 1, value >> 8)
    store(w, index * 8 + 2, value >> 16)
    store(w, index * 8 + 3, value >> 24)
    store(w, index * 8 + 4, value >> 32)
    store(w, index * 8 + 5, value >> 40)
    store(w, index * 8 + 6, value >> 48)
    store(w, index * 8 + 7, value >> 56)
    return value
'''


def source_program():
    source = SOURCE
    for name, number in (('REQUEST_MAGIC', REQUEST_MAGIC), ('STATE_MAGIC', STATE_MAGIC),
                         ('RESULT_MAGIC', RESULT_MAGIC)):
        source = source.replace('@' + name + '@', str(number))
    return source


def document():
    nodes = ast.parse(source_program()).body
    names = {node.name: 'f' + str(i) for i, node in enumerate(nodes)}
    signatures = {node.name: ([a.annotation.id for a in node.args.args], node.returns.id)
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
        'module': 'execution_budget', 'functions': functions})


def main():
    path = Path(__file__).resolve().parents[1] / 'examples/hia_bootstrap/execution_budget.hepta'
    path.write_text(render_assembly(document()))
    print(path.name, path.stat().st_size)


if __name__ == '__main__':
    main()

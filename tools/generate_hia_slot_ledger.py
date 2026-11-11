"""Author HIA slot/version/lease decisions over the original SQLite rows.

The three-buffer protocol streams retained generations without a row-count cap.
SQL, JSON object transport and the existing proof/evaluation gates remain foreign
effects; none may substitute a hosted decision for a selected native image.
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

REQUEST_MAGIC = int.from_bytes(b'HIASLRQ1', 'little')
RESULT_MAGIC = int.from_bytes(b'HIASLRS1', 'little')
STATE_MAGIC = int.from_bytes(b'HIASLST1', 'little')
STATE_BYTES = 128

SOURCE = r'''
def slot_main(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 128 or length(o) < 64 or length(w) != 128:
        return 4294967293
    if read_word(s, 0) != @REQUEST_MAGIC@:
        return 4294967293
    if valid_packet(s) == 0:
        return answer(o, 12, 0, 0, 0, read_word(s, 8))
    op = read_word(s, 8)
    count = read_word(s, 16)
    flags = read_word(s, 24)
    a = read_word(s, 32)
    b = read_word(s, 40)
    if op >= 7 and op <= 9:
        return fold(s, o, w, op, count, flags, a, b)
    return stateless(s, o, w, op, count, flags, a, b)

def valid_packet(s:readbuf) -> u64:
    op = read_word(s, 8)
    count = read_word(s, 16)
    if op == 0 or op > 16 or count > 7:
        return 0
    if read_word(s, 48) != 0 or read_word(s, 56) != 0 or read_word(s, 96) != 0 or read_word(s, 104) != 0 or read_word(s, 112) != 0 or read_word(s, 120) != 0:
        return 0
    if count * 8 > length(s) - 128:
        return 0
    remaining = length(s) - 128 - count * 8
    i = 0
    while i < count:
        size = read_word(s, 128 + i * 8)
        if size > remaining:
            return 0
        remaining = remaining - size
        i = i + 1
    if remaining != 0:
        return 0
    if op >= 7 and op <= 9:
        if read_word(s, 64) == 0 and read_word(s, 72) == 0:
            return 0
        if read_word(s, 80) == 0 and read_word(s, 88) == 0:
            return 0
        return 1
    if read_word(s, 64) != 0 or read_word(s, 72) != 0 or read_word(s, 80) != 0 or read_word(s, 88) != 0:
        return 0
    return 1


def stateless(s:readbuf, o:mutbuf, w:mutbuf, op:u64, count:u64, flags:u64, a:u64, b:u64) -> u32:
    if op == 1:
        return u64_request(s, o, w, op, count, flags, a, b)
    if op == 2:
        return snapshot_request(s, o, w, op, count, flags, a, b)
    if op == 3:
        return conditional_request(s, o, w, op, count, flags, a, b)
    if op == 4 or op == 5 or op == 11:
        return compatibility_request(s, o, w, op, count, flags, a, b)
    if op == 6:
        return presence_request(s, o, w, op, count, flags, a, b)
    if op == 10:
        return retained_request(s, o, w, op, count, flags, a, b)
    if op == 12:
        return adoption_request(s, o, w, op, count, flags, a, b)
    if op == 13 or op == 14:
        return lease_request(s, o, w, op, count, flags, a, b)
    if op == 15:
        return acquire_request(s, o, w, op, count, flags, a, b)
    if op == 16:
        return lease_keys_request(s, o, w, op, count, flags, a, b)
    return answer(o, 12, 0, 0, 0, op)

def u64_request(s:readbuf, o:mutbuf, w:mutbuf, op:u64, count:u64, flags:u64, a:u64, b:u64) -> u32:
    if (count != 1 and count != 2) or flags == 0 or flags > 3 or a != 0 or b != 0:
        return answer(o, 12, 0, 0, 0, op)
    if count == 2 and flags != 1:
        return answer(o, 12, 0, 0, 0, op)
    if canonical(s, field_start(s, 0), field_size(s, 0), w) == 0:
        return answer(o, 2, 0, 1, 0, op)
    first = get(w, 13)
    second = 0
    if count == 2:
        if canonical(s, field_start(s, 1), field_size(s, 1), w) == 0:
            return answer(o, 2, 0, 2, 0, op)
        second = get(w, 13)
    return answer(o, 0, 0, first, second, op)

def snapshot_request(s:readbuf, o:mutbuf, w:mutbuf, op:u64, count:u64, flags:u64, a:u64, b:u64) -> u32:
    if flags > 1 or b != 0:
        return answer(o, 12, 0, 0, 0, op)
    if flags == 0:
        if count != 0 or a != 0:
            return answer(o, 12, 0, 0, 0, op)
        return answer(o, 0, 0, 0, 0, op)
    if count != 4:
        return answer(o, 12, 0, 0, 0, op)
    return fields_answer(s, o, 4, 1, a, 0, op)

def conditional_request(s:readbuf, o:mutbuf, w:mutbuf, op:u64, count:u64, flags:u64, a:u64, b:u64) -> u32:
    if count != 4 or flags > 1 or a != 0 or b != 0:
        return answer(o, 12, 0, 0, 0, op)
    if flags == 0 or same_field(s, 0, 2) == 0 or same_field(s, 1, 3) == 0:
        return answer(o, 3, 0, 0, 0, op)
    return answer(o, 0, 0, 0, 0, op)

def compatibility_request(s:readbuf, o:mutbuf, w:mutbuf, op:u64, count:u64, flags:u64, a:u64, b:u64) -> u32:
    if count != 2 or flags != 0 or a != 0 or b != 0:
        return answer(o, 12, 0, 0, 0, op)
    status = 4
    if op == 5:
        status = 5
    if op == 11:
        status = 13
    if same_field(s, 0, 1) == 0:
        return answer(o, status, 0, 0, 0, op)
    return answer(o, 0, 0, 0, 0, op)

def presence_request(s:readbuf, o:mutbuf, w:mutbuf, op:u64, count:u64, flags:u64, a:u64, b:u64) -> u32:
    if count != 0 or flags > 1 or a > 1 or b != 0:
        return answer(o, 12, 0, 0, 0, op)
    if flags == 0:
        if a == 1:
            return answer(o, 9, 0, 0, 0, op)
        return answer(o, 8, 0, 0, 0, op)
    return answer(o, 0, 0, 0, 0, op)

def retained_request(s:readbuf, o:mutbuf, w:mutbuf, op:u64, count:u64, flags:u64, a:u64, b:u64) -> u32:
    if count != 0 or flags > 1 or a != 0 or b != 0:
        return answer(o, 12, 0, 0, 0, op)
    if flags == 0:
        return answer(o, 10, 0, 0, 0, op)
    return answer(o, 0, 0, 0, 0, op)

def adoption_request(s:readbuf, o:mutbuf, w:mutbuf, op:u64, count:u64, flags:u64, a:u64, b:u64) -> u32:
    if count != 0 or flags > 1 or a != 0 or b != 0:
        return answer(o, 12, 0, 0, 0, op)
    return answer(o, 0, 1 + flags, 0, 0, op)

def lease_request(s:readbuf, o:mutbuf, w:mutbuf, op:u64, count:u64, flags:u64, a:u64, b:u64) -> u32:
    if count != 7 or flags > 1 or a > 1 or b > 1:
        return answer(o, 12, 0, 0, 0, op)
    if flags == 0 or a == 0 or b == 0 or same_field(s, 1, 4) == 0 or same_field(s, 2, 5) == 0 or same_field(s, 3, 6) == 0:
        return answer(o, 11, 0, 0, 0, op)
    return fields_answer(s, o, 4, op - 12, 0, 0, op)

def acquire_request(s:readbuf, o:mutbuf, w:mutbuf, op:u64, count:u64, flags:u64, a:u64, b:u64) -> u32:
    if count != 4 or flags > 1 or a != 0 or b != 0:
        return answer(o, 12, 0, 0, 0, op)
    if flags == 0:
        return answer(o, 8, 0, 0, 0, op)
    return fields_answer(s, o, 4, 3, 0, 0, op)

def lease_keys_request(s:readbuf, o:mutbuf, w:mutbuf, op:u64, count:u64, flags:u64, a:u64, b:u64) -> u32:
    if count != 7 or flags > 1 or a != 0 or b != 0:
        return answer(o, 12, 0, 0, 0, op)
    if flags == 0 or active_field(s, 6) == 0 or same_field(s, 1, 4) == 0 or same_field(s, 2, 5) == 0:
        return answer(o, 11, 0, 0, 0, op)
    return fields_answer(s, o, 4, 1, 0, 0, op)

def fold(s:readbuf, o:mutbuf, w:mutbuf, op:u64, count:u64, flags:u64, a:u64, b:u64) -> u32:
    if a != 0 or b != 0:
        return answer(o, 12, 0, 0, 0, op)
    if op == 7:
        return initialize_fold(s, o, w, op, count, flags, a, b)
    if flags != 0 or valid_state(w) == 0:
        return answer(o, 12, 0, 0, 0, op)
    if get(w, 8) != read_word(s, 64) or get(w, 9) != read_word(s, 72) or get(w, 10) != read_word(s, 80) or get(w, 11) != read_word(s, 88):
        return answer(o, 12, 0, 0, 0, op)
    if op == 8:
        return fold_row(s, o, w, op, count, flags, a, b)
    return finish_fold(s, o, w, op, count, flags, a, b)

def initialize_fold(s:readbuf, o:mutbuf, w:mutbuf, op:u64, count:u64, flags:u64, a:u64, b:u64) -> u32:
    if flags == 0 or flags > 2 or count != flags:
        return answer(o, 12, 0, 0, 0, op)
    i = 0
    while i < 16:
        if get(w, i) != 0:
            return answer(o, 12, 0, 0, 0, op)
        i = i + 1
    if canonical(s, field_start(s, 0), field_size(s, 0), w) == 0:
        return answer(o, 2, 0, 1, 0, op)
    epoch = get(w, 13)
    target = 0
    if flags == 2:
        if canonical(s, field_start(s, 1), field_size(s, 1), w) == 0:
            return answer(o, 2, 0, 2, 0, op)
        target = get(w, 13)
    set(w, 0, @STATE_MAGIC@)
    set(w, 1, 1)
    set(w, 2, flags)
    set(w, 3, epoch)
    set(w, 6, target)
    set(w, 8, read_word(s, 64))
    set(w, 9, read_word(s, 72))
    set(w, 10, read_word(s, 80))
    set(w, 11, read_word(s, 88))
    set(w, 13, 0)
    seal(w)
    return answer(o, 0, 0, 0, 0, op)

def fold_row(s:readbuf, o:mutbuf, w:mutbuf, op:u64, count:u64, flags:u64, a:u64, b:u64) -> u32:
    if count != 1 or get(w, 2) != 1:
        return answer(o, 12, 0, 0, 0, op)
    if canonical(s, field_start(s, 0), field_size(s, 0), w) == 0:
        return answer(o, 2, 0, 1, 0, op)
    value = get(w, 13)
    if get(w, 5) == 0 or value > get(w, 4):
        set(w, 4, value)
    set(w, 5, 1)
    set(w, 13, 0)
    seal(w)
    return answer(o, 0, 0, 0, 0, op)

def finish_fold(s:readbuf, o:mutbuf, w:mutbuf, op:u64, count:u64, flags:u64, a:u64, b:u64) -> u32:
    if count != 0:
        return answer(o, 12, 0, 0, 0, op)
    generation = get(w, 6)
    epoch = get(w, 3)
    if get(w, 2) == 1:
        if get(w, 5) != 1:
            return answer(o, 12, 0, 0, 0, op)
        if get(w, 4) == 18446744073709551615 or epoch == 18446744073709551615:
            set(w, 1, 2)
            seal(w)
            return answer(o, 6, 0, 0, 0, op)
        generation = get(w, 4) + 1
    else:
        if epoch == 18446744073709551615:
            set(w, 1, 2)
            seal(w)
            return answer(o, 7, 0, 0, 0, op)
    epoch = epoch + 1
    needed = 80 + decimal_size(generation) + decimal_size(epoch)
    if length(o) < needed:
        return 4294967294
    set(w, 1, 2)
    set(w, 6, generation)
    set(w, 3, epoch)
    seal(w)
    return decimals_answer(o, generation, epoch, op)

def canonical(s:readbuf, start:u64, size:u64, w:mutbuf) -> u64:
    if size == 0 or size > 20:
        return 0
    if size > 1 and byte(s, start) == 48:
        return 0
    value = 0
    i = 0
    while i < size:
        ch = byte(s, start + i)
        if ch < 48 or ch > 57:
            return 0
        digit = ch - 48
        if value > 1844674407370955161 or (value == 1844674407370955161 and digit > 5):
            return 0
        value = value * 10 + digit
        i = i + 1
    set(w, 13, value)
    return 1

def active_field(s:readbuf, index:u64) -> u64:
    if field_size(s, index) != 2:
        return 0
    start = field_start(s, index)
    if byte(s, start) != 73 or byte(s, start + 1) != 49:
        return 0
    return 1

def field_size(s:readbuf, index:u64) -> u64:
    return read_word(s, 128 + index * 8)

def field_start(s:readbuf, index:u64) -> u64:
    at = 128 + read_word(s, 16) * 8
    i = 0
    while i < index:
        at = at + field_size(s, i)
        i = i + 1
    return at

def same_field(s:readbuf, left:u64, right:u64) -> u64:
    size = field_size(s, left)
    if size != field_size(s, right):
        return 0
    a = field_start(s, left)
    b = field_start(s, right)
    i = 0
    while i < size:
        if byte(s, a + i) != byte(s, b + i):
            return 0
        i = i + 1
    return 1

def answer(o:mutbuf, status:u64, action:u64, a:u64, b:u64, op:u64) -> u32:
    set(o, 0, @RESULT_MAGIC@)
    set(o, 1, status)
    set(o, 2, action)
    set(o, 3, 0)
    set(o, 4, a)
    set(o, 5, b)
    set(o, 6, 0)
    set(o, 7, op)
    return 64

def fields_answer(s:readbuf, o:mutbuf, count:u64, action:u64, a:u64, b:u64, op:u64) -> u32:
    payload = 0
    i = 0
    while i < count:
        payload = payload + field_size(s, i)
        i = i + 1
    needed = 64 + count * 8 + payload
    if needed > 4294967292 or length(o) < needed:
        return 4294967294
    answer(o, 0, action, a, b, op)
    set(o, 3, count)
    set(o, 6, payload)
    at = 64 + count * 8
    i = 0
    while i < count:
        size = field_size(s, i)
        set(o, 8 + i, size)
        start = field_start(s, i)
        j = 0
        while j < size:
            store(o, at + j, byte(s, start + j))
            j = j + 1
        at = at + size
        i = i + 1
    return needed

def decimal_size(value:u64) -> u64:
    i = 0
    while i < 19:
        if value >= decimal_power(i):
            return 20 - i
        i = i + 1
    return 1

def write_decimal(o:mutbuf, at:u64, value:u64) -> u64:
    size = decimal_size(value)
    i = 20 - size
    while i < 20:
        power = decimal_power(i)
        digit = 0
        while value >= power:
            value = value - power
            digit = digit + 1
        store(o, at, 48 + digit)
        at = at + 1
        i = i + 1
    return size

def decimals_answer(o:mutbuf, generation:u64, epoch:u64, op:u64) -> u32:
    left = decimal_size(generation)
    right = decimal_size(epoch)
    needed = 80 + left + right
    if length(o) < needed:
        return 4294967294
    answer(o, 0, 0, generation, epoch, op)
    set(o, 3, 2)
    set(o, 6, left + right)
    set(o, 8, left)
    set(o, 9, right)
    write_decimal(o, 80, generation)
    write_decimal(o, 80 + left, epoch)
    return needed

def valid_state(w:mutbuf) -> u64:
    if get(w, 0) != @STATE_MAGIC@ or get(w, 1) != 1 or get(w, 2) == 0 or get(w, 2) > 2 or get(w, 5) > 1:
        return 0
    if get(w, 7) != 0 or get(w, 13) != 0 or get(w, 14) != 0 or get(w, 15) != 0:
        return 0
    if get(w, 2) == 2 and (get(w, 4) != 0 or get(w, 5) != 0):
        return 0
    if get(w, 12) != checksum(w):
        return 0
    return 1

def checksum(w:mutbuf) -> u64:
    value = 1469598103934665603
    i = 0
    while i < 16:
        if i != 12:
            value = ((value << 7) | (value >> 57)) ^ get(w, i)
        i = i + 1
    return value

def seal(w:mutbuf) -> u64:
    value = checksum(w)
    set(w, 12, value)
    return value

def get(w:mutbuf, index:u64) -> u64:
    value = 0
    i = 0
    while i < 8:
        value = value | (byte(w, index * 8 + i) << (i * 8))
        i = i + 1
    return value

def read_word(s:readbuf, index:u64) -> u64:
    value = 0
    i = 0
    while i < 8:
        value = value | (byte(s, index + i) << (i * 8))
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
    source = SOURCE
    for name, number in (('REQUEST_MAGIC', REQUEST_MAGIC), ('RESULT_MAGIC', RESULT_MAGIC),
                         ('STATE_MAGIC', STATE_MAGIC)):
        source = source.replace('@' + name + '@', str(number))
    power = ['def decimal_power(index:u64) -> u64:']
    for i in range(19):
        power.extend(('    if index == ' + str(i) + ':',
                      '        return ' + str(10 ** (19 - i))))
    power.append('    return 1')
    return source + '\n' + '\n'.join(power) + '\n'

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
        'module': 'slot_ledger', 'functions': functions})

def main():
    path = ROOT / 'examples/hia_bootstrap/slot_ledger.hepta'
    path.write_text(render_assembly(document()))
    print(path.name, path.stat().st_size)

if __name__ == '__main__':
    main()

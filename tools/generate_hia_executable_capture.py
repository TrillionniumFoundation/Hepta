"""Author the complete executable-capture policy in HIA.

This generator is an additive, explicitly selected component. It does not alter
the original selfhost compiler capture or process owner. Kernel operations are
separate, one-attempt native primitives; all retry/cleanup choices below belong
to this HIA program. Generation/qualification is performed by the root runner.
"""
from __future__ import annotations
import ast
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions

SOURCE_NAME = 'examples/hia_bootstrap/executable_capture.hepta'
MAGIC = 0x3152504143584548
STATE_MAGIC = 0x3154534143584548
RECEIPT_MAGIC = 0x31524f4143584548
MASK = (1 << 64) - 1
MAX_BYTES = 1 << 20
ACTIONS = ('MEMFD', 'WRITE', 'CHMOD', 'ADD_SEALS', 'GET_SEALS', 'PREAD',
           'CLOSE', 'AUDIT', 'CHECK_SIGNALS', 'RAISE_ERRNO', 'RAISE_CAPTURE')


def source_program():
    source = f'''def capture(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 128 or length(s) > 1048704 or length(o) != 128:
        return 4294967293
    n = readword(s, 56)
    if n > 1048576 or length(s) != 128 + n or length(w) != 257 + n:
        return 4294967293
    if readword(s, 0) != {MAGIC} or readword(s, 8) != 1:
        return 4294967293
    lo = readword(s, 64)
    hi = readword(s, 72)
    if lo == 0 and hi == 0:
        return 4294967293
    i = 80
    while i < 128:
        if readword(s, i) != 0:
            return 4294967293
        i = i + 8
    event = readword(s, 16)
    if event == 0:
        if readword(s, 24) != 0 or readword(s, 32) != 0 or readword(s, 40) != 0 or readword(s, 48) != 0:
            return 4294967293
        i = 0
        while i < 256:
            if word(w, i) != 0:
                return 4294967293
            i = i + 8
        put(w, 0, {STATE_MAGIC})
        put(w, 8, 1)
        put(w, 16, lo)
        put(w, 24, hi)
        put(w, 32, 1)
        put(w, 56, {MASK})
        put(w, 72, n)
        return issue(o, w, 1)
    if event != 1 and event != 2:
        return 4294967293
    if word(w, 0) != {STATE_MAGIC} or word(w, 8) != 1 or word(w, 16) != lo or word(w, 24) != hi:
        return 4294967293
    if word(w, 32) != 1 or word(w, 72) != n or word(w, 128) != checksum(w, 128):
        return 4294967293
    i = 136
    while i < 256:
        if word(w, i) != 0:
            return 4294967293
        i = i + 8
    action = word(w, 48)
    if action < 1 or action > 11 or word(w, 40) == 0 or word(w, 40) == {MASK}:
        return 4294967293
    if readword(s, 24) != word(w, 40) or readword(s, 32) != action:
        return 4294967293
    if word(w, 64) > n or word(w, 88) > 2 or word(w, 104) > 1:
        return 4294967293
    if event == 2:
        error = readword(s, 48)
        if readword(s, 40) != 0 or error != word(w, 88) + 1 or error > 2:
            return 4294967293
        put(w, 88, error)
        if word(w, 56) != {MASK} and word(w, 104) == 0:
            put(w, 104, 1)
            return issue(o, w, 7)
        return terminal(o, w, 3)
    if readword(s, 48) != 0:
        return 4294967293
    result = readword(s, 40)
    if action >= 10:
        return 4294967293
    if action == 8 or action == 9:
        if result != 0:
            return 4294967293
        if action == 8:
            next_action = word(w, 120)
            if next_action < 3 or next_action > 5:
                return 4294967293
            return issue(o, w, next_action)
        next_action = word(w, 96)
        if next_action < 2 or next_action > 6:
            return 4294967293
        return issue(o, w, next_action)
    if result >= 18446744073709547521:
        number = {MASK} - result + 1
        if number == 4 and action >= 2 and action <= 6:
            put(w, 96, action)
            return issue(o, w, 9)
        put(w, 112, number)
        return issue(o, w, 10)
    if action == 1:
        if result > 2147483647 or word(w, 56) != {MASK}:
            return 4294967293
        put(w, 56, result)
        if n == 0:
            return audit(o, w, 3)
        return issue(o, w, 2)
    if action == 2:
        if result > n - word(w, 64):
            return 4294967293
        if result == 0:
            put(w, 112, 1)
            return issue(o, w, 11)
        put(w, 64, word(w, 64) + result)
        if word(w, 64) == n:
            return audit(o, w, 3)
        return issue(o, w, 2)
    if action == 3 or action == 4:
        if result != 0:
            return 4294967293
        return audit(o, w, action + 1)
    if action == 5:
        if result > 2147483647:
            return 4294967293
        put(w, 80, result)
        if result & 15 != 15:
            put(w, 112, 2)
            return issue(o, w, 11)
        return issue(o, w, 6)
    if action == 6:
        if result > n + 1:
            return 4294967293
        if result != n:
            put(w, 112, 2)
            return issue(o, w, 11)
        i = 0
        while i < n:
            if byte(s, 128 + i) != byte(w, 256 + i):
                put(w, 112, 2)
                return issue(o, w, 11)
            i = i + 1
        return terminal(o, w, 2)
    if result != 0 or action != 7 or word(w, 104) != 1 or word(w, 88) == 0:
        return 4294967293
    return terminal(o, w, 3)

def audit(o:mutbuf, w:mutbuf, next_action:u64) -> u32:
    put(w, 120, next_action)
    return issue(o, w, 8)

def issue(o:mutbuf, w:mutbuf, action:u64) -> u32:
    put(w, 40, word(w, 40) + 1)
    put(w, 48, action)
    put(w, 128, checksum(w, 128))
    return receipt(o, w, 1)

def terminal(o:mutbuf, w:mutbuf, kind:u64) -> u32:
    put(w, 32, kind)
    put(w, 48, 0)
    put(w, 128, checksum(w, 128))
    return receipt(o, w, kind)

def receipt(o:mutbuf, w:mutbuf, kind:u64) -> u32:
    action = word(w, 48)
    offset = 0
    count = 0
    arg = 0
    if action == 1:
        arg = 3
    if action == 2:
        offset = word(w, 64)
        count = word(w, 72) - offset
    if action == 3:
        arg = 320
    if action == 4:
        arg = 15
    if action == 6:
        count = word(w, 72) + 1
    if action == 8:
        arg = word(w, 120)
    if action == 9:
        arg = word(w, 96)
    if action == 10 or action == 11:
        arg = word(w, 112)
    put(o, 0, {RECEIPT_MAGIC})
    put(o, 8, 1)
    put(o, 16, kind)
    put(o, 24, word(w, 40))
    put(o, 32, action)
    put(o, 40, word(w, 56))
    put(o, 48, offset)
    put(o, 56, count)
    put(o, 64, arg)
    put(o, 72, word(w, 88))
    put(o, 80, word(w, 16))
    put(o, 88, word(w, 24))
    put(o, 96, word(w, 32))
    put(o, 104, checksum(o, 104))
    put(o, 112, 0)
    put(o, 120, 0)
    return 128

def checksum(w:mutbuf, end:u64) -> u64:
    value = 1469598103934665603
    i = 0
    while i < end:
        value = ((value ^ word(w, i)) * 1099511628211) & {MASK}
        i = i + 8
    return value
'''
    for name, kind in (('readword', 'readbuf'), ('word', 'mutbuf')):
        source += f'\ndef {name}(s:{kind}, at:u64) -> u64:\n    value = 0\n'
        for i in range(8):
            source += f'    value = value | (byte(s, at + {i}) << {8*i})\n'
        source += '    return value\n'
    source += '\ndef put(w:mutbuf, at:u64, value:u64) -> u64:\n'
    for i in range(8):
        source += f'    store(w, at + {i}, (value >> {8*i}) & 255)\n'
    return source + '    return 0\n'


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
        functions.append({'name': names[node.name],
                          'params': [builder.param(v) for v in builder.params],
                          'returns': [builder.returns], 'effects': ['read', 'write', 'trap'],
                          'entry': 'b0', 'blocks': builder.blocks})
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8',
                                  'module': 'executable_capture', 'functions': functions})


def main():
    target = Path(__file__).resolve().parents[1] / SOURCE_NAME
    target.write_text(render_assembly(document()))
    print(target.name, target.stat().st_size)


if __name__ == '__main__':
    main()

"""Author the complete bounded, in-process retirement policy/state owner in HIA.

This authoring tool is not a production policy interpreter. The generated HIA
owns a retained state block; the foreign adapter supplies observations/effects.
"""
from __future__ import annotations

import ast
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions

REQUEST_MAGIC = int.from_bytes(b'HIARREQ1', 'little')
STATE_MAGIC = int.from_bytes(b'HIARSTA1', 'little')
RESULT_MAGIC = int.from_bytes(b'HIARRES1', 'little')
STATE_BYTES = 4608
SOURCE = r'''
def retirement_main(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 128 or length(s) > 4224 or length(o) < 64 or length(w) != 4608:
        return 4294967293
    if read_word(s, 0) != @REQUEST_MAGIC@:
        return 4294967293
    event = read_word(s, 8)
    token = read_word(s, 16)
    now = read_word(s, 24)
    a = read_word(s, 32)
    b = read_word(s, 40)
    c = read_word(s, 48)
    d = read_word(s, 56)
    e = read_word(s, 64)
    f = read_word(s, 72)
    if event == 0:
        if a > 1 or (read_word(s, 112) == 0 and read_word(s, 120) == 0):
            return result(o, 1, 0, 0, 0, 0, 0, 0)
        i = 0
        while i < 4608:
            if byte(w, i) != 0:
                return result(o, 2, 0, 0, 0, 0, 0, 0)
            i = i + 1
        set_word(w, 0, @STATE_MAGIC@)
        set_word(w, 1, 1)
        set_word(w, 2, 1)
        set_word(w, 3, a)
        set_word(w, 55, read_word(s, 112))
        set_word(w, 56, read_word(s, 120))
        set_word(w, 45, length(s) - 128)
        i = 128
        while i < length(s):
            store(w, 512 + i - 128, byte(s, i))
            i = i + 1
        seal(w)
        return answer(o, w, 0, 0, 0, 0)
    if valid_state(w) == 0:
        return result(o, 2, 0, 0, 0, 0, 0, 0)
    if read_word(s, 112) != get_word(w, 55) or read_word(s, 120) != get_word(w, 56):
        return answer(o, w, 4, 0, 0, 0)
    if event == 1:
        if length(s) != 128:
            return answer(o, w, 1, 0, 0, 0)
        return answer(o, w, 0, 0, 0, 0)
    if event == 13:
        same = 1
        if a != get_word(w, 3) or b != get_word(w, 7) or length(s) - 128 != get_word(w, 45):
            same = 0
        if b != 0 and (c != get_word(w, 8) or d != get_word(w, 9)):
            same = 0
        i = 128
        while i < length(s) and same != 0:
            if byte(s, i) != byte(w, 512 + i - 128):
                same = 0
            i = i + 1
        return answer(o, w, 0, 0, 0, same)
    if length(s) != 128 and event != 20:
        return answer(o, w, 1, 0, 0, 0)
    if get_word(w, 2) == 18446744073709551615:
        return answer(o, w, 6, 0, 0, 0)
    next_token = get_word(w, 2) + 1
    if event == 2:
        if get_word(w, 4) != 0 or get_word(w, 11) != 0 or get_word(w, 10) != 0:
            return answer(o, w, 3, 0, 0, 0)
        if a > 1:
            return answer(o, w, 1, 0, 0, 0)
        set_word(w, 4, 1)
        set_word(w, 13, next_token)
        set_word(w, 54, 1)
        set_word(w, 48, a)
        set_word(w, 46, b)
        set_word(w, 47, c)
        advance(w, next_token)
        return answer(o, w, 0, 1 + get_word(w, 3), next_token, 0)
    if event == 3:
        if token == 0 or token != get_word(w, 13) or get_word(w, 54) == 0 or get_word(w, 5) != 0 or a > 2147483647:
            return answer(o, w, 4, 0, 0, 0)
        set_word(w, 5, 1)
        set_word(w, 6, a)
        set_word(w, 12, 1)
        advance(w, next_token)
        return answer(o, w, 0, 3, token, a)
    if event == 4:
        if token == 0 or token != get_word(w, 13) or get_word(w, 54) == 0 or get_word(w, 5) == 0:
            return answer(o, w, 4, 0, 0, 0)
        if get_word(w, 10) != 0 or get_word(w, 11) != 0:
            return answer(o, w, 4, 0, 0, 0)
        expected_type = 32768
        if get_word(w, 3) != 0:
            expected_type = 16384
        accepted = 1
        if get_word(w, 48) == 0 or (c & 61440) != expected_type or a != get_word(w, 46) or b != get_word(w, 47) or d != a or e != b:
            accepted = 0
        set_word(w, 54, 0)
        if accepted == 0:
            set_word(w, 51, 1)
            advance(w, next_token)
            return answer(o, w, 5, 0, 0, 0)
        set_word(w, 7, 1)
        set_word(w, 8, a)
        set_word(w, 9, b)
        advance(w, next_token)
        return answer(o, w, 0, 0, 0, 0)
    if event == 5:
        if token == 0 or token != get_word(w, 13):
            return answer(o, w, 4, 0, 0, 0)
        if get_word(w, 54) == 0 and get_word(w, 51) == 0:
            return answer(o, w, 4, 0, 0, 0)
        set_word(w, 54, 0)
        set_word(w, 51, 1)
        advance(w, next_token)
        return answer(o, w, 0, 0, 0, 0)
    if event == 6:
        if get_word(w, 11) != 0 or get_word(w, 5) == 0:
            return answer(o, w, 0, 0, 0, 0)
        if get_word(w, 51) == 0 and get_word(w, 10) == 0:
            return answer(o, w, 7, 0, 0, 0)
        set_word(w, 11, 1)
        set_word(w, 12, 2)
        set_word(w, 14, next_token)
        set_word(w, 41, now)
        advance(w, next_token)
        return answer(o, w, 0, 4, next_token, get_word(w, 6))
    if event == 7:
        if token == 0 or token != get_word(w, 14) or a > 1:
            return answer(o, w, 4, 0, 0, 0)
        if a != 0:
            set_word(w, 12, 3)
        set_word(w, 14, 0)
        set_word(w, 42, now)
        set_word(w, 43, 1)
        advance(w, next_token)
        return answer(o, w, 0, 0, 0, 0)
    if event == 8:
        if get_word(w, 10) != 0:
            return answer(o, w, 0, 0, 0, 0)
        if get_word(w, 32) != 1 and get_word(w, 29) != 1 and get_word(w, 29) != 4:
            return answer(o, w, 7, 0, 0, 0)
        set_word(w, 10, 1)
        advance(w, next_token)
        return answer(o, w, 0, 0, 0, 0)
    if event == 9:
        if a > 2:
            return answer(o, w, 1, 0, 0, 0)
        observed = 0
        if a == 1:
            observed = 1
        elif a == 2:
            observed = 6
        elif get_word(w, 10) != 0:
            observed = 5
        elif get_word(w, 7) == 0 or get_word(w, 5) == 0 or get_word(w, 11) != 0:
            observed = 4
        set_word(w, 32, observed)
        set_word(w, 33, next_token)
        set_word(w, 50, now)
        set_word(w, 34, 0)
        set_word(w, 35, b)
        set_word(w, 36, c)
        set_word(w, 37, d)
        action = 0
        if observed == 0:
            set_word(w, 34, 1)
            action = 3
        advance(w, next_token)
        return answer(o, w, 0, action, next_token, get_word(w, 6))
    if event == 10:
        if token == 0 or token != get_word(w, 33) or get_word(w, 34) == 0 or a > 2:
            return answer(o, w, 4, 0, 0, 0)
        observed = 3
        if a == 1:
            observed = 1
        elif a == 2:
            observed = 6
        else:
            expected_type = 32768
            if get_word(w, 3) != 0:
                expected_type = 16384
            if (get_word(w, 37) & 61440) == expected_type and get_word(w, 35) == get_word(w, 8) and get_word(w, 36) == get_word(w, 9) and b == get_word(w, 8) and c == get_word(w, 9):
                observed = 2
        set_word(w, 32, observed)
        set_word(w, 34, 0)
        set_word(w, 33, next_token)
        advance(w, next_token)
        return answer(o, w, 0, 0, next_token, 0)
    if event == 11 or event == 24:
        if token == 0 or token != get_word(w, 33) or get_word(w, 34) != 0:
            return answer(o, w, 4, 0, 0, 0)
        if event == 11 and (get_word(w, 3) == 0 or get_word(w, 15) != 0):
            return answer(o, w, 7, 0, 0, 0)
        if event == 24 and get_word(w, 15) == 0:
            return answer(o, w, 7, 0, 0, 0)
        if event == 24 and (a == 0 or a != get_word(w, 52) or token <= a):
            return answer(o, w, 4, 0, 0, 0)
        if event == 11:
            if get_word(w, 28) == 18446744073709551615:
                return answer(o, w, 6, 0, 0, 0)
            set_word(w, 28, get_word(w, 28) + 1)
            set_word(w, 44, now)
        set_word(w, 52, 0)
        set_word(w, 33, 0)
        set_word(w, 30, 0)
        set_word(w, 53, event)
        action = 0
        status = 3
        if get_word(w, 32) == 1:
            status = 1
            set_word(w, 10, 1)
            action = 8
        elif event == 24 and native_succeeded(w) == 0:
            status = 2
        elif get_word(w, 32) == 2:
            matches = 1
            if event == 24 and (get_word(w, 16) == 0 or get_word(w, 7) == 0 or get_word(w, 17) != get_word(w, 8) or get_word(w, 18) != get_word(w, 9)):
                matches = 0
            if matches != 0:
                status = 6
                set_word(w, 30, next_token)
                action = 5
                if event == 11:
                    action = 6
        set_word(w, 29, status)
        advance(w, next_token)
        return answer(o, w, 0, action, get_word(w, 30), status)
    if event == 12 or event == 25:
        expected = 24
        if event == 12:
            expected = 11
        if token == 0 or token != get_word(w, 30) or get_word(w, 53) != expected or a > 2:
            return answer(o, w, 4, 0, 0, 0)
        set_word(w, 30, 0)
        action = 0
        status = 5
        if a == 0:
            status = 4
            action = 8
        elif a == 1:
            status = 1
            action = 8
        if action == 8:
            set_word(w, 10, 1)
        set_word(w, 29, status)
        advance(w, next_token)
        return answer(o, w, 0, action, 0, status)
    if event == 26:
        if get_word(w, 15) == 0:
            return answer(o, w, 7, 0, 0, 0)
        if get_word(w, 28) == 18446744073709551615:
            return answer(o, w, 6, 0, 0, 0)
        set_word(w, 28, get_word(w, 28) + 1)
        set_word(w, 44, now)
        set_word(w, 29, 6)
        set_word(w, 30, 0)
        set_word(w, 52, next_token)
        set_word(w, 53, 24)
        advance(w, next_token)
        return answer(o, w, 0, 0, next_token, 0)
    if event == 20:
        if get_word(w, 15) != 0 or get_word(w, 3) != 0 or get_word(w, 54) != 0 or a > 1 or d > 1 or e > 1 or (e != 0 and f > 2147483647):
            return answer(o, w, 7, 0, 0, 0)
        if e != 0 and get_word(w, 5) != 0 and f == get_word(w, 6):
            return answer(o, w, 7, 0, 0, 0)
        if length(s) - 128 != get_word(w, 45):
            return answer(o, w, 7, 0, 0, 0)
        i = 128
        while i < length(s):
            if byte(s, i) != byte(w, 512 + i - 128):
                return answer(o, w, 7, 0, 0, 0)
            i = i + 1
        set_word(w, 15, 1)
        set_word(w, 16, a)
        set_word(w, 17, b)
        set_word(w, 18, c)
        set_word(w, 19, d)
        set_word(w, 20, e)
        set_word(w, 21, f)
        set_word(w, 31, read_word(s, 80))
        advance(w, next_token)
        return answer(o, w, 0, 0, 0, 0)
    if event == 21:
        if get_word(w, 15) == 0:
            return answer(o, w, 7, 0, 0, 0)
        if get_word(w, 22) != 0:
            return answer(o, w, 0, 0, 0, 0)
        set_word(w, 22, 1)
        set_word(w, 25, next_token)
        set_word(w, 38, now)
        set_word(w, 23, get_word(w, 19) * 2)
        set_word(w, 24, get_word(w, 20) * 2)
        set_word(w, 26, get_word(w, 19))
        set_word(w, 27, get_word(w, 20))
        advance(w, next_token)
        return answer(o, w, 0, 7, next_token, get_word(w, 19) + get_word(w, 20) * 2)
    if event == 22:
        if token == 0 or token != get_word(w, 25) or a < 1 or a > 2 or b > 1:
            return answer(o, w, 4, 0, 0, 0)
        pending = 25 + a
        status_index = 22 + a
        if get_word(w, pending) == 0:
            return answer(o, w, 4, 0, 0, 0)
        set_word(w, pending, 0)
        if b != 0:
            set_word(w, status_index, 3)
        advance(w, next_token)
        return answer(o, w, 0, 0, 0, 0)
    if event == 23:
        if token == 0 or token != get_word(w, 25) or get_word(w, 26) != 0 or get_word(w, 27) != 0:
            return answer(o, w, 4, 0, 0, 0)
        set_word(w, 25, 0)
        set_word(w, 39, now)
        set_word(w, 40, 1)
        advance(w, next_token)
        return answer(o, w, 0, 0, 0, 0)
    return answer(o, w, 1, 0, 0, 0)

def valid_state(w:mutbuf) -> u64:
    if get_word(w, 0) != @STATE_MAGIC@ or get_word(w, 1) != 1 or get_word(w, 2) == 0 or get_word(w, 45) > 4096:
        return 0
    if get_word(w, 49) != checksum(w):
        return 0
    if get_word(w, 3) > 1 or get_word(w, 4) > 1 or get_word(w, 5) > 1 or get_word(w, 7) > 1 or get_word(w, 10) > 1 or get_word(w, 11) > 1 or get_word(w, 15) > 1 or get_word(w, 16) > 1 or get_word(w, 19) > 1 or get_word(w, 20) > 1 or get_word(w, 22) > 1 or get_word(w, 26) > 1 or get_word(w, 27) > 1 or get_word(w, 34) > 1 or get_word(w, 40) > 1 or get_word(w, 43) > 1 or get_word(w, 48) > 1 or get_word(w, 51) > 1 or get_word(w, 54) > 1:
        return 0
    if get_word(w, 12) > 3 or get_word(w, 23) > 3 or get_word(w, 24) > 3 or get_word(w, 29) > 6 or get_word(w, 32) > 6:
        return 0
    if get_word(w, 55) == 0 and get_word(w, 56) == 0:
        return 0
    i = 57
    while i < 64:
        if get_word(w, i) != 0:
            return 0
        i = i + 1
    i = 512 + get_word(w, 45)
    while i < 4608:
        if byte(w, i) != 0:
            return 0
        i = i + 1
    return 1

def native_succeeded(w:mutbuf) -> u64:
    if get_word(w, 22) != 0 and (get_word(w, 23) == 0 or get_word(w, 23) == 3) and (get_word(w, 24) == 0 or get_word(w, 24) == 3):
        return 1
    return 0

def answer(o:mutbuf, w:mutbuf, code:u64, action:u64, token:u64, value:u64) -> u32:
    flags = 0
    released = 0
    if get_word(w, 54) == 0 and (get_word(w, 5) == 0 or (get_word(w, 11) != 0 and get_word(w, 12) == 3)):
        flags = flags | 1
        released = 1
    if get_word(w, 7) != 0 and get_word(w, 5) != 0 and get_word(w, 11) == 0:
        flags = flags | 2
    native = native_succeeded(w)
    if native != 0:
        flags = flags | 4
    if native != 0 and released != 0 and (get_word(w, 29) == 1 or get_word(w, 29) == 4):
        flags = flags | 8
    return result(o, code, action, token, value, flags, get_word(w, 2), get_word(w, 32))

def result(o:mutbuf, code:u64, action:u64, token:u64, value:u64, flags:u64, sequence:u64, observed:u64) -> u32:
    set_word(o, 0, @RESULT_MAGIC@)
    set_word(o, 1, code)
    set_word(o, 2, action)
    set_word(o, 3, token)
    set_word(o, 4, value)
    set_word(o, 5, flags)
    set_word(o, 6, sequence)
    set_word(o, 7, observed)
    return 64

def checksum(w:mutbuf) -> u64:
    value = 1469598103934665603
    i = 0
    while i < 576:
        if i != 49:
            value = ((value << 7) | (value >> 57)) ^ get_word(w, i)
        i = i + 1
    return value

def seal(w:mutbuf) -> u64:
    value = checksum(w)
    set_word(w, 49, value)
    return value

def advance(w:mutbuf, sequence:u64) -> u64:
    set_word(w, 2, sequence)
    return seal(w)

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
    # Keep the existing native compiler's per-function CFG bound. This is an
    # authoring split of whole event branches, not a new runtime dispatcher or
    # an enlargement of any compiler admission limit.
    pin_start = SOURCE.index('    if event == 2:\n')
    disk_start = SOURCE.index('    if event == 11 or event == 24:\n')
    native_start = SOURCE.index('    if event == 20:\n')
    helpers_start = SOURCE.index('\ndef valid_state(')
    dispatch = '''    if event <= 10:
        return pin_transition(s, o, w, event, token, now, next_token)
    if event == 11 or event == 12 or event == 24 or event == 25 or event == 26:
        return disk_transition(s, o, w, event, token, now, next_token)
    if event >= 20 and event <= 23:
        return native_transition(s, o, w, event, token, now, next_token)
    return answer(o, w, 1, 0, 0, 0)
'''
    def handler(name, body):
        return ('\ndef ' + name + '(s:readbuf, o:mutbuf, w:mutbuf, event:u64, token:u64, now:u64, next_token:u64) -> u32:\n'
            '    a = read_word(s, 32)\n    b = read_word(s, 40)\n    c = read_word(s, 48)\n'
            '    d = read_word(s, 56)\n    e = read_word(s, 64)\n    f = read_word(s, 72)\n'
            + body + '    return answer(o, w, 1, 0, 0, 0)\n')
    value = (SOURCE[:pin_start] + dispatch
        + handler('pin_transition', SOURCE[pin_start:disk_start])
        + handler('disk_transition', SOURCE[disk_start:native_start])
        + handler('native_transition', SOURCE[native_start:helpers_start].rsplit(
            '    return answer(o, w, 1, 0, 0, 0)', 1)[0])
        + SOURCE[helpers_start:])
    for name, number in {'REQUEST_MAGIC': REQUEST_MAGIC, 'STATE_MAGIC': STATE_MAGIC,
                         'RESULT_MAGIC': RESULT_MAGIC}.items():
        value = value.replace('@' + name + '@', str(number))
    return value


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
            'params': [builder.param(value) for value in builder.params],
            'returns': [builder.returns], 'effects': ['read', 'write', 'trap'],
            'entry': 'b0', 'blocks': builder.blocks})
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8',
        'module': 'retirement_state', 'functions': functions})


def main():
    path = Path(__file__).resolve().parents[1] / 'examples/hia_bootstrap/retirement_state.hiaasm'
    path.write_text(render_assembly(document()))
    print(path.name, path.stat().st_size)


if __name__ == '__main__':
    main()

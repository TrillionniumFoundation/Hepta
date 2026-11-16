"""Author every branch, loop and exception transition of original _hia_read."""
from __future__ import annotations
import ast
from pathlib import Path
import re
import sys
import textwrap

ROOT = Path(__file__).resolve().parents[1]
if __package__ in (None, ''):
    sys.path.insert(0, str(ROOT))
from hepta.hia_agent_assembly import render_assembly
from hepta.hia_service_read_protocol import PORT, PORTS
from tools.generate_hia_selfhost import compact_authoring_cfg, total_scalar_functions
from tools.generate_hia_service_context import ContextBuilder

REQUEST_MAGIC = int.from_bytes(b'HSRDRQ01', 'little')
RESULT_MAGIC = int.from_bytes(b'HSRDRS01', 'little')
STATE_MAGIC = int.from_bytes(b'HSRDST01', 'little')
SOURCE_NAME = 'examples/hia_bootstrap/service_read.hepta'
CHOICES = {
    'cursor_present': ('limit', 'cursor_select'),
    'cursor_missing': ('cursor_id_test', 'cursor_reject'),
    'cursor_id_test': ('cursor_sha_test', 'cursor_reject'),
    'cursor_sha_test': ('cursor_offset', 'cursor_reject'),
    'first_exception_match': ('outer_exception_match', 'first_chunk_trim'),
    'budget_test': ('next_cursor_none', 'budget_chunk_halve'),
    'end_test': ('result', 'next_cursor_digest'),
}
JUMPS = {
    'cursor_reject': 'cursor_offset',
    'cursor_offset': 'limit',
    'first_chunk_decode': 'budget_test',
    'later_base64': 'budget_test',
    'later_chunk_decode': 'budget_test',
    'result': 'release_locals',
    'release_locals': 'return',
}
PREDICATES = set(CHOICES) | {'outer_exception_match', 'later_exception_match'}
TRANSITIONS = {name: f'if observed == 0:\n    next_port = @{targets[0]}@\nelse:\n    next_port = @{targets[1]}@'
               for name, targets in CHOICES.items()}
TRANSITIONS.update({name: f'next_port = @{target}@' for name, target in JUMPS.items()})
TRANSITIONS.update({
    'first_chunk_trim': 'return advance(o, w, @first_chunk_decode@, 7)',
    'later_chunk_trim': 'return advance(o, w, @later_chunk_decode@, 7)',
    'outer_exception_match': '''if observed == 0:
    set(w, 12, 1)
    return advance(o, w, 0, 5)
next_port = @initial_base64@''',
    'later_exception_match': '''if observed == 0:
    set(w, 12, 1)
    return advance(o, w, 0, 5)
next_port = @later_chunk_trim@''',
    'encoding_utf8': 'set(w, 8, 0)',
    'initial_base64': '''set(w, 8, 1)
return advance(o, w, @budget_test@, 7)''',
    'budget_chunk_halve': '''next_port = @later_chunk_decode@
if get(w, 8) == 1:
    next_port = @later_base64@''',
    'return': 'return advance(o, w, 0, 4)',
})

PROTOCOL = r'''
def service_read(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) != 80 or length(o) != 96 or length(w) != 128:
        return 4294967293
    if read_word(s, 0) != @REQUEST_MAGIC@ or read_word(s, 64) != 0 or read_word(s, 72) != 0:
        return 4294967293
    event = read_word(s, 8)
    if event == 0:
        return initialize(s, o, w)
    if valid_state(w) == 0:
        return 4294967293
    if read_word(s, 40) != 1 or read_word(s, 48) != get(w, 6) or read_word(s, 56) != get(w, 7):
        return refuse(o, w)
    if read_word(s, 16) != get(w, 4) or read_word(s, 24) != get(w, 3):
        return refuse(o, w)
    if event == 1:
        if (get(w, 5) != 1 and get(w, 5) != 7) or read_word(s, 32) != 0:
            return refuse(o, w)
        set(w, 5, 2)
        seal(w)
        return answer(o, w, 0)
    if event == 2:
        if get(w, 5) != 2:
            return refuse(o, w)
        observed = read_word(s, 32)
        if is_predicate(get(w, 3)) == 1:
            if observed > 1:
                return refuse(o, w)
        elif observed != 0:
            return refuse(o, w)
        return succeeded(o, w, observed)
    if event == 3:
        if get(w, 5) != 2 or read_word(s, 32) != 0:
            return refuse(o, w)
        return failed_effect(o, w)
    return refuse(o, w)

def initialize(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if read_word(s, 40) != 1 or read_word(s, 16) != 0 or read_word(s, 24) != 0 or read_word(s, 32) != 0:
        return 4294967293
    if read_word(s, 48) == 0 and read_word(s, 56) == 0:
        return 4294967293
    i = 0
    while i < 128:
        if byte(w, i) != 0:
            return 4294967293
        i = i + 1
    set(w, 0, @STATE_MAGIC@)
    set(w, 1, 1)
    set(w, 2, 1)
    set(w, 3, @artifact_argument@)
    set(w, 4, 1)
    set(w, 5, 1)
    set(w, 6, read_word(s, 48))
    set(w, 7, read_word(s, 56))
    seal(w)
    return answer(o, w, 0)

def valid_state(w:mutbuf) -> u64:
    if get(w, 0) != @STATE_MAGIC@ or get(w, 1) != 1 or get(w, 2) != 1:
        return 0
    if get(w, 4) == 0 or get(w, 5) == 0 or get(w, 5) == 3 or get(w, 5) > 7:
        return 0
    if get(w, 8) > 1 or get(w, 9) != 0 or get(w, 11) != 0 or get(w, 12) > 1:
        return 0
    if get(w, 14) != 0 or get(w, 15) != 0 or get(w, 13) != 0:
        return 0
    if checksum(w) != get(w, 10):
        return 0
    port = get(w, 3)
    if get(w, 5) == 1 or get(w, 5) == 2 or get(w, 5) == 7:
        if port == 0 or port > @MAX_PORT@:
            return 0
    elif port != 0:
        return 0
    if get(w, 5) == 7:
        if port != @first_chunk_decode@ and port != @later_chunk_decode@ and port != @budget_test@:
            return 0
    return 1

def failed_effect(o:mutbuf, w:mutbuf) -> u32:
    port = get(w, 3)
    if port == @whole_data_decode@ or port == @first_exception_match@ or port == @first_chunk_trim@:
        return advance(o, w, @outer_exception_match@, 1)
    if port == @first_chunk_decode@:
        return advance(o, w, @first_exception_match@, 1)
    if port == @later_chunk_decode@:
        return advance(o, w, @later_exception_match@, 1)
    set(w, 12, 1)
    return advance(o, w, 0, 5)

def advance(o:mutbuf, w:mutbuf, port:u64, phase:u64) -> u32:
    if get(w, 4) == 18446744073709551615:
        return refuse(o, w)
    set(w, 3, port)
    set(w, 4, get(w, 4) + 1)
    set(w, 5, phase)
    seal(w)
    return answer(o, w, 0)

def refuse(o:mutbuf, w:mutbuf) -> u32:
    set(w, 3, 0)
    set(w, 5, 6)
    seal(w)
    return answer(o, w, 1)

def answer(o:mutbuf, w:mutbuf, status:u64) -> u32:
    set(o, 0, @RESULT_MAGIC@)
    set(o, 1, status)
    set(o, 2, get(w, 3))
    set(o, 3, get(w, 4))
    set(o, 4, get(w, 5))
    set(o, 5, get(w, 2))
    set(o, 6, get(w, 12))
    set(o, 7, get(w, 8))
    set(o, 8, get(w, 6))
    set(o, 9, get(w, 7))
    set(o, 10, 0)
    set(o, 11, 0)
    return 96

def checksum(w:mutbuf) -> u64:
    value = 1469598103934665603
    i = 0
    while i < 16:
        if i != 10:
            value = ((value << 7) | (value >> 57)) ^ get(w, i)
        i = i + 1
    return value

def seal(w:mutbuf) -> u64:
    value = checksum(w)
    set(w, 10, value)
    return value

def read_word(s:readbuf, index:u64) -> u64:
    value = 0
    i = 0
    while i < 8:
        value = value | (byte(s, index + i) << (i * 8))
        i = i + 1
    return value

def get(w:mutbuf, index:u64) -> u64:
    value = 0
    i = 0
    while i < 8:
        value = value | (byte(w, index * 8 + i) << (i * 8))
        i = i + 1
    return value

def set(w:mutbuf, index:u64, value:u64) -> u64:
    return put_word(w, index * 8, value)

def put_word(w:mutbuf, index:u64, value:u64) -> u64:
    i = 0
    while i < 8:
        store(w, index + i, value >> (i * 8))
        i = i + 1
    return value
'''

def source_program():
    groups = [PORTS[index:index + 20] for index in range(0, len(PORTS), 20)]
    fragments = [PROTOCOL, 'def succeeded(o:mutbuf, w:mutbuf, observed:u64) -> u32:\n    port = get(w, 3)\n']
    for index, names in enumerate(groups):
        fragments.append(f'    if port <= {PORT[names[-1]]}:\n        return successor_{index}(o, w, observed)\n')
    fragments.append('    return refuse(o, w)\n\n')
    for index, names in enumerate(groups):
        fragments.append(f'def successor_{index}(o:mutbuf, w:mutbuf, observed:u64) -> u32:\n    port = get(w, 3)\n    next_port = port + 1\n')
        first = True
        for name in names:
            if name not in TRANSITIONS:
                continue
            fragments.append(f'    {"if" if first else "elif"} port == {PORT[name]}:\n')
            fragments.append(textwrap.indent(TRANSITIONS[name], '        ') + '\n')
            first = False
        fragments.append('    return advance(o, w, next_port, 1)\n\n')
    fragments.append('def is_predicate(port:u64) -> u64:\n')
    predicates = sorted(PORT[name] for name in PREDICATES)
    for index in range(0, len(predicates), 8):
        condition = ' or '.join(f'port == {value}' for value in predicates[index:index + 8])
        fragments.append('    if ' + condition + ':\n        return 1\n')
    fragments.append('    return 0\n\n')
    values = {**PORT, 'REQUEST_MAGIC': REQUEST_MAGIC, 'RESULT_MAGIC': RESULT_MAGIC,
              'STATE_MAGIC': STATE_MAGIC, 'MAX_PORT': len(PORTS)}
    return re.sub(r'@([A-Za-z_][A-Za-z0-9_]*)@', lambda match: str(values[match[1]]), ''.join(fragments))


def document():
    nodes = ast.parse(source_program()).body
    names = {node.name: 'f' + str(index) for index, node in enumerate(nodes)}
    signatures = {node.name: ([arg.annotation.id for arg in node.args.args], node.returns.id)
                  for node in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = ContextBuilder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({'name': names[node.name], 'params': [builder.param(value) for value in builder.params],
            'returns': [builder.returns], 'effects': ['read', 'write', 'trap'],
            'entry': 'b0', 'blocks': builder.blocks})
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8',
                                  'module': 'service_read', 'functions': functions})


if __name__ == '__main__':
    path = ROOT / SOURCE_NAME
    path.write_text(render_assembly(document()))
    print(path.name, path.stat().st_size)

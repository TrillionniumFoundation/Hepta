"""Emit complete Service verification control into HIA; no retained-body call."""
from __future__ import annotations
import ast
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parents[1]
if __package__ in (None, ''):
    sys.path.insert(0, str(ROOT))
from hepta.hia_agent_assembly import render_assembly
from hepta.hia_service_verification_protocol import (
    PORT, MODE_RANGES, GENERATOR_RESUME_PORTS, REQUEST_MAGIC, RESULT_MAGIC, STATE_MAGIC, SOURCE_NAME)
from tools.hia_service_verification_graph import ROWS
from tools.generate_hia_selfhost import compact_authoring_cfg, total_scalar_functions
from tools.generate_hia_service_context import ContextBuilder

COMMON = '''def service_verification(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) != 128 or length(o) != 96 or length(w) != 192:
        return 4294967293
    if read_word(s, 0) != @REQUEST_MAGIC@:
        return 4294967293
    index = 64
    while index < 128:
        if read_word(s, index) != 0:
            return 4294967293
        index = index + 8
    event = read_word(s, 8)
    if event == 0:
        return initialize(s, o, w)
    if valid_state(w) == 0:
        return 4294967293
    if read_word(s, 40) != get(w, 2) or read_word(s, 48) != get(w, 6) or read_word(s, 56) != get(w, 7):
        return refuse(o, w)
    if read_word(s, 16) != get(w, 4) or read_word(s, 24) != get(w, 3):
        return refuse(o, w)
    observed = read_word(s, 32)
    phase = get(w, 5)
    port = get(w, 3)
    if event == 1:
        if (phase != 1 and phase != 9) or observed != 0:
            return refuse(o, w)
        set(w, 5, 2)
        seal(w)
        return answer(o, w, 0)
    if event == 2:
        if phase != 2 or observed > observation_limit(port):
            return refuse(o, w)
        return succeeded(o, w, observed)
    if event == 3:
        if phase != 2 or observed != 0:
            return refuse(o, w)
        return raised(o, w)
    if event == 4:
        if port != 0 or observed != 0:
            return refuse(o, w)
        if phase == 6:
            return advance(o, w, 0, 4)
        if phase == 7:
            return advance(o, w, 0, 5)
        if phase == 10 and get(w, 2) >= 22:
            return advance(o, w, 0, 11)
        return refuse(o, w)
    if event == 5 or event == 6:
        if phase != 11 or port != 0 or observed != 0 or get(w, 2) < 22:
            return refuse(o, w)
        if event == 5:
            return advance(o, w, resume_port(get(w, 2)), 1)
        return advance(o, w, exception_port(get(w, 2)), 1)
    return refuse(o, w)

def initialize(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    mode = read_word(s, 40)
    if mode == 0 or mode > 26:
        return 4294967293
    if read_word(s, 16) != 0 or read_word(s, 24) != 0 or read_word(s, 32) != 0:
        return 4294967293
    if read_word(s, 48) == 0 and read_word(s, 56) == 0:
        return 4294967293
    index = 0
    while index < 192:
        if byte(w, index) != 0:
            return 4294967293
        index = index + 1
    set(w, 0, @STATE_MAGIC@)
    set(w, 1, 1)
    set(w, 2, mode)
    set(w, 3, entry_port(mode))
    set(w, 4, 1)
    set(w, 5, 1)
    set(w, 6, read_word(s, 48))
    set(w, 7, read_word(s, 56))
    seal(w)
    return answer(o, w, 0)

def valid_state(w:mutbuf) -> u64:
    if get(w, 0) != @STATE_MAGIC@ or get(w, 1) != 1:
        return 0
    mode = get(w, 2)
    if mode == 0 or mode > 26:
        return 0
    phase = get(w, 5)
    port = get(w, 3)
    if get(w, 4) == 0 or phase == 0 or phase == 3 or phase > 11:
        return 0
    if get(w, 8) != 0 or get(w, 9) != 0 or get(w, 11) != 0 or get(w, 12) > 1:
        return 0
    index = 13
    while index < 24:
        if get(w, index) != 0:
            return 0
        index = index + 1
    if checksum(w) != get(w, 10):
        return 0
    if phase == 1 or phase == 2 or phase == 9:
        if owned_port(mode, port) == 0 or get(w, 12) != error_port(port):
            return 0
        if phase == 9 and get(w, 12) != 0:
            return 0
    elif port != 0:
        return 0
    if phase == 10 or phase == 11:
        if mode < 22 or get(w, 12) != 0:
            return 0
    if phase == 4 or phase == 6:
        if get(w, 12) != 0:
            return 0
    if phase == 5 or phase == 7:
        if get(w, 12) != 1:
            return 0
    return 1

def advance(o:mutbuf, w:mutbuf, port:u64, phase:u64) -> u32:
    if get(w, 4) == 18446744073709551615:
        return refuse(o, w)
    set(w, 3, port)
    set(w, 4, get(w, 4) + 1)
    set(w, 5, phase)
    if phase == 5 or phase == 7:
        set(w, 12, 1)
    elif phase == 4 or phase == 6 or phase == 10 or phase == 11:
        set(w, 12, 0)
    else:
        set(w, 12, error_port(port))
    seal(w)
    return answer(o, w, 0)

def refuse(o:mutbuf, w:mutbuf) -> u32:
    set(w, 3, 0)
    set(w, 5, 8)
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
    set(o, 7, 0)
    set(o, 8, get(w, 6))
    set(o, 9, get(w, 7))
    set(o, 10, 0)
    set(o, 11, 0)
    return 96

def checksum(w:mutbuf) -> u64:
    value = 1469598103934665603
    index = 0
    while index < 24:
        if index != 10:
            value = ((value << 7) | (value >> 57)) ^ get(w, index)
        index = index + 1
    return value

def seal(w:mutbuf) -> u64:
    value = checksum(w)
    set(w, 10, value)
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

def _edge(target, *, leave=False):
    if target == '@return':
        return 'return advance(o, w, 0, 6)'
    if target == '@propagate':
        return 'return advance(o, w, 0, 7)'
    if target == '@yield':
        return 'return advance(o, w, 0, 10)'
    return 'return advance(o, w, %d, %d)' % (PORT[target], 9 if leave else 1)

def _lookup(name, items, *, default=0, chunk=12, argument='port'):
    # Bounded partitions keep each function below the existing profile. This
    # emits authoring source only; it is never a selected Python dispatch path.
    groups = [items[index:index + chunk] for index in range(0, len(items), chunk)]
    result = ['def %s(%s:u64) -> u64:' % (name, argument)]
    for index, group in enumerate(groups):
        result += ['    if %s <= %d:' % (argument, group[-1][0]),
                   '        return %s_%d(%s)' % (name, index, argument)]
    result.append('    return %d' % default)
    pieces = ['\n'.join(result) + '\n']
    for index, group in enumerate(groups):
        lines = ['def %s_%d(%s:u64) -> u64:' % (name, index, argument)]
        for key, value in group:
            lines += ['    if %s == %d:' % (argument, key), '        return %d' % value]
        lines.append('    return %d' % default)
        pieces.append('\n'.join(lines) + '\n')
    return pieces


def _bitset(name, ports):
    # Fixed protocol membership is authored as HIA bit operations. No Python
    # membership decision remains in an installed entry, and out-of-domain
    # words keep the former lookup's zero result.
    words = {}
    for port in ports:
        word = port >> 6
        words[word] = words.get(word, 0) | (1 << (port & 63))
    lines = ['def %s(port:u64) -> u64:' % name,
             '    if port > %d:' % len(PORT), '        return 0',
             '    word = port >> 6', '    mask = 0']
    for word, mask in sorted(words.items()):
        lines += ['    if word == %d:' % word, '        mask = %d' % mask]
    lines += ['    return (mask >> (port & 63)) & 1']
    return '\n'.join(lines) + '\n'


def _mode_bounds():
    # Two 18-bit (first,last) pairs per u64. Port ids fit exactly in nine bits;
    # the installed program still validates the complete actual mode range.
    if tuple(MODE_RANGES) != tuple(range(1, len(MODE_RANGES) + 1)):
        raise ValueError('verification mode order differs')
    packed = []
    values = list(MODE_RANGES.values())
    for index in range(0, len(values), 2):
        word = 0
        for position, bounds in enumerate(values[index:index + 2]):
            first, last = bounds
            if not 0 < first <= last <= 511:
                raise ValueError('verification port range exceeds packed ABI')
            word |= (first | (last << 9)) << (position * 18)
        packed.append(word)
    lines = ['def mode_bounds(mode:u64) -> u64:',
             '    if mode == 0 or mode > %d:' % len(values),
             '        return 0', '    index = (mode - 1) >> 1', '    word = 0']
    for index, word in enumerate(packed):
        lines += ['    if index == %d:' % index, '        word = %d' % word]
    lines += ['    return (word >> (((mode - 1) & 1) * 18)) & 262143']
    return '\n'.join(lines) + '\n'

def source_program():
    if len(ROWS) != len(PORT) or tuple(row['name'] for row in ROWS) != tuple(PORT):
        raise ValueError('verification authoring/protocol identity differs')
    pieces = [COMMON]
    pieces.append(_mode_bounds())
    pieces.append('def entry_port(mode:u64) -> u64:\n    return mode_bounds(mode) & 511\n')
    pieces.append('def exception_port(mode:u64) -> u64:\n    return (mode_bounds(mode) >> 9) & 511\n')
    pieces.extend(_lookup('resume_port', list(GENERATOR_RESUME_PORTS.items()), argument='mode'))
    pieces.append('def owned_port(mode:u64, port:u64) -> u64:\n'
                  '    bounds = mode_bounds(mode)\n'
                  '    if bounds != 0 and port >= (bounds & 511) and port <= (bounds >> 9):\n'
                  '        return 1\n    return 0\n')
    pieces.append(_bitset('boolean_port', [row['id'] for row in ROWS if row['kind'] == 'boolean']))
    choices = [row for row in ROWS if row['kind'] == 'choice']
    limits = ['def observation_limit(port:u64) -> u64:']
    for row in choices:
        limits += ['    if port == %d:' % row['id'],
                   '        return %d' % max(map(int, row['cases']))]
    limits.append('    return boolean_port(port)')
    pieces.append('\n'.join(limits) + '\n')
    pieces.append(_bitset('error_port', [row['id'] for row in ROWS if row.get('handler')]))
    for kind in ('succeeded', 'raised'):
        # Ordinary consecutive edges and a mode's final propagation port have a
        # single HIA default. The authoring rows still state every complete edge.
        if kind == 'succeeded':
            selected = [row for row in ROWS if row['kind'] != 'effect'
                or row.get('leave_handler') or PORT.get(row.get('next')) != row['id'] + 1]
        else:
            selected = [row for row in ROWS
                if PORT.get(row['raised']) != MODE_RANGES[row['mode']][1]]
        groups = [selected[index:index + 12] for index in range(0, len(selected), 12)]
        arguments = ', observed:u64' if kind == 'succeeded' else ''
        passed = ', observed' if kind == 'succeeded' else ''
        default = ('return advance(o, w, port + 1, 1)' if kind == 'succeeded' else
                   'return advance(o, w, exception_port(get(w, 2)), 1)')
        lines = ['def %s(o:mutbuf, w:mutbuf%s) -> u32:' % (kind, arguments),
                 '    port = get(w, 3)', '    if owned_port(get(w, 2), port) == 0:',
                 '        return refuse(o, w)']
        for index, group in enumerate(groups):
            lines += ['    if port <= %d:' % group[-1]['id'],
                      '        return %s_%d(o, w%s)' % (kind, index, passed)]
        lines.append('    ' + default)
        pieces.append('\n'.join(lines) + '\n')
        for index, group in enumerate(groups):
            lines = ['def %s_%d(o:mutbuf, w:mutbuf%s) -> u32:' % (kind, index, arguments),
                     '    port = get(w, 3)']
            for row in group:
                lines.append('    if port == %d:' % row['id'])
                if kind == 'raised':
                    lines.append('        ' + _edge(row['raised']))
                elif row['kind'] == 'boolean':
                    lines += ['        if observed == 1:',
                              '            ' + _edge(row['yes'], leave=row.get('leave_handler', False)),
                              '        ' + _edge(row['no'], leave=row.get('leave_handler', False))]
                elif row['kind'] == 'choice':
                    for value, target in row['cases'].items():
                        lines += ['        if observed == %s:' % value, '            ' + _edge(target)]
                    lines.append('        return refuse(o, w)')
                else:
                    lines.append('        ' + _edge(row['next'], leave=row.get('leave_handler', False)))
            lines.append('    ' + default)
            pieces.append('\n'.join(lines) + '\n')
    source = '\n'.join(pieces)
    for name, value in {'REQUEST_MAGIC': REQUEST_MAGIC, 'RESULT_MAGIC': RESULT_MAGIC,
                        'STATE_MAGIC': STATE_MAGIC}.items():
        source = source.replace('@' + name + '@', str(value))
    return source

def document():
    nodes = ast.parse(source_program()).body
    names = {node.name: 'f' + str(index) for index, node in enumerate(nodes)}
    signatures = {node.name: ([arg.annotation.id for arg in node.args.args],
                             node.returns.id) for node in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = ContextBuilder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({'name': names[node.name],
            'params': [builder.param(value) for value in builder.params],
            'returns': [builder.returns], 'effects': ['read', 'write', 'trap'],
            'entry': 'b0', 'blocks': builder.blocks})
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8',
        'module': 'service_verification', 'functions': functions})

if __name__ == '__main__':
    path = ROOT / SOURCE_NAME
    path.write_text(render_assembly(document()))
    print(path.name, path.stat().st_size)

"""Author the complete bootstrap/lifecycle/profile control graph in HIA.

This file is a source author, not an equivalence result. Generate only inside a
root-owned qualification attempt; no checked-in output is claimed by the draft.
"""
from __future__ import annotations
import ast
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parents[1]
if __package__ in (None, ''):
    sys.path.insert(0, str(ROOT))
from hepta.hia_agent_assembly import render_assembly
from hepta.hia_service_bootstrap_protocol import (
    PORT, PORTS, GRAPH, MODE_RANGES, MODE_START, SOURCE_NAME,
    REQUEST_MAGIC, RESULT_MAGIC, STATE_MAGIC)
from tools.generate_hia_selfhost import compact_authoring_cfg, total_scalar_functions
from tools.generate_hia_service_context import ContextBuilder

def _destination(value, indent='        '):
    if type(value) is str:
        if value == 'RETURN':
            return indent + 'return advance(o, w, 0, 6)\n'
        if value == 'PROPAGATE':
            return indent + 'return advance(o, w, 0, 7)\n'
        if value == 'YIELD':
            return indent + 'return advance(o, w, 0, 9)\n'
        return indent + 'return advance(o, w, ' + str(PORT[value]) + ', 1)\n'
    if 'leave' in value:
        return indent + 'return advance(o, w, ' + str(PORT[value['leave']]) + ', 11)\n'
    if 'mode' in value:
        out = ''
        for key, target in value['mode'].items():
            out += indent + 'if get(w, 2) == ' + str(key) + ':\n'
            out += _destination(target, indent + '    ')
        return out + indent + 'return refuse(o, w)\n'
    return (indent + 'if observed == 0:\n' +
            _destination(value['0'], indent + '    ') +
            _destination(value['1'], indent))

def source_program():
    out = """def service_bootstrap(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) != 128 or length(o) != 96 or length(w) != 192:
        return 4294967293
    if read_word(s, 0) != REQUEST_MAGIC_VALUE:
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
        if phase != 1 or observed != 0:
            return refuse(o, w)
        set(w, 5, 2)
        seal(w)
        return answer(o, w, 0)
    if event == 2:
        if phase != 2:
            return refuse(o, w)
        if boolean_port(port) == 1:
            if observed > 1:
                return refuse(o, w)
        elif observed != 0:
            return refuse(o, w)
        return succeeded(o, w, observed)
    if event == 3:
        if phase != 2 or observed != 0:
            return refuse(o, w)
        set(w, 12, 1)
        return raised(o, w)
    if event == 4:
        if port != 0 or observed != 0:
            return refuse(o, w)
        if phase == 6:
            return advance(o, w, 0, 4)
        if phase == 7:
            return advance(o, w, 0, 5)
        if phase == 9 and get(w, 2) >= 6:
            return advance(o, w, 0, 10)
        return refuse(o, w)
    if event == 5:
        if phase != 10 or get(w, 2) < 6 or observed != 0 or get(w, 12) != 0:
            return refuse(o, w)
        return advance(o, w, GENERATOR_NEXT_VALUE, 1)
    if event == 6:
        if phase != 10 or get(w, 2) < 6 or observed != 0:
            return refuse(o, w)
        set(w, 12, 1)
        return advance(o, w, GENERATOR_UNWIND_VALUE, 1)
    if event == 7:
        if phase != 11 or observed != 0 or get(w, 12) != 1:
            return refuse(o, w)
        return advance(o, w, port, 1)
    return refuse(o, w)

def initialize(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    mode = read_word(s, 40)
    if mode < 1 or mode > 7:
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
    set(w, 0, STATE_MAGIC_VALUE)
    set(w, 1, 1)
    set(w, 2, mode)
    set(w, 3, initial_port(mode))
    set(w, 4, 1)
    set(w, 5, 1)
    set(w, 6, read_word(s, 48))
    set(w, 7, read_word(s, 56))
    seal(w)
    return answer(o, w, 0)

def initial_port(mode:u64) -> u64:
"""
    for mode, name in MODE_START.items():
        out += '    if mode == ' + str(mode) + ':\n        return ' + str(PORT[name]) + '\n'
    out += '    return 0\n\ndef owned_port(mode:u64, port:u64) -> u64:\n'
    for mode, limits in MODE_RANGES.items():
        out += ('    if mode == ' + str(mode) + ':\n        if port >= ' + str(limits[0]) +
                ' and port <= ' + str(limits[1]) + ':\n            return 1\n')
    out += """    return 0

def valid_state(w:mutbuf) -> u64:
    if get(w, 0) != STATE_MAGIC_VALUE or get(w, 1) != 1:
        return 0
    mode = get(w, 2)
    if mode < 1 or mode > 7:
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
    if phase == 1 or phase == 2 or phase == 11:
        if owned_port(mode, port) == 0:
            return 0
        if mode == 6 and port == GENERATOR_DIR_VALUE:
            return 0
        if mode == 7 and port == GENERATOR_ROOT_VALUE:
            return 0
    elif port != 0:
        return 0
    if phase == 4 or phase == 6 or phase == 9 or phase == 10:
        if get(w, 12) != 0:
            return 0
    if phase == 5 or phase == 7 or phase == 11:
        if get(w, 12) != 1:
            return 0
    if phase == 9 or phase == 10:
        if mode < 6:
            return 0
    return 1

def boolean_port(port:u64) -> u64:
"""
    for name in PORTS:
        value = GRAPH[name]['next']
        if type(value) is dict and '0' in value:
            out += '    if port == ' + str(PORT[name]) + ':\n        return 1\n'
    out += '    return 0\n\n'
    groups = [PORTS[start:start + 12] for start in range(0, len(PORTS), 12)]
    for name, field, observed in (('succeeded', 'next', True), ('raised', 'raised', False)):
        arguments = ', observed:u64' if observed else ''
        out += 'def ' + name + '(o:mutbuf, w:mutbuf' + arguments + ') -> u32:\n    port = get(w, 3)\n'
        for index, group in enumerate(groups):
            out += ('    if port <= ' + str(PORT[group[-1]]) + ':\n        return ' + name + '_' + str(index) +
                    '(o, w' + (', observed' if observed else '') + ')\n')
        out += '    return refuse(o, w)\n\n'
        for index, group in enumerate(groups):
            out += 'def ' + name + '_' + str(index) + '(o:mutbuf, w:mutbuf' + arguments + ') -> u32:\n    port = get(w, 3)\n'
            for port in group:
                out += '    if port == ' + str(PORT[port]) + ':\n'
                out += _destination(GRAPH[port][field])
            out += '    return refuse(o, w)\n\n'
    out += """def advance(o:mutbuf, w:mutbuf, port:u64, phase:u64) -> u32:
    if get(w, 4) == 18446744073709551615:
        return refuse(o, w)
    set(w, 3, port)
    set(w, 4, get(w, 4) + 1)
    set(w, 5, phase)
    seal(w)
    return answer(o, w, 0)

def refuse(o:mutbuf, w:mutbuf) -> u32:
    set(w, 3, 0)
    set(w, 5, 8)
    seal(w)
    return answer(o, w, 1)

def answer(o:mutbuf, w:mutbuf, status:u64) -> u32:
    set(o, 0, RESULT_MAGIC_VALUE)
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
    shift = 0
    while shift < 8:
        value = value | (byte(s, index + shift) << (shift * 8))
        shift = shift + 1
    return value

def get(w:mutbuf, index:u64) -> u64:
    value = 0
    shift = 0
    while shift < 8:
        value = value | (byte(w, index * 8 + shift) << (shift * 8))
        shift = shift + 1
    return value

def set(w:mutbuf, index:u64, value:u64) -> u64:
    shift = 0
    while shift < 8:
        store(w, index * 8 + shift, value >> (shift * 8))
        shift = shift + 1
    return value
"""
    for key, value in {
        'REQUEST_MAGIC_VALUE': REQUEST_MAGIC, 'RESULT_MAGIC_VALUE': RESULT_MAGIC,
        'STATE_MAGIC_VALUE': STATE_MAGIC, 'GENERATOR_NEXT_VALUE': PORT['generator_next'],
        'GENERATOR_UNWIND_VALUE': PORT['generator_error_unwind'],
        'GENERATOR_DIR_VALUE': PORT['generator_dir_value'],
        'GENERATOR_ROOT_VALUE': PORT['generator_root_value'],
    }.items():
        out = out.replace(key, str(value))
    return out

def document():
    nodes = ast.parse(source_program()).body
    names = {node.name: 'f' + str(index) for index, node in enumerate(nodes)}
    signatures = {node.name: ([arg.annotation.id for arg in node.args.args], node.returns.id) for node in nodes}
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
        'module': 'service_bootstrap', 'functions': functions})

if __name__ == '__main__':
    path = ROOT / SOURCE_NAME
    path.write_text(render_assembly(document()))
    print(path.name, path.stat().st_size)

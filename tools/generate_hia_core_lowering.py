"""Render complete Core Function control as bounded, separate HIA units.

Only this authoring tool imports the finite source compiler. Runtime uses the
resulting HIA images and ABI metadata; it never executes the authoring policy.
"""
from __future__ import annotations

import ast
import json
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions
from tools.hia_core_lowering_ir import Ref, Raw, compile_policy

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / 'tools/hia_core_lowering_policy.py'
ABI = 0xfffffffd
MAGIC = int.from_bytes(b'HIALOW02', 'little')
POOL_MAGIC = int.from_bytes(b'HIALIT01', 'little')
CHUNK = 64
GROUP = 8
SLOTS = 1024
INTERNAL = 4
REQUEST = 1
HANDOFF = 2
FINISHED = 0


def helpers():
    result = []
    for name, typ in (('word', 'readbuf'), ('get', 'mutbuf')):
        lines = ['def ' + name + '(b:' + typ + ', at:u64) -> u64:']
        lines.append('    value = 0')
        for i in range(8):
            lines.append('    value = value | (byte(b, at + ' + str(i) + ') << ' + str(8 * i) + ')')
        lines.append('    return value')
        result.append('\n'.join(lines))
    lines = ['def put(b:mutbuf, at:u64, value:u64) -> u64:']
    for i in range(8):
        lines.append('    store(b, at + ' + str(i) + ', (value >> ' + str(8 * i) + ') & 255)')
    lines.append('    return 0')
    result.append('\n'.join(lines))
    return '\n\n'.join(result) + '\n'


def value_text(value):
    if isinstance(value, Raw):
        return str(value.value)
    if not isinstance(value, Ref):
        raise TypeError('unknown finite operand')
    if value.kind == 'constant':
        return str(value.index + 1)
    if value.kind == 'slot':
        return 'get(w, ' + str(SLOTS + value.index * 8) + ')'
    raise ValueError('unknown reference class')


def put_slot(destination, value):
    if destination.kind != 'slot':
        raise ValueError('invalid lowering destination')
    return 'put(w, ' + str(SLOTS + destination.index * 8) + ', ' + value + ')'


def effect_lines(instruction):
    arguments = instruction['arguments']
    vector = instruction.get('vector', ())
    destinations = instruction['destinations']
    lines = [
        'if get(w, 16) == 18446744073709551615:',
        '    return ' + str(ABI),
        'put(w, 16, get(w, 16) + 1)',
        'put(w, 8, 1)',
        'put(w, 24, ' + str(instruction['pc'] + 1) + ')',
        'put(w, 48, ' + str(instruction['opcode']) + ')',
        'put(w, 56, ' + str(len(destinations)) + ')',
    ]
    for i in range(4):
        offset = SLOTS + destinations[i].index * 8 if i < len(destinations) else 0
        lines.append('put(w, ' + str(64 + i * 8) + ', ' + str(offset) + ')')
    header = (MAGIC, None, instruction['opcode'], len(arguments), len(vector),
              len(destinations), instruction['pc'], 0)
    for i, number in enumerate(header):
        text = 'get(w, 16)' if number is None else str(number)
        lines.append('put(o, ' + str(i * 8) + ', ' + text + ')')
    for i in range(8):
        text = value_text(arguments[i]) if i < len(arguments) else '0'
        lines.append('put(o, ' + str(64 + i * 8) + ', ' + text + ')')
    for i, value in enumerate(vector):
        lines.append('put(o, ' + str(128 + i * 8) + ', ' + value_text(value) + ')')
    lines.append('return 1')
    return lines


def instruction_lines(instruction):
    kind, pc = instruction['kind'], instruction['pc']
    if kind == 'effect':
        return effect_lines(instruction)
    if kind == 'yield':
        return [
            'if get(w, 16) == 18446744073709551615:',
            '    return ' + str(ABI),
            'put(w, 16, get(w, 16) + 1)',
            'put(o, 0, ' + str(MAGIC) + ')',
            'put(o, 8, get(w, 16))',
            'put(o, 16, 20)',
            'put(o, 24, ' + value_text(instruction['value']) + ')',
            'put(w, 24, ' + str(pc + 1) + ')',
            'put(w, 96, ' + str((pc - 1) // CHUNK) + ')',
            'put(w, 8, 4)',
            'return 3',
        ]
    if kind == 'return':
        return [
            'put(o, 0, ' + str(MAGIC) + ')',
            'put(o, 8, get(w, 16))',
            'put(o, 16, 0)',
            'put(o, 24, ' + value_text(instruction['value']) + ')',
            'put(w, 8, 3)',
            'return 0',
        ]
    if kind == 'move':
        lines = [put_slot(instruction['destination'], value_text(instruction['value']))]
        target = pc + 1
    elif kind == 'jump':
        lines, target = [], instruction['target']
    elif kind == 'flag':
        return ['if get(w, 40) != 0:',
                '    put(w, 24, ' + str(instruction['yes']) + ')',
                'else:',
                '    put(w, 24, ' + str(instruction['no']) + ')',
                'return 4']
    elif kind == 'identity':
        operator = '!=' if instruction['negate'] else '=='
        return ['if ' + value_text(instruction['left']) + ' ' + operator + ' ' + value_text(instruction['right']) + ':',
                '    ' + put_slot(instruction['destination'], value_text(instruction['true'])),
                'else:',
                '    ' + put_slot(instruction['destination'], value_text(instruction['false'])),
                'put(w, 24, ' + str(pc + 1) + ')',
                'return 4']
    else:
        raise ValueError('unrendered lowering instruction: ' + kind)
    return lines + ['put(w, 24, ' + str(target) + ')', 'return 4']


def start_source(entries):
    groups = [list(entries.items())[i:i + 4] for i in range(0, len(entries), 4)]
    functions = []
    dispatch = ['def start(s:readbuf, w:mutbuf) -> u64:']
    for group_index, group in enumerate(groups):
        dispatch += ['    if word(s, 24) <= ' + str(group[-1][1]['mode']) + ':',
                     '        return start_' + str(group_index) + '(s, w)']
        lines = ['def start_' + str(group_index) + '(s:readbuf, w:mutbuf) -> u64:']
        for name, entry in group:
            count = len(entry['parameters'])
            lines += ['    if word(s, 24) == ' + str(entry['mode']) + ':',
                      '        if word(s, 32) != ' + str(count) + ':',
                      '            return ' + str(ABI)]
            for i in range(6):
                operator = '==' if i < count else '!='
                lines += ['        if word(s, ' + str(40 + i * 8) + ') ' + operator + ' 0:',
                          '            return ' + str(ABI)]
            for i in range(count):
                lines.append('        put(w, ' + str(SLOTS + i * 8) + ', word(s, ' + str(40 + i * 8) + '))')
            lines += [
                '        put(w, 0, ' + str(MAGIC) + ')',
                '        put(w, 8, 0)',
                '        put(w, 16, 0)',
                '        put(w, 24, ' + str(entry['pc']) + ')',
                '        put(w, 32, ' + str(entry['mode']) + ')',
                '        put(w, 40, 0)',
                '        put(w, 48, 0)',
                '        put(w, 56, 0)',
                '        put(w, 64, 0)',
                '        put(w, 72, 0)',
                '        put(w, 80, 0)',
                '        put(w, 88, 0)',
                '        put(w, 96, 0)',
                '        return 0',
            ]
        lines.append('    return ' + str(ABI))
        functions.append('\n'.join(lines))
    dispatch.append('    return ' + str(ABI))
    return '\n\n'.join(['\n'.join(dispatch), *functions]) + '\n'


def main_source(unit, first, last, total, workspace, output):
    # The sequence is advanced for each effect and each cross-unit handoff.
    # The private continuation is the sole authority for resume destinations.
    return f'''
def lower(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) != 128 or length(w) < {workspace} or length(o) < {output}:
        return {ABI}
    if word(s, 0) != {MAGIC}:
        return {ABI}
    i = 88
    while i < 128:
        if word(s, i) != 0:
            return {ABI}
        i = i + 8
    command = word(s, 8)
    if command == 0:
        if {unit} != 0 or get(w, 0) != 0 or get(w, 8) != 0 or word(s, 16) != 0:
            return {ABI}
        if start(s, w) != 0:
            return {ABI}
    else:
        if get(w, 0) != {MAGIC} or word(s, 16) != get(w, 16):
            return {ABI}
        if command == 1:
            if get(w, 8) != 1 or word(s, 24) != get(w, 56):
                return {ABI}
            if word(s, 32) > 1 or word(s, 72) != 0 or word(s, 80) != 0:
                return {ABI}
            opcode = get(w, 48)
            if opcode != 9 and opcode != 10 and word(s, 32) != 0:
                return {ABI}
            count = get(w, 56)
            if count > 4:
                return {ABI}
            i = 0
            while i < 4:
                if i < count:
                    if word(s, 40 + i * 8) == 0:
                        return {ABI}
                else:
                    if word(s, 40 + i * 8) != 0:
                        return {ABI}
                i = i + 1
            if opcode == 9 and word(s, 32) == 0 and word(s, 40) != 1:
                return {ABI}
            i = 0
            while i < count:
                put(w, get(w, 64 + i * 8), word(s, 40 + i * 8))
                i = i + 1
            put(w, 40, word(s, 32))
            put(w, 8, 0)
        else:
            if command == 2:
                if get(w, 8) != 2:
                    return {ABI}
            else:
                if command != 3 or get(w, 8) != 4:
                    return {ABI}
            if get(w, 96) != {unit} or word(s, 24) != {unit}:
                return {ABI}
            if word(s, 32) != 0 or word(s, 40) != 0 or word(s, 48) != 0 or word(s, 56) != 0 or word(s, 64) != 0 or word(s, 72) != 0 or word(s, 80) != 0:
                return {ABI}
            put(w, 8, 0)
    while True:
        pc = get(w, 24)
        if pc == 0 or pc > {total}:
            return {ABI}
        if pc < {first} or pc > {last}:
            if get(w, 16) == 18446744073709551615:
                return {ABI}
            target = (pc - 1) >> 6
            put(w, 16, get(w, 16) + 1)
            put(w, 8, 2)
            put(w, 96, target)
            put(o, 0, {MAGIC})
            put(o, 8, get(w, 16))
            put(o, 16, 21)
            put(o, 24, target)
            return 2
        result = dispatch(w, o)
        if result != 4:
            return result
    return {ABI}
'''


def unit_source(unit, selected, entries, total, workspace, output):
    first, last = selected[0]['pc'], selected[-1]['pc']
    chunks = [selected[i:i + GROUP] for i in range(0, len(selected), GROUP)]
    main = main_source(unit, first, last, total, workspace, output)
    leaves = []
    for number, group in enumerate(chunks):
        lines = ['def group_' + str(number) + '(w:mutbuf, o:mutbuf) -> u64:',
                 '    pc = get(w, 24)']
        for instruction in group:
            lines.append('    if pc == ' + str(instruction['pc']) + ':')
            lines += ['        ' + line for line in instruction_lines(instruction)]
        lines.append('    return ' + str(ABI))
        leaves.append('\n'.join(lines))
    lines = ['def dispatch(w:mutbuf, o:mutbuf) -> u64:',
             '    pc = get(w, 24)']
    for number, group in enumerate(chunks):
        lines += ['    if pc <= ' + str(group[-1]['pc']) + ':',
                  '        return group_' + str(number) + '(w, o)']
    lines.append('    return ' + str(ABI))
    # Initial mode admission exists in unit zero only; other units cannot start.
    startup = start_source(entries) if unit == 0 else (
        'def start(s:readbuf, w:mutbuf) -> u64:\n    return ' + str(ABI) + '\n')
    return main + '\n' + startup + '\n' + '\n\n'.join(leaves + ['\n'.join(lines)]) + '\n' + helpers()


def pool_wire(values):
    data = bytearray(POOL_MAGIC.to_bytes(8, 'little') + len(values).to_bytes(8, 'little'))
    for value in values:
        if value is None:
            kind, word, tail = 0, 0, b''
        elif type(value) is bool:
            kind, word, tail = 1, int(value), b''
        elif type(value) is int:
            kind, word, tail = 2, value, b''
        elif type(value) is str:
            raw = value.encode('utf-8')
            kind, word, tail = 3, len(raw), raw + b'\0' * (-len(raw) % 8)
        else:
            raise ValueError('literal escaped the finite typed pool')
        data += kind.to_bytes(8, 'little') + word.to_bytes(8, 'little') + tail
    return bytes(data)


def pool_source(raw):
    # Literal bytes are authored as HIA writes, not a hosted policy lookup table.
    chunks = [raw[i:i + 192] for i in range(0, len(raw), 192)]
    lines = [
        'def literals(s:readbuf, o:mutbuf, w:mutbuf) -> u32:',
        '    if length(s) != 0 or length(w) != 0 or length(o) < ' + str(len(raw)) + ':',
        '        return ' + str(ABI),
    ]
    for index in range(len(chunks)):
        lines.append('    write_' + str(index) + '(o)')
    lines.append('    return ' + str(len(raw)))
    functions = ['\n'.join(lines)]
    for index, chunk in enumerate(chunks):
        lines = ['def write_' + str(index) + '(o:mutbuf) -> u64:']
        for i in range(0, len(chunk), 8):
            word = int.from_bytes(chunk[i:i + 8], 'little')
            lines.append('    put(o, ' + str(index * 192 + i) + ', ' + str(word) + ')')
        lines.append('    return 0')
        functions.append('\n'.join(lines))
    # Only put is used by the literal owner.
    functions.append(helpers().split('def put(', 1)[1])
    functions[-1] = 'def put(' + functions[-1]
    return '\n\n'.join(functions) + '\n'


def document(source, module):
    nodes = ast.parse(source).body
    names = {node.name: 'f' + str(i) for i, node in enumerate(nodes)}
    signatures = {node.name: ([a.annotation.id for a in node.args.args], node.returns.id) for node in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = Builder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({'name': names[node.name],
                          'params': [builder.param(value) for value in builder.params],
                          'returns': [builder.returns],
                          'effects': ['read', 'write', 'trap'],
                          'entry': 'b0', 'blocks': builder.blocks})
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8', 'module': module, 'functions': functions})


def generated():
    literals, functions, entries, instructions = compile_policy(POLICY.read_text())
    if CHUNK != 64:
        raise ValueError('the native unit route is fixed to 64 control instructions')
    if not instructions:
        raise ValueError('empty native lowering policy')
    maximum_slots = max(function.slot_count for function in functions)
    workspace = (SLOTS + maximum_slots * 8 + 63) & -64
    maximum_vector = max((len(item.get('vector', ())) for item in instructions), default=0)
    output = (128 + maximum_vector * 8 + 63) & -64
    wire = pool_wire(literals.values)
    sources = [('core_lowering_pool', pool_source(wire))]
    units = []
    for unit, at in enumerate(range(0, len(instructions), CHUNK)):
        name = 'core_lowering_' + f'{unit:03d}'
        units.append(name)
        sources.append((name, unit_source(unit, instructions[at:at + CHUNK], entries,
                                         len(instructions), workspace, output)))
    abi = {
        'schema': 'hepta.hia.core-lowering-abi.v2',
        'protocol_magic': MAGIC,
        'pool_magic': POOL_MAGIC,
        'packet_bytes': 128,
        'workspace_bytes': workspace,
        'output_bytes': output,
        'pool_bytes': len(wire),
        'literal_count': len(literals.values),
        'units': units,
        'generator_modes': [name for name, entry in entries.items() if entry['generator']],
        'modes': {name: {'number': entry['mode'], 'arity': len(entry['parameters'])}
                  for name, entry in entries.items()},
    }
    return sources, abi


def write(output, metadata):
    sources, abi = generated()
    output.mkdir(parents=True, exist_ok=True)
    for name, source in sources:
        assembly = render_assembly(document(source, name))
        (output / (name + '.hiaasm')).write_text(assembly)
    metadata.write_text(json.dumps(abi, indent=2, sort_keys=True) + '\n')
    return [str(output / (name + '.hiaasm')) for name, _ in sources]


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / 'examples/hia_bootstrap')
    parser.add_argument('--metadata', type=Path, default=ROOT / 'hepta/hia_core_lowering_abi.json')
    arguments = parser.parse_args()
    for path in write(arguments.output, arguments.metadata):
        print(path)

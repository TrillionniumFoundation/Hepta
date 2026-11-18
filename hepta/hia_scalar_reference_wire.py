"""Serialize verified scalar Core for the independent HIA reference interpreter."""

from functools import lru_cache
import json
import struct

from .hia_opcodes import SCALARS, WIDTHS

PROGRAM_MAGIC = int.from_bytes(b'HIASPG01', 'little')
PROGRAM_RESULT = int.from_bytes(b'HIASPR01', 'little')
MAX_PACKET_BYTES = 8 << 20
MAX_FRAME_WORDS = 4096
MASK = (1 << 64) - 1
TYPES = ('bool', 'unit', *WIDTHS)
TRAPS = ('user', 'overflow', 'division_by_zero', 'bounds', 'allocation')
COMMAND = struct.Struct('<8Q')
CONSTANT, CALL, RETURN, TRAP, JUMP, BRANCH = range(32, 38)


@lru_cache(maxsize=8)
def program_wire(canonical: bytes, entry: str):
    """No evaluation here: assign register slots and freeze exact CFG edges."""
    from .hia_scalar_reference_native import OPCODES

    functions = {fn['name']: fn for fn in json.loads(canonical)['functions']}
    reachable = {entry}
    order = [entry]
    for name in order:
        fn = functions[name]
        if not all(typ in SCALARS for typ in fn['returns']):
            return None
        for block in fn['blocks']:
            if not all(param['type'] in SCALARS for param in block['params']):
                return None
            for ins in block['ops']:
                op = ins['op']
                if not all(out['type'] in SCALARS for out in ins['out']):
                    return None
                if op == 'call':
                    callee = ins['attrs']['function']
                    if callee not in reachable:
                        reachable.add(callee)
                        order.append(callee)
                elif op not in ('const', 'int.cast') and op not in OPCODES:
                    return None

    # The first eight words are written for each invocation. The next
    # words locate the entry block of each reachable function.
    output = bytearray(64 + 8*len(order))
    locations = {}
    identifiers = {name: index for index, name in enumerate(order)}
    for name in order:
        fn = functions[name]
        for block in fn['blocks']:
            locations[name, block['id']] = len(output)
            output.extend(bytes(64*(len(block['ops']) + 1)))
            if len(output) > MAX_PACKET_BYTES:
                return None
        struct.pack_into('<Q', output, 64 + 8*identifiers[name], locations[name, fn['entry']])

    def append_words(items):
        at = len(output)
        output.extend(struct.pack(f'<{len(items)}Q', *items))
        return at

    max_regs = max_arguments = 1
    for name in order:
        fn = functions[name]
        for block in fn['blocks']:
            registers = {param['name']: (index, param['type'])
                         for index, param in enumerate(block['params'])}
            if block['id'] == fn['entry']:
                if fn['params'] != block['params']:
                    return None
            at = locations[name, block['id']]
            for ins in block['ops']:
                operands = [registers[arg] for arg in ins['args']]
                outputs = []
                for result in ins['out']:
                    outputs.append(len(registers))
                    registers[result['name']] = (len(registers), result['type'])
                op = ins['op']
                if op == 'const':
                    command = (CONSTANT, outputs[0], int(ins['attrs']['value'] or 0) & MASK)
                elif op == 'call':
                    arguments = [index for index, _ in operands]
                    max_arguments = max(max_arguments, len(arguments), len(outputs))
                    command = (CALL, identifiers[ins['attrs']['function']], append_words(arguments),
                               len(arguments), append_words(outputs), len(outputs))
                else:
                    typ = ins['out'][0]['type']
                    opcode = 'cast.' + ins['attrs']['mode'] if op == 'int.cast' else op
                    sign = int(typ.startswith('i'))
                    indexes = []
                    for index, (register, argument_type) in enumerate(operands):
                        indexes.append(register)
                        sign |= int(argument_type.startswith('i')) << (index+1)
                    indexes.extend([0] * (3-len(indexes)))
                    command = (OPCODES[opcode], outputs[0], *indexes, WIDTHS.get(typ, 1), sign, TYPES.index(typ))
                COMMAND.pack_into(output, at, *command, *([0]*(8-len(command))))
                at += 64
            max_regs = max(max_regs, len(registers))
            term = block['term']

            def encode_edge(edge):
                nonlocal max_arguments
                arguments = [registers[arg][0] for arg in edge['args']]
                max_arguments = max(max_arguments, len(arguments))
                return append_words((locations[name, edge['target']], append_words(arguments), len(arguments)))

            kind = term['op']
            if kind == 'ret':
                returns = [registers[arg][0] for arg in term['values']]
                max_arguments = max(max_arguments, len(returns))
                command = (RETURN, append_words(returns), len(returns))
            elif kind == 'trap':
                command = (TRAP, TRAPS.index(term['code']))
            elif kind == 'jump':
                command = (JUMP, encode_edge(term))
            else:
                command = (BRANCH, registers[term['cond']][0],
                           encode_edge(term['then']), encode_edge(term['else']))
            COMMAND.pack_into(output, at, *command, *([0]*(8-len(command))))
    if len(output) > MAX_PACKET_BYTES or max_regs + max_arguments > MAX_FRAME_WORDS:
        return None
    return bytes(output), max_regs, max_arguments, tuple(functions[entry]['returns'])

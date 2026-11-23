"""Serialize admitted Core instructions and capability sites for the HIA reference VM."""

from dataclasses import dataclass
from functools import lru_cache
import json
import os
import struct

from .hia_opcodes import RESOURCES, SCALARS, WIDTHS, opcode_spec

PROGRAM_MAGIC = int.from_bytes(b'HIASPG01', 'little')
RESOURCE_PROGRAM_MAGIC = int.from_bytes(b'HIARPG02', 'little')
PROGRAM_RESULT = int.from_bytes(b'HIASPR01', 'little')
# The verified input is bounded independently by Core's 8 MiB / 262,144
# nodes. The execution wire expands instructions and repeated lists.
MAX_PACKET_BYTES = 32 << 20
MAX_FRAME_WORDS = 524288
MASK = (1 << 64) - 1
TYPES = ('bool', 'unit', *WIDTHS)
TRAPS = ('user', 'overflow', 'division_by_zero', 'bounds', 'allocation')
COMMAND = struct.Struct('<8Q')
CONSTANT, CALL, RETURN, TRAP, JUMP, BRANCH = range(32, 38)
RESOURCE, RESOURCE_RETURN = 38, 39

RESOURCE_KINDS = (None, 'buffer', 'chain', 'readbuf', 'mutbuf')
RESOURCE_SIGNATURES = {
    'buffer.new': (None,), 'buffer.try_new': (None,),
    'buffer.len': ('buffer', 'readbuf', 'mutbuf'),
    'buffer.load': ('readbuf', 'mutbuf'),
    'buffer.store': ('mutbuf',), 'buffer.fill': ('mutbuf',), 'buffer.fill_range': ('mutbuf',),
    'buffer.copy': ('mutbuf',), 'buffer.copy_range': ('mutbuf',),
    'buffer.move_within': ('mutbuf',), 'buffer.swap': ('mutbuf',),
    'borrow.read': ('buffer', 'readbuf', 'mutbuf'), 'borrow.mut': ('buffer', 'mutbuf'),
    'loan.end': ('readbuf', 'mutbuf'), 'owner.move': ('buffer', 'chain'), 'owner.drop': ('buffer', 'chain'),
    'chain.empty': (None,), 'chain.is_empty': ('chain',), 'chain.try_push': ('chain',),
    'chain.pop': ('chain',), 'chain.head_read': ('chain',), 'chain.head_mut': ('chain',),
}
RESOURCE_NAMES = tuple(RESOURCE_SIGNATURES)
RESOURCE_CODES = {name: i for i, name in enumerate(RESOURCE_NAMES, 1)}
RESOURCE_SITE = struct.Struct('<4Q')
RETURN_LOANS_CODE = len(RESOURCE_CODES) + 1


@dataclass(frozen=True, slots=True)
class ResourceRequest:
    operation: str
    first_kind: str | None
    inputs: int
    outputs: int
    return_loans: tuple[tuple[int, int, bool], ...] = ()


def resource_request(wire, offset):
    extent = struct.unpack_from('<Q', wire, 40)[0]
    if not 72 <= offset <= extent - RESOURCE_SITE.size or offset % 8:
        raise ValueError('invalid Core resource command position')
    code, kind, inputs, outputs = RESOURCE_SITE.unpack_from(wire, offset)
    if code == RETURN_LOANS_CODE:
        start = offset + RESOURCE_SITE.size
        if kind or not 0 < outputs <= inputs or inputs == outputs or outputs > (extent - start) // 8:
            raise ValueError('invalid Core returned-loan command')
        bindings = []
        for index in range(outputs):
            tag = struct.unpack_from('<Q', wire, start + 8 * index)[0]
            if tag:
                origin = (tag >> 1) - 1
                if not outputs <= origin < inputs:
                    raise ValueError('invalid Core returned-loan origin')
                bindings.append((index, origin, bool(tag & 1)))
        if not bindings:
            raise ValueError('missing Core returned-loan origins')
        return ResourceRequest('return_loans', None, inputs, outputs, tuple(bindings))
    if not 1 <= code <= len(RESOURCE_CODES) or kind >= len(RESOURCE_KINDS):
        raise ValueError('invalid Core resource command')
    operation = RESOURCE_NAMES[code - 1]
    first = RESOURCE_KINDS[kind]
    signature = opcode_spec(operation)
    if first not in RESOURCE_SIGNATURES[operation] or (inputs, outputs) != (
            len(signature.operands), len(signature.results)):
        raise ValueError('invalid Core resource command arity or operand kind')
    return ResourceRequest(operation, first, inputs, outputs)


@lru_cache(maxsize=8)
def program_wire(canonical: bytes, entry: str, *, allow_resources=False):
    """No evaluation here: assign register slots and freeze exact CFG edges."""
    from .hia_scalar_reference_native import OPCODES

    functions = {fn['name']: fn for fn in json.loads(canonical)['functions']}
    reachable = {entry}
    order = [entry]
    types = SCALARS | RESOURCES if allow_resources else SCALARS
    for name in order:
        fn = functions[name]
        if any(typ not in types for typ in fn['returns']):
            return None
        for block in fn['blocks']:
            if not all(param['type'] in types for param in block['params']):
                return None
            for ins in block['ops']:
                op = ins['op']
                if not all(out['type'] in types for out in ins['out']):
                    return None
                if op == 'call':
                    callee = ins['attrs']['function']
                    if callee not in reachable:
                        reachable.add(callee)
                        order.append(callee)
                elif (op not in ('const', 'int.cast') and op not in OPCODES
                      and not allow_resources):
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
            loan_return = any(fn.get('return_loans', ())) and block['term']['op'] == 'ret'
            output.extend(bytes(64*(len(block['ops']) + 1 + loan_return)))
            if len(output) > MAX_PACKET_BYTES:
                return None
        struct.pack_into('<Q', output, 64 + 8*identifiers[name], locations[name, fn['entry']])

    def append_words(items):
        at = len(output)
        output.extend(struct.pack(f'<{len(items)}Q', *items))
        return at

    max_regs = max_arguments = 1
    resource_sites = False
    loan_layouts = {}
    for name in order:
        fn = functions[name]
        origins = fn.get('return_loans')
        if not origins or not any(origins):
            continue
        # Entry arguments stay pinned across subsequent blocks or recursive
        # calls. Ordinary register assignments never touch these upper slots.
        first = max(len(block['params']) + sum(len(op['out']) for op in block['ops'])
                    for block in fn['blocks'])
        params = {p['name']: (pos, p['type']) for pos, p in enumerate(fn['params'])}
        bindings = {}
        for origin in origins:
            if origin is not None and origin not in bindings:
                pos, kind = params[origin]
                bindings[origin] = (pos, first + len(bindings), kind)
        pairs = [word for index, saved, _ in bindings.values() for word in (index, saved)]
        output_slots = tuple(range(first + len(bindings), first + len(bindings) + len(origins)))
        loan_layouts[name] = bindings, output_slots, append_words(pairs), len(bindings)
        max_regs = max(max_regs, output_slots[-1] + 1)

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
                    callee = ins['attrs']['function']
                    pinned, pin_count = loan_layouts[callee][2:] if callee in loan_layouts else (0, 0)
                    command = (CALL, identifiers[callee], append_words(arguments),
                               len(arguments), append_words(outputs), len(outputs), pinned, pin_count)
                elif op == 'int.cast' or op in OPCODES:
                    typ = ins['out'][0]['type']
                    opcode = 'cast.' + ins['attrs']['mode'] if op == 'int.cast' else op
                    sign = int(typ.startswith('i'))
                    indexes = []
                    for index, (register, argument_type) in enumerate(operands):
                        indexes.append(register)
                        sign |= int(argument_type.startswith('i')) << (index+1)
                    indexes.extend([0] * (3-len(indexes)))
                    command = (OPCODES[opcode], outputs[0], *indexes, WIDTHS.get(typ, 1), sign, TYPES.index(typ))
                else:
                    arguments = [index for index, _ in operands]
                    max_arguments = max(max_arguments, len(arguments), len(outputs))
                    first = operands[0][1] if operands and operands[0][1] in RESOURCES else None
                    if op not in RESOURCE_CODES or first not in RESOURCE_SIGNATURES[op]:
                        return None  # Additional verified resource opcodes must acquire a wire grammar.
                    site = append_words((RESOURCE_CODES[op], RESOURCE_KINDS.index(first),
                                         len(arguments), len(outputs)))
                    command = (RESOURCE, site, append_words(arguments), len(arguments),
                               append_words(outputs), len(outputs))
                    resource_sites = True
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
                if name in loan_layouts:
                    bindings, output_slots, _, _ = loan_layouts[name]
                    inputs = returns + [saved for _, saved, _ in bindings.values()]
                    lookup = {origin: len(returns) + i for i, origin in enumerate(bindings)}
                    restorations = tuple(0 if origin is None else
                                         ((lookup[origin] + 1) << 1) | (typ == 'mutbuf')
                                         for typ, origin in zip(fn['returns'], fn['return_loans']))
                    site = append_words((RETURN_LOANS_CODE, 0, len(inputs), len(output_slots),
                                         *restorations))
                    resource_sites = True
                    COMMAND.pack_into(output, at, RESOURCE, site,
                                      append_words(inputs), len(inputs), append_words(output_slots),
                                      len(output_slots), 0, 0)
                    max_arguments = max(max_arguments, len(inputs))
                    at += 64
                    command = (RESOURCE_RETURN, append_words(output_slots), len(returns))
                else:
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
    return bytes(output), max_regs, max_arguments, tuple(functions[entry]['returns']), resource_sites



def selected_program_wire(canonical: bytes, entry: str, *, allow_resources=False):
    """Use the selected HIA scalar projector before the resource-capable encoder."""
    manifest = os.environ.get('HEPTA_HIA_EVALUATE_REFERENCE_WIRE_MANIFEST')
    if manifest is not None:
        from .hia_evaluate_reference_wire_native import NativeEvaluateReferenceWire, SCHEMA, SOURCE
        from .hia_json_preflight_native import _installed_json_image
        try:
            selected = _installed_json_image(manifest, SOURCE, SCHEMA, NativeEvaluateReferenceWire)
            projected = selected.project(canonical, entry)
        except (ValueError, OSError) as error:
            # Runner input refusal is recoverable. A selected helper that lost its
            # identity or returned a malformed packet must stop that request.
            raise RuntimeError('invalid selected HIA Evaluate reference projector') from error
        if projected is not None:
            return projected
    return program_wire(canonical, entry, allow_resources=allow_resources)

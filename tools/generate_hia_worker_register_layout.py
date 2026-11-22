"""Author sealed JSON ingress for HIA's checked register-coordinate packet."""
from __future__ import annotations

import ast
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_json_decode import source_program as json_decoder
from tools.generate_hia_machine_plan import LEAF_OPS, REGISTERS, packed, source_program as machine_plan
from tools.generate_hia_release_install import POLICY_SOURCE as RELEASE
from tools.generate_hia_worker_block_layout import INPUT_BYTES, MAX_NODES, PREFLIGHT_BYTES
from tools.generate_hia_worker_inspection_effect import function, literal as render_literal

SOURCE = Path('examples/hia_bootstrap/worker_register_layout.hepta')
WORKSPACE_BYTES = 128 << 20
INVALID = 0xfffffffd
NONE = (1 << 64) - 1
WITNESS_TAG = int.from_bytes(b'HIARWT01', 'little')
WITNESS_RULE_TEXT = b'closed-block inclusive lifetimes; all edge sources staged before target writes'
WITNESS_KEYS = ('rule', 'functions', 'callee_saved_registers', 'intervals',
                'caller_clobbered_leaf_registers', 'leaf_opcode_inventory',
                'block', 'value', 'type', 'register', 'first', 'last')

POLICY = r'''
def register_layout(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 8 or length(s) > INPUT_MAX or length(o) < PREFLIGHT or length(w) < WORKSPACE:
        return INVALID
    put(o, 48, NODES)
    put(o, 56, 128)
    arena = widen(decode_json(s, w, o))
    count = get(w, 96)
    if arena >= 4294967292 or get(w, 64) != 5 or (count != 3 and count != 4):
        return INVALID
    packet = align8(arena)
    end = typed_tree(s, w, packet)
    if end == INVALID:
        return INVALID
    extent = bound_register_packet(o, w, packet, align8(end))
    if extent == INVALID or extent >= 2147483648 or count == 3:
        return extent
    witness = welement(w, packet, 3)
    if literal(w, witness, 4, 6, DERIVE_WITNESS, 0, 0, 0, 0, 0) != 0:
        return render_witness(w, o)
    if check_witness(w, o, witness) == 0:
        return INVALID
    return extent

# Compare the original evidence's closed-block witness with fresh typed
# Core calculations. This is not a claim about physical ELF bytes.
def check_witness(w:mutbuf, o:mutbuf, witness:u64) -> u64:
    if wtag(w, witness) != 6 or wtotal(w, witness) != 2:
        return 0
    if witness_rule(w, witness_field(w, witness, 1)) == 0:
        return 0
    observed = witness_field(w, witness, 2)
    mappings = field(w, get(w, 80), 8)
    if wtag(w, observed) != 6 or wtotal(w, observed) != wtotal(w, mappings):
        return 0
    functions = get(w, 112)
    fn = functions + 24
    index = 0
    while index < wtotal(w, functions):
        name = field(w, fn, 13)
        expected = find_mapping(w, mappings, name)
        if expected != NONE:
            actual = find_mapping(w, observed, name)
            if actual == NONE or actual == INVALID or bind_assignment(w, o, fn, expected) != 0:
                return 0
            if witness_function(w, actual) == 0:
                return 0
        fn = wend(w, fn)
        index = index + 1
    return 1

def witness_function(w:mutbuf, node:u64) -> u64:
    leaf_version = get(w, 128) != 0
    if wtag(w, node) != 6 or wtotal(w, node) != choose(leaf_version, 4, 2):
        return 0
    callee = witness_field(w, node, 3)
    if witness_inventory(w, callee, get(w, 224), False) == 0:
        return 0
    if leaf_version:
        leaf = get(w, 288)
        if witness_inventory(w, witness_field(w, node, 5), leaf, False) == 0:
            return 0
        opcodes = choose(leaf == 0, 0, get(w, 232))
        if witness_inventory(w, witness_field(w, node, 6), opcodes, True) == 0:
            return 0
    intervals = witness_field(w, node, 4)
    count = get(w, 208)
    if wtag(w, intervals) != 5 or wtotal(w, intervals) != count:
        return 0
    sort_rows(w, 0)
    rows = get(w, 264)
    at = intervals + 24
    index = 0
    while index < count:
        if witness_interval(w, at, get(w, rows + index * 8)) == 0:
            return 0
        at = wend(w, at)
        index = index + 1
    return 1

def witness_inventory(w:mutbuf, node:u64, expected:u64, opcodes:bool) -> u64:
    if wtag(w, node) != 5:
        return 0
    at = node + 24
    index = 0
    former = 0
    while index < wtotal(w, node):
        current = register_id(w, at)
        if opcodes:
            current = leaf_op_id(w, at)
        if current <= former:
            return 0
        bit = 1 << (current - 1)
        if expected & bit == 0:
            return 0
        expected = expected ^ bit
        former = current
        at = wend(w, at)
        index = index + 1
    return choose(expected == 0, 1, 0)

def witness_interval(w:mutbuf, node:u64, row:u64) -> u64:
    if wtag(w, node) != 6 or wtotal(w, node) != 6:
        return 0
    if same(w, witness_field(w, node, 7), get(w, row + 16)) == 0:
        return 0
    if same(w, witness_field(w, node, 8), get(w, row)) == 0:
        return 0
    if same(w, witness_field(w, node, 9), get(w, row + 8)) == 0:
        return 0
    if register_id(w, witness_field(w, node, 10)) != get(w, row + 48):
        return 0
    if witness_position(w, witness_field(w, node, 11), get(w, row + 32)) == 0:
        return 0
    return witness_position(w, witness_field(w, node, 12), get(w, row + 40))

def witness_position(w:mutbuf, node:u64, expected:u64) -> u64:
    if wtag(w, node) != 2:
        return 0
    count = wsize(w, node)
    if count < 1 or count > 5:
        return 0
    value = 0
    index = 0
    while index < count:
        digit = byte(w, node + 16 + index)
        if digit < 48 or digit > 57:
            return 0
        value = value * 10 + digit - 48
        index = index + 1
    return choose(value == expected, 1, 0)

def witness_field(w:mutbuf, node:u64, key:u64) -> u64:
    at = node + 24
    index = 0
    while index < wtotal(w, node):
        value = wend(w, at)
        if witness_key(w, at) == key:
            return value
        at = wend(w, value)
        index = index + 1
    return NONE

# Walk the already decoded tree without a separate stack. Open container
# output offsets replace their no-longer-used original source spans.
def typed_tree(s:readbuf, w:mutbuf, cursor:u64) -> u64:
    node = 64
    while True:
        parent = get(w, node + 8)
        if parent != NONE:
            owner = 64 + parent * 72
            if get(w, owner) == 6:
                cursor = typed_string(w, get(w, node + 40), get(w, node + 48), cursor)
                if cursor == INVALID:
                    return INVALID
        kind = get(w, node)
        if kind == 5 or kind == 6:
            if length(w) - cursor < 24:
                return INVALID
            put(w, cursor, kind)
            count = get(w, node + 32)
            put(w, cursor + 8, 8)
            put(w, cursor + 16, count)
            if count != 0:
                put(w, node + 56, cursor)
                cursor = cursor + 24
                node = 64 + get(w, node + 24) * 72
            else:
                cursor = cursor + 24
                closed = close_through(w, node, cursor)
                if closed == NONE:
                    return cursor
                node = closed
        else:
            cursor = typed_leaf(s, w, node, cursor, kind)
            if cursor == INVALID:
                return INVALID
            closed = close_through(w, node, cursor)
            if closed == NONE:
                return cursor
            node = closed
    return INVALID

def close_through(w:mutbuf, node:u64, cursor:u64) -> u64:
    while True:
        sibling = get(w, node + 16)
        if sibling != NONE:
            return 64 + sibling * 72
        parent = get(w, node + 8)
        if parent == NONE:
            return NONE
        node = 64 + parent * 72
        start = get(w, node + 56)
        put(w, start + 8, cursor - start - 16)
    return NONE

def typed_leaf(s:readbuf, w:mutbuf, node:u64, cursor:u64, kind:u64) -> u64:
    at = get(w, node + 24)
    size = get(w, node + 32)
    if kind == 4:
        return typed_string(w, at, size, cursor)
    if kind == 3:
        return typed_number(s, w, at, size, cursor)
    extent = choose(kind == 0, 16, 17)
    if extent > length(w) - cursor:
        return INVALID
    put(w, cursor, choose(kind == 0, 0, 1))
    put(w, cursor + 8, extent - 16)
    if kind != 0:
        store(w, cursor + 16, kind - 1)
    return cursor + extent

def typed_string(w:mutbuf, at:u64, size:u64, cursor:u64) -> u64:
    if 16 + size > length(w) - cursor:
        return INVALID
    put(w, cursor, 4)
    put(w, cursor + 8, size)
    index = 0
    while index < size:
        store(w, cursor + 16 + index, byte(w, at + index))
        index = index + 1
    return cursor + 16 + size

def typed_number(s:readbuf, w:mutbuf, at:u64, size:u64, cursor:u64) -> u64:
    if size == 2 and byte(s, at) == 45 and byte(s, at + 1) == 48:
        at = at + 1
        size = 1
    if 16 + size > length(w) - cursor:
        return INVALID
    kind = 2
    index = 0
    while index < size:
        value = byte(s, at + index)
        if value == 46 or value == 69 or value == 101:
            kind = 3
        store(w, cursor + 16 + index, value)
        index = index + 1
    put(w, cursor, kind)
    put(w, cursor + 8, size)
    return cursor + 16 + size
'''


RENDERER = r'''
def render_witness(w:mutbuf, o:mutbuf) -> u64:
    # The typed plan has already passed bound_register_packet. Emit from the
    # same checked interval machinery, not a witness supplied by the caller.
    mappings = field(w, get(w, 80), 8)
    count = wtotal(w, mappings)
    node = mappings + 24
    cursor = witness_begin(o, 16)
    index = 0
    while index < count:
        if cursor > length(o) - 4096:
            return INVALID
        if index != 0:
            store(o, cursor, 44)
            cursor = cursor + 1
        fn = find_function(w, node)
        if fn == NONE:
            return INVALID
        mapping = wend(w, node)
        if bind_assignment(w, o, fn, mapping) != 0:
            return INVALID
        cursor = witness_name(w, o, field(w, fn, 13), cursor)
        if cursor == INVALID:
            return INVALID
        cursor = witness_callee(o, cursor)
        cursor = witness_array(o, cursor, get(w, 224), False)
        if get(w, 128) != 0:
            cursor = witness_leaf(o, cursor)
            cursor = witness_array(o, cursor, get(w, 288), False)
        cursor = witness_intervals(o, cursor)
        cursor = witness_rows(w, o, cursor)
        if cursor == INVALID:
            return INVALID
        if get(w, 128) != 0:
            cursor = witness_opcode(o, cursor)
            leaf = get(w, 288)
            cursor = witness_array(o, cursor, choose(leaf == 0, 0, get(w, 232)), True)
        store(o, cursor, 125)
        cursor = cursor + 1
        node = wend(w, mapping)
        index = index + 1
    cursor = witness_end(o, cursor)
    put(o, 0, WITNESS_TAG)
    put(o, 8, cursor - 16)
    return cursor

def witness_rows(w:mutbuf, o:mutbuf, at:u64) -> u64:
    sort_rows(w, 0)
    rows = get(w, 264)
    count = get(w, 208)
    i = 0
    while i < count:
        if at > length(o) - 4096:
            return INVALID
        if i != 0:
            store(o, at, 44)
            at = at + 1
        row = get(w, rows + i * 8)
        at = witness_block(o, at)
        at = witness_name(w, o, get(w, row + 16), at)
        if at == INVALID:
            return INVALID
        at = decimal(o, witness_first(o, at), get(w, row + 32))
        at = decimal(o, witness_last(o, at), get(w, row + 40))
        at = witness_register_name(o, witness_register(o, at), get(w, row + 48))
        at = witness_name(w, o, get(w, row + 8), witness_type(o, at))
        if at == INVALID:
            return INVALID
        at = witness_name(w, o, get(w, row), witness_value(o, at))
        if at == INVALID:
            return INVALID
        store(o, at, 125)
        at = at + 1
        i = i + 1
    store(o, at, 93)
    return at + 1

def witness_array(o:mutbuf, at:u64, mask:u64, opcodes:bool) -> u64:
    first = True
    ordinal = 1
    while mask != 0:
        if mask & 1 != 0:
            if first == False:
                store(o, at, 44)
                at = at + 1
            first = False
            if opcodes:
                at = witness_opcode_name(o, at, ordinal)
            else:
                at = witness_register_name(o, at, ordinal)
        mask = mask >> 1
        ordinal = ordinal + 1
    store(o, at, 93)
    return at + 1

def witness_name(w:mutbuf, o:mutbuf, node:u64, cursor:u64) -> u64:
    # Only the admitted Core identifier alphabet can be copied unescaped.
    if wtag(w, node) != 4:
        return INVALID
    width = wsize(w, node)
    if width < 1 or width > 128:
        return INVALID
    store(o, cursor, 34)
    i = 0
    while i < width:
        unit = byte(w, node + 16 + i)
        upper = unit >= 65 and unit <= 90
        lower = unit >= 97 and unit <= 122
        digit = i > 0 and unit >= 48 and unit <= 57
        if upper == False and lower == False and digit == False and unit != 95:
            return INVALID
        store(o, cursor + 1 + i, unit)
        i = i + 1
    store(o, cursor + 1 + width, 34)
    return cursor + 2 + width
'''

def witness_literals():
    source = ['def witness_key(w:mutbuf, node:u64) -> u64:']
    for index, key in enumerate(WITNESS_KEYS, 1):
        source.extend((f'    if literal(w, node, 4, {packed(key)}) != 0:', f'        return {index}'))
    rule = WITNESS_RULE_TEXT
    source.extend(('    return 0', '', 'def witness_rule(w:mutbuf, node:u64) -> u64:',
                   f'    if wtag(w, node) != 4 or wsize(w, node) != {len(rule)}:',
                   '        return 0'))
    for offset in range(0, len(rule), 8):
        part = rule[offset:offset + 8]
        observed = f'get(w, node + {16 + offset})'
        if len(part) < 8:
            observed = f'({observed} & {(1 << (8 * len(part))) - 1})'
        source.extend((f'    if {observed} != {int.from_bytes(part, "little")}:', '        return 0'))
    source.append('    return 1')
    return '\n'.join(source)


def witness_renderer():
    templates = {
        'begin': b'{"functions":{',
        'callee': b':{"callee_saved_registers":[',
        'leaf': b',"caller_clobbered_leaf_registers":[',
        'intervals': b',"intervals":[',
        'opcode': b',"leaf_opcode_inventory":[',
        'block': b'{"block":',
        'first': b',"first":',
        'last': b',"last":',
        'register': b',"register":',
        'type': b',"type":',
        'value': b',"value":',
        'end': b'},"rule":"' + WITNESS_RULE_TEXT + b'"}',
    }
    renderers = [render_literal('witness_' + name, text).replace('state_put(', 'put(')
                 for name, text in templates.items()]
    for kind, names in (('register', REGISTERS), ('opcode', LEAF_OPS)):
        destination = 'witness_' + kind + '_name'
        unpacked = [f'def {destination}(o:mutbuf, at:u64, ordinal:u64) -> u64:']
        for i, name in enumerate(names, 1):
            encoded = ('"' + name + '"').encode('ascii')
            body = render_literal(destination, encoded).replace('state_put(', 'put(').splitlines()[1:]
            unpacked.append(f'    if ordinal == {i}:')
            unpacked.extend('    ' + line for line in body)
        unpacked.append('    return at')
        renderers.append('\n'.join(unpacked))
    return '\n'.join((RENDERER, *renderers, *(function(RELEASE, name) for name in ('decimal', 'divide10'))))


def program():
    constants = dict(INPUT_MAX=INPUT_BYTES, NODES=MAX_NODES, PREFLIGHT=PREFLIGHT_BYTES,
                     WORKSPACE=WORKSPACE_BYTES, INVALID=INVALID, NONE=NONE,
                     DERIVE_WITNESS=int.from_bytes(b'derive', 'little'), WITNESS_TAG=WITNESS_TAG)

    class Constants(ast.NodeTransformer):
        def visit_Name(self, node):
            if node.id in constants:
                return ast.copy_location(ast.Constant(constants[node.id]), node)
            return node

    raw_decoder = json_decoder(wire_spans=True)
    guard = 'if length(s) > 8388608 or length(w) < 128'
    if raw_decoder.count(guard) != 2:
        raise ValueError('JSON decoder admission sites differ')
    raw_decoder = raw_decoder.replace(guard, guard.replace('8388608', str(INPUT_BYTES)))
    reader = Constants().visit(ast.parse('\n'.join((POLICY, witness_literals(), witness_renderer()))))
    machinery = ast.parse(machine_plan()).body
    decoder = ast.parse(raw_decoder).body
    nodes = {node.name: node for node in (*decoder, *machinery, *reader.body)}
    # Keep only the exact shared decisions required by the standalone role.
    selected = {}
    pending = ['register_layout']
    while pending:
        name = pending.pop()
        if name in selected:
            continue
        node = selected[name] = nodes[name]
        pending.extend(callee.func.id for callee in ast.walk(node)
                       if isinstance(callee, ast.Call) and isinstance(callee.func, ast.Name)
                       and callee.func.id in nodes and callee.func.id not in selected)
    reachable = [reader.body[0], *(node for name, node in nodes.items()
                                 if name in selected and name != 'register_layout')]
    return ast.unparse(ast.fix_missing_locations(ast.Module(body=reachable, type_ignores=[])))


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(document(program(), SOURCE.stem)), encoding='utf-8')

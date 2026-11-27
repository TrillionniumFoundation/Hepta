"""Explicit development ABI: acknowledge physically empty CALL operands.

No claim is moved. HIA receives one fixed physical observation at the original
ACK, then may omit a RELEASE whose slots are already empty.  All other policy,
including partial CALL errors and cell retirement, follows the original path.
This authoring module is not imported by the runtime bridge.
"""
from __future__ import annotations
import ast
import copy

CAPABILITY_MAGIC = int.from_bytes(b'HIAECAP1', 'little')
EMPTY_TAG = int.from_bytes(b'HIAEACK1', 'little')


def body(original):
    text = original.CONTROL_BODY
    edits = []
    def replace(before, after):
        nonlocal text
        assert text.count(before) == 1, before
        text = text.replace(before, after)
        edits.append({'before': before, 'after': after})
    replace('    command=get(w,0)\n    if command == 0:', f'''    command=get(w,0)
    if command == 5:
        if get(w,8) != 0 or get(w,16) != 0 or get(w,24) != 0 or get(w,32) != 0 or get(w,40) != 0 or get(w,48) != 0 or get(w,128) != 0:
            return ABI
        put(o,0,{CAPABILITY_MAGIC})
        put(o,8,1)
        put(o,16,{EMPTY_TAG})
        put(o,24,1)
        return 16
    if command == 0:''')
    replace('    op=get(w,184)\n    if get(w,32) != 0:', f'''    op=get(w,184)
    tag=get(w,48)
    start=0
    consumed=0
    if tag != 0:
        if tag != {EMPTY_TAG} or request != 1 or op != CALL:
            return ABI
        at=get(w,200)
        consumed=byte(s,at+5)
        if consumed == 0:
            return ABI
        start=at+14+byte(s,at+2)*2+byte(s,at+3)*2+byte(s,at+4)*4+short(s,at+6)*2
        i=0
        while i < consumed:
            slot=short(s,start+i*2)
            if slot >= get(w,248) or byte(s,get(w,256)+slot) != 1:
                return ABI
            i=i+1
    if get(w,32) != 0:''')
    replace('        put(w,272,0)\n        return 0\n    if request == 3:', '''        put(w,272,0)
        if tag != 0:
            clear_refs(s,w,start,consumed)
            put(w,272,1)
        return 0
    if request == 3:''')
    replace('    if consumed != 0:\n        put(w,288,at+14+destinations*2+byte(s,at+3)*2+byte(s,at+4)*4+short(s,at+6)*2)', '''    if consumed != 0 and tag != 0:
        clear_refs(s,w,start,consumed)
        put(w,160,get(w,160)+1)
        put(w,168,0)
        return 0
    if consumed != 0:
        put(w,288,at+14+destinations*2+byte(s,at+3)*2+byte(s,at+4)*4+short(s,at+6)*2)''')
    replace('    return 1\n\ndef retire(s:readbuf', '''    if op == CALL:
        put(o,80,byte(s,at+5))
        put(o,88,at+14+nd*2+na*2+nr*4+nv*2)
    return 1

def retire(s:readbuf''')
    replace('    put(o,72,request)\n    return 0', '''    put(o,72,request)
    put(o,80,0)
    put(o,88,0)
    return 0''')
    return text, edits


def source(original):
    parsed = original.source()
    changed, edits = body(original)
    # Reuse the exact already authored table, transport and delivery functions.
    controls = ast.parse(changed).body
    constants = {
        'MAGIC': original.MAGIC, 'EMIT_MAGIC': original.EMIT_MAGIC,
        'ABI': original.ABI, 'OUTPUT_BYTES': original.OUTPUT,
        'TABLE_BYTES': len(original.table(original.program())),
        'WORKSPACE_BYTES': 1024 + 8 * max(fn.next_slot for fn in original.program().functions),
        **original.OPS,
    }
    class Names(ast.NodeTransformer):
        def visit_Name(self, node):
            return ast.copy_location(ast.Constant(constants[node.id]), node) if node.id in constants else node
    controls = [Names().visit(node) for node in controls]
    candidate = copy.deepcopy(parsed)
    assert [node.name for node in candidate.body[:len(controls)]] == [node.name for node in controls]
    candidate.body[:len(controls)] = controls
    ast.fix_missing_locations(candidate)
    return candidate, edits


def document(original):
    parsed, edits = source(original)
    nodes = parsed.body
    names = {node.name: 'f' + str(index) for index, node in enumerate(nodes)}
    signatures = {node.name: ([arg.annotation.id for arg in node.args.args], node.returns.id)
                  for node in nodes}
    total = original.total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = original.Builder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({'name': names[node.name],
            'params': [builder.param(v) for v in builder.params],
            'returns': [builder.returns], 'effects': ['read', 'write', 'trap'],
            'entry': 'b0', 'blocks': builder.blocks})
    result = original.compact_authoring_cfg({
        'schema': 'hepta.hia.program.v8', 'module': 'agent_contract_empty_ack_r2',
        'functions': functions})
    return result, {'exact_replacements': edits, 'preclaim': False,
                    'capability_magic': CAPABILITY_MAGIC, 'empty_tag': EMPTY_TAG}

"""Author the bounded public-bytes JSON front door in HIA.

The image keeps Core's ordered UTF-8, syntax/budget, integer-policy and
canonical-wire decisions. A fixed second image encodes that canonical wire
as a nominal packet; no payload object is constructed in the host.
"""
from __future__ import annotations
import ast
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_json_canonical import SOURCE as canonical_source
from tools.generate_hia_json_decode import source_program as decoder_source
from tools.generate_hia_nominal_json import SOURCE as nominal_source
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions

CONSTANTS = {
    'REQUEST_MAGIC': int.from_bytes(b'HIACJQ01', 'little'),
    'REPLY_MAGIC': int.from_bytes(b'HIACJP01', 'little'),
    'ARENA_MAGIC': 5208772604367785521,
    'NONE': (1 << 64) - 1,
    'MAX_BYTES': 8 * 1024 * 1024,
    'MAX_NODES': 262144,
    'MAX_DEPTH': 64,
    'BAD_JSON': 0xffffffff,
    'BAD_BUDGET': 0xfffffffe,
    'BAD_ABI': 0xfffffffd,
    'BAD_DUPLICATE': 0xfffffffc,
    'BAD_BYTES': 0xfffffffb,
    'BAD_INTEGER': 0xfffffffa,
    'BAD_INTERNAL': 0xfffffff9,
}

SOURCE = r'''
def core_json_bytes(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) > MAX_BYTES:
        return BAD_BYTES
    if length(w) < 128 or length(o) < 128:
        return BAD_ABI
    if get(w, 0) != REQUEST_MAGIC:
        return BAD_ABI
    digits = get(w, 8)
    if digits != 0 and digits < 640:
        return BAD_ABI
    index = 16
    while index < 64:
        if get(w, index) != 0:
            return BAD_ABI
        index = index + 8
    bound = ((length(s) + 1) >> 1) + 1
    if bound > MAX_NODES:
        bound = MAX_NODES
    arena_bound = 64 + bound * 56 + length(s)
    if arena_bound < 128 + (MAX_DEPTH + 1) * 32:
        arena_bound = 128 + (MAX_DEPTH + 1) * 32
    key_bound = (length(s) >> 2) + 1
    if key_bound > MAX_NODES:
        key_bound = MAX_NODES
    slots = 2
    while slots < key_bound * 2:
        slots = slots * 2
    output_bound = slots * 8
    if output_bound < 128 + (MAX_DEPTH + 1) * 48:
        output_bound = 128 + (MAX_DEPTH + 1) * 48
    if output_bound < length(s):
        output_bound = length(s)
    if length(w) < arena_bound or length(o) < output_bound:
        return BAD_ABI
    # Python's public bytes API decodes the complete UTF-8 wire first.
    # Invalid UTF-8 at the end therefore precedes an earlier syntax/budget error.
    if njs_utf8(s) == 0:
        return BAD_JSON
    put(o, 48, MAX_NODES)
    put(o, 56, MAX_DEPTH)
    result = widen(decode_json(s, w, o))
    if result >= BAD_DUPLICATE:
        return result
    if result < 64 or result > length(w):
        return BAD_INTERNAL
    count = get(w, 8)
    base = get(w, 16)
    if get(w, 0) != ARENA_MAGIC or count < 1 or count > bound or base != 64 + count * 56:
        return BAD_INTERNAL
    if get(w, 24) != result or get(w, 32) != result or get(w, 40) != length(s):
        return BAD_INTERNAL
    if get(w, 48) != 1 or get(w, 56) != 0 or result < base:
        return BAD_INTERNAL
    # Full syntax, duplicate keys and Core structural limits precede integer
    # conversion. This walk applies the selected decimal policy in source order.
    status = njs_validate(s, w, count, base, result, digits)
    if status != 0:
        return status
    # Reuse the native canonicalizer after admission. It sorts decoded Unicode
    # keys and normalizes -0 before the packet codec sees the canonical wire.
    put(w, 48, MAX_NODES)
    put(w, 56, MAX_DEPTH)
    produced = widen(canonical_json(s, o, w))
    if produced < 1 or produced > length(s) or produced > length(o):
        return BAD_INTERNAL
    put(w, 0, REPLY_MAGIC)
    put(w, 8, produced)
    put(w, 16, digits)
    put(w, 24, length(s))
    put(w, 32, count)
    put(w, 40, MAX_NODES)
    put(w, 48, MAX_DEPTH)
    put(w, 56, 1)
    return produced
'''


def source_program():
    helpers = [node for node in ast.parse(nominal_source).body
               if node.name in {'njs_utf8', 'njs_validate'}]
    nodes = ast.parse(SOURCE + canonical_source + decoder_source()).body + helpers

    class Constants(ast.NodeTransformer):
        def visit_Name(self, node):
            if isinstance(node.ctx, ast.Load) and node.id in CONSTANTS:
                return ast.copy_location(ast.Constant(CONSTANTS[node.id]), node)
            return node

    return [Constants().visit(node) for node in nodes]


def document():
    nodes = source_program()
    names = {node.name: 'f' + str(i) for i, node in enumerate(nodes)}
    signatures = {node.name: ([arg.annotation.id for arg in node.args.args], node.returns.id)
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
                                  'module': 'core_json_bytes', 'functions': functions})


def main():
    path = Path(__file__).resolve().parents[1] / 'examples/hia_bootstrap/core_json_bytes.hepta'
    path.write_text(render_assembly(document()))
    print(path.name, path.stat().st_size)


if __name__ == '__main__':
    main()

"""Emit the complete seven-method Agent verification continuation.

The immutable control table is compressed only as an authoring representation.
The HIA image emits and expands every byte itself; the runtime never receives
a host-created policy table. No compiler profile or public input is narrowed.
"""
from __future__ import annotations

import argparse
import ast
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
if __package__ in (None, ''):
    sys.path.insert(0, str(ROOT))

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions
from tools.generate_hia_machine_plan_control import (
    BODY as CONTROL_BODY, helpers, table, MAGIC, EMIT_MAGIC, ABI, OUTPUT)
from tools.hia_exception_delivery import BODY as EXCEPTION_BODY
from tools.hia_service_verification_control import compile_policy, OPS
from tools.hia_core_lowering_table import BODY as EXPAND_BODY, compress_table, reference_expand


def program():
    return compile_policy((ROOT / 'tools/hia_service_verification_policy.py').read_text())


def emission(data, packed):
    padded = packed + bytes((-len(packed)) % 112)
    values = struct.unpack('<' + 'Q' * (len(padded) // 8), padded)
    groups = [values[index:index + 224] for index in range(0, len(values), 224)]
    functions = ['def emit_policy(o:mutbuf,w:mutbuf) -> u32:\n'
        '    if length(o) < ' + str(len(data) + len(padded)) + ' or length(w) < 96:\n'
        '        return ABI\n    put(w,88,' + str(len(data)) + ')\n' +
        '\n'.join('    emit_part_' + str(index) + '(o,w)' for index in range(len(groups))) +
        '\n    return expand_policy(o)']
    for index, group in enumerate(groups):
        functions.append('def emit_part_' + str(index) + '(o:mutbuf,w:mutbuf) -> u64:\n' +
            '\n'.join('    words14(o,w,' + ','.join(map(str, group[at:at + 14])) + ')'
                      for at in range(0, len(group), 14)) + '\n    return 0')
    return '\n\n'.join(functions)


def transport_helpers():
    nodes = [node for node in ast.parse(helpers()).body if node.name != 'words']
    fixed = ast.unparse(ast.Module(body=nodes, type_ignores=[]))
    signature = ','.join('v' + str(index) + ':u64' for index in range(14))
    writer = 'def words14(o:mutbuf,w:mutbuf,' + signature + ') -> u64:\n' + \
        '\n'.join('    put(o,get(w,88)+' + str(index * 8) + ',v' + str(index) + ')'
                  for index in range(14)) + '\n    put(w,88,get(w,88)+112)\n    return 0'
    return fixed + '\n\n' + writer


def source():
    policy = program()
    data = table(policy)
    packed = compress_table(data)
    if reference_expand(packed) != data:
        raise AssertionError('control-table representation is not lossless')
    constants = {'MAGIC': MAGIC, 'EMIT_MAGIC': EMIT_MAGIC, 'ABI': ABI,
                 'OUTPUT_BYTES': OUTPUT, 'TABLE_BYTES': len(data),
                 'PACKED_BYTES': len(packed),
                 'WORKSPACE_BYTES': 1024 + 8 * max(function.next_slot for function in policy.functions),
                 **OPS}
    parsed = ast.parse(CONTROL_BODY + '\n' + transport_helpers() + '\n' +
                       emission(data, packed) + '\n' + EXPAND_BODY + '\n' + EXCEPTION_BODY)
    class Names(ast.NodeTransformer):
        def visit_Name(self, node):
            return ast.copy_location(ast.Constant(constants[node.id]), node) if node.id in constants else node
    return ast.fix_missing_locations(Names().visit(parsed))


def document():
    nodes = source().body
    names = {node.name: 'f' + str(index) for index, node in enumerate(nodes)}
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
                                  'module': 'service_verification', 'functions': functions})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / 'examples/hia_bootstrap/service_verification.hepta')
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    raw = render_assembly(document()).encode('utf-8')
    if args.check:
        if args.output.read_bytes() != raw:
            raise AssertionError('checked verification HIA differs from its complete policy')
    else:
        args.output.write_bytes(raw)
    print(args.output)


if __name__ == '__main__':
    main()

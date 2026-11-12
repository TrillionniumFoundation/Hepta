"""Generate complete borrowed-byte normalization and wrapper HIA policy."""
from __future__ import annotations

import argparse
import ast
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if __package__ in (None, ''):
    sys.path.insert(0, str(ROOT))

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions
from tools.generate_hia_machine_plan_control import (
    BODY as CONTROL_BODY, table, MAGIC, EMIT_MAGIC, ABI, OUTPUT)
from tools.generate_hia_core_lowering import emission, transport_helpers
from tools.hia_core_lowering_table import BODY as EXPAND_BODY, compress_table, reference_expand
from tools.hia_exception_delivery import BODY as EXCEPTION_BODY
from tools.hia_native_byte_abi_control import compile_policy, OPS


def program():
    return compile_policy((ROOT / 'tools/hia_native_byte_abi_policy.py').read_text())


def source():
    policy = program()
    data = table(policy)
    packed = compress_table(data)
    if reference_expand(packed) != data:
        raise AssertionError('byte ABI policy representation is not lossless')
    constants = {'MAGIC': MAGIC, 'EMIT_MAGIC': EMIT_MAGIC, 'ABI': ABI,
                 'OUTPUT_BYTES': OUTPUT, 'TABLE_BYTES': len(data),
                 'PACKED_BYTES': len(packed),
                 'WORKSPACE_BYTES': 1024 + 8 * max(fn.next_slot for fn in policy.functions),
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
        functions.append({'name': names[node.name], 'params': [builder.param(v) for v in builder.params],
            'returns': [builder.returns], 'effects': ['read', 'write', 'trap'],
            'entry': 'b0', 'blocks': builder.blocks})
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8',
                                  'module': 'native_byte_abi', 'functions': functions})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path,
                        default=ROOT / 'examples/hia_bootstrap/native_byte_abi.hiaasm')
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    raw = render_assembly(document()).encode()
    if args.check:
        if args.output.read_bytes() != raw:
            raise AssertionError('borrowed-byte HIA differs from its complete policy')
    else:
        args.output.write_bytes(raw)
    print(args.output)


if __name__ == '__main__':
    main()

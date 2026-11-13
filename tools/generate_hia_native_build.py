"""Generate complete native-build normalization and wrapper HIA policy."""
from __future__ import annotations

import argparse
import ast
from pathlib import Path
import sys
import struct

ROOT = Path(__file__).resolve().parents[1]
if __package__ in (None, ''):
    sys.path.insert(0, str(ROOT))

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions
from tools.generate_hia_machine_plan_control import (
    BODY as CONTROL_BODY, MAGIC, EMIT_MAGIC, ABI, OUTPUT)
from tools.generate_hia_core_lowering_control import emission, transport_helpers
from tools.hia_core_lowering_table import BODY as EXPAND_BODY, compress_table, reference_expand
from tools.hia_exception_delivery import BODY as EXCEPTION_BODY
from tools.hia_native_build_control import compile_policy, OPS


def table(policy):
    starts = {}
    count = 0
    for function in policy.functions:
        starts[function.mode] = count + 1
        count += len(function.instructions)
    data = bytearray(64 + len(policy.functions) * 32)
    for function in policy.functions:
        metadata = len(data)
        data += bytes((int(i in function.temporary_slots) |
                       (2 * int(i in function.cell_slots)))
                      for i in range(function.next_slot))
        for own, outer in function.captures.values():
            data += struct.pack('<H', own.slot)
        info = (len(function.parameters) |
                (int(function.kind == 'generator') << 16) |
                (len(function.captures) << 32))
        struct.pack_into('<4Q', data, 64 + (function.mode - 1) * 32,
                         starts[function.mode], function.next_slot, info, metadata)
    offsets_at = len(data)
    data += b'\0' * (4 * count)
    ordinal = 0
    for function in policy.functions:
        shift = starts[function.mode] - 1
        for instruction in function.instructions:
            struct.pack_into('<I', data, offsets_at + ordinal * 4, len(data))
            ordinal += 1
            kind = instruction['kind']
            if kind == 'effect':
                destinations, arguments = instruction['destinations'], instruction['arguments']
                raw, vector = instruction['raw'], instruction['vector']
                consume = instruction['consume']
                handler = instruction['handler']
                data += struct.pack('<6BH I H', 1, instruction['opcode'], len(destinations),
                                    len(arguments), len(raw), len(consume), len(vector),
                                    handler + shift if handler else 0, 0)
                for ref in (*destinations, *arguments):
                    data += struct.pack('<H', ref.slot)
                for value in raw:
                    data += struct.pack('<I', value)
                for ref in (*vector, *consume):
                    data += struct.pack('<H', ref.slot)
            elif kind == 'jump':
                data += struct.pack('<BI', 2, instruction['target'] + shift)
            elif kind == 'flag':
                data += struct.pack('<BII', 3, instruction['yes'] + shift,
                                    instruction['no'] + shift)
            elif kind in ('return', 'yield'):
                data += struct.pack('<BH', 4 if kind == 'return' else 5,
                                    instruction['value'].slot)
            elif kind == 'error_return':
                data += b'\6'
            else:
                raise ValueError('unrendered instruction')
    literals_at = len(data)
    data += b'\0' * (4 * len(policy.literals))
    for index, value in enumerate(policy.literals):
        struct.pack_into('<I', data, literals_at + 4 * index, len(data))
        if value is None:
            kind, raw = 0, b''
        elif type(value) is bool:
            kind, raw = 1, bytes((int(value),))
        elif type(value) is int:
            kind, raw = 2, str(value).encode('ascii')
        elif type(value) is bytes:
            kind, raw = 5, value
        elif type(value) is str:
            # CPython interns its ASCII name-character constants. Record that
            # representation in the immutable HIA-owned table, so the runtime
            # bridge does not infer a policy or change the object's identity.
            interned = all(c in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_'
                           for c in value)
            kind, raw = (4 if interned else 3), value.encode('utf-8')
        else:
            raise ValueError('unrendered literal')
        data += struct.pack('<BQ', kind, len(raw)) + raw
    data += bytes((-len(data)) % 8)
    struct.pack_into('<8Q', data, 0, MAGIC, len(data), len(policy.functions), count,
                     64, offsets_at, literals_at, len(policy.literals))
    return bytes(data)


def program():
    return compile_policy((ROOT / 'tools/hia_native_build_policy.py').read_text())


def source():
    policy = program()
    data = table(policy)
    packed = compress_table(data)
    if reference_expand(packed) != data:
        raise AssertionError('native-build policy representation is not lossless')
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
                                  'module': 'native_build', 'functions': functions})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path,
                        default=ROOT / 'examples/hia_bootstrap/native_build.hepta')
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    raw = render_assembly(document()).encode()
    if args.check:
        if args.output.read_bytes() != raw:
            raise AssertionError('native-build HIA differs from its complete policy')
    else:
        args.output.write_bytes(raw)
    print(args.output)


if __name__ == '__main__':
    main()

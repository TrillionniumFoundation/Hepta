"""Generate the complete HIA final Core structure visitor and late gate.

The host combines fixed authoring text only. HIA consumes actual ObjectToken
producer frames and private native-issued source/summary leases; no Python
tree count, dictionary lookup, opaque combination, or error choice is used.
"""
from __future__ import annotations

import ast
import copy
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions
from tools.generate_hia_composite_object_ir import SOURCE as IR_SOURCE
from tools.generate_hia_composite_core_final_common import CONSTANTS, COMMON, literals_source
from tools.generate_hia_composite_core_final_stream import BODY

SOURCE_PATH = 'examples/hia_bootstrap/composite_core_final.hiaasm'


def source_program():
    fixed = {node.name: node for node in ast.parse(IR_SOURCE).body if isinstance(node, ast.FunctionDef)}
    names = ('word', 'get', 'put', 'source_header', 'source_same', 'source_node',
             'continuation_byte', 'utf8')
    if not set(names) <= fixed.keys():
        raise ValueError('missing fixed source-lease/UTF-8 dependency')
    nodes = ast.parse(BODY + COMMON + literals_source()).body
    nodes += [copy.deepcopy(fixed[name]) for name in names]
    if len({node.name for node in nodes}) != len(nodes):
        raise ValueError('duplicate native visitor authoring function')

    class Expand(ast.NodeTransformer):
        def visit_Name(self, node):
            if node.id in CONSTANTS:
                return ast.copy_location(ast.Constant(CONSTANTS[node.id]), node)
            return node

    tree = ast.fix_missing_locations(Expand().visit(ast.Module(body=nodes, type_ignores=[])))
    return ast.unparse(tree) + '\n'


class SpanBuilder(Builder):
    def expr(self, expression):
        if isinstance(expression, ast.Call) and isinstance(expression.func, ast.Name):
            if expression.func.id == 'copy_input':
                source, start, target, destination, size = [self.expr(arg) for arg in expression.args]
                return self.op('buffer.copy_range', [target, source,
                    self.cast(destination, 'usize'), self.cast(start, 'usize'), self.cast(size, 'usize')])
            if expression.func.id == 'move_output':
                target, start, destination, size = [self.expr(arg) for arg in expression.args]
                return self.op('buffer.move_within', [target, self.cast(destination, 'usize'),
                    self.cast(start, 'usize'), self.cast(size, 'usize')])
        return super().expr(expression)


def document():
    nodes = ast.parse(source_program()).body
    names = {node.name: 'f' + str(i + 1) for i, node in enumerate(nodes)}
    signatures = {node.name: ([arg.annotation.id for arg in node.args.args], node.returns.id)
                  for node in nodes}
    total = total_scalar_functions(nodes)
    params = [{'name': 'v0', 'type': 'readbuf'}, {'name': 'v1', 'type': 'mutbuf'},
              {'name': 'v2', 'type': 'mutbuf'}]
    functions = [{'name': 'f0', 'params': params, 'returns': ['u32'],
                  'effects': ['read', 'write', 'trap'], 'entry': 'b0', 'blocks': [{
                      'id': 'b0', 'params': params, 'ops': [
                          {'op': 'borrow.read', 'args': ['v1'], 'out': [{'name': 'v3', 'type': 'readbuf'}], 'attrs': {}},
                          {'op': 'call', 'args': ['v0', 'v3', 'v2'], 'out': [{'name': 'v4', 'type': 'u32'}],
                           'attrs': {'function': names['core_final']}},
                          {'op': 'loan.end', 'args': ['v3'], 'out': [], 'attrs': {}}],
                      'term': {'op': 'ret', 'values': ['v4']}}]}]
    for node in nodes:
        builder = SpanBuilder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({'name': names[node.name], 'params': [builder.param(arg) for arg in builder.params],
                          'returns': [builder.returns], 'effects': ['read', 'write', 'trap'],
                          'entry': 'b0', 'blocks': builder.blocks})
    result = compact_authoring_cfg({'schema': 'hepta.hia.program.v8',
                                     'module': 'composite_core_final', 'functions': functions})
    limits = {'functions': len(functions), 'blocks': sum(len(fn['blocks']) for fn in functions),
              'instructions': sum(len(block['ops']) for fn in functions for block in fn['blocks']),
              'maximum_function_blocks': max(len(fn['blocks']) for fn in functions),
              'maximum_block_params': max(len(block['params']) for fn in functions for block in fn['blocks'])}
    if (limits['functions'] > 128 or limits['blocks'] > 1536 or limits['instructions'] > 8192
            or limits['maximum_function_blocks'] > 256 or limits['maximum_block_params'] > 16):
        raise ValueError({'original_compiler_limits_exceeded': limits})
    return result


if __name__ == '__main__':
    root = Path(__file__).resolve().parents[1]
    result = document()
    target = root / SOURCE_PATH
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(render_assembly(result))
    print(target.name, len(result['functions']),
          sum(len(fn['blocks']) for fn in result['functions']),
          sum(len(block['ops']) for fn in result['functions'] for block in fn['blocks']),
          target.stat().st_size, flush=True)

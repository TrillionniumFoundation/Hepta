"""Author the complete native helper request/QUERY and result transport kernels.

All descriptor selection, packet construction, result validation, and state
transitions execute in HIA. Python combines fixed authoring functions and emits
assembly; it never receives an input descriptor or plans a helper invocation.
"""
from __future__ import annotations

import ast
import copy
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions
from tools.generate_hia_composite_type_requests import SOURCE as IR_SOURCE
from tools.generate_hia_composite_type_transport_common import COMMON as TYPE_COMMON, CONSTANTS as TYPE_CONSTANTS
from tools.generate_hia_composite_type_transport_json import BODY as TYPE_JSON
from tools.generate_hia_composite_type_transport_encoding import BODY as TYPE_ENCODING
from tools.generate_hia_composite_helper_transport_common import COMMON, CONSTANTS, literals_source
from tools.generate_hia_composite_helper_transport_request import BODY as REQUEST
from tools.generate_hia_composite_helper_transport_reply import BODY as REPLY

SOURCES = {which: 'examples/hia_bootstrap/composite_helper_transport_' + which + '.hiaasm'
           for which in ('request', 'reply')}


def source_functions(raw, names):
    nodes = {node.name: node for node in ast.parse(raw).body if isinstance(node, ast.FunctionDef)}
    assert set(names) <= set(nodes), set(names) - set(nodes)
    return [copy.deepcopy(nodes[name]) for name in names]


def ir_functions():
    names = ('resolved', 'kind', 'count', 'child', 'list_shape', 'unsigned',
             'reserve', 'header', 'container', 'finish', 'integer', 'scalar',
             'source_value', 'push', 'emit_view')
    substitutions = {name: 'ir_' + name for name in names}
    substitutions.update({'word': 'read', 'fail': 'ir_fail',
                          'STACK': 'IR_STACK', 'MODE': 'IR_MODE',
                          'CURSOR': 'IR_CURSOR', 'BASE': 'IR_OUTPUT_BASE',
                          'LIMIT': 'IR_LIMIT', 'DEPTH': 'IR_DEPTH',
                          'COUNT': 'IR_COUNT', 'ERROR': 'IR_ERROR'})

    class Rename(ast.NodeTransformer):
        def visit_Name(self, node):
            if node.id in substitutions:
                return ast.copy_location(ast.Name(substitutions[node.id], node.ctx), node)
            return node

        def visit_FunctionDef(self, node):
            node = self.generic_visit(node)
            node.name = substitutions.get(node.name, node.name)
            return node

    return [Rename().visit(node) for node in source_functions(IR_SOURCE, names)]


def response_functions():
    shared = source_functions(TYPE_COMMON, ('reserve', 'resume_memory', 'scratch_node',
                                           'end_node', 'same_string', 'zero_words'))
    encoding = ast.parse(TYPE_ENCODING).body

    class HeaderOffset(ast.NodeTransformer):
        """The same private JSON grammar, with a 64-byte helper frame prefix."""
        def visit_Constant(self, node):
            if type(node.value) is int and 128 <= node.value <= 132:
                return ast.copy_location(ast.Constant(node.value - 64), node)
            return node

    for node in encoding:
        if node.name in ('json_byte', 'json_length', 'json_copy', 'json_prepare'):
            HeaderOffset().visit(node)
    return shared + ast.parse(TYPE_JSON).body + encoding


def source_program(which):
    if which not in SOURCES:
        raise ValueError('unknown helper transport kernel')
    raw = (REQUEST if which == 'request' else REPLY) + COMMON + literals_source()
    nodes = ast.parse(raw).body
    nodes += ir_functions() if which == 'request' else response_functions()
    powers = ['def power(index:u64) -> u64:']
    for i in range(20):
        powers += [f'    if index == {i}:', f'        return {10 ** i}']
    powers += ['    return 1']
    nodes += ast.parse('\n'.join(powers)).body
    definitions = {node.name: node for node in nodes}
    if len(definitions) != len(nodes):
        raise ValueError('duplicate helper transport function')
    entry = 'helper_' + which
    needed, queue = {entry}, [entry]
    while queue:
        name = queue.pop()
        for node in ast.walk(definitions[name]):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                child = node.func.id
                if child in definitions and child not in needed:
                    needed.add(child)
                    queue.append(child)
    nodes = [node for node in nodes if node.name in needed]
    constants = dict(CONSTANTS)
    constants.update({name: 2048 + value for name, value in TYPE_CONSTANTS.items()
                      if name.startswith('S_')})
    constants['S_BROKEN'] = CONSTANTS['H_BROKEN']
    constants['S_GROW'] = CONSTANTS['H_GROW']

    class Expand(ast.NodeTransformer):
        def visit_Name(self, node):
            if node.id in constants:
                return ast.copy_location(ast.Constant(constants[node.id]), node)
            return node

    tree = ast.Module(body=nodes, type_ignores=[])
    return ast.unparse(ast.fix_missing_locations(Expand().visit(tree))) + '\n'


class CopyBuilder(Builder):
    def expr(self, expression):
        if isinstance(expression, ast.Call) and isinstance(expression.func, ast.Name):
            name = expression.func.id
            if name in ('copy_bytes', 'move_bytes'):
                values = [self.expr(arg) for arg in expression.args]
                if name == 'copy_bytes':
                    assert len(values) == 5 and values[0][1] == 'mutbuf' and values[1][1] == 'readbuf'
                    return self.op('buffer.copy_range', values[:2] + [self.cast(x, 'usize') for x in values[2:]])
                assert len(values) == 4 and values[0][1] == 'mutbuf'
                return self.op('buffer.move_within', values[:1] + [self.cast(x, 'usize') for x in values[1:]])
        return super().expr(expression)


def document(which):
    nodes = ast.parse(source_program(which)).body
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
                           'attrs': {'function': names['helper_' + which]}},
                          {'op': 'loan.end', 'args': ['v3'], 'out': [], 'attrs': {}}],
                      'term': {'op': 'ret', 'values': ['v4']}}]}]
    for node in nodes:
        builder = CopyBuilder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({'name': names[node.name], 'params': [builder.param(x) for x in builder.params],
                          'returns': [builder.returns], 'effects': ['read', 'write', 'trap'],
                          'entry': 'b0', 'blocks': builder.blocks})
    doc = compact_authoring_cfg({'schema': 'hepta.hia.program.v8',
                                 'module': 'composite_helper_transport_' + which,
                                 'functions': functions})
    limits = {'functions': len(functions), 'blocks': sum(len(fn['blocks']) for fn in functions),
              'instructions': sum(len(block['ops']) for fn in functions for block in fn['blocks']),
              'maximum_function_blocks': max(len(fn['blocks']) for fn in functions),
              'maximum_block_params': max(len(block['params']) for fn in functions for block in fn['blocks'])}
    if (limits['functions'] > 128 or limits['blocks'] > 1536 or limits['instructions'] > 8192
            or limits['maximum_function_blocks'] > 256 or limits['maximum_block_params'] > 16):
        raise ValueError({'original_compiler_limits_exceeded': limits})
    return doc


def main():
    root = Path(__file__).resolve().parents[1]
    for which, name in SOURCES.items():
        doc = document(which)
        path = root / name
        path.write_text(render_assembly(doc))
        print(which, len(doc['functions']), sum(len(fn['blocks']) for fn in doc['functions']),
              sum(len(b['ops']) for fn in doc['functions'] for b in fn['blocks']), path.stat().st_size,
              flush=True)


if __name__ == '__main__':
    main()

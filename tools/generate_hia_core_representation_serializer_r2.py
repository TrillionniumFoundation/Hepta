"""Share traversal and escaping while retaining both actual append policies.

The complete canonical document and a renderer subtree differ at exactly three
root tests. Those remain explicit scalar-controlled expressions. Checked
renderer appends still record their original workspace failure; the canonical
path retains its original direct store (including its possible trap).
"""
from __future__ import annotations

import argparse
import ast
import copy
import hashlib
import json
from pathlib import Path
import types

from hepta.hia_agent_assembly import render_assembly
from tools import generate_hia_core_representation_context as previous

SOURCE_PATH = 'examples/hia_bootstrap/core_representation_serializer_r2.hepta'
NONE = 18446744073709551615


def expr(text):
    return ast.parse(text, mode='eval').body


def structural(node):
    return ast.dump(ast.fix_missing_locations(node), include_attributes=False)


def source_program():
    before, report = previous.source_program()
    nodes = {node.name: copy.deepcopy(node) for node in before.body}
    fragment = nodes['render_render_fragment']
    canonical = nodes['canonical_canonical_json']
    start = next(i for i, stmt in enumerate(canonical.body)
                 if isinstance(stmt, ast.Assign) and ast.unparse(stmt.targets[0]) == 'node')
    assert ast.unparse(canonical.body[start]) == 'node = 0'
    assert ast.unparse(fragment.body[0]) == 'node = root'

    class CanonicalToFragment(ast.NodeTransformer):
        def __init__(self):
            self.counts = {'parent': 0, 'sibling': 0, 'finish': 0, 'byte': 0, 'string': 0}

        def visit_If(self, node):
            node = self.generic_visit(node)
            if ast.unparse(node.test) == f'parent != {NONE}':
                node.test = expr('node != root'); self.counts['parent'] += 1
            elif ast.unparse(node.test) == f'parent == {NONE}':
                node.test = expr('node == root'); self.counts['finish'] += 1
            return node

        def visit_Assign(self, node):
            node = self.generic_visit(node)
            if ast.unparse(node) == 'node = 0':
                node.value = ast.Name('root', ast.Load())
            elif ast.unparse(node) == 'sibling = render_get(w, record + 16)':
                node.value = expr(f'choose(node == root, {NONE}, render_get(w, record + 16))')
                self.counts['sibling'] += 1
            return node

        def visit_Call(self, node):
            node = self.generic_visit(node)
            if isinstance(node.func, ast.Name) and node.func.id in ('canonical_append_byte', 'canonical_append_string'):
                key = 'byte' if node.func.id.endswith('_byte') else 'string'
                self.counts[key] += 1
                node.func.id = 'render_append_' + key
            return node

    projection = CanonicalToFragment()
    projected = projection.visit(ast.Module(body=copy.deepcopy(canonical.body[start:]), type_ignores=[]))
    assert projection.counts == {'parent': 1, 'sibling': 1, 'finish': 1, 'byte': 7, 'string': 2}, projection.counts
    assert structural(projected) == structural(ast.Module(body=fragment.body, type_ignores=[]))

    # Escaping is identical apart from the selected append implementation.
    left = copy.deepcopy(nodes['canonical_append_string'])
    left.name = 'render_append_string'
    class AppendNames(ast.NodeTransformer):
        def visit_Call(self, node):
            node = self.generic_visit(node)
            if isinstance(node.func, ast.Name) and node.func.id == 'canonical_append_byte':
                node.func.id = 'render_append_byte'
            return node
    left = AppendNames().visit(left)
    assert structural(left) == structural(nodes['render_append_string'])

    class SharedCalls(ast.NodeTransformer):
        def visit_Call(self, node):
            node = self.generic_visit(node)
            if isinstance(node.func, ast.Name) and node.func.id in ('render_append_byte', 'render_append_string'):
                node.func.id = 'shared_emit_' + ('byte' if node.func.id.endswith('_byte') else 'string')
                node.args.append(ast.Name('checked', ast.Load()))
            return node

    shared = copy.deepcopy(fragment)
    shared.name = 'shared_serialize'
    shared.args.args.append(ast.arg('checked', ast.Name('u64', ast.Load())))
    root_counts = {'parent': 0, 'sibling': 0, 'finish': 0}
    class RootTests(ast.NodeTransformer):
        def visit_If(self, node):
            node = self.generic_visit(node)
            if ast.unparse(node.test) == 'node != root':
                node.test = expr(f'choose(checked == 1, node != root, parent != {NONE})')
                root_counts['parent'] += 1
            elif ast.unparse(node.test) == 'node == root':
                node.test = expr(f'choose(checked == 1, node == root, parent == {NONE})')
                root_counts['finish'] += 1
            return node
        def visit_Assign(self, node):
            node = self.generic_visit(node)
            if ast.unparse(node.targets[0]) == 'sibling':
                assert ast.unparse(node.value) == f'choose(node == root, {NONE}, render_get(w, record + 16))'
                node.value = expr(f'choose(checked == 1 and node == root, {NONE}, render_get(w, record + 16))')
                root_counts['sibling'] += 1
            return node
    shared = SharedCalls().visit(RootTests().visit(shared))
    assert root_counts == {'parent': 1, 'sibling': 1, 'finish': 1}
    escaping = copy.deepcopy(nodes['render_append_string'])
    escaping.name = 'shared_emit_string'
    escaping.args.args.append(ast.arg('checked', ast.Name('u64', ast.Load())))
    escaping = SharedCalls().visit(escaping)

    # Only fixed-call wrappers select the two original policies. No caller-
    # supplied node arena or mutable function pointer is added to the ABI.
    wrappers = ast.parse('''
def render_render_fragment(s:readbuf, o:mutbuf, w:mutbuf, root:u64) -> u64:
    return shared_serialize(s, o, w, root, 1)

def shared_emit_byte(o:mutbuf, w:mutbuf, value:u64, checked:u64) -> u64:
    if checked == 1:
        return render_append_byte(o, w, value)
    return canonical_append_byte(o, w, value)

def render_append_string(o:mutbuf, w:mutbuf, start:u64, size:u64) -> u64:
    return shared_emit_string(o, w, start, size, 1)
''').body
    canonical.body = canonical.body[:start] + ast.parse('return shared_serialize(s, o, w, 0, 0)').body
    nodes['canonical_canonical_json'] = canonical
    removed = {'render_render_fragment', 'canonical_append_string', 'render_append_string'}
    result = [node for name, node in nodes.items() if name not in removed] + wrappers + [shared, escaping]
    report['serializer_projection'] = {
        'exact_original_AST_comparison': True, 'explicit_root_differences': projection.counts,
        'escaping_body_exact_under_append_callee_projection': True,
        'both_original_append_functions_retained_unchanged': True,
        'canonical_decode_and_initial_cursor_prefix_retained_unchanged': True,
        'no_new_workspace_bytes_or_pointers': True,
        'fixed_internal_checked_values': [0, 1],
        'original_function_AST_sha256': {name: hashlib.sha256(structural(nodes[name]).encode()).hexdigest()
            for name in ('render_append_byte', 'canonical_append_byte')},
    }
    return ast.fix_missing_locations(ast.Module(body=result, type_ignores=[])), report


def document():
    namespace = dict(vars(previous.previous), source_program=source_program)
    doc, report = types.FunctionType(previous.previous.document.__code__, namespace)()
    doc['module'] = 'core_representation_serializer_r2'
    return doc, report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    doc, report = document()
    raw = render_assembly(doc).encode()
    assert len(raw) <= 1048576
    target = Path(__file__).resolve().parents[1] / SOURCE_PATH
    if args.check:
        assert target.read_bytes() == raw
    else:
        target.open('xb').write(raw)
    report['source_bytes'] = len(raw)
    report['max_block_parameters'] = max(len(b['params']) for f in doc['functions'] for b in f['blocks'])
    args.report.open('x').write(json.dumps(report, sort_keys=True, indent=2) + '\n')
    print(json.dumps({k: report[k] for k in ('functions', 'blocks', 'operations', 'source_bytes', 'max_block_parameters')}))


if __name__ == '__main__':
    main()

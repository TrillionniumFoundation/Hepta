"""Compose three complete pure-HIA representation policies in a fixed resident.

The initial revision only namespaces and shares complete identical function
bodies and signatures. It does not remove any semantic decision or change the
original helper implementations. A caller-owned request in workspace word 0
selects one of three fixed entries; there is no pointer or dynamic code input.
"""
from __future__ import annotations

import ast
import copy
import json
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools import generate_hia_file_render_frontend as frontend
from tools import generate_hia_core_json_bytes as canonical
from tools import generate_hia_assembly_reparse as reparser
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions

RENDER_MAGIC = int.from_bytes(b'HIARFR01', 'little')
REPARSE_MAGIC = int.from_bytes(b'HIARPR01', 'little')
CANONICAL_MAGIC = int.from_bytes(b'HIACJQ01', 'little')
DIAGNOSTIC_MAGIC = int.from_bytes(b'HIACJDQ1', 'little')
SOURCE_PATH = 'examples/hia_bootstrap/core_representation.hepta'


def group_nodes():
    return [('render', ast.parse(frontend.source_program()).body),
            ('canonical', canonical.source_program()),
            ('reparse', reparser.source_program().body)]


def source_program():
    originals = []
    roots = {}
    groups = {}
    for prefix, nodes in group_nodes():
        names = {node.name: prefix + '_' + node.name for node in nodes}
        assert len(names) == len(nodes)
        roots[prefix] = names[nodes[0].name]
        groups[prefix] = len(nodes)

        class Namespace(ast.NodeTransformer):
            def visit_Call(self, node):
                node = self.generic_visit(node)
                if isinstance(node.func, ast.Name) and node.func.id in names:
                    node.func.id = names[node.func.id]
                return node

        for original in nodes:
            node = Namespace().visit(copy.deepcopy(original))
            node.name = names[original.name]
            originals.append(node)
    by_name = {node.name: node for node in originals}
    assert len(by_name) == len(originals)
    aliases = {name: name for name in by_name}

    def mapped(node, mapping):
        class Calls(ast.NodeTransformer):
            def visit_Call(self, value):
                value = self.generic_visit(value)
                if isinstance(value.func, ast.Name) and value.func.id in mapping:
                    value.func.id = mapping[value.func.id]
                return value
        return ast.fix_missing_locations(Calls().visit(copy.deepcopy(node)))

    def key(node):
        node = copy.deepcopy(node)
        node.name = 'body'
        return ast.dump(node, include_attributes=False)

    passes = 0
    while True:
        passes += 1
        assert passes <= len(originals) + 1
        seen = {}
        updated = {}
        for node in originals:
            signature = key(mapped(node, aliases))
            updated[node.name] = seen.setdefault(signature, node.name)
        if updated == aliases:
            break
        aliases = updated
    unique = [mapped(node, aliases) for node in originals if aliases[node.name] == node.name]
    representatives = {node.name: node for node in unique}
    # Every original body must be exactly the selected representative after
    # only namespace/callee renaming. Signature, order and expressions remain.
    for node in originals:
        assert key(mapped(node, aliases)) == key(representatives[aliases[node.name]])
    entry = ast.parse(f'''
def representation(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) < 8:
        return 4294967293
    mode = {aliases['render_get']}(w, 0)
    if mode == {RENDER_MAGIC}:
        return {aliases[roots['render']]}(s, o, w)
    if mode == {REPARSE_MAGIC}:
        return {aliases[roots['reparse']]}(s, o, w)
    if mode == {CANONICAL_MAGIC} or mode == {DIAGNOSTIC_MAGIC}:
        return {aliases[roots['canonical']]}(s, o, w)
    return 4294967293
''').body[0]
    all_nodes = [entry] + unique
    names = {node.name for node in all_nodes}
    edges = {node.name: {call.func.id for call in ast.walk(node)
                        if isinstance(call, ast.Call) and isinstance(call.func, ast.Name)
                        and call.func.id in names} for node in all_nodes}
    reachable = {'representation'}
    pending = ['representation']
    while pending:
        name = pending.pop()
        for other in edges[name] - reachable:
            reachable.add(other)
            pending.append(other)
    kept = [node for node in all_nodes if node.name in reachable]
    report = {'original_groups': groups, 'original_functions': len(originals),
              'shared_complete_functions': len(originals) - len(unique),
              'unique_functions': len(unique), 'retained_with_dispatch': len(kept),
              'unreachable': sorted(names - reachable), 'aliases': aliases,
              'all_original_AST_signatures_and_bodies_equal_under_only_callee_projection': True,
              'shared_policy_branches_removed': False, 'deduplication_passes': passes,
              'semantic_Core_authority': False, 'aggregate_fits': False}
    return ast.fix_missing_locations(ast.Module(body=kept, type_ignores=[])), report


def document():
    source, report = source_program()
    nodes = source.body
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
    doc = compact_authoring_cfg({'schema': 'hepta.hia.program.v8',
                                'module': 'core_representation', 'functions': functions})
    report['functions'] = len(doc['functions'])
    report['blocks'] = sum(len(fn['blocks']) for fn in doc['functions'])
    report['operations'] = sum(len(block['ops']) for fn in doc['functions'] for block in fn['blocks'])
    report['source_function_names'] = names
    assert report['functions'] <= 128
    assert report['blocks'] <= 1536
    assert report['operations'] <= 8192
    return doc, report


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    doc, report = document()
    raw = render_assembly(doc).encode()
    assert len(raw) <= 1048576
    path = Path(__file__).resolve().parents[1] / SOURCE_PATH
    if args.check:
        assert path.read_bytes() == raw
    else:
        with path.open('xb') as stream:
            stream.write(raw)
    report['source_bytes'] = len(raw)
    with args.report.open('x') as stream:
        json.dump(report, stream, sort_keys=True, indent=2)
        stream.write('\n')
    print(json.dumps({k: report[k] for k in ('functions', 'blocks', 'operations',
                                            'original_functions', 'shared_complete_functions',
                                            'source_bytes')}))


if __name__ == '__main__':
    main()

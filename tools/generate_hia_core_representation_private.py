"""Private roundtrip resident; the complete public R7 image is retained.

Only the three controller requests HIARFR01, HIARPR01 and HIACIR01 enter this
separate image. The public normal/diagnostic requests are explicitly rejected.
All internal parsing/UTF-8/duplicate/integer/structure/bounds decisions remain.
The projection removes only branches that require the absent diagnostic entry,
then removes functions unreachable from the single fixed machine entry f0.
"""
from __future__ import annotations

import argparse
import ast
import copy
from hashlib import sha256
import json
from pathlib import Path
import types

from hepta.hia_agent_assembly import render_assembly
from tools import generate_hia_core_representation_internal as previous
from tools import generate_hia_core_representation_shared as author

SOURCE_PATH = 'examples/hia_bootstrap/core_representation_private.hepta'
INTERNAL_MAGIC = int.from_bytes(b'HIACIR01', 'little')
NORMAL_MAGIC = int.from_bytes(b'HIACJQ01', 'little')
DIAGNOSTIC_MAGIC = int.from_bytes(b'HIACJDQ1', 'little')


def structural(node):
    return ast.dump(ast.fix_missing_locations(copy.deepcopy(node)), include_attributes=False)


def expression(text):
    return ast.parse(text, mode='eval').body


class KnownBoolean(ast.NodeTransformer):
    """Simplify only booleans explicitly established by this projection."""
    def visit_If(self, node):
        node = self.generic_visit(node)
        if isinstance(node.test, ast.Constant) and type(node.test.value) is bool:
            return node.body if node.test.value else node.orelse
        return node

    def visit_BoolOp(self, node):
        node = self.generic_visit(node)
        values = []
        for value in node.values:
            if isinstance(value, ast.Constant) and type(value.value) is bool:
                if isinstance(node.op, ast.And):
                    if value.value:
                        continue
                    # All use sites have the established false condition first.
                    assert not values
                    return ast.Constant(False)
                assert isinstance(node.op, ast.Or)
                if not value.value:
                    continue
                assert not values
                return ast.Constant(True)
            values.append(value)
        if not values:
            return ast.Constant(isinstance(node.op, ast.And))
        if len(values) == 1:
            return values[0]
        node.values = values
        return node

    def visit_Call(self, node):
        node = self.generic_visit(node)
        if (isinstance(node.func, ast.Name) and node.func.id == 'choose'
                and len(node.args) == 3 and isinstance(node.args[0], ast.Constant)
                and type(node.args[0].value) is bool):
            # choose eagerly evaluates operands in this authoring language.
            # Only literal branches can therefore be removed here.
            assert all(isinstance(x, ast.Constant) for x in node.args[1:])
            return node.args[1 if node.args[0].value else 2]
        return node


def source_program():
    original, prior_report = previous.source_program()
    nodes = {node.name: copy.deepcopy(node) for node in original.body}
    before = {node.name: structural(node) for node in original.body}
    counts = {'dispatch': 0, 'canonical_header': 0, 'diagnostic_local': 0,
              'diagnostic_conditions': 0, 'private_arena_condition': 0,
              'unused_arena_calculation': 0}
    dispatch = nodes['representation']
    expected_dispatch = expression(f'mode == {NORMAL_MAGIC} or mode == {DIAGNOSTIC_MAGIC} or mode == {INTERNAL_MAGIC}')
    for statement in dispatch.body:
        if isinstance(statement, ast.If) and structural(statement.test) == structural(expected_dispatch):
            statement.test = expression(f'mode == {INTERNAL_MAGIC}')
            counts['dispatch'] += 1

    canonical = nodes['canonical_core_json_bytes']
    body = []
    for statement in canonical.body:
        text = ast.unparse(statement)
        if text == 'diagnostic = 0':
            counts['diagnostic_local'] += 1
        elif isinstance(statement, ast.If) and ast.unparse(statement.test) == f'render_get(w, 0) == {DIAGNOSTIC_MAGIC}':
            assert ast.unparse(statement.body[0]) == 'diagnostic = 1' and len(statement.body) == 1
            alternate, = statement.orelse
            assert ast.unparse(alternate.test) == f'render_get(w, 0) != {NORMAL_MAGIC} and render_get(w, 0) != {INTERNAL_MAGIC}'
            assert [ast.unparse(s) for s in alternate.body] == ['return 4294967293'] and not alternate.orelse
            body += ast.parse(f'if render_get(w, 0) != {INTERNAL_MAGIC}:\n    return 4294967293\n').body
            counts['canonical_header'] += 1
        elif text == 'arena_bound = 64 + bound * 56 + length(s)':
            counts['unused_arena_calculation'] += 1
        elif isinstance(statement, ast.If) and ast.unparse(statement.test) == 'arena_bound < 128 + (64 + 1) * 32':
            assert [ast.unparse(s) for s in statement.body] == ['arena_bound = 128 + (64 + 1) * 32'] and not statement.orelse
            counts['unused_arena_calculation'] += 1
        else:
            body.append(statement)
    canonical.body = body

    class InternalCanonical(ast.NodeTransformer):
        def visit_Compare(self, node):
            if ast.unparse(node) == 'diagnostic == 1':
                counts['diagnostic_conditions'] += 1
                return ast.Constant(False)
            return self.generic_visit(node)

        def visit_If(self, node):
            if ast.unparse(node.test) == f'render_get(w, 0) != {INTERNAL_MAGIC} and length(w) < arena_bound or length(o) < output_bound':
                node.test = expression('length(o) < output_bound')
                counts['private_arena_condition'] += 1
            return self.generic_visit(node)

    nodes['canonical_core_json_bytes'] = KnownBoolean().visit(InternalCanonical().visit(canonical))
    assert counts == {'dispatch': 1, 'canonical_header': 1, 'diagnostic_local': 1,
                      'diagnostic_conditions': 3, 'private_arena_condition': 1,
                      'unused_arena_calculation': 2}, counts
    assert all(not (isinstance(n, ast.Name) and n.id in ('diagnostic', 'arena_bound'))
               for n in ast.walk(nodes['canonical_core_json_bytes']))

    # The sole remaining entry calls install mode 1 for a complete decoder or
    # mode 0 for the admitted attrs slice. Each field is <2**24 and the wrapper
    # owns word8 until the original save/restore completes; no external caller
    # supplies an arena or a scanner context to f0.
    expected_calls = {
        'render_decode_json': 'shared_preflight_entry(s, w, o, length(s) << 24 | 281474976710656)',
        'reparse_attributes': 'shared_preflight_entry(s, o, w, start | end - start << 24)',
    }
    calls = {}
    for name, node in nodes.items():
        for call in ast.walk(node):
            if isinstance(call, ast.Call) and isinstance(call.func, ast.Name) and call.func.id == 'shared_preflight_entry':
                assert name not in calls
                calls[name] = ast.unparse(call)
    assert calls == expected_calls, calls
    mode = structural(expression('(render_get(w, 8) >> 48) & 3'))
    mode_counts = {}
    for name in ('shared_preflight', 'shared_string_token'):
        tally = {'Eq': 0, 'NotEq': 0}

        class AbsentDiagnosticMode(ast.NodeTransformer):
            def visit_Compare(self, node):
                if (structural(node.left) == mode and len(node.ops) == len(node.comparators) == 1
                        and isinstance(node.comparators[0], ast.Constant) and node.comparators[0].value == 2):
                    op = type(node.ops[0]).__name__
                    assert op in tally
                    tally[op] += 1
                    return ast.Constant(op == 'NotEq')
                return self.generic_visit(node)

        nodes[name] = KnownBoolean().visit(AbsentDiagnosticMode().visit(nodes[name]))
        mode_counts[name] = tally
    assert mode_counts == {'shared_preflight': {'Eq': 16, 'NotEq': 1},
                           'shared_string_token': {'Eq': 1, 'NotEq': 0}}, mode_counts

    # Exact function-call reachability from the one executable entry, not name
    # similarity or heuristic elimination. Every reachable validation remains.
    edges = {name: sorted({n.func.id for n in ast.walk(node)
                          if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id in nodes})
             for name, node in nodes.items()}
    reachable = {'representation'}
    while True:
        expanded = reachable | {callee for caller in reachable for callee in edges[caller]}
        if expanded == reachable:
            break
        reachable = expanded
    changed = sorted(name for name in nodes if structural(nodes[name]) != before[name])
    assert changed == ['canonical_core_json_bytes', 'representation', 'shared_preflight', 'shared_string_token']
    assert {'render_render_core', 'reparse_reparse', 'canonical_core_json_bytes',
            'canonical_njs_utf8', 'canonical_njs_validate', 'render_decode_json',
            'shared_preflight', 'shared_insert_key', 'shared_serialize'} <= reachable
    removed = sorted(set(nodes) - reachable)
    assert removed == ['canonical_cj_error', 'canonical_cj_integer_error',
                       'render_append_string', 'shared_string_reason'], removed
    original_nodes = {node.name: node for node in original.body}
    original_edges = {name: {n.func.id for n in ast.walk(node)
                            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id in original_nodes}
                      for name, node in original_nodes.items()}
    original_reachable = {'representation'}
    while True:
        expanded = original_reachable | {callee for caller in original_reachable for callee in original_edges[caller]}
        if expanded == original_reachable:
            break
        original_reachable = expanded
    assert 'render_append_string' not in original_reachable
    result = [nodes[node.name] for node in original.body if node.name in reachable]
    report = {'scope': 'distinct three-request private resident; complete public R7 retained separately',
              'before': prior_report, 'private_requests': ['HIARFR01', 'HIARPR01', 'HIACIR01'],
              'explicitly_rejected_public_requests': ['HIACJQ01', 'HIACJDQ1'],
              'public_request_compatibility_claimed': False, 'projection_counts': counts,
              'scanner_mode_projection_counts': mode_counts, 'remaining_scanner_context_calls': calls,
              'changed_functions': changed, 'unreachable_functions_removed': removed,
              'already_unreachable_in_complete_R7': sorted(set(removed) - original_reachable),
              'reachable_call_edges': {name: edges[name] for name in sorted(reachable)},
              'function_AST_sha256_before': {n: sha256(before[n].encode()).hexdigest() for n in sorted(nodes)},
              'function_AST_sha256_after': {n: sha256(structural(nodes[n]).encode()).hexdigest() for n in sorted(reachable)},
              'attrs_limits': {'nodes': 2048, 'depth': 16},
              'full_first_validation_retained': True, 'aggregate_fits': False,
              'matching_cold': False, 'whole': False}
    return ast.fix_missing_locations(ast.Module(body=result, type_ignores=[])), report


def document():
    namespace = dict(vars(author), source_program=source_program)
    doc, report = types.FunctionType(author.document.__code__, namespace)()
    doc['module'] = 'core_representation_private'
    return doc, report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--report', type=Path)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    doc, report = document()
    raw = render_assembly(doc).encode()
    assert len(raw) <= 1048576
    target = Path(__file__).resolve().parents[1] / SOURCE_PATH
    if args.check:
        assert target.read_bytes() == raw
    elif args.report is not None:
        target.open('xb').write(raw)
    else:
        target.write_bytes(raw)
    report['source_bytes'] = len(raw)
    report['max_block_parameters'] = max(len(b['params']) for f in doc['functions'] for b in f['blocks'])
    if args.report is not None:
        args.report.open('x').write(json.dumps(report, sort_keys=True, indent=2) + '\n')
    print(json.dumps({k: report[k] for k in ('functions', 'blocks', 'operations', 'source_bytes', 'max_block_parameters')}))


if __name__ == '__main__':
    main()

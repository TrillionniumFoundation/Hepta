"""Reuse one actual admitted arena inside one private canonical invocation.

The original first decode and njs_validate remain verbatim. Between that decode
and serialization the validator only reads the immutable input and the owned
arena. A second decode of those exact bytes would reconstruct the same arena
and scratch. This private successor serializes the actual first arena after
restoring its two original header fields. It is not a cross-call cache and does
not accept a serialized arena as authority. Direct public source assets stay
unchanged. Native and VM controls must establish ordinary-return full frames;
fuel/intermediate-state equality is expressly not asserted.
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
from tools import generate_hia_core_representation_serializer_r2 as previous

SOURCE_PATH = 'examples/hia_bootstrap/core_representation_admitted.hepta'


def structural(node):
    return ast.dump(ast.fix_missing_locations(node), include_attributes=False)


def source_program():
    before, report = previous.source_program()
    nodes = {n.name: copy.deepcopy(n) for n in before.body}
    core = nodes['canonical_core_json_bytes']
    wrapper = nodes['canonical_canonical_json']
    calls = [(n.name, c) for n in nodes.values() for c in ast.walk(n)
             if isinstance(c, ast.Call) and isinstance(c.func, ast.Name)
             and c.func.id == 'canonical_canonical_json']
    assert len(calls) == 1 and calls[0][0] == core.name
    produced = [i for i, s in enumerate(core.body)
                if isinstance(s, ast.Assign) and ast.unparse(s.targets[0]) == 'produced']
    assert len(produced) == 1
    at = produced[0]
    expected = ['render_put(w, 48, 262144)', 'render_put(w, 56, 64)',
                'produced = render_widen(canonical_canonical_json(s, o, w))']
    assert [ast.unparse(n) for n in core.body[at - 2:at + 1]] == expected
    # This is the actual header emitted by the decoder, not an author claim
    # passed from a caller. All existing validations above still execute.
    after = ast.parse('''
render_put(w, 48, 1)
render_put(w, 56, 0)
produced = render_widen(shared_serialize(s, o, w, 0, 0))
''').body
    original_body = copy.deepcopy(core.body)
    core.body[at - 2:at + 1] = after
    assert structural(ast.Module(body=original_body[:at - 2], type_ignores=[])) == structural(
        ast.Module(body=core.body[:at - 2], type_ignores=[]))
    assert structural(ast.Module(body=original_body[at + 1:], type_ignores=[])) == structural(
        ast.Module(body=core.body[at + 1:], type_ignores=[]))

    # Close the validator's actual dependency graph. Reads may still trap if
    # the already checked arena were invalid; the validator itself is retained.
    seen = set()
    pending = ['canonical_njs_validate']
    while pending:
        name = pending.pop()
        if name in seen:
            continue
        seen.add(name)
        node = nodes[name]
        for call in ast.walk(node):
            if not isinstance(call, ast.Call):
                continue
            assert isinstance(call.func, ast.Name)
            target = call.func.id
            if target in ('length', 'byte', 'choose'):
                continue
            assert target in nodes, target
            assert target not in ('render_put', 'render_store', 'store', 'fill_range')
            pending.append(target)
    for name in seen:
        assert not any(isinstance(call, ast.Call) and isinstance(call.func, ast.Name)
                       and call.func.id in ('store', 'fill_range') for call in ast.walk(nodes[name]))
    report['within_invocation_arena_reuse'] = {
        'removed_wrapper_AST_sha256': hashlib.sha256(structural(wrapper).encode()).hexdigest(),
        'first_decode_and_all_admission_statements_unchanged': True,
        'selected_integer_policy_and_all_original_header_checks_unchanged': True,
        'validator_read_only_dependency_closure': sorted(seen),
        'only_between_decode_and_serialization_writes': ['arena[48]=max_nodes', 'arena[56]=max_depth'],
        'new_restoration_of_successful_decoder_header': {'48': 1, '56': 0},
        'first_decoded_arena_not_caller_supplied': True,
        'source_and_three_buffer_nonalias_contract': 'fixed typed private resident call; no callback or concurrent mutation',
        'no_cross_invocation_state': True,
        'all_exit_or_step_count_equivalence_claimed': False,
        'ordinary_return_full_frames_tested': False,
    }
    result = [node for name, node in nodes.items() if name != 'canonical_canonical_json']
    return ast.fix_missing_locations(ast.Module(body=result, type_ignores=[])), report


def document():
    base = previous.previous.previous
    namespace = dict(vars(base), source_program=source_program)
    doc, report = types.FunctionType(base.document.__code__, namespace)()
    doc['module'] = 'core_representation_admitted'
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

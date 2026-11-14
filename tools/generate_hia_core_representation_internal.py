"""Add a distinct private actual-arena canonical request to the representation.

HIACJQ01 and HIACJDQ1 retain their original worst-case allocation admission.
HIACIR01 still performs the entire UTF-8/preflight/decoder/structure/integer
policy; the decoder itself admits its real node arena against the real span.
It supplies no arena, digest, or VerifiedProgram capability from the caller.
All three spans and every node/depth/ABI limit remain unchanged.
"""
from __future__ import annotations
import argparse
import ast
import copy
import json
from pathlib import Path
import types

from hepta.hia_agent_assembly import render_assembly
from tools import generate_hia_core_representation_admitted as previous

SOURCE_PATH = 'examples/hia_bootstrap/core_representation_internal.hepta'
INTERNAL_MAGIC = int.from_bytes(b'HIACIR01', 'little')
REQUEST_MAGIC = int.from_bytes(b'HIACJQ01', 'little')
DIAGNOSTIC_MAGIC = int.from_bytes(b'HIACJDQ1', 'little')


def expression(value):
    return ast.parse(value, mode='eval').body


def source_program():
    before, report = previous.source_program()
    nodes = [copy.deepcopy(n) for n in before.body]
    changes = {'dispatcher': 0, 'request_magic': 0, 'actual_arena': 0}
    for node in nodes:
        if node.name == 'representation':
            for statement in ast.walk(node):
                if isinstance(statement, ast.If) and ast.unparse(statement.test) == f'mode == {REQUEST_MAGIC} or mode == {DIAGNOSTIC_MAGIC}':
                    statement.test = expression(f'mode == {REQUEST_MAGIC} or mode == {DIAGNOSTIC_MAGIC} or mode == {INTERNAL_MAGIC}')
                    changes['dispatcher'] += 1
        elif node.name == 'canonical_core_json_bytes':
            for statement in ast.walk(node):
                if not isinstance(statement, ast.If):
                    continue
                old = ast.unparse(statement.test)
                if old == f'render_get(w, 0) != {REQUEST_MAGIC}':
                    statement.test = expression(f'render_get(w, 0) != {REQUEST_MAGIC} and render_get(w, 0) != {INTERNAL_MAGIC}')
                    changes['request_magic'] += 1
                elif old == 'length(w) < arena_bound or length(o) < output_bound':
                    statement.test = expression(f'(render_get(w, 0) != {INTERNAL_MAGIC} and length(w) < arena_bound) or length(o) < output_bound')
                    changes['actual_arena'] += 1
    assert changes == {'dispatcher': 1, 'request_magic': 1, 'actual_arena': 1}, changes
    report['internal_canonical_ABI'] = {
        'request_magic': 'HIACIR01', 'integer_policy_word8': '0 or at least640; unchanged',
        'reserved_request_words16_to63': 'zero; unchanged',
        'existing_public_normal_and_diagnostic_requests_unchanged': True,
        'exact_modified_conditions': changes,
        'actual_arena_guard': 'original decode_json: length(arena) >= 64 + actual_nodes*56 + length(input)',
        'same_actual_node_and_depth_and_key_table_limits': True,
        'same_full_UTF8_first_check_and_integer_policy': True,
        'same_decoder_source_and_all_first_error_logic': True,
        'independent_of_an_arena_supplied_by_caller': True,
        'whole_8MiB_domain_claimed': False,
        'all_actual_tests_executed': False,
    }
    return ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[])), report


def document():
    base = previous.previous.previous.previous
    namespace = dict(vars(base), source_program=source_program)
    doc, report = types.FunctionType(base.document.__code__, namespace)()
    doc['module'] = 'core_representation_internal'
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

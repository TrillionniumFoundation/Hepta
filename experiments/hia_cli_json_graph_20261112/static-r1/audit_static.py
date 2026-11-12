"""Read-only source/AST audit; never import candidate or repository modules.

Creates only this checkpoint's explicitly named derived reports. It does not
generate HIA, execute a Core VM, build/load native code, sort foreign inputs,
call the original CLI, or run a test suite.
"""
from __future__ import annotations

import ast
import difflib
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent
REPOSITORY = ROOT.parent / 'publication-cold-ingress-r1' / 'source'


def record(raw):
    return {
        'bytes': len(raw),
        'sha256': hashlib.sha256(raw).hexdigest(),
        'git_blob': hashlib.sha1(b'blob ' + str(len(raw)).encode('ascii') + b'\0' + raw).hexdigest(),
    }


def new_json(name, value):
    raw = (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + '\n').encode('ascii')
    with (ROOT / name).open('xb') as stream:
        stream.write(raw)
    return record(raw)


def main():
    expected = json.loads((ROOT / 'EXPECTED-REPOSITORY-PINS.json').read_bytes())
    repository = []
    python_trees = {}
    for original in expected['files']:
        path = original['path']
        raw = (REPOSITORY / path).read_bytes()
        actual = record(raw)
        if actual['git_blob'] != original['git_blob'] or actual['bytes'] != original['bytes']:
            raise ValueError('repository source identity mismatch: ' + path)
        repository.append({'path': path, 'mode': original['mode'], **actual})
        if path.endswith('.py'):
            python_trees[path] = ast.parse(raw, filename=path)

    reference = json.loads((ROOT / 'REFERENCE-PINS.json').read_bytes())
    references = []
    for original in reference['cpython'] + reference['timsort']['files']:
        raw = (ROOT / original['local']).read_bytes()
        actual = record(raw)
        for field in ('bytes', 'sha256', 'git_blob'):
            if actual[field] != original[field]:
                raise ValueError('primary source identity mismatch: ' + original['local'])
        references.append({'path': original['local'], **actual})

    candidate_path = 'inputs/tools/generate_hia_cli_json_text.py'
    candidate_raw = (ROOT / candidate_path).read_bytes()
    candidate_tree = ast.parse(candidate_raw, filename=candidate_path)
    assignment = next(node for node in candidate_tree.body
                      if isinstance(node, ast.Assign)
                      and len(node.targets) == 1
                      and isinstance(node.targets[0], ast.Name)
                      and node.targets[0].id == 'SOURCE')
    literal = ast.literal_eval(assignment.value)
    literal_tree = ast.parse(literal, filename=candidate_path + ':SOURCE')
    nodes = literal_tree.body
    if any(not isinstance(node, ast.FunctionDef) for node in nodes):
        raise ValueError('non-function in authoring literal')
    names = [node.name for node in nodes]
    if len(names) != len(set(names)):
        raise ValueError('duplicate authoring function')
    symbol_assignment = next(node for node in candidate_tree.body
                             if isinstance(node, ast.Assign)
                             and len(node.targets) == 1
                             and isinstance(node.targets[0], ast.Name)
                             and node.targets[0].id == 'SYMBOLS')
    symbols = {ast.literal_eval(key) for key in symbol_assignment.value.keys}
    arithmetic = (ast.Add, ast.Sub, ast.Mult, ast.BitAnd, ast.BitOr,
                  ast.BitXor, ast.LShift, ast.RShift)
    builtin_calls = {'length', 'byte', 'store', 'choose', 'format_render_binary64'}
    reads = []
    for node in nodes:
        parameters = [argument.arg for argument in node.args.args]
        locals_ = set(parameters)
        locals_.update(item.id for item in ast.walk(node)
                       if isinstance(item, ast.Name) and isinstance(item.ctx, ast.Store))
        unknown = {item.id for item in ast.walk(node)
                   if isinstance(item, ast.Name) and isinstance(item.ctx, ast.Load)}
        unknown -= locals_ | set(names) | symbols | builtin_calls | {'u32', 'u64', 'readbuf', 'mutbuf'}
        if unknown:
            raise ValueError('unbound static source names: ' + node.name + ':' + repr(sorted(unknown)))
        bad_arithmetic = [ast.dump(item) for item in ast.walk(node)
                          if isinstance(item, ast.BinOp) and not isinstance(item.op, arithmetic)]
        if bad_arithmetic:
            raise ValueError('unsupported existing-Builder operator: ' + node.name)
        if len(parameters) > 16:
            raise ValueError('source signature exceeds original 16 argument cap')
        reads.append({'function': node.name, 'parameters': parameters,
                      'returns': node.returns.id,
                      'ast_sha256': hashlib.sha256(ast.dump(node, include_attributes=False).encode()).hexdigest()})

    # Check the exact narrow mixed-width issue found by static inspection.
    finish = next(node for node in nodes if node.name == 'finish')
    counts = [item for item in ast.walk(finish) if isinstance(item, ast.Call)
              and isinstance(item.func, ast.Name) and item.func.id == 'choose']
    if len(counts) != 1 or ast.unparse(counts[0].args[0]) != 'widen(status) == 0':
        raise ValueError('status/count guard lost its explicit width conversion')

    original_cli = python_trees['hepta/cli.py']
    output = next(node for node in original_cli.body
                  if isinstance(node, ast.FunctionDef) and node.name == 'output_json')
    output_body = ast.get_source_segment((REPOSITORY / 'hepta/cli.py').read_text(), output)
    test_tree = python_trees['tests/test_hia_cli_native.py']
    population = []
    for cls in test_tree.body:
        if isinstance(cls, ast.ClassDef):
            for method in cls.body:
                if isinstance(method, ast.FunctionDef) and method.name.startswith('test_'):
                    population.append('tests.test_hia_cli_native.' + cls.name + '.' + method.name)

    diffs = []
    for name in ('encoder.py', '_json.c', 'listobject.c'):
        old = ROOT / 'reference/cpython-v3.14.4' / name
        new = ROOT / 'reference/cpython-v3.14.10' / name
        raw = ''.join(difflib.unified_diff(old.read_text().splitlines(keepends=True),
                                         new.read_text().splitlines(keepends=True),
                                         fromfile='v3.14.4/' + name,
                                         tofile='v3.14.10/' + name)).encode()
        destination = ROOT / ('CPYTHON-3.14.4-TO-3.14.10-' + name.replace('.', '-') + '.diff')
        with destination.open('xb') as stream:
            stream.write(raw)
        diffs.append({'path': destination.name, **record(raw)})

    report = {
        'schema': 'hia.cli-json.source-audit.v1',
        'status': 'STATIC_SOURCE_AUDIT_PASS_NOT_HIA_GENERATION_OR_PRODUCT_PASS',
        'source': {'head': expected['source_head'], 'tree': expected['source_tree']},
        'repository_files': repository,
        'primary_reference_files': references,
        'actual_repository_python_ast_parses': len(python_trees),
        'actual_candidate_python_ast_parse': True,
        'actual_candidate_literal_ast_parse': True,
        'candidate': {'path': candidate_path, **record(candidate_raw)},
        'authoring_literal': {'bytes': len(literal.encode()),
                             'sha256': hashlib.sha256(literal.encode()).hexdigest(),
                             'functions': reads,
                             'composed_format_program': 'not executed, composed or generated in this audit'},
        'narrow_static_checks': {
            'literal_function_names_unique': True,
            'literal_name_resolution_set_check': True,
            'literal_existing_Builder_binary_operator_set': True,
            'literal_parameter_counts_at_most_16': True,
            'finish_status_compare_explicit_u32_to_u64': True,
        },
        'not_checked_by_ast': ['control-flow liveness and full typed Core validity',
                               'generated function/block/SSA/edge limits',
                               'complete finite formatter composition',
                               'generated assembly or native bytes',
                               'runtime equivalence or all integer-limit behavior'],
        'original_public_body': output_body,
        'original_public_body_ast_sha256': hashlib.sha256(ast.dump(output, include_attributes=False).encode()).hexdigest(),
        'original_cli_test_method_ids_in_source_order': population,
        'original_cli_methods_loaded_or_executed': False,
        'runtime_version_diffs': diffs,
        'graph_protocol_status': 'DESIGN_ONLY_NOT_EXECUTABLE',
        'planned_trace_cases': len([case for group in json.loads((ROOT / 'TRACE-PLAN.json').read_bytes())['groups'] for case in group['cases']]),
        'planned_trace_cases_loaded': [],
        'planned_trace_cases_executed': [],
        'default_selection_changed': False,
        'native_compilation_or_execution': False,
        'complete_cli_equivalence_claimed': False,
        'prior_timsort_ack_or_ingress_state_changed': False,
    }
    result = new_json('SOURCE-AUDIT.json', report)
    print(json.dumps({'status': report['status'], 'report': result,
                      'repository_files': len(repository), 'reference_files': len(references),
                      'literal_functions': len(nodes), 'original_cli_ids': len(population),
                      'new_planned_trace_cases': report['planned_trace_cases']}))


if __name__ == '__main__':
    main()

"""Independent read-only v8 r2 source/receipt-format audit, no product calls."""
import ast
from hashlib import sha256
import json
from pathlib import Path
import sys
import zipfile

ROOT = Path('/workspace/scratch/hia-machine-encoder-native-20261111/source')
V8 = ROOT / 'experiments/hia_v67_qualification_runner_20261111'
CLI = Path('/workspace/scratch/hia-cli-control-revision2-20261111/source')
EVIDENCE = Path('/workspace/scratch/hia-cli-control-revision2-20261111/complete-development-r6-r1/fixtures/installed-control')
OUT = Path(__file__).resolve().parent
EXPECTED = {
    'run_hia_qualification_v8.py': '5b7a2dfb32fd7767c3c402d84b61c2773f7d863bd116c9a5ce28c4176c96d310',
    'native_owner_gates.py': 'a2d2a8f1ffcdf9032efc98f774f2f4e23bc94aaceb56f95a359b7d4442a1eb30',
    'check_v8_gate_controls.py': '522036f10265a94421663a514dbac25fa9f4bd5670d630547c2c32b1e5bcc123',
}


def pin(path):
    raw = path.read_bytes()
    return {'path': str(path), 'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}


def dump(node):
    return ast.dump(node, include_attributes=False)


def functions(tree):
    return {node.name: node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}


def assignments(tree, name):
    return [node for node in ast.walk(tree) if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == name for target in node.targets)]


def main():
    before = {name: pin(V8 / name) for name in EXPECTED}
    assert all(before[name]['sha256'] == expected for name, expected in EXPECTED.items())
    old = ast.parse((V8 / 'run_hia_qualification_v7_original.py').read_bytes())
    new = ast.parse((V8 / 'run_hia_qualification_v8.py').read_bytes())
    old_functions, new_functions = functions(old), functions(new)
    names = ('_pinned_state', 'file_record', 'suite', 'selected_journal_callers',
             'selected_machine_plan_callers', 'selected_json_wire_callers')
    preserved = {}
    for name in names:
        assert dump(old_functions[name]) == dump(new_functions[name]), name
        preserved[name] = sha256(dump(new_functions[name]).encode()).hexdigest()
    preserved_assignments = {}
    for name in ('reproduce_code', 'cold_completed', 'cold_ok', 'mandatory_gates'):
        left, right = assignments(old, name), assignments(new, name)
        assert list(map(dump, left)) == list(map(dump, right)), name
        preserved_assignments[name] = [sha256(dump(node).encode()).hexdigest() for node in right]
    old_groups, new_groups = [ast.literal_eval(assignments(tree, 'groups')[0].value) for tree in (old, new)]
    assert all(new_groups[name] == modules for name, modules in old_groups.items())
    assert set(new_groups) - set(old_groups) == {'json-wire-cache', 'cli'}
    for file, expected in {
        'guardian.py': 'd0b56d24905895ad59120f401d006badfdb1df5b3e0ab17a80e8414da78a1023',
        'process_owner_impl.py': '36946082b3345f45ee2b28f1f810a22936d182a586cd0404154dfb01b3bd53a2',
        'workflow_process.py': 'f3ebc453de2d2c9ecd3825547e301c122b6c7fa05af1aacd9103b8a67893ee80',
    }.items():
        assert pin(V8 / file)['sha256'] == expected
    frozen = ROOT / 'tests/fixtures/hia_machine_x64_e09.py.txt'
    remote = OUT / 'e09-hia_machine_x64.py'
    assert frozen.read_bytes() == remote.read_bytes()
    assert pin(frozen)['sha256'] == '8795fb4e5034673401f5f6a5a60e57872c48a3982dbdcb4d3b8198ee7b3f41a9'
    original = ast.parse(remote.read_bytes())
    current = ast.parse((ROOT / 'hepta/hia_machine_x64.py').read_bytes())
    old_classes = [node for node in original.body if isinstance(node, ast.ClassDef) and node.name == 'Code']
    new_classes = [node for node in current.body if isinstance(node, ast.ClassDef) and node.name == 'Code']
    assert len(old_classes) == len(new_classes) == 1
    a, b = old_classes[0], new_classes[0]
    removed = [node for node in b.body if isinstance(node, ast.FunctionDef) and node.name == '__new__']
    assert len(removed) == 1
    assert not any(isinstance(node, ast.FunctionDef) and node.name == '__new__' for node in a.body)
    b.body = [node for node in b.body if node not in removed]
    assert dump(a) == dump(b)
    old_methods = [node.name for node in a.body if isinstance(node, ast.FunctionDef)]
    for name in ('_reg', '_s32', '_condition'):
        assert dump(functions(original)[name]) == dump(functions(current)[name])
    for name in ('_REGISTERS', '_CONDITIONS', '_SYMBOL', 'MAX_CODE_BYTES'):
        assert list(map(dump, assignments(original, name))) == list(map(dump, assignments(current, name)))
    test_path = ROOT / 'tests/test_hia_machine_encoding_native.py'
    test_tree = ast.parse(test_path.read_bytes())
    assert ast.literal_eval(assignments(test_tree, 'RETAINED_SOURCE_SHA256')[0].value) == pin(remote)['sha256']
    cli_test = CLI / 'tests/test_hia_cli_native.py'
    assert pin(cli_test)['sha256'] == '177da1a1ce8ec570131bffb376305d27bf3143d6db07b645d7b27d8cbb991a4b'
    cli_tree = ast.parse(cli_test.read_bytes())
    cli_ids = [node.name + '.' + method.name for node in cli_tree.body if isinstance(node, ast.ClassDef)
               for method in node.body if isinstance(method, ast.FunctionDef) and method.name.startswith('test_')]
    assert len(cli_ids) == 17
    encoding_ids = [node.name + '.' + method.name for node in test_tree.body if isinstance(node, ast.ClassDef)
                    for method in node.body if isinstance(method, ast.FunctionDef) and method.name.startswith('test_')]
    assert len(encoding_ids) == 9
    actual = json.loads((EVIDENCE / 'report.json').read_bytes())
    observed = actual['installed_execution']
    assert actual['scope'] == 'EXPLICIT_DEVELOPMENT_ONLY'
    assert actual['status'] == 'PASS_INSTALLED_NATIVE_CLI_CONTROL'
    assert 'original_manifest' in actual and 'original_development_manifest' not in actual
    assert observed == json.loads((EVIDENCE / 'installed-execution.json').read_bytes())
    assert observed == json.loads((EVIDENCE / 'installed-execution.stdout').read_bytes())
    assert len(actual['processes']) == 3 and len(observed['calls']) == 8 and len(observed['refusals']) == 9
    assert set(observed['native_returns']) == {'control', 'format'} and all(observed['native_returns'].values())
    for row in actual['processes']:
        assert row['returncode'] == 0
        assert pin(EVIDENCE / (row['label'] + '.stdout'))['sha256'] == row['stdout_sha256']
        assert pin(EVIDENCE / (row['label'] + '.stderr'))['sha256'] == row['stderr_sha256']
    wheel = Path(actual['wheel']['path'])
    assert pin(wheel)['sha256'] == actual['wheel']['sha256']
    assert pin(wheel)['bytes'] == actual['wheel']['bytes']
    with zipfile.ZipFile(wheel) as archive:
        for name in ('control', 'format'):
            resource = 'examples/hia_bootstrap/cli_' + name + '.hiaasm'
            assert archive.namelist().count('hepta/_data/' + resource) == 1
            assert sha256(archive.read('hepta/_data/' + resource)).hexdigest() == actual['source_sha256_before'][name]
    after = {name: pin(V8 / name) for name in EXPECTED}
    assert before == after
    result = {
        'schema': 'hia.v8-r2-independent-static-review.v1', 'status': 'STATIC_REVIEW_CLEAR',
        'scope': 'READ_ONLY_SOURCE_AST_AND_EXISTING_DEVELOPMENT_RECEIPT_FORMAT',
        'product_or_cold_execution_performed': False, 'python': sys.version,
        'inputs_before': before, 'inputs_after': after,
        'v7_preserved_function_ast_sha256': preserved,
        'v7_preserved_assignments_ast_sha256': preserved_assignments,
        'v7_complete_groups_preserved': old_groups,
        'new_complete_groups': {name: new_groups[name] for name in ('json-wire-cache', 'cli')},
        'code_baseline': {
            'canonical_commit': 'e09c6faf5507fc4e38d8b7c36ba2650a1c0a10d6',
            'path': 'hepta/hia_machine_x64.py', 'remote_bytes_match_fixture': True,
            'raw_bytes': 11057, 'raw_sha256': pin(remote)['sha256'],
            'git_blob_sha1': '8e87bd317c5f61e00993bb0bf8d803c5385d6556',
            'retained_method_names': old_methods, 'retained_methods': len(old_methods),
            'only_removed_current_class_method': '__new__',
            'full_remaining_class_ast_equal_in_same_interpreter': True,
            'original_three_operand_helpers_and_four_constant_assignments_unchanged': True,
            'guard_source': pin(test_path)},
        'cli_producer': {'source': pin(cli_test), 'test_method_ids': cli_ids,
                         'actual_report': pin(EVIDENCE / 'report.json'),
                         'actual_report_scope': actual['scope'], 'field': 'original_manifest',
                         'processes': 3, 'calls': 8, 'refusals': 9,
                         'actual_native_return_counts': {k: len(v) for k,v in observed['native_returns'].items()},
                         'actual_development_receipt_relabelled_cold': False},
        'encoding_component_method_ids': encoding_ids,
        'review_conclusion': [
            'No blocking mismatch found between the reviewed current-source receipt gates and actual producer field shapes.',
            'New cold-bound CLI/encoding, cache and retained-caller conjunctions are mandatory; default or whole-stack qualification is not inferred.',
            'Old source reproduction, cold invocation, full-suite observer and three selected-caller validators remain AST-identical.',
            'The e09 reference guard fixes interpreter-specific ast.dump rendering without weakening any pre-existing Code method comparison.',
            'Actual Actions export, current-source cold/full execution and corresponding cold-built receipts remain separate pending work.'
        ]}
    (OUT / 'audit.json').write_text(json.dumps(result,sort_keys=True,indent=2) + '\n')
    print(json.dumps({'status': result['status'], 'retained_Code_methods': len(old_methods),
                      'cli_methods': len(cli_ids), 'encoding_methods': len(encoding_ids),
                      'product_or_cold_execution_performed': False}))


if __name__ == '__main__':
    main()

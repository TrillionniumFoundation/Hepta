"""Read/AST-check the isolated candidate; never import or execute its code."""
from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path


def seal(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'git_blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}


def read_json(path):
    return json.loads(path.read_bytes())


def main():
    root = Path(__file__).resolve().parents[1]
    base = read_json(root / 'BASE.json')
    source = Path(base['read_only_source'])
    checks = []
    def require(name, condition, **facts):
        checks.append({'name': name, 'ok': bool(condition), **facts})
        if not condition:
            raise AssertionError(name)
    require('fixed-base', base['commit'] == '0504beb11c0dae875d8590660c42488b7bc634fb'
            and base['tree'] == '596ab07e8813e4811a8dca51800cd51eb397aeb2')
    parsed = []
    for path in sorted((root / 'inputs').rglob('*.py')):
        raw = path.read_bytes()
        ast.parse(raw, filename=str(path))
        parsed.append({'path': str(path.relative_to(root)), **seal(raw)})
    require('three-authored-Python-files-parse-only', len(parsed) == 3)
    for row in base['physically_pinned_files']:
        actual = seal((source / row['path']).read_bytes())
        require('base-body:' + row['path'], all(actual[k] == row[k] for k in actual), **actual)
    upstream = read_json(root / 'reference/UPSTREAM.json')
    selected_bodies = []
    for row in upstream['versions']:
        version = row['version']
        raw = (root / 'reference' / ('sqlite-' + version) / 'util.c.original').read_bytes()
        selected = (root / 'inputs' / row['selected_file']).read_bytes()
        start, end = row['contiguous_byte_range']
        require('full-original-seal:' + version, seal(raw) == row['full_util_original'])
        require('selected-contiguous-region:' + version, raw[start:end] == selected
                and seal(selected) == row['selected'])
        fossil = (root / 'reference' / ('sqlite-' + version) / 'manifest.uuid.original').read_text().strip()
        require('original-Fossil-source-id:' + version, fossil == row['upstream_fossil_source_id'].split()[-1])
        adapter = (root / 'inputs/tests/fixtures/sqlite_varint' / version / 'adapter.c').read_bytes()
        require('adapter-seal:' + version, seal(adapter) == row['adapter'])
        selected_bodies.append(selected)
    require('two-complete-originals-byteequal', len(selected_bodies) == 2
            and selected_bodies[0] == selected_bodies[1])
    retained = read_json(root / 'reference/RETAINED-CONTROLS.json')
    old_ids = []
    for row in retained['files']:
        raw = (Path(retained['source_root']) / row['path']).read_bytes()
        actual = seal(raw)
        require('retained-whole-test-body:' + row['path'], all(actual[k] == row[k] for k in actual))
        module = ast.parse(raw)
        ids = [cls.name + '.' + method.name for cls in module.body if isinstance(cls, ast.ClassDef)
               for method in cls.body if isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef))
               and method.name.startswith('test_')]
        require('retained-test-IDs:' + row['path'], ids == row['test_ids_in_source_order'])
        old_ids.extend((row['path'], value) for value in ids)
    require('old-59-test-methods-preserved-not-executed', len(old_ids) == 59)
    test_path = root / 'inputs/tests/test_hia_sqlite_varint_source.py'
    test_raw = test_path.read_bytes()
    test_ast = ast.parse(test_raw)
    names = next(ast.literal_eval(node.value) for node in test_ast.body
                 if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'EXPECTED_NAMES' for t in node.targets))
    cls = next(node for node in test_ast.body if isinstance(node, ast.ClassDef) and node.name == 'SQLiteVarintSourceTests')
    ids = ['tests.test_hia_sqlite_varint_source.SQLiteVarintSourceTests.' + node.name
           for node in cls.body if isinstance(node, ast.FunctionDef) and node.name.startswith('test_')]
    plan = read_json(root / 'plan/PREEXECUTION-PLAN.json')
    require('new-eight-exact-ordered-source-IDs', len(ids) == 8 and len(names) == 8
            and ids == plan['source_request']['ordered_expected_ids']
            and [x.rsplit('.', 1)[1] for x in ids] == list(names))
    values = {0, 1, 2, 0x7f, 0x80, 0xff, 0x100, 0xffff, 0x10000,
              0xffffffff, 0x100000000, 0x7fffffffffffffff,
              0x8000000000000000, 0x8000000000000001,
              0xfffffffffffffffe, 0xffffffffffffffff}
    for bit in range(1, 64):
        values.update(((1 << bit) - 1, 1 << bit, (1 << bit) + 1))
    require('planned-191-values-not-run', len(values) == 191
            and [str(value) for value in sorted(values)] == plan['source_request']['boundary_u64_values_decimal'])
    families = plan['source_request']['expected_case_families']
    require('planned-1618-VM-returns-not-run', sum(families.values()) == 1618
            == plan['source_request']['expected_native_shaped_Core_VM_return_count'])
    require('exact-lexer-line-cap-expression', b'len(self.assembly.split("\\n")), 16384' in test_raw)
    author = ast.parse((root / 'inputs/tools/generate_hia_sqlite_varint.py').read_bytes())
    source_text = next(ast.literal_eval(node.value) for node in author.body if isinstance(node, ast.Assign)
                       and any(isinstance(t, ast.Name) and t.id == 'SOURCE' for t in node.targets))
    algorithm = ast.parse(source_text)
    require('six-HIA-authoring-functions-static', [node.name for node in algorithm.body] == [
        'sqlite_varint', 'decode_varint', 'encode_varint', 'input_word', 'control_word', 'write_word'])
    abi = read_json(root / 'inputs/hepta/hia_sqlite_varint_abi.json')
    require('six-actual-ABI-arguments-three-spans', abi['actual_abi_argument_count'] == 6
            and len(abi['native_arguments']) == 6 and abi['logical_span_count'] == 3)
    require('no-ready-or-functional-claim', plan['initial_request_ready'] is False
            and plan['functional_or_database_closure_claimed'] is False
            and plan['future_native_request']['status'] == 'NOT_FROZEN_OR_AUTHORIZED')
    result = {'schema': 'hia.sqlite-varint.static-readback.v1', 'status': 'STATIC_READBACK_PASS_ONLY',
              'checks': checks, 'check_count': len(checks), 'new_Python_AST_only': parsed,
              'base_read_file_count': len(base['physically_pinned_files']), 'old_test_method_count': len(old_ids),
              'new_source_test_count': len(ids), 'expected_VM_returns_unexecuted': 1618,
              'generation_Core_verification_VM_C_native_database_network_execution': False,
              'full_1686_source_rehash_performed_here': False}
    destination = root / 'audit/STATIC-READBACK.json'
    with destination.open('x', encoding='utf-8') as stream:
        json.dump(result, stream, indent=2, sort_keys=True)
        stream.write('\n')
    print(json.dumps({'path': str(destination), **seal(destination.read_bytes()),
                      'checks': len(checks), 'status': result['status']}))


if __name__ == '__main__':
    main()

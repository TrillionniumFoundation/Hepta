"""Prepare the fixed R16 Source + unchanged62 harness, without product execution."""
from __future__ import annotations
import ast
import base64
import difflib
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
R16 = HERE.parent
R14 = R16.parent / 'v97-union-r14/formal-preparation-r2'
BASE = R14 / 'harness'
OUT = HERE / 'harness'
PARENT = 'e613cadfac0449794711d49dffc95d871fe30139'
BRANCH = 'codex/hia-combined-source-parser-v103-r16-20261113-dda7'
PLAN_BLOB = 'cb22fcf729aab99441773428a10e83308380ff33'
IDS_BLOB = '616e1a0e6c9d27585d23474049ea0e65e5cfc45e'
DRIVER_BLOB = '1ce3ab5dc1513f0848de33e2589fef81473c19ef'


def encode(value):
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + '\n').encode()


def pin(raw):
    return {'bytes': len(raw), 'git_blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest(),
            'sha256': hashlib.sha256(raw).hexdigest(), 'mode': '100644'}


def put(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as stream:
        stream.write(raw)
    path.chmod(0o644)


def exactly(text, before, after):
    assert text.count(before) == 1, before
    return text.replace(before, after)


def tree(files):
    children, leaves = {}, []
    for name, mode, oid in files:
        first, separator, rest = name.partition('/')
        if separator:
            children.setdefault(first, []).append((rest, mode, oid))
        else:
            leaves.append((first, mode, oid, False))
    for name, rows in children.items():
        leaves.append((name, '40000', tree(rows), True))
    leaves.sort(key=lambda row: row[0].encode() + (b'/' if row[3] else b''))
    raw = b''.join(mode.encode() + b' ' + name.encode() + b'\0' + bytes.fromhex(oid)
                   for name, mode, oid, _ in leaves)
    return hashlib.sha1(b'tree ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()


def main():
    assert not OUT.exists()
    previous = json.loads((R14 / 'HARNESS-PUBLICATION-INTENT.json').read_bytes())
    assert previous['expected_harness_tree'] == '905608f4246645547ae551f2ea74b545dedb12a8'
    before = {}
    for name, expected in previous['files'].items():
        raw = (BASE / name).read_bytes()
        assert pin(raw) == expected, name
        before[name] = raw
    assert len(before) == 16
    after = dict(before)
    plan_raw = (R16 / 'harness/inputs/MATERIALIZATION-R16.json').read_bytes()
    ids_raw = (R16 / 'FORMAL-EXPECTED-IDS.json').read_bytes()
    driver_raw = (R16 / 'harness/tools/materialize_candidate_r16.py').read_bytes()
    assert pin(plan_raw)['git_blob'] == PLAN_BLOB and len(plan_raw) == 342530
    assert pin(ids_raw)['git_blob'] == IDS_BLOB and len(ids_raw) == 1280554
    assert pin(driver_raw)['git_blob'] == DRIVER_BLOB and len(driver_raw) == 54862
    plan, ids = json.loads(plan_raw), json.loads(ids_raw)
    old_ids = json.loads(before['inputs/FORMAL-EXPECTED-IDS.json'])
    assert ids['bounded_groups'] == old_ids['bounded_groups'] and ids['bounded_total'] == 62
    expected = ids['r16_expected_ordered_ids']
    assert len(expected) == len(set(expected)) == 1357
    projections = {'r15_expected_ordered_ids': 1356, 'r14_expected_ordered_ids': 1353,
                   'r13_expected_ordered_ids': 1352, 'r12_expected_ordered_ids': 1342,
                   'required_r11_ordered_projection': 1329, 'original_r10_r2_ordered_ids': 1319}
    for name, size in projections.items():
        original = ids[name]
        assert len(original) == len(set(original)) == size
        assert [test for test in expected if test in set(original)] == original
        if name in old_ids:
            assert original == old_ids[name], name
    assert len(plan['packets']) == 78 and type(plan['expected_authored_files']) is int and plan['expected_authored_files'] == 481
    assert len(plan['allowed_overrides']) == 230 and len(plan['generators']) == 134
    assert plan['source_registration']['selectors'] == ids['selectors'] and len(ids['selectors']) == 232
    old_plan = json.loads(before['inputs/MATERIALIZATION.json'])
    assert plan['packets'][:75] == old_plan['packets']
    assert plan['source_test_environment'] == dict(old_plan['source_test_environment'],
        HEPTA_HIA_REPRESENTATION_SOURCE_EVIDENCE='@EVIDENCE@/checks/hia-candidate-build-source/representation')
    after['inputs/MATERIALIZATION.json'] = plan_raw
    after['inputs/FORMAL-EXPECTED-IDS.json'] = ids_raw
    after['tools/materialize_candidate.py'] = driver_raw

    # The only materializer definition change is the already reviewed fourth
    # fixed, fresh external evidence location in source_gate.
    old_driver_ast, new_driver_ast = ast.parse(before['tools/materialize_candidate.py']), ast.parse(driver_raw)
    assert len(old_driver_ast.body) == len(new_driver_ast.body)
    driver_changed = []
    for old_node, new_node in zip(old_driver_ast.body, new_driver_ast.body):
        if ast.dump(old_node, include_attributes=False) != ast.dump(new_node, include_attributes=False):
            assert isinstance(old_node, ast.FunctionDef) and isinstance(new_node, ast.FunctionDef)
            assert old_node.name == new_node.name == 'source_gate'
            driver_changed.append(old_node.name)
    assert driver_changed == ['source_gate']

    runner_name = 'tools/run_parser_bounded.py'
    runner = before[runner_name].decode()
    substitutions = [
        ('len(rows) == 3121', 'len(rows) == 3133'),
        ("result['product_tests_executed'] == 1353", "result['product_tests_executed'] == 1357"),
        ("expected = ids['r14_expected_ordered_ids']", "expected = ids['r16_expected_ordered_ids']"),
        ("len(expected) == 1353", "len(expected) == 1357"),
        ("'required_original_projection': 1329, 'tests_run': 1353", "'required_original_projection': 1329, 'tests_run': 1357"),
        ("'hepta.r14-formal-parser-bounded.v1'", "'hepta.r16-formal-parser-bounded.v1'"),
        ('The original materializer, Source runner and product workflow are not modified.',
         'The Source runner and product workflow are unchanged; the fixed materializer adds only the reviewed fourth evidence location.'),
    ]
    for a, b in substitutions:
        runner = exactly(runner, a, b)
    old_projection_line = "    for key, count in (('r13_expected_ordered_ids', 1352), ('r12_expected_ordered_ids', 1342),\n"
    new_projection_line = "    for key, count in (('r15_expected_ordered_ids', 1356), ('r14_expected_ordered_ids', 1353),\n                       ('r13_expected_ordered_ids', 1352), ('r12_expected_ordered_ids', 1342),\n"
    runner = exactly(runner, old_projection_line, new_projection_line)
    inverse = exactly(runner, new_projection_line, old_projection_line)
    for a, b in reversed(substitutions):
        inverse = exactly(inverse, b, a)
    assert inverse.encode() == before[runner_name]
    after[runner_name] = runner.encode()
    fixed = json.loads(before['inputs/PARSER-CONTROLS.json'])
    old_fixed = json.loads(before['inputs/PARSER-CONTROLS.json'])
    fixed['schema'] = 'hepta.r16-formal-parser-controls.v1'
    fixed['materialization_plan'] = pin(plan_raw)
    fixed['materialization_driver'] = pin(driver_raw)
    fixed['expected_ids'] = pin(ids_raw)
    fixed['harness_files'][runner_name] = pin(after[runner_name])
    fixed['harness_files']['tools/materialize_candidate.py'] = pin(driver_raw)
    for name, wanted in fixed['repaired_source_files'].items():
        actual = pin((R16 / 'source' / name).read_bytes())
        assert all(actual[key] == wanted[key] for key in ('bytes', 'sha256', 'git_blob')), name
    for wanted in fixed['original_test_files']:
        actual = pin((R16 / 'source' / wanted['path']).read_bytes())
        assert all(actual[key] == wanted[key] for key in ('bytes', 'sha256', 'git_blob')), wanted['path']
    compiler = bytearray()
    for part in fixed['compiler']['parts']:
        raw = before[part['path']]
        decoded = base64.b64decode(raw, validate=True)
        for candidate, wanted in ((raw, part['encoded']), (decoded, part['decoded'])):
            assert all(pin(candidate)[k] == wanted[k] for k in ('bytes', 'sha256', 'git_blob'))
        compiler.extend(decoded)
    assert len(compiler) == 673413
    assert hashlib.sha256(compiler).hexdigest() == 'bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0'
    projected_fixed = json.loads(encode(fixed))
    for key in ('schema', 'materialization_plan', 'materialization_driver', 'expected_ids'):
        projected_fixed[key] = old_fixed[key]
    for name in (runner_name, 'tools/materialize_candidate.py'):
        projected_fixed['harness_files'][name] = old_fixed['harness_files'][name]
    assert projected_fixed == old_fixed
    after['inputs/PARSER-CONTROLS.json'] = encode(fixed)

    workflow_name = '.github/workflows/hia-combined-source.yml'
    workflow = before[workflow_name].decode()
    workflow_substitutions = [
        ('codex/hia-combined-source-parser-v97-r14-20261113-dda7', BRANCH),
        ('hia-combined-source-v97-r14', 'hia-combined-source-v103-r16'),
        ('hia-parser-bounded-v97-r14', 'hia-parser-bounded-v103-r16'),
        (pin(before['inputs/MATERIALIZATION.json'])['git_blob'], PLAN_BLOB),
        (pin(before['tools/materialize_candidate.py'])['git_blob'], DRIVER_BLOB),
        (pin(before['inputs/PARSER-CONTROLS.json'])['git_blob'], pin(after['inputs/PARSER-CONTROLS.json'])['git_blob']),
    ]
    for a, b in workflow_substitutions:
        assert a in workflow
        workflow = workflow.replace(a, b)
    inverse_workflow = workflow
    for a, b in reversed(workflow_substitutions):
        inverse_workflow = inverse_workflow.replace(b, a)
    assert inverse_workflow.encode() == before[workflow_name]
    after[workflow_name] = workflow.encode()
    changes = []
    for name in sorted(after):
        if after[name] != before[name]:
            changes.append({'path': name, 'before': pin(before[name]), 'after': pin(after[name]),
                            'diff': ''.join(difflib.unified_diff(before[name].decode().splitlines(keepends=True),
                                after[name].decode().splitlines(keepends=True), fromfile='R14/' + name, tofile='R16/' + name))})
        put(OUT / name, after[name])
        if name.endswith('.py'):
            compile(ast.parse(after[name], filename=name), name, 'exec', dont_inherit=True)
    assert len(changes) == 6
    manifest = {name: pin(raw) for name, raw in sorted(after.items())}
    root_tree = tree([(name, row['mode'], row['git_blob']) for name, row in manifest.items()])
    report = {'schema': 'hepta.r16-formal-harness-preparation.v1', 'status': 'AUTHORED_NOT_PUBLISHED_NOT_EXECUTED',
        'repository': 'TrillionniumFoundation/Hepta', 'branch': BRANCH, 'sole_parent': PARENT,
        'parent_harness_tree': previous['expected_harness_tree'],
        'files': manifest, 'expected_harness_tree': root_tree, 'file_count': 16, 'unchanged_files': 10,
        'changed_files': 6, 'plan': pin(plan_raw), 'expected_ids': pin(ids_raw),
        'parser_controls': pin(after['inputs/PARSER-CONTROLS.json']), 'source_file_count': 3133,
        'source_tree_before_real_regeneration': '6272c76d61e55393b665f7091d274720d50451ca',
        'source_expected': 1357, 'selectors': 232, 'generators': 134,
        'explicit_original_ordered_projections': projections, 'bounded_tests': 62,
        'bounded_groups': fixed['groups'], 'budgets': fixed['budgets'],
        'original_Source_timeout_seconds': 1800, 'original_workflow_timeout_minutes': 90,
        'original_workflow_inverse_projection_exact': True,
        'materializer_definition_changes': driver_changed, 'source_evidence_environment_keys': 4,
        'all62_helpers_unchanged': True, 'fixed_original_test_file_bytes_unchanged': True,
        'all9_parser_repair_file_pins_preserved': True, 'five_development_image_compiles_required': True,
        'same_actual314_packaging_and_installed_child': True, 'both_original_always_upload_steps_preserved': True,
        'R14_formal_Source_and62': 'Already terminal PASS; no transferred result to R16',
        'current_source_cold_qualification': False, 'whole_native': False, 'product_executions_during_preparation': 0,
        'commit_created': False, 'ref_created': False, 'requires_parent_review_before_publication': True}
    put(HERE / 'HARNESS-PUBLICATION-INTENT.json', encode(report))
    put(HERE / 'EXACT-DIFFS.json', encode({'changes': changes, 'runner_exact_substitutions': substitutions,
        'runner_added_projection': {'before': old_projection_line, 'after': new_projection_line},
        'workflow_metadata_only_substitutions': workflow_substitutions}))
    put(HERE / 'HARNESS-MANIFEST.json', encode(manifest))
    print(json.dumps({'status': report['status'], 'tree': root_tree, 'files': 16, 'changed': 6,
        'workflow': manifest[workflow_name], 'runner': manifest[runner_name], 'controls': report['parser_controls'],
        'intent': pin(encode(report))}, sort_keys=True), flush=True)


if __name__ == '__main__':
    main()

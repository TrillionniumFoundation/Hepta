"""Prepare the fixed R14 formal Source plus original62 harness; no execution or refs."""
from __future__ import annotations
import ast
import difflib
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
R14 = HERE.parent
OLD = R14.parent / 'v94-union-r12-r2'
BASE = OLD / 'formal-harness'
OUT = HERE / 'harness'
PARENT = 'b35ef1d4e53533f75f09ff46b7d88a1341c95546'
BRANCH = 'codex/hia-combined-source-parser-v97-r14-20261113-dda7'
PLAN_BLOB = 'df4dc7e7b204f280eb5250b91cb4a49c66c1d95a'
IDS_BLOB = '8e2560232f5c0b47eedaa417968866bdcfeb2893'


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
    previous = json.loads((OLD / 'HARNESS-PUBLICATION-INTENT.json').read_bytes())
    before = {}
    for name, expected in previous['files'].items():
        raw = (BASE / name).read_bytes()
        assert pin(raw) == expected, name
        before[name] = raw
    assert len(before) == 16
    after = dict(before)
    plan_raw = (R14 / 'harness/inputs/MATERIALIZATION-R14.json').read_bytes()
    ids_raw = (R14 / 'FORMAL-EXPECTED-IDS.json').read_bytes()
    assert pin(plan_raw)['git_blob'] == PLAN_BLOB and len(plan_raw) == 335324
    assert pin(ids_raw)['git_blob'] == IDS_BLOB and len(ids_raw) == 918822
    plan, ids = json.loads(plan_raw), json.loads(ids_raw)
    old_ids = json.loads(before['inputs/FORMAL-EXPECTED-IDS.json'])
    assert ids['bounded_groups'] == old_ids['bounded_groups'] and ids['bounded_total'] == 62
    expected = ids['r14_expected_ordered_ids']
    assert len(expected) == len(set(expected)) == 1353
    projections = {'r13_expected_ordered_ids': 1352, 'r12_expected_ordered_ids': 1342,
                   'required_r11_ordered_projection': 1329, 'original_r10_r2_ordered_ids': 1319}
    for name, size in projections.items():
        original = ids[name]
        assert len(original) == len(set(original)) == size
        assert [test for test in expected if test in set(original)] == original
    assert ids['r12_expected_ordered_ids'] == old_ids['r12_expected_ordered_ids']
    assert len(plan['packets']) == 75 and len(plan['expected_authored_files']) == 469
    assert len(plan['allowed_overrides']) == 226 and len(plan['generators']) == 131
    assert plan['source_registration']['selectors'] == ids['selectors'] and len(ids['selectors']) == 231
    after['inputs/MATERIALIZATION.json'] = plan_raw
    after['inputs/FORMAL-EXPECTED-IDS.json'] = ids_raw
    runner_name = 'tools/run_parser_bounded.py'
    runner = before[runner_name].decode()
    substitutions = [
        ('len(rows) == 3108', 'len(rows) == 3121'),
        ("result['product_tests_executed'] == 1342", "result['product_tests_executed'] == 1353"),
        ("expected = ids['r12_expected_ordered_ids']", "expected = ids['r14_expected_ordered_ids']"),
        ("len(expected) == 1342", "len(expected) == 1353"),
        ("'required_original_projection': 1329, 'tests_run': 1342", "'required_original_projection': 1329, 'tests_run': 1353"),
        ("'hepta.r12-r2-formal-parser-bounded.v1'", "'hepta.r14-formal-parser-bounded.v1'"),
    ]
    for a, b in substitutions:
        runner = exactly(runner, a, b)
    marker = "          'original1329 Source projection changed')\n"
    extra = """    for key, count in (('r13_expected_ordered_ids', 1352), ('r12_expected_ordered_ids', 1342),
                       ('original_r10_r2_ordered_ids', 1319)):
        retained = ids[key]
        check(len(retained) == len(set(retained)) == count and
              [name for name in expected if name in set(retained)] == retained,
              'fixed earlier Source ordered projection changed: ' + key)
"""
    runner = exactly(runner, marker, marker + extra)
    inverse = runner.replace(extra, '')
    for a, b in reversed(substitutions):
        inverse = exactly(inverse, b, a)
    assert inverse.encode() == before[runner_name]
    after[runner_name] = runner.encode()
    fixed = json.loads(before['inputs/PARSER-CONTROLS.json'])
    old_fixed = json.loads(before['inputs/PARSER-CONTROLS.json'])
    fixed['schema'] = 'hepta.r14-formal-parser-controls.v1'
    fixed['materialization_plan'] = pin(plan_raw)
    fixed['expected_ids'] = pin(ids_raw)
    fixed['harness_files'][runner_name] = pin(after[runner_name])
    assert fixed['materialization_driver']['git_blob'] == 'cfe319279641b124bcd724437857686f36d1aa07'
    assert after['tools/materialize_candidate.py'] == before['tools/materialize_candidate.py']
    for name, wanted in fixed['repaired_source_files'].items():
        actual = pin((R14 / 'source' / name).read_bytes())
        assert all(actual[key] == wanted[key] for key in ('bytes', 'sha256', 'git_blob')), name
    for wanted in fixed['original_test_files']:
        actual = pin((R14 / 'source' / wanted['path']).read_bytes())
        assert all(actual[key] == wanted[key] for key in ('bytes', 'sha256', 'git_blob')), wanted['path']
    projected_fixed = json.loads(encode(fixed))
    for key in ('schema', 'materialization_plan', 'expected_ids'):
        projected_fixed[key] = old_fixed[key]
    projected_fixed['harness_files'][runner_name] = old_fixed['harness_files'][runner_name]
    assert projected_fixed == old_fixed
    after['inputs/PARSER-CONTROLS.json'] = encode(fixed)
    workflow_name = '.github/workflows/hia-combined-source.yml'
    workflow = before[workflow_name].decode()
    workflow_substitutions = [
        ('codex/hia-combined-source-parser-v94-r12-r2-20261113-dda7', BRANCH),
        ('hia-combined-source-v94-r12-r2', 'hia-combined-source-v97-r14'),
        ('hia-parser-bounded-v94-r12-r2', 'hia-parser-bounded-v97-r14'),
        (pin(before['inputs/MATERIALIZATION.json'])['git_blob'], PLAN_BLOB),
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
                                after[name].decode().splitlines(keepends=True), fromfile='R12-R2/' + name, tofile='R14/' + name))})
        put(OUT / name, after[name])
        if name.endswith('.py'):
            compile(ast.parse(after[name], filename=name), name, 'exec', dont_inherit=True)
    assert len(changes) == 5
    manifest = {name: pin(raw) for name, raw in sorted(after.items())}
    root_tree = tree([(name, row['mode'], row['git_blob']) for name, row in manifest.items()])
    report = {'schema': 'hepta.r14-formal-harness-preparation.v1', 'status': 'AUTHORED_NOT_PUBLISHED_NOT_EXECUTED',
        'repository': 'TrillionniumFoundation/Hepta', 'branch': BRANCH, 'sole_parent': PARENT,
        'files': manifest, 'expected_harness_tree': root_tree, 'file_count': 16, 'unchanged_files': 11,
        'changed_files': 5, 'plan': pin(plan_raw), 'expected_ids': pin(ids_raw),
        'parser_controls': pin(after['inputs/PARSER-CONTROLS.json']), 'source_file_count': 3121,
        'source_tree_before_real_regeneration': '5ec5ee372b8e1dd50a15d317fe3615bef22baed2',
        'source_expected': 1353, 'selectors': 231, 'generators': 131,
        'explicit_original_ordered_projections': projections, 'bounded_tests': 62,
        'bounded_groups': fixed['groups'], 'budgets': fixed['budgets'],
        'original_Source_timeout_seconds': 1800, 'original_workflow_timeout_minutes': 90,
        'original_workflow_inverse_projection_exact': True, 'R14_materializer_unchanged': True,
        'all62_helpers_unchanged': True, 'fixed_original_test_file_bytes_unchanged': True,
        'all9_parser_repair_file_pins_preserved': True, 'five_development_image_compiles_required': True,
        'same_actual314_packaging_and_installed_child': True, 'both_original_always_upload_steps_preserved': True,
        'R13_incomplete_local_source_scope': 'UNKNOWN_INTERRUPTED; no inherited Source pass',
        'R12_R2_formal_Source_and62': 'Already terminal PASS; preserved historical result, not transferred to R14',
        'current_source_cold_qualification': False, 'whole_native': False, 'product_executions_during_preparation': 0,
        'commit_created': False, 'ref_created': False, 'requires_parent_review_before_publication': True}
    put(HERE / 'HARNESS-PUBLICATION-INTENT.json', encode(report))
    put(HERE / 'EXACT-DIFFS.json', encode({'changes': changes, 'runner_exact_substitutions': substitutions,
                                        'runner_added_projection_guard': extra,
                                        'workflow_metadata_only_substitutions': workflow_substitutions}))
    put(HERE / 'HARNESS-MANIFEST.json', encode(manifest))
    print(json.dumps({'status': report['status'], 'tree': root_tree, 'files': 16, 'changed': 5,
        'workflow': manifest[workflow_name], 'runner': manifest[runner_name], 'controls': report['parser_controls'],
        'intent': pin(encode(report))}, sort_keys=True), flush=True)


if __name__ == '__main__':
    main()

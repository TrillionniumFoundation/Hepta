"""Extend the exact R14 formal plan with the public and private residents."""
from __future__ import annotations
import ast
import base64
from copy import deepcopy
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import traceback
import zlib

ROOT = Path(__file__).resolve().parent
BASE = ROOT.parent / 'v97-union-r14'
spec = importlib.util.spec_from_file_location('h', ROOT.parent / 'v94-union-r12/prepare_plan_r12.py')
h = importlib.util.module_from_spec(spec)
spec.loader.exec_module(h)


def put(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as f:
        f.write(raw)
    assert path.read_bytes() == raw


def main():
    assert not (ROOT / 'harness').exists() and not (ROOT / 'input-blobs').exists()
    old_raw = (BASE / 'harness/inputs/MATERIALIZATION-R14.json').read_bytes()
    old = json.loads(old_raw)
    assert len(old['packets']) == 75 and len(old['allowed_overrides']) == 226
    original_authors = {r['path']: r for r in json.loads((BASE / 'harness/inputs/AUTHORING-R14.json').read_bytes())}
    assert len(original_authors) == old['expected_authored_files'] == 469
    before_manifest = json.loads((ROOT.parent / 'v102-union-r15/BASELINE-MANIFEST.json').read_bytes())
    after_manifest = json.loads((ROOT / 'SOURCE-MANIFEST.json').read_bytes())
    before = h.read_exact(ROOT.parent / 'v97-source-parser-r14-original/readback-r1/candidate-ci314', before_manifest)
    after = h.read_exact(ROOT / 'source', after_manifest)
    assert h.tree_hash(before_manifest) == '94ea52604a5e61806d9da98a20326111d3081a83'
    assert h.tree_hash(after_manifest) == '6272c76d61e55393b665f7091d274720d50451ca'
    changed = sorted(n for n in after if n not in before or after[n] != before[n])
    existing = sorted(n for n in changed if n in before)
    added = sorted(set(after) - set(before))
    assert len(existing) == 4 and len(added) == 12 and len(changed) == 16
    assert set(existing) <= set(original_authors) and not set(added) & set(original_authors)
    assert not set(changed) & {r['path'] for r in old['exact_retained'] + old['regeneration_seeds']}
    for n in existing:
        assert original_authors[n]['text'].encode() == before[n]
        assert original_authors[n]['sha'] == before_manifest[n]['git_blob']
    assert all(before[n] == after[n] for n in before if n.startswith('tests/'))
    workflow = after['.github/workflows/hia-core.yml'].decode()
    previous_workflow = before['.github/workflows/hia-core.yml'].decode()
    assert workflow.split('  native:\n', 1)[1] == previous_workflow.split('  native:\n', 1)[1]
    source = '  source:\n' + workflow.split('  source:\n', 1)[1].split('  native:\n', 1)[0]
    previous_source = '  source:\n' + previous_workflow.split('  source:\n', 1)[1].split('  native:\n', 1)[0]
    assert h.identity(previous_source.encode())['git_blob'] == old['source_registration']['after_fragment']['blob']
    generators = re.search(r'for component in (.*?); do', source).group(1).split()
    new_generators = ['assembly_reparse', 'core_representation_internal', 'core_representation_private']
    assert generators == old['generators'] + new_generators and len(generators) == 134
    selectors = re.findall(r"^\s*'(tests\.[^']+)',\s*$", source, re.MULTILINE)
    new_selector = 'tests.test_hia_core_representation_source.CoreRepresentationSourceTests'
    assert selectors == old['source_registration']['selectors'] + [new_selector] and len(selectors) == 232
    restored_source = source.replace(' ' + ' '.join(new_generators) + '; do', '; do', 1)
    restored_source = restored_source.replace(next(s for s in restored_source.splitlines(keepends=True) if new_selector in s), '', 1)
    restored_source = restored_source.replace(next(s for s in restored_source.splitlines(keepends=True) if 'HEPTA_HIA_REPRESENTATION_SOURCE_EVIDENCE:' in s), '', 1)
    assert restored_source == previous_source
    assert len(h.literal_assignment(after['tools/hia_selfhost_contract.py'], 'SOURCE_FILES')) == 1357
    assert len(h.literal_assignment(after['hepta/hia_agent_contract.py'], 'ENTRY_BUILD_FILES')) == 22
    assert len(h.literal_assignment(after['hepta/hia_agent_contract.py'], 'NATIVE_SOURCE_FILES')) == 92

    inherited_harness = h.file_inventory(BASE / 'harness')
    inherited_inputs = h.file_inventory(BASE / 'input-blobs')
    shutil.copytree(BASE / 'harness', ROOT / 'harness', copy_function=os.link)
    shutil.copytree(BASE / 'input-blobs', ROOT / 'input-blobs', copy_function=os.link)
    plan, authors = deepcopy(old), deepcopy(original_authors)
    chunks, rows = [], []
    for name in changed:
        row = {'path': name, 'before': before_manifest.get(name),
            'after': dict(after_manifest[name], text=after[name].decode())}
        if rows and len(h.encode({'files': rows + [row]})) > 630000:
            chunks.append(rows)
            rows = [row]
        else:
            rows.append(row)
    if rows:
        chunks.append(rows)
    new_packets = []
    for i, rows in enumerate(chunks):
        label = 'representation-components-integration-r16-' + str(i).zfill(2)
        raw = h.encode({'schema': 'hia.reviewed-joint-source-overlay.v1', 'label': label,
            'scope': 'R16_AUTHORED_NOT_FULLY_GENERATED_NOT_FULL_SOURCE_TESTED',
            'base_plan': h.identity(old_raw), 'actual_R14_base_tree': h.tree_hash(before_manifest),
            'prepared_R16_tree': h.tree_hash(after_manifest), 'files': rows, 'whole_native': False})
        assert len(raw) <= 650000
        pin = {'label': label, 'blob': h.identity(raw)['git_blob'], 'bytes': len(raw),
            'sha256': h.identity(raw)['sha256'], 'layout': 'array-after', 'files': len(rows)}
        put(ROOT / 'input-blobs' / (pin['blob'] + '.blob'), raw)
        plan['packets'].append(pin)
        new_packets.append(pin)
        for row in rows:
            name, value = row['path'], row['after']
            if name in authors:
                prior = authors[name]
                assert prior['sha'] == row['before']['git_blob']
                plan['allowed_overrides'].append({'path': name, 'from_packet': prior['packet'],
                    'to_packet': label, 'from': prior['sha'], 'to': value['git_blob']})
            authors[name] = {'path': name, 'text': value['text'], 'sha': value['git_blob'], 'bytes': value['bytes'],
                'mode': value['mode'], 'packet': label, 'packet_blob': pin['blob']}
    assert len(authors) == 481 and len(plan['allowed_overrides']) == 230
    assert plan['packets'][:75] == old['packets'] and plan['allowed_overrides'][:226] == old['allowed_overrides']
    for name, row in authors.items():
        if name in changed:
            assert row['text'].encode() == after[name]
        else:
            assert row == original_authors[name]
    plan['expected_authored_files'] = 481
    plan['generators'] = generators
    plan['source_contract']['declared_paths'] = 1357
    registration = plan['source_registration']
    registration['prior_after_fragment_r14'] = deepcopy(registration['after_fragment'])
    registration['after_fragment'] = dict(h.identity(source.encode()), blob=h.identity(source.encode())['git_blob'])
    registration['generators'], registration['selectors'] = generators, selectors
    registration['extra_selectors'].append(new_selector)
    registration['authored_counts'] = dict(generators=134, owner_loop_generators=134, selectors=232,
        actual_loaded_test_ids=None, actual_executed_tests=None)
    registration['prior_required_support_actions_r14'] = deepcopy(registration['required_support_actions'])
    registration['required_support_actions'] = [s.replace('all131 owner', 'all134 owner').replace('actual231 selectors', 'actual232 selectors')
        for s in registration['required_support_actions']]
    registration['notes'].append('R16 adds the separate complete public R7 representation, independent formatter inverse and private three-request R8 representation: twelve new paths, three generators, three ENTRY build assets and four Source controls in one new selector. Six author helpers are dependencies, not additional generator entries. Existing R14 test files and the entire original Native121 workflow remain byte-identical. No component Native/VM, installed, portable or cold result transfers to the combined source. R15 fixture failures and its three-control passing successor remain separate originals.')

    driver_before = (BASE / 'harness/tools/materialize_candidate_r14.py').read_bytes()
    driver = driver_before.decode()
    for old_text, new_text in [
        ('    process_name = "HEPTA_HIA_LINUX_PROCESS_SOURCE_EVIDENCE"\n',
         '    process_name = "HEPTA_HIA_LINUX_PROCESS_SOURCE_EVIDENCE"\n    representation_name = "HEPTA_HIA_REPRESENTATION_SOURCE_EVIDENCE"\n'),
        ('        process_name: "@EVIDENCE@/checks/hia-linux-process-source",\n',
         '        process_name: "@EVIDENCE@/checks/hia-linux-process-source",\n        representation_name: "@EVIDENCE@/checks/hia-candidate-build-source/representation",\n'),
        ('    locations = {candidate_name: evidence, portable_name: portable_evidence, process_name: process_evidence}\n',
         '    locations = {candidate_name: evidence, portable_name: portable_evidence, process_name: process_evidence,\n                 representation_name: evidence / "representation"}\n'),
        ('        "process_directory_created_by": "original process Source fixture",\n',
         '        "process_directory_created_by": "original process Source fixture",\n        "representation_directory_created_by": "new representation Source fixture",\n'),
    ]:
        assert driver.count(old_text) == 1, old_text
        driver = driver.replace(old_text, new_text)
    driver_raw = driver.encode()
    def definitions(raw):
        return {n.name: ast.dump(n, include_attributes=False) for n in ast.parse(raw).body
                if isinstance(n, (ast.FunctionDef, ast.ClassDef))}
    left, right = definitions(driver_before), definitions(driver_raw)
    assert [n for n in left if left[n] != right[n]] == ['source_gate']
    driver_path = 'tools/materialize_candidate_r16.py'
    put(ROOT / 'harness' / driver_path, driver_raw)
    driver_pin = dict(h.identity(driver_raw), path=driver_path, blob=h.identity(driver_raw)['git_blob'])
    plan['harness_files'].append(driver_pin)
    plan['source_test_environment']['HEPTA_HIA_REPRESENTATION_SOURCE_EVIDENCE'] = '@EVIDENCE@/checks/hia-candidate-build-source/representation'
    plan['source_evidence_capture_r16'] = {'driver': driver_pin, 'prior_driver': h.identity(driver_before),
        'changed_function_only': 'source_gate', 'all_other_definitions_AST_exact': True,
        'fixed_environment_keys': 4, 'new_buffers_captured_under_existing_candidate_archive': True,
        'original_source_runner_unchanged': True, 'original_1800_second_Source_limit_unchanged': True,
        'new_source_fixture_creates_its_fresh_directory': True, 'qualification': False}
    ids_raw = (ROOT / 'FORMAL-EXPECTED-IDS.json').read_bytes()
    ids = json.loads(ids_raw)
    assert ids['selectors'] == selectors and len(ids['r16_expected_ordered_ids']) == 1357
    for k in ('r15_expected_ordered_ids', 'r14_expected_ordered_ids', 'r13_expected_ordered_ids',
              'r12_expected_ordered_ids', 'required_r11_ordered_projection', 'original_r10_r2_ordered_ids'):
        assert [n for n in ids['r16_expected_ordered_ids'] if n in set(ids[k])] == ids[k]
    plan['r16_integration'] = {'base_plan': h.identity(old_raw), 'actual_formal_R14_tree': h.tree_hash(before_manifest),
        'prepared_source_tree': h.tree_hash(after_manifest), 'prepared_source_files': 3133,
        'changed_existing_paths': existing, 'new_paths': added, 'expected_ids': h.identity(ids_raw),
        'Source_expected': 1357, 'generators': 134, 'selectors': 232, 'resources': 213,
        'all_original_ordered_projections_required': True, 'entire_Native_workflow_byte_exact': True,
        'full_Source_executed': False, 'component_results_inherited': False, 'whole_native': False}
    permitted = {'allowed_overrides', 'expected_authored_files', 'generators', 'packets', 'source_contract',
                 'source_registration', 'source_test_environment', 'harness_files'}
    for k, value in old.items():
        assert k in permitted or plan[k] == value, k
    for group, pins in [('harness', inherited_harness), ('input-blobs', inherited_inputs)]:
        for name, pin in pins.items():
            assert h.identity((ROOT / group / name).read_bytes()) == pin
    author_raw = h.encode([authors[name] for name in sorted(authors)])
    plan_raw = h.encode(plan)
    put(ROOT / 'harness/inputs/AUTHORING-R16.json', author_raw)
    put(ROOT / 'harness/inputs/MATERIALIZATION-R16.json', plan_raw)
    put(ROOT / 'harness/inputs/SOURCE-R16-FRAGMENT.yml', source.encode())
    transport = h.encode({'schema': 'hia.zlib-complete-author-table.v1', 'rows': 481,
        'raw_bytes': len(author_raw), 'raw_git_blob': h.identity(author_raw)['git_blob'],
        'raw_sha256': h.identity(author_raw)['sha256'], 'payload': base64.b64encode(zlib.compress(author_raw, 9)).decode()})
    put(ROOT / 'AUTHORING-R16.zlib.json', transport)
    put(ROOT / 'AUTHORING-R16-INDEX.json', h.encode({'rows': 481, 'full_author_table': h.identity(author_raw),
        'transport': h.identity(transport), 'files': [{k: v for k, v in authors[name].items() if k != 'text'} for name in sorted(authors)]}))
    report = {'schema': 'hia.r16.formal-plan-preparation.v1', 'status': 'PREPARED_NOT_FULLY_GENERATED_NOT_FULL_SOURCE_TESTED',
        'base_plan': h.identity(old_raw), 'plan': h.identity(plan_raw), 'driver': driver_pin,
        'prepared_tree': h.tree_hash(after_manifest), 'source_files': 3133, 'authors': 481,
        'overrides': 230, 'packets': len(plan['packets']), 'new_packets': new_packets,
        'generators': 134, 'selectors': 232, 'Source_expected': 1357, 'resources': 213,
        'SOURCE_FILES': 1357, 'ENTRY': 22, 'NATIVE': 92, 'Core': 54, 'MECH': 54,
        'old_Native121_fragment_exact': True, 'source_environment_keys': 4,
        'inherited_harness': inherited_harness, 'inherited_inputs': inherited_inputs,
        'current_source_cold_qualified': False, 'whole_native': False}
    put(ROOT / 'PREPARATION.json', h.encode(report))
    assert h.read_exact(ROOT / 'source', after_manifest) == after
    print(json.dumps({k: report[k] for k in ('status', 'plan', 'prepared_tree', 'source_files', 'authors', 'overrides', 'packets', 'generators', 'Source_expected', 'whole_native')}))


if __name__ == '__main__':
    try:
        main()
    except BaseException:
        put(ROOT / 'PLAN-PREPARATION-FAILURE-R1.json', h.encode({'status': 'FAIL', 'traceback': traceback.format_exc(), 'whole_native': False}))
        raise

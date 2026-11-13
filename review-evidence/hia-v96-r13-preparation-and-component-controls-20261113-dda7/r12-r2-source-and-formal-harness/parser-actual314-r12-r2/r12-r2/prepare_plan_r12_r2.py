"""Prepare the exact R12 successor. No product import, generation or tests."""
from __future__ import annotations

import ast
import base64
from copy import deepcopy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import zlib

ROOT = Path(__file__).resolve().parent
BASE = ROOT.parent / 'v94-union-r12'
REPAIR = ROOT.parent / 'v94-cli-parser-context-r11-r2'
BASE_PLAN = 'ca0b2839afd68742ab68f3f0e433d8bc983c3ed0'
DRIVER = 'cfe319279641b124bcd724437857686f36d1aa07'

spec = importlib.util.spec_from_file_location('frozen_r12_prepare_helpers', BASE / 'prepare_plan_r12.py')
helpers = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helpers)
encode, identity, tree_hash, read_exact = helpers.encode, helpers.identity, helpers.tree_hash, helpers.read_exact


def put(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        assert path.is_file() and not path.is_symlink() and path.read_bytes() == value, path
        return
    with path.open('xb') as stream:
        stream.write(value)


def repair_identity(row):
    value = {k:v for k,v in row.items() if k != 'text'}
    assert value['mode'] == 0o644
    value['mode'] = '100644'
    return value


def original_groups():
    groups = {}
    observations = {}
    for group, label, count in [('original43', 'original43-r2', 43), ('source', 'source10-r3', 10), ('native', 'native9-r2', 9)]:
        folder = REPAIR / 'evidence' / label
        raw = (folder / 'REPORT.json').read_bytes()
        value = json.loads(raw)
        owner_raw = (REPAIR / 'evidence' / (label + '-owner') / 'owner.json').read_bytes()
        owner = json.loads(owner_raw)
        ids = value['loaded_ids']
        assert value['status'] == 'PASS' and value['source_unchanged'] is True
        assert len(ids) == len(set(ids)) == value['loaded'] == value['tests_run'] == count
        assert ids == value['started_ids'] == value['stopped_ids']
        assert not any(value[k] for k in ('loader_errors', 'errors', 'failures', 'skipped', 'expected_failures', 'unexpected_successes'))
        assert owner['status'] == 'OWNED_PROCESS_COMPLETED' and type(owner['returncode']) is int and owner['returncode'] == 0
        assert owner['qualification_seconds'] == 180 and owner['cleanup_seconds'] == 3
        assert owner['cleanup']['complete'] is True and owner['cleanup']['observed_echild'] is True
        before_raw, after_raw = (folder / 'SOURCE-BEFORE.json').read_bytes(), (folder / 'SOURCE-AFTER.json').read_bytes()
        assert before_raw == after_raw
        groups[group] = ids
        observations[group] = {'report': identity(raw), 'owner': identity(owner_raw),
            'source_before': identity(before_raw), 'source_after': identity(after_raw),
            'local_report': str(folder / 'REPORT.json'), 'status': value['status'],
            'tests_run': count, 'python': value['python'], 'wall_ns': value['wall_ns'],
            'qualification_transferred_to_formal_run': False}
        if group == 'original43':
            observations[group]['packaging_scope'] = value['packaging_scope']
            observations[group]['declared_packaging_interpreter'] = value['declared_packaging_interpreter']
            observations[group]['pure_314_packaging_qualified'] = False
    assert sum(map(len, groups.values())) == 62
    return groups, observations


def source_ids(groups, plan, after):
    original_path = ROOT.parent / 'v92-source-r10-r2-original/artifact/raw/checks/SOURCE-TESTS.json'
    raw = original_path.read_bytes()
    original = json.loads(raw)
    old = original['ordered_ids']
    assert original['status'] == 'PASS' and original['complete'] is True
    assert old == original['actual_started_ids'] == original['actual_stopped_ids']
    assert len(old) == len(set(old)) == original['expected'] == original['tests_run'] == 1319
    assert not any(original[k] for k in ('errors', 'failures', 'skipped', 'expected_failures', 'unexpected_successes'))
    assert all(not v for v in original['loader_errors'].values())
    prior = old + groups['source']
    assert len(prior) == len(set(prior)) == 1329
    declared = json.loads((BASE / 'REGISTRATION-SPEC.json').read_bytes())['Source_declared_added_ids']
    assert len(declared) == len(set(declared)) == 13
    expected = list(prior)
    for new_id in declared:
        assert new_id not in expected
        prefix = new_id.rsplit('.', 1)[0] + '.'
        matching = [i for i, value in enumerate(expected) if value.startswith(prefix)]
        if matching:
            start, end = matching[0], matching[-1] + 1
            assert matching == list(range(start, end))
            current = expected[start:end]
            assert current == sorted(current)
            expected[start:end] = sorted(current + [new_id])
        else:
            expected.append(new_id)
        module, cls, name = new_id.rsplit('.', 2)
        module_path = module.replace('.', '/') + '.py'
        body = ast.parse(after[module_path])
        target = next(node for node in body.body if isinstance(node, ast.ClassDef) and node.name == cls)
        assert any(isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name for node in target.body)
    assert len(expected) == len(set(expected)) == 1342
    prior_set = set(prior)
    assert [value for value in expected if value in prior_set] == prior
    assert [value for value in prior if value in set(old)] == old
    r11_selectors = json.loads((ROOT.parent / 'v93-union-r11/harness/inputs/MATERIALIZATION-R11.json').read_bytes())['source_registration']['selectors']
    assert r11_selectors == original['selectors'] + ['tests.test_hia_cli_discovery_routing_native.CliDiscoveryRoutingSourceTests']
    assert plan['source_registration']['selectors'] == r11_selectors + ['tests.test_hia_linux_file.LinuxFileSourceTests']
    return {'schema': 'hepta.fixed-r12-r2-source-and-parser-ids.v1',
        'source_scope': 'EXPECTED_ORDERED_IDS_NOT_AN_EXECUTION_RESULT',
        'original_r10_r2_report': identity(raw), 'original_r10_r2_ordered_ids': old,
        'required_r11_ordered_projection': prior, 'r12_expected_ordered_ids': expected,
        'r12_new_ids': declared, 'selectors': plan['source_registration']['selectors'],
        'bounded_groups': groups, 'bounded_total': 62}


def main():
    assert not (ROOT / 'harness').exists()
    baseline_raw = (BASE / 'SOURCE-MANIFEST.json').read_bytes()
    baseline = json.loads(baseline_raw)
    before = read_exact(BASE / 'source', baseline)
    assert len(before) == 3108 and tree_hash(baseline) == '06524acb76047fc271ab6b6597362fd5f3499d00'
    draft_raw = (REPAIR / 'handoff/SOURCE-REPAIR-R1.json').read_bytes()
    repair = json.loads(draft_raw)
    assert len(repair['changes']) == 9 and sum(row['authoring_source'] for row in repair['changes']) == 6
    groups, observations = original_groups()
    repair['status'] = 'LOCAL_ACTUAL314_62_CONTROLS_PASS_PURE314_FORMAL_PENDING'
    repair['local_completed_controls'] = observations
    repair['local_final_frozen_report_caveats'] = [
        'The local original43 packaging subprocess used the existing Python3.12 packaging-only override; test bodies and installed children used actual CPython3.14.4.',
        'Original43-r2 started while build-r4 was still completing. Both terminal results and original timings remain; no performance conclusion is drawn.',
        'Original failures and all earlier sources remain unchanged. This record does not reclassify them.',
        'This isolated repair is not a current-source cold qualification.']
    final_repair_raw = encode(repair)
    put(ROOT / 'SOURCE-REPAIR-FINAL.json', final_repair_raw)
    put(ROOT / 'LOCAL-CONTROLS.json', encode(observations))
    put(ROOT / 'BASELINE-MANIFEST.json', baseline_raw)
    if (ROOT / 'source').exists():
        assert read_exact(ROOT / 'source', baseline) == before
    else:
        shutil.copytree(BASE / 'source', ROOT / 'source')
    after = dict(before)
    for row in repair['changes']:
        name = row['path']
        assert row['before']['text'].encode() == before[name]
        assert repair_identity(row['before']) == identity(before[name])
        value = row['after']['text'].encode()
        assert value == (REPAIR / 'source' / name).read_bytes()
        assert repair_identity(row['after']) == identity(value)
        (ROOT / 'source' / name).write_bytes(value)
        after[name] = value
    changed = sorted(name for name in before if after[name] != before[name])
    assert set(changed) == {row['path'] for row in repair['changes']} and len(changed) == 9
    final = {name: identity(value) for name,value in after.items()}
    assert read_exact(ROOT / 'source', final) == after
    for row in repair['unchanged_original_test_files']:
        name = row['path']
        assert after[name] == before[name]
        assert identity(after[name])['git_blob'] == row['git_blob']
    put(ROOT / 'SOURCE-MANIFEST.json', encode(final))
    old_plan_raw = (BASE / 'harness/inputs/MATERIALIZATION-R12.json').read_bytes()
    assert identity(old_plan_raw)['git_blob'] == BASE_PLAN
    old_plan = json.loads(old_plan_raw)
    plan = deepcopy(old_plan)
    original_authors = {row['path']:row for row in json.loads((BASE / 'harness/inputs/AUTHORING-R12.json').read_bytes())}
    authors = deepcopy(original_authors)
    assert len(authors) == plan['expected_authored_files'] == 456
    assert len(plan['packets']) == 67 and len(plan['allowed_overrides']) == 189
    assert set(changed) <= set(authors)
    assert not set(changed) & {row['path'] for row in plan['exact_retained'] + plan['regeneration_seeds']}
    for name in changed:
        assert authors[name]['text'].encode() == before[name]
        assert authors[name]['sha'] == identity(before[name])['git_blob']

    shutil.copytree(BASE / 'input-blobs', ROOT / 'input-blobs', copy_function=os.link)
    shutil.copytree(BASE / 'harness', ROOT / 'harness', copy_function=os.link)
    # New output filenames below avoid writing through any inherited hard link.
    chunk = [{'path':name,'before':identity(before[name]),'after':dict(identity(after[name]),text=after[name].decode())} for name in changed]
    label = 'cli-parser-actual314-repair-r12-r2'
    normalized = {'schema':'hia.reviewed-joint-source-overlay.v1','label':label,
        'scope':'EXACT_ACTUAL314_PARSER_GRAPH_REPAIR_FORMAL_SOURCE_AND_62_PENDING',
        'base_plan':identity(old_plan_raw),'complete_before_after_repair':identity(final_repair_raw),
        'full_before_bytes_preserved':True,'original_test_files_unchanged':repair['unchanged_original_test_files'],
        'local_control_scope':observations,'matching_current_source_cold':False,'default_changed':False,
        'whole_native':False,'files':chunk}
    packet_raw = encode(normalized)
    assert len(packet_raw) <= 650000
    pin = {'label':label,'blob':identity(packet_raw)['git_blob'],'bytes':len(packet_raw),
        'sha256':identity(packet_raw)['sha256'],'layout':'array-after','files':len(chunk)}
    put(ROOT / 'input-blobs' / (pin['blob'] + '.blob'), packet_raw)
    plan['packets'].append(pin)
    for row in chunk:
        name, value = row['path'],row['after']
        previous = authors[name]
        plan['allowed_overrides'].append({'path':name,'from_packet':previous['packet'],
            'to_packet':label,'from':previous['sha'],'to':value['git_blob']})
        authors[name] = {'path':name,'text':value['text'],'sha':value['git_blob'],
            'bytes':value['bytes'],'mode':value['mode'],'packet':label,'packet_blob':pin['blob']}
    assert len(authors) == 456 and len(plan['packets']) == 68 and len(plan['allowed_overrides']) == 198
    ids = source_ids(groups, plan, after)
    ids_raw = encode(ids)
    put(ROOT / 'FORMAL-EXPECTED-IDS.json', ids_raw)
    workflow = '.github/workflows/hia-core.yml'
    assert before[workflow] == after[workflow]
    native_fragment = after[workflow].split(b'  native:\n', 1)[1]
    assert plan['source_contract']['declared_paths'] == 1332
    assert len(plan['generators']) == 126 and len(plan['source_registration']['selectors']) == 230
    assert plan['source_test_environment'] == {
        'HEPTA_HIA_CANDIDATE_BUILD_TEST_EVIDENCE':'@EVIDENCE@/checks/hia-candidate-build-source',
        'HEPTA_HIA_LINUX_PROCESS_SOURCE_EVIDENCE':'@EVIDENCE@/checks/hia-linux-process-source',
        'HEPTA_HIA_LINUX_STDIO_SOURCE_EVIDENCE':'@EVIDENCE@/checks/hia-linux-stdio-source'}
    integration = {'schema':'hepta.r12-r2-parser-integration.v1',
        'status':'AUTHORED_EXACT_OVERLAY_NOT_GENERATED_NOT_FORMALLY_EXECUTED',
        'base_plan':identity(old_plan_raw),'source_repair':identity(final_repair_raw),
        'base_manifest':identity(baseline_raw),'source_manifest':identity(encode(final)),
        'base_tree':tree_hash(baseline),'source_tree':tree_hash(final),'source_files':3108,
        'changes':{name:{'before':identity(before[name]),'after':identity(after[name])} for name in changed},
        'new_source_paths':[],'authoring_source_paths':[row['path'] for row in repair['changes'] if row['authoring_source']],
        'actual314_generated_paths':[row['path'] for row in repair['changes'] if not row['authoring_source']],
        'all_other_3099_source_bytes_and_modes_unchanged':True,
        'author_origin_classification':{'existing_packet_owned_overrides':9,'new_authors':0,
            'authors_before':456,'authors_after':456,'overrides_before':189,'overrides_after':198},
        'generator_count':126,'Source_selectors':230,'Source_expected':1342,
        'prior1329_required_as_ordered_projection':True,'expected_ids':identity(ids_raw),
        'SOURCE_FILES':1332,'ENTRY':14,'NATIVE':92,'all_resources':205,'Core':54,'MECH':53,
        'Native_steps':121,'Native_fragment_byte_identical':identity(native_fragment),
        'workflow_byte_identical':identity(after[workflow]),
        'R14_three_source_environments_unchanged':plan['source_test_environment'],
        'fixed_parser_control_groups':{name:len(value) for name,value in groups.items()},
        'formal_packaging_and_installed_children':'ACTUAL_SYS_EXECUTABLE_CPYTHON_3_14_4',
        'limits':repair['limits_unchanged'],'local_controls':observations,
        'prior_formal_R11_failure_unchanged':plan['prior_formal_source_failure_r11'],
        'prior_R11_failure_custody_proof':'16250b770c1a3822fcf33ba2506ba05d140fecea',
        'prior_R10R2_success_custody_proof':'a770ef1c1d285d359da03b2439f1286614701b48',
        'generation_executed':False,'product_tests_executed':0,'matching_current_source_cold':False,
        'whole_native':False,'old_13_file_CLI_actions_implemented':False}
    integration_raw = encode(integration)
    put(ROOT / 'INTEGRATION.json', integration_raw)
    plan['r12_r2_parser_repair'] = {'base_plan':identity(old_plan_raw),'integration':identity(integration_raw),
        'repair':identity(final_repair_raw),'source_tree':tree_hash(final),'changed_paths':changed,
        'source_files':3108,'expected_ids':identity(ids_raw),'Source_expected':1342,
        'required_prior_projection_count':1329,'mandatory_following_parser_tests':62,
        'full_source_then_bounded_controls_in_same_actual314_workflow':True,
        'local_control_scope':observations,'R11_original_failure_unchanged':True,
        'qualification_inherited':False,'generation_or_tests_run_on_this_combination':False,
        'default_changed':False,'matching_current_source_cold':False,'whole_native':False}
    for key in old_plan:
        if key not in ('packets','allowed_overrides'):
            assert plan[key] == old_plan[key], key
    assert plan['packets'][:67] == old_plan['packets']
    assert plan['allowed_overrides'][:189] == old_plan['allowed_overrides']
    plan_raw = encode(plan)
    put(ROOT / 'harness/inputs/MATERIALIZATION-R12-R2.json', plan_raw)
    author_raw = encode([authors[name] for name in sorted(authors)])
    put(ROOT / 'harness/inputs/AUTHORING-R12-R2.json', author_raw)
    compressed = zlib.compress(author_raw, 9)
    author_transport = encode({'schema':'hia.zlib-complete-author-table.v1','encoding':'base64+zlib',
        'raw_bytes':len(author_raw),'raw_sha256':identity(author_raw)['sha256'],
        'raw_git_blob':identity(author_raw)['git_blob'],'rows':len(authors),'payload':base64.b64encode(compressed).decode()})
    assert zlib.decompress(base64.b64decode(json.loads(author_transport)['payload'],validate=True)) == author_raw
    put(ROOT / 'AUTHORING-R12-R2.zlib.json', author_transport)
    put(ROOT / 'AUTHORING-R12-R2-INDEX.json', encode({'schema':'hia.complete-author-table-index.v1',
        'rows':len(authors),'full_author_table':identity(author_raw),'transport':identity(author_transport),
        'files':[{k:v for k,v in authors[name].items() if k != 'text'} for name in sorted(authors)]}))
    driver = (ROOT / 'harness/tools/materialize_candidate_r14.py').read_bytes()
    assert identity(driver)['git_blob'] == DRIVER
    for item in plan['harness_files']:
        raw = (ROOT / 'harness' / item['path']).read_bytes()
        assert len(raw) == item['bytes'] and identity(raw)['git_blob'] == item['blob']
    old_local = (BASE / 'run_local_generation_r12.py').read_text()
    local = old_local
    replacements = [('v94-union-r12','v94-union-r12-r2'),(BASE_PLAN,identity(plan_raw)['git_blob']),
        ('MATERIALIZATION-R12.json','MATERIALIZATION-R12-R2.json'),
        ('AUTHORING-R12.json','AUTHORING-R12-R2.json'),('all_67_source_packets_checked','all_68_source_packets_checked')]
    for left,right in replacements:
        assert local.count(left) == 1,(left,local.count(left))
        local = local.replace(left,right)
    projected = local
    for left,right in reversed(replacements):
        assert projected.count(right) == 1
        projected = projected.replace(right,left)
    assert projected == old_local
    ast.parse(local)
    put(ROOT / 'run_local_generation_r12_r2.py', local.encode())
    report = {'schema':'hepta.r12-r2-preparation.v1','status':'PREPARED_NOT_GENERATED_NOT_TESTED',
        'plan':identity(plan_raw),'driver':identity(driver),'integration':identity(integration_raw),
        'new_packets':[pin],'total_packets':68,'authors':456,'overrides':198,
        'source_tree':tree_hash(final),'source_files':3108,'changed_paths':changed,
        'new_paths':[],'ownership_collisions':[],'full_original_histories_unchanged':True,
        'source_registration_unchanged':True,'expected_ids':identity(ids_raw),
        'Source_expected':1342,'prior_source_projection':1329,'mandatory_parser_ids':62,
        'Native121_fragment':identity(native_fragment),'local_script':identity(local.encode()),
        'local_script_projection':replacements,'local_script_executed':False,
        'generation_executed':False,'product_tests_executed':0}
    put(ROOT / 'PREPARATION.json', encode(report))
    assert read_exact(BASE / 'source', baseline) == before
    assert read_exact(ROOT / 'source', final) == after
    print(json.dumps(report,indent=2,sort_keys=True))


if __name__ == '__main__':
    main()

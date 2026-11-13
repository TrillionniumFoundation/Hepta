"""Freeze R13 materialization inputs; never execute product modules here."""
from __future__ import annotations
import ast
import base64
from copy import deepcopy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import traceback
import zlib
import yaml

ROOT = Path(__file__).resolve().parent
BASE = ROOT.parent / 'v94-union-r12-r2'
spec = importlib.util.spec_from_file_location('prior_plan_helpers', ROOT.parent / 'v94-union-r12/prepare_plan_r12.py')
helpers = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helpers)
encode, identity, read_exact, tree_hash = helpers.encode, helpers.identity, helpers.read_exact, helpers.tree_hash
WORKFLOW = '.github/workflows/hia-core.yml'
OLD_PLAN = '2712736a2cfbdea235356b419b6813000277a995'
DRIVER = 'cfe319279641b124bcd724437857686f36d1aa07'

def put(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as stream:
        stream.write(raw)
    assert path.read_bytes() == raw

def main():
    assert not (ROOT / 'harness').exists() and not (ROOT / 'input-blobs').exists()
    capsule_raw = (ROOT / 'SOURCE-PACKET.zlib.json').read_bytes()
    wrapper = json.loads(capsule_raw)
    decoded = zlib.decompress(base64.b64decode(wrapper['payload'], validate=True))
    assert identity(decoded) == wrapper['decoded']
    packet = json.loads(decoded)
    integration_raw = (ROOT / 'INTEGRATION.json').read_bytes()
    integration = json.loads(integration_raw)
    assert packet['registration'] == integration
    before_manifest = json.loads((ROOT / 'BASELINE-MANIFEST.json').read_bytes())
    after_manifest = json.loads((ROOT / 'SOURCE-MANIFEST.json').read_bytes())
    assert before_manifest == packet['base_manifest'] and after_manifest == packet['current_manifest']
    assert len(before_manifest) == 3108 and len(after_manifest) == 3121
    assert tree_hash(before_manifest) == packet['base_tree'] == '49284c6dfdccd54ca67bdfc1bb5ac9c5ec728f19'
    assert tree_hash(after_manifest) == packet['current_tree'] == 'f9502ae42339254bd45d7910eb3d7319ab323dbd'
    before, after = read_exact(BASE / 'source', before_manifest), read_exact(ROOT / 'source', after_manifest)
    changed = sorted(name for name in after if before.get(name) != after[name])
    new_paths = sorted(set(after) - set(before))
    assert len(changed) == 28 and len(new_paths) == 13 and not set(before) - set(after)
    assert changed == sorted(integration['changes']) == sorted(row['path'] for row in packet['files'])
    for row in packet['files']:
        for key, source in [('before', before), ('after', after)]:
            name, value = row['path'], row[key]
            if value is None:
                assert name not in source
            else:
                assert value['text'].encode() == source[name]
                assert {k:v for k,v in value.items() if k != 'text'} == identity(source[name])
    old_plan_raw = (BASE / 'harness/inputs/MATERIALIZATION-R12-R2.json').read_bytes()
    assert identity(old_plan_raw)['git_blob'] == OLD_PLAN
    old_plan = json.loads(old_plan_raw)
    plan = deepcopy(old_plan)
    original_authors = {row['path']:row for row in json.loads((BASE / 'harness/inputs/AUTHORING-R12-R2.json').read_bytes())}
    authors = deepcopy(original_authors)
    assert len(authors) == old_plan['expected_authored_files'] == 456
    assert len(old_plan['packets']) == 68 and len(old_plan['allowed_overrides']) == 198
    existing = sorted(set(changed) & set(authors))
    first = sorted(set(changed) - set(authors))
    assert len(existing) == 15 and first == new_paths
    assert not set(changed) & {r['path'] for r in plan['exact_retained'] + plan['regeneration_seeds']}
    for name in existing:
        assert authors[name]['text'].encode() == before[name]
        assert authors[name]['sha'] == before_manifest[name]['git_blob']
        assert authors[name]['mode'] == after_manifest[name]['mode']
    workflow, old_workflow = after[WORKFLOW].decode(), before[WORKFLOW].decode()
    source, native = workflow.split('  native:\n', 1)
    old_source, old_native = old_workflow.split('  native:\n', 1)
    assert native == old_native and workflow.split('  source:\n',1)[0] == old_workflow.split('  source:\n',1)[0]
    jobs = yaml.safe_load(workflow)['jobs']
    assert len(jobs['native']['steps']) == 121
    generators = re.search(r'for component in (.*?); do', source).group(1).split()
    additions = ['selfhost_linux_file_render', 'linux_file_render_entry', 'file_render_frontend', 'file_render_checker', 'native_file_render']
    assert generators == plan['generators'] + additions and len(generators) == 131
    selectors = integration['workflow_projection']['selectors_after']
    assert selectors == plan['source_registration']['selectors'] + ['tests.test_hia_linux_file_render.LinuxFileRenderSourceTests']
    assert len(selectors) == 231
    fragment = '  source:\n' + workflow.split('  source:\n',1)[1].split('  native:\n',1)[0]
    old_fragment = '  source:\n' + old_workflow.split('  source:\n',1)[1].split('  native:\n',1)[0]
    assert identity(old_fragment.encode())['git_blob'] == plan['source_registration']['after_fragment']['blob']
    assert fragment.replace(' ' + ' '.join(additions) + '; do','; do',1).replace(
        next(line for line in fragment.splitlines(keepends=True) if selectors[-1] in line),'',1) == old_fragment
    contract = helpers.literal_assignment(after['tools/hia_selfhost_contract.py'], 'SOURCE_FILES')
    old_contract = helpers.literal_assignment(before['tools/hia_selfhost_contract.py'], 'SOURCE_FILES')
    assert len(contract) == len(set(contract)) == 1345 and len(old_contract) == 1332
    assert [name for name in contract if name in old_contract] == list(old_contract)
    assert set(contract) - set(old_contract) == set(new_paths)
    assert len(helpers.literal_assignment(after['hepta/hia_agent_contract.py'], 'ENTRY_BUILD_FILES')) == 19
    assert len(helpers.literal_assignment(after['hepta/hia_agent_contract.py'], 'NATIVE_SOURCE_FILES')) == 92
    assert len(helpers.literal_assignment(after['hepta/hia_checker_identity.py'], 'SEMANTIC_CORE_SOURCE_FILES')) == 54
    assert len(helpers.literal_assignment(after['hepta/hia_checker_identity.py'], 'MECHANISM_SOURCE_FILES')) == 54
    for name, evidence in integration['Source_method_preservation'].items():
        a, b = helpers.methods(before[name], name), helpers.methods(after[name], name)
        assert [key for key in b if key in a] == list(a)
        assert {key.rsplit('.',1)[1] for key in a if a[key][0] != b[key][0]} == set(evidence['changed_Source_methods'])
        assert [key for key in b if key not in a] == evidence['added_ids']
        assert all(b[key][1] >= a[key][1] for key in a)
    prior_ids_raw = (BASE / 'FORMAL-EXPECTED-IDS.json').read_bytes()
    prior_ids = json.loads(prior_ids_raw)
    ids = list(prior_ids['r12_expected_ordered_ids'])
    assert len(ids) == len(set(ids)) == 1342
    for new_id in integration['Source_added_ids']:
        assert new_id not in ids
        prefix = new_id.rsplit('.',1)[0] + '.'
        positions = [index for index,value in enumerate(ids) if value.startswith(prefix)]
        if positions:
            start, end = positions[0], positions[-1] + 1
            assert positions == list(range(start,end)) and ids[start:end] == sorted(ids[start:end])
            ids[start:end] = sorted(ids[start:end] + [new_id])
        else:
            ids.append(new_id)
        path = new_id.rsplit('.',2)[0].replace('.','/') + '.py'
        assert new_id in helpers.methods(after[path],path)
    assert len(ids) == len(set(ids)) == 1352
    for key in ('r12_expected_ordered_ids','required_r11_ordered_projection','original_r10_r2_ordered_ids'):
        assert [value for value in ids if value in set(prior_ids[key])] == prior_ids[key]
    ids_report = dict(deepcopy(prior_ids), schema='hia.fixed-r13-source-ids.v1', selectors=selectors,
        prior_r12_r2_ids=identity(prior_ids_raw), r13_expected_ordered_ids=ids, r13_added_ids=integration['Source_added_ids'])
    inherited_harness = helpers.file_inventory(BASE / 'harness')
    inherited_inputs = helpers.file_inventory(BASE / 'input-blobs')
    shutil.copytree(BASE / 'harness',ROOT / 'harness',copy_function=os.link)
    shutil.copytree(BASE / 'input-blobs',ROOT / 'input-blobs',copy_function=os.link)
    chunks, current = [], []
    for name in changed:
        row = {'path':name,'before':identity(before[name]) if name in before else None,
               'after':dict(identity(after[name]),text=after[name].decode())}
        if current and len(encode({'files':current + [row]})) > 635000:
            chunks.append(current)
            current = [row]
        else:
            current.append(row)
    if current:
        chunks.append(current)
    new_packets = []
    for index, chunk in enumerate(chunks):
        label = 'linux-file-render-v2-integration-r13-' + str(index).zfill(2)
        normalized = {'schema':'hia.reviewed-joint-source-overlay.v1','label':label,
            'scope':'AUTHORED_R13_FROZEN_FILE_RENDER_V2_NOT_GENERATED_NOT_TESTED',
            'component_integration_packet':identity(capsule_raw),'component_integration_report':identity(integration_raw),
            'base_plan':identity(old_plan_raw),'full_before_bytes_preserved_in_integration_capsule':True,
            'original_native121_fragment_exact':True,'whole_native':False,'files':chunk}
        payload = encode(normalized)
        assert len(payload) <= 650000, (label,len(payload))
        pin = dict(label=label,blob=identity(payload)['git_blob'],bytes=len(payload),sha256=identity(payload)['sha256'],layout='array-after',files=len(chunk))
        put(ROOT / 'input-blobs' / (pin['blob'] + '.blob'),payload)
        plan['packets'].append(pin)
        new_packets.append(pin)
        for row in chunk:
            name,value = row['path'],row['after']
            if name in authors:
                previous = authors[name]
                assert previous['sha'] == row['before']['git_blob']
                plan['allowed_overrides'].append(dict(path=name,from_packet=previous['packet'],to_packet=label,
                    **{'from':previous['sha'],'to':value['git_blob']}))
            authors[name] = dict(path=name,text=value['text'],sha=value['git_blob'],bytes=value['bytes'],mode=value['mode'],packet=label,packet_blob=pin['blob'])
    assert len(authors) == 469 and len(plan['allowed_overrides']) == 213
    assert plan['packets'][:68] == old_plan['packets'] and plan['allowed_overrides'][:198] == old_plan['allowed_overrides']
    for name,row in authors.items():
        assert row['text'].encode() == after[name]
        assert name in changed or row == original_authors[name]
    plan['expected_authored_files'] = 469
    plan['generators'] = generators
    registration = plan['source_registration']
    registration['prior_after_fragment_r12_r2'] = deepcopy(registration['after_fragment'])
    registration['after_fragment'] = dict(identity(fragment.encode()),blob=identity(fragment.encode())['git_blob'])
    registration['generators'],registration['selectors'] = generators,selectors
    registration['extra_selectors'].append(selectors[-1])
    registration['authored_counts'] = dict(generators=131,owner_loop_generators=131,selectors=231,actual_loaded_test_ids=None,actual_executed_tests=None)
    registration['prior_required_support_actions_r12_r2'] = deepcopy(registration['required_support_actions'])
    registration['required_support_actions'] = [value.replace('all126 owner','all131 owner').replace('actual230 selectors','actual231 selectors') for value in registration['required_support_actions']]
    registration['notes'].append('R13 adds the frozen v2 file renderer, five generators, thirteen source paths, five ENTRY assets, one explicit mechanism provider, nine component Source controls, and one SourceSuffix control. All old IDs, original assertion counts, and 121 Native workflow steps are retained. No component result transfers to this union, no old CLI action is retired, and no current-source cold qualification is claimed. R12-R2 historical parser records and failures remain exact.')
    plan['source_contract']['declared_paths'] = 1345
    ids_raw = encode(ids_report)
    plan['r13_integration'] = dict(integration_packet=identity(capsule_raw),integration_report=identity(integration_raw),
        base_plan=identity(old_plan_raw),source_tree=tree_hash(after_manifest),source_files=3121,changed_paths=changed,
        new_paths=new_paths,packet_owned_overrides=existing,expected_ids=identity(ids_raw),Source_expected=1352,
        prior1342_ordered_projection_required=True,prior1329_ordered_projection_required=True,prior1319_ordered_projection_required=True,
        generation_executed=False,product_tests_executed=0,component_results_inherited=False,whole_native=False,current_source_cold_qualified=False,
        full_13_cli_file_actions_replaced=False,default_changed=False)
    changed_keys = {'allowed_overrides','expected_authored_files','generators','packets','source_contract','source_registration'}
    for key,value in old_plan.items():
        assert key in changed_keys or plan[key] == value, key
    assert plan['source_test_environment'] == old_plan['source_test_environment'] and len(plan['source_test_environment']) == 3
    author_raw,plan_raw = encode([authors[name] for name in sorted(authors)]),encode(plan)
    put(ROOT / 'harness/inputs/AUTHORING-R13.json',author_raw)
    put(ROOT / 'harness/inputs/MATERIALIZATION-R13.json',plan_raw)
    put(ROOT / 'harness/inputs/SOURCE-R13-FRAGMENT.yml',fragment.encode())
    put(ROOT / 'FORMAL-EXPECTED-IDS.json',ids_raw)
    assert identity((ROOT / 'harness/tools/materialize_candidate_r14.py').read_bytes())['git_blob'] == DRIVER
    for group,values in [('harness',inherited_harness),('input-blobs',inherited_inputs)]:
        for name,pin in values.items():
            assert identity((ROOT / group / name).read_bytes()) == pin
    for pin in plan['harness_files']:
        raw = (ROOT / 'harness' / pin['path']).read_bytes()
        assert len(raw) == pin['bytes'] and identity(raw)['git_blob'] == pin['blob']
    transport = encode({'schema':'hia.zlib-complete-author-table.v1','encoding':'base64+zlib','rows':469,
        'raw_bytes':len(author_raw),'raw_sha256':identity(author_raw)['sha256'],'raw_git_blob':identity(author_raw)['git_blob'],
        'payload':base64.b64encode(zlib.compress(author_raw,9)).decode()})
    assert zlib.decompress(base64.b64decode(json.loads(transport)['payload'],validate=True)) == author_raw
    put(ROOT / 'AUTHORING-R13.zlib.json',transport)
    put(ROOT / 'AUTHORING-R13-INDEX.json',encode({'schema':'hia.complete-author-table-index.v1','rows':469,
        'full_author_table':identity(author_raw),'transport':identity(transport),
        'files':[{key:value for key,value in authors[name].items() if key != 'text'} for name in sorted(authors)]}))
    assert read_exact(ROOT / 'source',after_manifest) == after and read_exact(BASE / 'source',before_manifest) == before
    report = dict(schema='hia.r13.materialization-preparation.v1',status='PREPARED_NOT_GENERATED_NOT_TESTED',
        base_plan=identity(old_plan_raw),plan=identity(plan_raw),source_capsule=identity(capsule_raw),integration=identity(integration_raw),
        source_files=3121,source_tree=tree_hash(after_manifest),source_contract=1345,authors=469,overrides=213,new_packets=new_packets,
        total_packets=len(plan['packets']),generators=131,selectors=231,Source_expected=1352,expected_ids=identity(ids_raw),
        resources=210,ENTRY=19,NATIVE=92,Core=54,MECH=54,Native_steps=121,native_fragment=identity(native.encode()),
        driver_blob=DRIVER,changed_existing=15,new_paths=13,inherited_harness=inherited_harness,inherited_input_blobs=inherited_inputs,
        changed_old_plan_keys=sorted(changed_keys),historical_failure_records_exact=True,generation_executed=False,product_tests_executed=0,
        current_source_cold_qualified=False,default_changed=False,whole_native=False)
    put(ROOT / 'PREPARATION.json',encode(report))
    print(json.dumps({key:value for key,value in report.items() if key not in ('inherited_harness','inherited_input_blobs')},sort_keys=True),flush=True)

if __name__ == '__main__':
    try:
        main()
    except BaseException as error:
        put(ROOT / 'PREPARATION-FAILURE-R1.json',encode({'status':'FAIL','type':type(error).__name__,'error':str(error),'traceback':traceback.format_exc(),'whole_native':False}))
        raise

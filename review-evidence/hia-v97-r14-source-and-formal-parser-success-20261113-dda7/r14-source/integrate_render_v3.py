"""Integrate the exact frozen v3 delta into the actually generated R13 tree."""
from __future__ import annotations
import ast
import base64
from copy import deepcopy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import traceback
import zlib

ROOT = Path(__file__).resolve().parent
BASE = ROOT.parent / 'v96-union-r13'
INPUT = ROOT.parent / 'v95-audit-mount-r1/v96-render-v3'
spec = importlib.util.spec_from_file_location('fixed_preparation_helpers',ROOT.parent/'v94-union-r12/prepare_plan_r12.py')
h = importlib.util.module_from_spec(spec)
spec.loader.exec_module(h)
encode, identity, tree_hash = h.encode, h.identity, h.tree_hash

def put(path, raw):
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('xb') as stream:
        stream.write(raw)
    assert path.read_bytes() == raw

def unwrap(path, blob):
    raw = path.read_bytes()
    assert identity(raw)['git_blob'] == blob
    wrapper = json.loads(raw)
    decoded = zlib.decompress(base64.b64decode(wrapper['payload'],validate=True))
    assert identity(decoded) == wrapper['decoded']
    return raw,json.loads(decoded)

def replace_hardlink(path, raw):
    assert path.is_file() and not path.is_symlink()
    path.unlink()
    put(path,raw)

def main():
    assert not (ROOT/'source').exists() and not (ROOT/'base-source').exists()
    v2_raw,v2 = unwrap(ROOT.parent/'v95-native-file-render-r2/handoff-r3/SOURCE-PACKET.zlib.json',
        '120718a7f8b48bd267b82d3dd1a91bc32b2407dd')
    component_raw,component = unwrap(INPUT/'SOURCE-PACKET.zlib.json','d67e2799638faed73f8596dc4dbec66bcfd152e8')
    registration_raw,contract_raw = (INPUT/'spec.json').read_bytes(),(INPUT/'contract.json').read_bytes()
    assert identity(registration_raw)['git_blob'] == 'f30937be367c5d93962e636d55e0954d9571ff3d'
    assert identity(contract_raw)['git_blob'] == '59d26fb7d84ba82cebb1cef2b1c9741c75fac2e4'
    registration,contract = json.loads(registration_raw),json.loads(contract_raw)
    assert component['registration'] == registration and component['contract'] == contract
    assert component['prior_manifest'] == v2['current_manifest']
    assert component['prior_tree'] == v2['current_tree'] == 'cee29d828985f1c43b39eb11d68d931b0f7001f7'
    assert len(component['prior_manifest']) == len(component['current_manifest']) == 3121
    reconstructed = deepcopy(component['prior_manifest'])
    for name,value in component['files'].items():
        bp,ap = identity(value['before']['text'].encode()),identity(value['text'].encode())
        assert bp == {k:v for k,v in value['before'].items() if k!='text'} == reconstructed[name]
        assert ap == {k:v for k,v in value.items() if k not in ('before','text')} == component['current_manifest'][name]
        assert bp != ap
        reconstructed[name] = ap
    assert reconstructed == component['current_manifest']
    assert tree_hash(component['prior_manifest']) == component['prior_tree']
    assert tree_hash(reconstructed) == component['current_tree'] == '0a59f35ad40399f44287ece9011d6323c4535ce3'
    assert sorted(component['files']) == sorted(registration['delta_paths']) and len(component['files']) == 11
    assert registration['new_paths'] == registration['deleted_paths'] == []
    assert all(registration[k] == [] for k in ['ENTRY_BUILD_FILES_additions','MANIFEST_in_additions','SOURCE_FILES_additions','mechanism_or_provider_edge_additions'])
    root_component_proof = dict(schema='hia.root.file-render-v3-source-readback.v1',status='PASS',
        source_index='b5943f7db03bf0ea041733e179f0ee06c2926ffe',capsule=identity(component_raw),
        source_files=3121,changed_paths=sorted(component['files']),prior_tree=component['prior_tree'],current_tree=component['current_tree'],
        complete_before_after_bytes_verified=True,complete_manifests_and_both_trees_verified=True,whole_native=False)
    put(ROOT/'COMPONENT-ROOT-READBACK.json',encode(root_component_proof))
    gen_raw = (BASE/'local-generation-r1/evidence/raw/LOCAL-RESULT.json').read_bytes()
    gen = json.loads(gen_raw)
    assert gen['status'] == 'LOCAL_GENERATION_PASS' and gen['generation']['real_generation_passes'] == 2
    assert gen['generation']['generator_count'] == 131 and gen['generation']['tree'] == 'c6bab7f5054960a818dda0d8b19dc678952fd9fb'
    assert gen['python'].startswith('3.14.4 ') and gen['failures'] == []
    index_raw = (BASE/'local-generation-r1/evidence/raw/terminal-worktree/INDEX.json').read_bytes()
    index = json.loads(index_raw)
    assert len(index['files']) == 3121 and all(x['kind']=='regular' and x['mode']==0o644 for x in index['files'])
    baseline = {x['path']:{'bytes':x['bytes'],'git_blob':x['blob'],'mode':'100644','sha256':x['sha256']} for x in index['files']}
    assert len(baseline) == 3121 and tree_hash(baseline) == gen['generation']['tree']
    frozen = json.loads((BASE/'SOURCE-MANIFEST.json').read_bytes())
    before = h.read_exact(BASE/'source',frozen)
    assert set(before) == set(baseline)
    derived = sorted(name for name in baseline if frozen[name] != baseline[name])
    assert derived == ['docs/HIA_NATIVE_REWRITE_INVENTORY.json','docs/HIA_SELFHOST_CORE_SUPPORT.json','hepta/hia_checker_identity.py']
    for name in derived:
        result = subprocess.run(['git','--no-lazy-fetch','cat-file','blob',baseline[name]['git_blob']],
            cwd=BASE/'local-source-r1',capture_output=True,timeout=30)
        assert result.returncode == 0 and result.stderr == b'' and identity(result.stdout) == baseline[name]
        before[name] = result.stdout
    assert all(identity(raw) == baseline[name] for name,raw in before.items())
    after = dict(before)
    for name,value in component['files'].items():
        assert value['before']['text'].encode() == before[name], name
        after[name] = value['text'].encode()
    mapping_paths = ['tools/check_hia_core_only.py','tests/test_hia_source_suffix.py']
    for name in mapping_paths:
        old = before[name].decode()
        assert old.count('hepta.hia.linux-file-render.v2') == 1
        new = old.replace('hepta.hia.linux-file-render.v2','hepta.hia.linux-file-render.v3')
        assert new.replace('hepta.hia.linux-file-render.v3','hepta.hia.linux-file-render.v2') == old
        after[name] = new.encode()
    changed = sorted(name for name in after if before[name] != after[name])
    assert len(changed) == 13 and set(changed) == set(component['files']) | set(mapping_paths)
    assert before['.github/workflows/hia-core.yml'] == after['.github/workflows/hia-core.yml']
    role_counts = {}
    for path,key,count in [('tools/hia_selfhost_contract.py','SOURCE_FILES',1345),
        ('hepta/hia_agent_contract.py','ENTRY_BUILD_FILES',19),('hepta/hia_agent_contract.py','NATIVE_SOURCE_FILES',92),
        ('hepta/hia_checker_identity.py','SEMANTIC_CORE_SOURCE_FILES',54),('hepta/hia_checker_identity.py','MECHANISM_SOURCE_FILES',54)]:
        a,b = h.literal_assignment(before[path],key),h.literal_assignment(after[path],key)
        assert a == b and len(b) == count
        role_counts[key] = count
    method_review = {}
    for name in ['tests/test_hia_linux_file_render.py','tests/test_hia_source_suffix.py']:
        a,b = h.methods(before[name],name),h.methods(after[name],name)
        assert [key for key in b if key in a] == list(a)
        assert all(b[key][1] >= a[key][1] for key in a)
        method_review[name] = {'old_definition_ids':list(a),'new_ids':[key for key in b if key not in a],
            'changed_old_methods':{key:{'before':identity(a[key][0]),'after':identity(b[key][0]),
                'assertions_before':a[key][1],'assertions_after':b[key][1]} for key in a if a[key][0]!=b[key][0]},
            'all_other_old_method_bytes_exact':True,'old_assertion_counts_not_reduced':True}
    added = [x for value in method_review.values() for x in value['new_ids']]
    assert added == [registration['one_new_Source_id']]
    ids_raw = (BASE/'FORMAL-EXPECTED-IDS.json').read_bytes()
    expected = json.loads(ids_raw)
    old_ids = expected['r13_expected_ordered_ids']
    assert len(old_ids) == len(set(old_ids)) == 1352
    new_id = added[0]
    ids = list(old_ids)
    prefix = new_id.rsplit('.',1)[0]+'.'
    positions = [i for i,value in enumerate(ids) if value.startswith(prefix)]
    first,last = positions[0],positions[-1]+1
    assert positions == list(range(first,last)) and ids[first:last] == registration['old9_ordered_projection']
    ids[first:last] = sorted(ids[first:last]+[new_id])
    assert ids[first:first+10] == registration['actual10_ordered_ids'] and len(ids) == len(set(ids)) == 1353
    for key in ['r13_expected_ordered_ids','r12_expected_ordered_ids','required_r11_ordered_projection','original_r10_r2_ordered_ids']:
        assert [x for x in ids if x in set(expected[key])] == expected[key]
    expected.update(schema='hia.fixed-r14-source-ids.v1',r14_expected_ordered_ids=ids,r14_new_ids=added,
        prior_r13_expected_ids=identity(ids_raw),source_scope='EXPECTED_ORDERED_IDS_NOT_AN_EXECUTION_RESULT')
    shutil.copytree(BASE/'source',ROOT/'base-source',copy_function=os.link)
    for name in derived:
        replace_hardlink(ROOT/'base-source'/name,before[name])
    assert h.read_exact(ROOT/'base-source',baseline) == before
    shutil.copytree(ROOT/'base-source',ROOT/'source',copy_function=os.link)
    for name in changed:
        replace_hardlink(ROOT/'source'/name,after[name])
    current = {name:identity(raw) for name,raw in after.items()}
    assert h.read_exact(ROOT/'source',current) == after
    report = dict(schema='hia.r14.file-render-v3-integration.v1',status='AUTHORED_NOT_GENERATED_NOT_TESTED',
        base_tree=tree_hash(baseline),source_tree=tree_hash(current),source_files=3121,
        base_actual314_generation_result=identity(gen_raw),base_actual_generation_source_index=identity(index_raw),
        component_capsule=identity(component_raw),component_registration=identity(registration_raw),component_contract=identity(contract_raw),
        original_component_tree=component['prior_tree'],component_tree=component['current_tree'],
        changes={name:{'before':identity(before[name]),'after':identity(after[name])}for name in changed},
        extra_exact_profile_maps=mapping_paths,new_paths=[],deleted_paths=[],roles=role_counts,
        resources=210,generators=131,selectors=231,Source_expected=1353,Source_added_ids=added,
        method_review=method_review,entire_workflow_bytes_preserved=True,original_Native_steps=121,
        original_VM7_scope='V3 actual 6PASS1FAIL preserved; no inherited PASS',
        v3_development_results_inherited=False,base_generation_qualification_inherited=False,
        generation_executed=False,product_tests_executed=0,current_source_cold_qualified=False,whole_native=False)
    capsule = dict(schema='hia.r14.full-before-after-source-overlay.v1',base_tree=report['base_tree'],current_tree=report['source_tree'],
        base_manifest=baseline,current_manifest=current,registration=report,
        files=[{'path':name,'before':dict(identity(before[name]),text=before[name].decode()),
                'after':dict(identity(after[name]),text=after[name].decode())}for name in changed],whole_native=False)
    decoded = encode(capsule)
    wrapper = encode({'schema':'hia.lossless.zlib-json.v1','decoded':identity(decoded),'payload':base64.b64encode(zlib.compress(decoded,9)).decode()})
    for name,value in [('BASELINE-MANIFEST.json',baseline),('SOURCE-MANIFEST.json',current),('INTEGRATION.json',report),
        ('FORMAL-EXPECTED-IDS.json',expected),('REGISTRATION-SPEC.json',registration)]:
        put(ROOT/name,encode(value))
    put(ROOT/'SOURCE-PACKET.zlib.json',wrapper)
    assert h.read_exact(ROOT/'base-source',baseline) == before
    assert h.read_exact(BASE/'source',frozen) == {name:(BASE/'source'/name).read_bytes()for name in frozen}
    print(json.dumps({key:report[key]for key in ['status','base_tree','source_tree','source_files','generators','selectors','Source_expected','new_paths','entire_workflow_bytes_preserved','whole_native']},sort_keys=True),flush=True)

if __name__ == '__main__':
    try:
        main()
    except BaseException as error:
        put(ROOT/'INTEGRATION-FAILURE-R1.json',encode({'status':'FAIL','type':type(error).__name__,'error':str(error),'traceback':traceback.format_exc(),'whole_native':False}))
        raise

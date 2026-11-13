"""Normalize the frozen R14 source delta, preserving every historical packet."""
from pathlib import Path
from copy import deepcopy
import base64
import importlib.util
import json
import os
import shutil
import traceback
import zlib

ROOT = Path(__file__).resolve().parent
BASE = ROOT.parent/'v96-union-r13'
spec = importlib.util.spec_from_file_location('fixed_helpers',ROOT.parent/'v94-union-r12/prepare_plan_r12.py')
h = importlib.util.module_from_spec(spec)
spec.loader.exec_module(h)
encode, identity = h.encode,h.identity

def put(path,raw):
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('xb') as f:f.write(raw)
    assert path.read_bytes() == raw

def main():
    assert not (ROOT/'harness').exists() and not (ROOT/'input-blobs').exists()
    before_manifest = json.loads((ROOT/'BASELINE-MANIFEST.json').read_bytes())
    after_manifest = json.loads((ROOT/'SOURCE-MANIFEST.json').read_bytes())
    before = h.read_exact(ROOT/'base-source',before_manifest)
    after = h.read_exact(ROOT/'source',after_manifest)
    assert len(before) == len(after) == 3121 and set(before) == set(after)
    assert h.tree_hash(before_manifest) == 'c6bab7f5054960a818dda0d8b19dc678952fd9fb'
    assert h.tree_hash(after_manifest) == '5ec5ee372b8e1dd50a15d317fe3615bef22baed2'
    integration_raw = (ROOT/'INTEGRATION.json').read_bytes()
    integration = json.loads(integration_raw)
    changed = sorted(name for name in after if after[name] != before[name])
    assert changed == sorted(integration['changes']) and len(changed) == 13
    capsule_raw = (ROOT/'SOURCE-PACKET.zlib.json').read_bytes()
    wrapper = json.loads(capsule_raw)
    decoded = zlib.decompress(base64.b64decode(wrapper['payload'],validate=True))
    assert identity(decoded) == wrapper['decoded']
    capsule = json.loads(decoded)
    assert capsule['base_manifest'] == before_manifest and capsule['current_manifest'] == after_manifest
    assert capsule['registration'] == integration
    for row in capsule['files']:
        for key,data in [('before',before),('after',after)]:
            value = row[key]
            assert value['text'].encode() == data[row['path']]
            assert {k:v for k,v in value.items()if k!='text'} == identity(data[row['path']])
    old_raw = (BASE/'harness/inputs/MATERIALIZATION-R13.json').read_bytes()
    assert identity(old_raw)['git_blob'] == '97daf30bf0ff5abd42e27329756b7b6ad585937a'
    old = json.loads(old_raw)
    plan = deepcopy(old)
    original = {r['path']:r for r in json.loads((BASE/'harness/inputs/AUTHORING-R13.json').read_bytes())}
    authors = deepcopy(original)
    assert len(authors) == old['expected_authored_files'] == 469
    assert len(old['packets']) == 73 and len(old['allowed_overrides']) == 213
    assert set(changed) <= set(authors)
    assert not set(changed) & {r['path']for r in old['exact_retained']+old['regeneration_seeds']}
    for name in changed:
        assert authors[name]['text'].encode() == before[name]
        assert authors[name]['sha'] == before_manifest[name]['git_blob']
    inherited_harness = h.file_inventory(BASE/'harness')
    inherited_inputs = h.file_inventory(BASE/'input-blobs')
    shutil.copytree(BASE/'harness',ROOT/'harness',copy_function=os.link)
    shutil.copytree(BASE/'input-blobs',ROOT/'input-blobs',copy_function=os.link)
    chunks,current = [],[]
    for name in changed:
        row = {'path':name,'before':identity(before[name]),'after':dict(identity(after[name]),text=after[name].decode())}
        if current and len(encode({'files':current+[row]})) > 635000:
            chunks.append(current);current=[row]
        else:current.append(row)
    if current:chunks.append(current)
    additions = []
    for i,rows in enumerate(chunks):
        label = 'linux-file-render-v3-integration-r14-'+str(i).zfill(2)
        raw = encode({'schema':'hia.reviewed-joint-source-overlay.v1','label':label,
            'scope':'R14_AUTHORED_NOT_GENERATED_NOT_TESTED','base_plan':identity(old_raw),
            'complete_before_after_capsule':identity(capsule_raw),'integration':identity(integration_raw),
            'entire_workflow_byte_identical':True,'whole_native':False,'files':rows})
        assert len(raw) <= 650000
        pin = {'label':label,'blob':identity(raw)['git_blob'],'bytes':len(raw),'sha256':identity(raw)['sha256'],'layout':'array-after','files':len(rows)}
        put(ROOT/'input-blobs'/(pin['blob']+'.blob'),raw)
        plan['packets'].append(pin);additions.append(pin)
        for row in rows:
            name,value = row['path'],row['after'];prior=authors[name]
            plan['allowed_overrides'].append({'path':name,'from_packet':prior['packet'],'to_packet':label,'from':prior['sha'],'to':value['git_blob']})
            authors[name] = dict(path=name,text=value['text'],sha=value['git_blob'],bytes=value['bytes'],mode=value['mode'],packet=label,packet_blob=pin['blob'])
    assert len(authors) == 469 and len(plan['allowed_overrides']) == 226
    assert plan['packets'][:73] == old['packets'] and plan['allowed_overrides'][:213] == old['allowed_overrides']
    assert {x['path']for x in plan['allowed_overrides'][213:]} == set(changed)
    for name,row in authors.items():
        if name in changed:assert row['text'].encode() == after[name]
        else:assert row == original[name]
    workflow = after['.github/workflows/hia-core.yml']
    assert workflow == before['.github/workflows/hia-core.yml']
    fragment = ('  source:\n'+workflow.decode().split('  source:\n',1)[1].split('  native:\n',1)[0]).encode()
    assert identity(fragment)['git_blob'] == plan['source_registration']['after_fragment']['blob']
    assert fragment == (BASE/'harness/inputs/SOURCE-R13-FRAGMENT.yml').read_bytes()
    ids_raw = (ROOT/'FORMAL-EXPECTED-IDS.json').read_bytes();ids=json.loads(ids_raw)
    assert ids['selectors'] == plan['source_registration']['selectors'] and len(ids['r14_expected_ordered_ids']) == 1353
    plan['source_registration']['notes'].append('R14 applies the exact frozen file-render v2-to-v3 delta and two exact-path version maps. It adds one Source method, with all old IDs and assertions retained. No selector, generator, resource role, provider edge, Source environment or Native workflow step changes. Development130, Source10 and newVM4 do not qualify this union; the actual oldVM7 6PASS1FAIL remains a separate preserved version transition. No cold or whole-native result is inherited.')
    plan['r14_integration'] = {'base_plan':identity(old_raw),'capsule':identity(capsule_raw),'integration':identity(integration_raw),
        'base_actual_generated_tree':h.tree_hash(before_manifest),'source_tree':h.tree_hash(after_manifest),'source_files':3121,
        'changed_paths':changed,'new_paths':[],'expected_ids':identity(ids_raw),'Source_expected':1353,'generators':131,'selectors':231,
        'all1352_1342_1329_1319_ordered_projections_required':True,'entire_workflow_byte_identical':True,
        'generation_executed':False,'product_tests_executed':0,'component_results_inherited':False,'whole_native':False}
    for key,value in old.items():
        assert key in {'allowed_overrides','packets','source_registration'} or plan[key] == value,key
    assert plan['source_registration']['selectors'] == old['source_registration']['selectors']
    assert plan['source_registration']['generators'] == old['source_registration']['generators']
    for key,value in old['source_registration'].items():
        assert key=='notes' or plan['source_registration'][key] == value,key
    author_raw = encode([authors[name]for name in sorted(authors)]);plan_raw=encode(plan)
    put(ROOT/'harness/inputs/AUTHORING-R14.json',author_raw)
    put(ROOT/'harness/inputs/MATERIALIZATION-R14.json',plan_raw)
    put(ROOT/'harness/inputs/SOURCE-R14-FRAGMENT.yml',fragment)
    for folder,pins in [('harness',inherited_harness),('input-blobs',inherited_inputs)]:
        for name,pin in pins.items():assert identity((ROOT/folder/name).read_bytes())==pin
    for pin in plan['harness_files']:
        raw=(ROOT/'harness'/pin['path']).read_bytes();assert identity(raw)['git_blob']==pin['blob'] and len(raw)==pin['bytes']
    transport = encode({'schema':'hia.zlib-complete-author-table.v1','rows':469,'raw_bytes':len(author_raw),
        'raw_git_blob':identity(author_raw)['git_blob'],'raw_sha256':identity(author_raw)['sha256'],
        'payload':base64.b64encode(zlib.compress(author_raw,9)).decode()})
    assert zlib.decompress(base64.b64decode(json.loads(transport)['payload'],validate=True)) == author_raw
    put(ROOT/'AUTHORING-R14.zlib.json',transport)
    put(ROOT/'AUTHORING-R14-INDEX.json',encode({'schema':'hia.complete-author-table-index.v1','rows':469,
        'full_author_table':identity(author_raw),'transport':identity(transport),
        'files':[{k:v for k,v in authors[name].items()if k!='text'}for name in sorted(authors)]}))
    report={'schema':'hia.r14.materialization-preparation.v1','status':'PREPARED_NOT_GENERATED_NOT_TESTED',
        'base_plan':identity(old_raw),'plan':identity(plan_raw),'source_capsule':identity(capsule_raw),'integration':identity(integration_raw),
        'source_tree':h.tree_hash(after_manifest),'source_files':3121,'authors':469,'overrides':226,'total_packets':len(plan['packets']),
        'new_packets':additions,'generators':131,'selectors':231,'Source_expected':1353,'expected_ids':identity(ids_raw),
        'source_contract':1345,'ENTRY':19,'NATIVE':92,'resources':210,'Core':54,'MECH':54,'Native_steps':121,
        'entire_workflow_bytes_preserved':True,'inherited_harness':inherited_harness,'inherited_inputs':inherited_inputs,
        'generation_executed':False,'product_tests_executed':0,'current_source_cold_qualified':False,'whole_native':False}
    put(ROOT/'PREPARATION.json',encode(report))
    assert h.read_exact(ROOT/'base-source',before_manifest)==before and h.read_exact(ROOT/'source',after_manifest)==after
    print(json.dumps({k:v for k,v in report.items()if k not in ('inherited_harness','inherited_inputs')},sort_keys=True),flush=True)

if __name__=='__main__':
    try:main()
    except BaseException as error:
        put(ROOT/'PREPARATION-FAILURE-R1.json',encode({'status':'FAIL','type':type(error).__name__,'error':str(error),'traceback':traceback.format_exc(),'whole_native':False}))
        raise

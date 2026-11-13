"""Independent exact-ID/readback review of the completed formal parser gate."""
from pathlib import Path
import hashlib
import json

ROOT = Path(__file__).resolve().parent
INPUT = ROOT.parent/'v95-audit-mount-r1/v96-r12r2-formal'
pins = {'source':'b8eaddb0eeae5aa9c6256f958d3d037da7a537be',
    'bounded':'7fdf085185f2cb7fc2dbd88d0f1d2d80ff90a787','source10':'121667569644d6215e4ff16d5be2d9c193671a45',
    'original43':'bf80213d2f383edc757aaded840d3af7f5de647e','native9':'b348c33f3d0c5773da57067954dcf7ea927f4b63'}

def identity(raw):
    return {'bytes':len(raw),'git_blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest(),'sha256':hashlib.sha256(raw).hexdigest()}

raws = {name:(INPUT/(name+'.json')).read_bytes()for name in pins}
for name,raw in raws.items():assert identity(raw)['git_blob']==pins[name]
values = {name:json.loads(raw)for name,raw in raws.items()}
expected_raw = (ROOT.parent/'v94-union-r12-r2/FORMAL-EXPECTED-IDS.json').read_bytes()
assert identity(expected_raw)['git_blob'] == '4ab32818fd0c141678e629ac7c86829648351a70'
expected = json.loads(expected_raw)
s,b = values['source'],values['bounded']
assert s['status']=='PASS' and s['complete'] is True
assert s['ordered_ids']==s['actual_started_ids']==s['actual_stopped_ids']==expected['r12_expected_ordered_ids']
assert s['tests_run']==s['expected']==len(set(s['ordered_ids']))==1342
assert s['selectors']==expected['selectors'] and len(s['selectors'])==230
for key in ['errors','failures','skipped','expected_failures','unexpected_successes','duplicate_ids',
    'missing_a733_ids','missing_frozen_a733_ids','missing_frozen_main_ids','missing_main_ids']:
    assert not s[key],key
assert all(not value for value in s['loader_errors'].values())
for key in ['required_r11_ordered_projection','original_r10_r2_ordered_ids']:
    assert [x for x in s['ordered_ids']if x in set(expected[key])]==expected[key]
assert b['status']=='PASS' and b['tests_run']==b['required_tests']==62 and not b['failures']
assert b['source_unchanged'] is True and b['python'].startswith('3.14.4 ')
assert b['executable']=='/opt/hostedtoolcache/Python/3.14.4/x64/bin/python3.14'
assert b['source_authority']['source_tree']=='2e4f2b681b8e15f8cc978134819943c583a591fd'
assert b['source_authority']['source_files']==3108 and b['source_authority']['tests_run']==1342
assert b['whole_native'] is False and b['product_refs_changed'] is False
groups=[]
for group,name,n in [('source','source10',10),('original43','original43',43),('native','native9',9)]:
    value=values[name];g=b['groups'][group]
    assert value==g['report'] and identity(raws[name])==g['report_pin']
    assert value['status']=='PASS' and value['loaded']==value['tests_run']==n
    assert value['loaded_ids']==value['started_ids']==value['stopped_ids']==expected['bounded_groups'][group]
    assert len(set(value['loaded_ids']))==n
    assert value['source_unchanged'] is True and value['python']==b['python']
    assert all(not value[k]for k in ['errors','failures','loader_errors','skipped','expected_failures','unexpected_successes'])
    assert g['status']=='PASS' and g['command']['returncode']==0
    groups.append({'group':group,'tests':n,'exact_original_ids':True,'source_unchanged':True,
        'command_limits':g['command']['owner_limits'],'wall_ns':g['command']['wall_ns'],'report':identity(raws[name])})
assert values['original43']['declared_packaging_interpreter']==b['executable']
for group in ['build','fresh5']:
    g=b['groups'][group]
    assert g['status']=='PASS' and g['report']['status']=='PASS' and g['command']['returncode']==0
    assert g['report']['source_unchanged'] is True and g['report']['python']==b['python']
report={'schema':'hia.root.formal-r12-r2-exact-id-readback.v1','status':'PASS','run':43488127451,'job':132101891247,
    'source_tests':1342,'source_selectors':230,'source_started_stopped_and_expected_ids_exact':True,
    'required1329_and_original1319_ordered_projections_exact':True,'source_wall_seconds':s['wall_seconds'],
    'bounded_original_tests':62,'groups':groups,'python':b['python'],'executable':b['executable'],
    'packaging_versions':b['packaging_versions'],'packaging_interpreter_equals_test_interpreter':True,
    'source_tree':b['source_authority']['source_tree'],'source_files':3108,'reports':{k:identity(v)for k,v in raws.items()},
    'expected_ids':identity(expected_raw),'raw_event_jsonl_and_full_source_archive_review':'SEPARATE_OWNER_CUSTODY_VALIDATION',
    'full_original_Native121_gate_qualified':False,'current_source_cold_qualified':False,'whole_native':False}
raw=(json.dumps(report,indent=2,sort_keys=True)+'\n').encode()
with (ROOT/'FORMAL-TERMINAL-REPORT-READBACK.json').open('xb')as f:f.write(raw)
print(json.dumps({'status':report['status'],'Source':1342,'bounded':62,'tree':report['source_tree'],
    'python':report['python'],'whole_native':False},sort_keys=True))

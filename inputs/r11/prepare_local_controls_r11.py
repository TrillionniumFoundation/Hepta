"""Discover the R11 affected controls without executing their bodies."""
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parent
SOURCE=ROOT/'source'
sys.path.insert(0,str(SOURCE))
def encode(v):return (json.dumps(v,sort_keys=True,indent=2)+'\n').encode()
def pin(raw):return {'bytes':len(raw),'blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest(),'sha256':hashlib.sha256(raw).hexdigest()}
def snapshot():
 return {p.relative_to(SOURCE).as_posix():pin(p.read_bytes()) for p in SOURCE.rglob('*') if p.is_file()}
def ids(suite):
 result=[]
 for item in suite:
  result.extend(ids(item) if isinstance(item,unittest.TestSuite) else [item.id()])
 return result

before=snapshot()
assert len(before)==3100
plan=json.loads((ROOT/'harness/inputs/MATERIALIZATION-R11.json').read_bytes())
prior_root=ROOT.parent/'v92-union-r10-r2'
prior=json.loads((prior_root/'LOCAL-CONTROL-SELECTION.json').read_bytes())
prior_result=json.loads((prior_root/'registration-controls-r1/evidence/raw/RESULT.json').read_bytes())
assert prior_result['status']=='PASS' and prior_result['source_unchanged']
old_ids=prior_result['tests']['all_loaded_ids']
assert old_ids==prior['formal_source_ids_expected'] and len(old_ids)==1319
loader=unittest.TestLoader()
all_ids=ids(loader.loadTestsFromNames(plan['source_registration']['selectors']))
assert not loader.errors,loader.errors
assert len(all_ids)==len(set(all_ids))==1329
assert [x for x in all_ids if x in set(old_ids)]==old_ids
new_ids=[x for x in all_ids if x not in set(old_ids)]
spec=json.loads((ROOT/'REGISTRATION-SPEC.json').read_bytes())
assert new_ids==spec['Source_exact_ids_additions'] and len(new_ids)==10
selected=prior['selected']+['tests.test_hia_cli_discovery_json.CliDiscoveryJsonSourceTests',spec['Source_selector_addition']]
loader=unittest.TestLoader()
expected=ids(loader.loadTestsFromNames(selected))
assert not loader.errors,loader.errors
assert len(expected)==len(set(expected))==254,len(expected)
assert [x for x in expected if x in set(prior['expected_ids'])]==prior['expected_ids']
outside=sorted(set(expected)-set(all_ids))
assert set(outside)==set(prior['additional_reference_ids_outside_formal_source_selectors']) and len(outside)==39
assert snapshot()==before
selection={'schema':'hia.r11.affected-source-selection.v1','status':'DISCOVERED_NOT_EXECUTED',
 'selected':selected,'expected_ids':expected,'formal_source_ids_expected':all_ids,
 'prior_r9_formal_source_ids':prior['prior_r9_formal_source_ids'],
 'prior_r10_loaded_source_ids':old_ids,'new_source_ids':new_ids,
 'additional_reference_ids_outside_formal_source_selectors':outside,
 'original_r9_failed_method_required':prior['original_r9_failed_method_required'],
 'source_files_unchanged_during_discovery':True,'generation_or_tests_executed':False,
 'whole_native':False,'complete_source_suite_executed':False}
with (ROOT/'LOCAL-CONTROL-SELECTION.json').open('xb') as f:f.write(encode(selection))
script=(prior_root/'run_targeted_source_controls_r10_r2.py').read_text()
for old,new,n in [
 ('Execute R10 CLI and exact registration controls, including the actual R9 archive regression.',
  'Execute R11 parser and routing Source controls, preserving the earlier complete affected projection.',1),
 ('MATERIALIZATION-R10-R2.json','MATERIALIZATION-R11.json',1),
 ('== 1319','== 1329',1),
 ('232','254',6)]:
 assert script.count(old)==n,(old,script.count(old))
 script=script.replace(old,new)
anchor="    assert all_ids == selection['formal_source_ids_expected']\n"
assert script.count(anchor)==1
script=script.replace(anchor,anchor+"    assert [x for x in all_ids if x in set(selection['prior_r10_loaded_source_ids'])] == selection['prior_r10_loaded_source_ids']\n")
compile(script,'run_targeted_source_controls_r11.py','exec')
with (ROOT/'run_targeted_source_controls_r11.py').open('x') as f:f.write(script)
print(json.dumps({'status':'SELECTION_DISCOVERED','formal_ids':len(all_ids),'prior_r10_loaded_projection':len(old_ids),
 'new_ids':len(new_ids),'selected':len(expected),'outside_formal_unchanged_reference_ids':len(outside),
 'source_unchanged':True,'product_tests_executed':0},sort_keys=True))

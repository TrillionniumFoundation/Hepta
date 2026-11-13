"""Choose actual affected controls and preserve every earlier ordered ID projection."""
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
assert len(before)==3083
plan=json.loads((ROOT/'harness/inputs/MATERIALIZATION-R10-R2.json').read_bytes())
prior=json.loads((ROOT.parent/'v91-union-r9/LOCAL-CONTROL-SELECTION.json').read_bytes())
formal_prior=json.loads((ROOT.parent/'v91-source-r9-original/artifact/raw/checks/SOURCE-TESTS.json').read_bytes())
old_ids=formal_prior['ordered_ids']
assert old_ids==prior['formal_source_ids_expected'] and len(old_ids)==1306
loader=unittest.TestLoader()
all_ids=ids(loader.loadTestsFromNames(plan['source_registration']['selectors']))
assert not loader.errors,loader.errors
assert len(all_ids)==len(set(all_ids))==1319
assert [x for x in all_ids if x in set(old_ids)]==old_ids
new_ids=[x for x in all_ids if x not in set(old_ids)]
declared=plan['r10_integration']['new_component_source_ids']
assert len(declared)==12 and len(new_ids)==13
assert set(new_ids)==set(declared)|{plan['r10_integration']['new_suffix_id']}
selected=prior['selected']+['tests.test_hia_integrated_workflow','tests.test_hia_linux_cli_process.LinuxCliProcessSourceTests']
loader=unittest.TestLoader()
expected=ids(loader.loadTestsFromNames(selected))
assert not loader.errors,loader.errors
assert len(expected)==len(set(expected))==232,len(expected)
assert [x for x in expected if x in set(prior['expected_ids'])]==prior['expected_ids']
outside=sorted(set(expected)-set(all_ids))
assert set(outside)==set(prior['additional_reference_ids_outside_formal_source_selectors'])
assert len(outside)==39
failed_id='tests.test_hia_integrated_workflow.CoreWorkflowContractTests.test_native_archives_cover_every_explicit_fixture_and_caller_destination'
assert failed_id in expected
assert snapshot()==before
selection={'schema':'hia.r10-r2.affected-source-selection.v1','status':'DISCOVERED_NOT_EXECUTED',
    'selected':selected,'expected_ids':expected,'formal_source_ids_expected':all_ids,
    'prior_r9_formal_source_ids':old_ids,'new_source_ids':new_ids,
    'additional_reference_ids_outside_formal_source_selectors':outside,
    'original_r9_failed_method_required':failed_id,
    'source_files_unchanged_during_discovery':True,'generation_or_tests_executed':False,
    'whole_native':False,'complete_source_suite_executed':False}
selection_raw=encode(selection)
selection_path=ROOT/'LOCAL-CONTROL-SELECTION.json'
assert selection_path.read_bytes()==selection_raw, 'retry may not replace the already completed original discovery'
script=(ROOT.parent/'v91-union-r9/run_targeted_source_controls_r9.py').read_text()
a='Execute every affected class for the R8 public Linux process profile and complete registrations.'
b='Execute R10 CLI and exact registration controls, including the actual R9 archive regression.'
assert script.count(a)==1
script=script.replace(a,b)
assert script.count('MATERIALIZATION-R9.json')==1
script=script.replace('MATERIALIZATION-R9.json','MATERIALIZATION-R10-R2.json')
assert script.count('== 1306')==1
script=script.replace('== 1306','== 1319')
old="assert all_ids[:1274] == prior_r2, 'the original ordered Source IDs changed'"
new="assert [x for x in all_ids if x in set(prior_r2)] == prior_r2, 'the original ordered Source ID projection changed'\n    assert [x for x in all_ids if x in set(selection['prior_r9_formal_source_ids'])] == selection['prior_r9_formal_source_ids']"
assert script.count(old)==1
script=script.replace(old,new)
assert script.count('200')==6
script=script.replace('200','232')
compile(script,'run_targeted_source_controls_r10_r2.py','exec')
(ROOT/'run_targeted_source_controls_r10_r2.py').write_text(script)
print(json.dumps({'status':'SELECTION_DISCOVERED','formal_ids':len(all_ids),'old_r9_projection':len(old_ids),
    'new_ids':len(new_ids),'selected':len(expected),'outside_formal_unchanged_reference_ids':len(outside),
    'source_unchanged':True,'tests_executed':0},sort_keys=True))

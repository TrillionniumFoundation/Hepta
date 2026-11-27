"""Run the complete original Source gate on the exact actual-314 R13 tree."""
from pathlib import Path
import hashlib
import importlib.util
import json
import sys
import traceback
import zipfile

ROOT = Path(__file__).resolve().parent
DRIVER = ROOT / 'harness/tools/materialize_candidate_r14.py'

def blob(raw):
    return hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()

driver = DRIVER.read_bytes()
assert blob(driver) == 'cfe319279641b124bcd724437857686f36d1aa07'
plan_raw = (ROOT/'harness/inputs/MATERIALIZATION-R13.json').read_bytes()
assert blob(plan_raw) == '97daf30bf0ff5abd42e27329756b7b6ad585937a'
gen_raw = (ROOT/'local-generation-r1/evidence/raw/LOCAL-RESULT.json').read_bytes()
gen = json.loads(gen_raw)
assert gen['status'] == 'LOCAL_GENERATION_PASS' and not gen['failures']
assert gen['generation'] == {'generator_count':131,'physical_paths_retired_in_development_tree':55,
    'real_generation_passes':2,'tree':'c6bab7f5054960a818dda0d8b19dc678952fd9fb'}
runtime_raw = (ROOT/'local-runtime-r1/RESULT.json').read_bytes()
runtime = json.loads(runtime_raw)
assert runtime['status'] == 'PASS' and sys.version == runtime['runtime']['python']
assert sys.executable == runtime['runtime']['executable']
spec = importlib.util.spec_from_file_location('original_r14_materializer',DRIVER)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
plan = module.strict_json(plan_raw)
capture = module.Capture(ROOT/'local-source-controls-r1','')
capture.basic = ''
capture.repo = ROOT/'local-source-r1'
capture.put('harness/DRIVER.py',driver)
capture.put('harness/LOCAL-SOURCE-DRIVER.py',Path(__file__).read_bytes())
capture.put('harness/INPUTS.json',plan_raw)
capture.put('harness/GENERATION-RESULT.json',gen_raw)
capture.put('harness/RUNTIME-RESULT.json',runtime_raw)
ids_raw = (ROOT/'FORMAL-EXPECTED-IDS.json').read_bytes()
expected = json.loads(ids_raw)
capture.put('harness/EXPECTED-IDS.json',ids_raw)
with zipfile.ZipFile(ROOT.parent/'recovered-v85/first-build.zip') as archive:
    original = module.strict_json(archive.read('raw/terminal-worktree/INDEX.json'))
    materialized = module.strict_json(archive.read('raw/sources/FIXED-TREE-BLOB-MATERIALIZATION.json'))
capture.original_oids = {row['oid']for row in materialized['after']}
capture.original_path_sets = {'recovered-original-failure':{row['path']for row in original['files']}}
report = {'schema':'hia.r13.actual314-local-full-source.v1','status':'RUNNING',
    'scope':'LOCAL_FULL_SOURCE_NOT_FORMAL_NATIVE_COLD_OR_PORTABLE_QUALIFICATION',
    'python':sys.version,'executable':sys.executable,'started_at':module.now(),
    'source_tree':gen['generation']['tree'],'expected_tests':1352,'selectors':231,'original_source_runner_changed':False,
    'original_group_budget_seconds':1800,'source_environment_count':3,
    'formal_packaging_versions_inherited':False,'packaging_versions':{k:runtime['runtime'][k]for k in ['pip','setuptools','wheel']},
    'whole_native':False,'product_default_changed':False,'failures':[]}
capture.json('LOCAL-SOURCE-INTENT.json',report)
try:
    module.assert_current_tree(capture,report['source_tree'],'before-r13-full-source')
    source, passed = module.source_gate(capture,plan,ROOT/'harness')
    report['source'] = source
    module.assert_current_tree(capture,report['source_tree'],'after-r13-full-source')
    assert source['ordered_ids'] == expected['r13_expected_ordered_ids']
    assert source['expected'] == len(source['ordered_ids']) == 1352
    assert source['selectors'] == expected['selectors']
    for key in ['r12_expected_ordered_ids','required_r11_ordered_projection','original_r10_r2_ordered_ids']:
        prior = expected[key]
        assert [name for name in source['ordered_ids'] if name in set(prior)] == prior
    report['all_1342_1329_1319_ordered_projections_exact'] = True
    report['status'] = 'LOCAL_SOURCE_PASS' if passed else 'FAIL'
except BaseException as error:
    report['status'] = 'FAIL'
    report['failures'].append({'type':type(error).__name__,'error':str(error),'traceback':traceback.format_exc()})
finally:
    try:
        report['terminal_source_snapshot'] = module.snapshot_failure_or_terminal_sources(capture)
    except BaseException as error:
        report['status'] = 'FAIL'
        report['failures'].append({'stage':'terminal_snapshot','type':type(error).__name__,'error':str(error),'traceback':traceback.format_exc()})
    report['finished_at'] = module.now()
    capture.json('LOCAL-SOURCE-RESULT.json',report)
    print(json.dumps({'status':report['status'],'source_status':report.get('source',{}).get('status'),
        'tests_run':report.get('source',{}).get('tests_run'),'failures':report['failures']},sort_keys=True),flush=True)
raise SystemExit(0 if report['status']=='LOCAL_SOURCE_PASS' else 1)

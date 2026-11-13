"""Repair the one actually failed original archive-coverage contract."""
import hashlib
import json
from pathlib import Path
import shutil
import yaml

ROOT = Path(__file__).resolve().parent
BASE = ROOT.parent/'v92-union-r10'
NAME = '.github/workflows/hia-core.yml'
def encode(value):
    return (json.dumps(value,indent=2,sort_keys=True,ensure_ascii=True)+'\n').encode()
def identity(raw):
    return {'bytes':len(raw),'git_blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest(),
            'sha256':hashlib.sha256(raw).hexdigest(),'mode':'100644'}

before = (BASE/'source'/NAME).read_bytes()
assert identity(before)['git_blob'] == '3d399cd5feda93c560ec08b6890c90019446e333'
anchor = '            ${{ runner.temp }}/hia-linux-stdio-matching-cold/\n'
added = '            ${{ runner.temp }}/hia-linux-process-matching-cold/\n'
text = before.decode()
assert text.count(anchor) == 1
assert text.count(added) == 1
after = text.replace(anchor,anchor+added,1).encode()
assert after.decode().replace(anchor+added,anchor,1).encode() == before
old_jobs,new_jobs = yaml.safe_load(before)['jobs'],yaml.safe_load(after)['jobs']
assert old_jobs['source'] == new_jobs['source']
old_steps,new_steps = old_jobs['native']['steps'],new_jobs['native']['steps']
assert len(old_steps) == len(new_steps) == 120
changed = [(a,b) for a,b in zip(old_steps,new_steps) if a!=b]
assert len(changed) == 1
old_step,new_step = changed[0]
assert old_step['name'] == new_step['name'] == 'Preserve actual cold failure and stage evidence'
copy_step = json.loads(json.dumps(new_step))
copy_step['with']['path'] = copy_step['with']['path'].replace('${{ runner.temp }}/hia-linux-process-matching-cold/\n','',1)
assert copy_step == old_step
plan_raw = (BASE/'harness/inputs/MATERIALIZATION-R10.json').read_bytes()
assert identity(plan_raw)['git_blob'] == '2213cb5040a82231698838895d528d6a118e7ae0'
plan = json.loads(plan_raw)
authors = {r['path']:r for r in json.loads((BASE/'harness/inputs/AUTHORING-R10.json').read_bytes())}
assert len(authors)==430 and len(plan['packets'])==60 and len(plan['allowed_overrides'])==165
assert authors[NAME]['sha'] == identity(before)['git_blob']
for name in ('source','input-blobs','harness'):
    shutil.copytree(BASE/name,ROOT/name,ignore=shutil.ignore_patterns('__pycache__'))
(ROOT/'source'/NAME).write_bytes(after)
label = 'linux-process-original-main-archive-coverage-r10-r2'
packet = {'schema':'hia.reviewed-joint-source-overlay.v1','label':label,
    'scope':'EXACT_ONE_LINE_REPAIR_OF_ACTUAL_ORIGINAL_FORMAL_SOURCE_FAILURE',
    'formal_failure_run':43455699432,'formal_failure_job':131989125837,
    'formal_failure_result_blob':'8634a2afa3aac1b9856d3cb7560c1d7af8f79090',
    'formal_failure_id':'tests.test_hia_integrated_workflow.CoreWorkflowContractTests.test_native_archives_cover_every_explicit_fixture_and_caller_destination',
    'all_original_test_file_bytes_unchanged':True,'all_native_execution_commands_conditions_and_budgets_unchanged':True,
    'source_fragment_byte_identical':True,'whole_native':False,'default_changed':False,
    'files':[{'path':NAME,'before':identity(before),'after':{**identity(after),'text':after.decode()}}]}
packet_raw=encode(packet)
pin={'label':label,'blob':identity(packet_raw)['git_blob'],'bytes':len(packet_raw),
     'sha256':identity(packet_raw)['sha256'],'layout':'array-after','files':1}
(ROOT/'input-blobs'/(pin['blob']+'.blob')).write_bytes(packet_raw)
plan['packets'].append(pin)
previous=authors[NAME]
plan['allowed_overrides'].append({'path':NAME,'from_packet':previous['packet'],'to_packet':label,
    'from':previous['sha'],'to':identity(after)['git_blob']})
authors[NAME]={'path':NAME,'text':after.decode(),'sha':identity(after)['git_blob'],'bytes':len(after),
              'mode':'100644','packet':label,'packet_blob':pin['blob']}
plan['prior_formal_source_failure_r9']={'run':43455699432,'job':131989125837,
    'harness_commit':'2df61cbfe17db622a7a0bdc65a09c73ff51de487',
    'result_blob':'8634a2afa3aac1b9856d3cb7560c1d7af8f79090','result_bytes':974104,
    'result_sha256':'e05ab40061313e1d7c50bc3bfa586dce47b6e5abdfd8064d8fb85616aad6d207',
    'status':'SOURCE_FAIL','actual_tests':1306,'actual_passes':1305,'actual_failures':1,
    'actual_errors':0,'actual_skips':0,'wall_seconds':832.256319047,
    'failure_id':packet['formal_failure_id'],'candidate_product_published':False}
plan['r10_r2_archive_coverage_repair']={'prior_plan':identity(plan_raw),'workflow_before':identity(before),
    'workflow_after':identity(after),'one_main_archive_path_added':'${{ runner.temp }}/hia-linux-process-matching-cold/',
    'old120_step_names_order_and_all_execution_commands_unchanged':True,
    'only_native_step_difference':'one path added to the original always archive',
    'independent_process_archive_retained':True,'source_fragment_unchanged':True,
    'all_original_tests_unchanged':True,'generation_or_tests_executed':False,'whole_native':False}
plan['source_registration']['notes'].append('R10-R2 repairs the actual R9 1305 PASS / 1 FAIL archive-coverage failure by adding only the new process evidence destination to the original main Native archive. The original failing test is unchanged. All old execution steps, conditions and budgets are unchanged; only that archive path list extends. R10 and R9 original records remain immutable.')
new_plan=encode(plan)
inputs=ROOT/'harness/inputs'
(inputs/'MATERIALIZATION-R10-R2.json').write_bytes(new_plan)
(inputs/'AUTHORING-R10-R2.json').write_bytes(encode([authors[n] for n in sorted(authors)]))
shutil.copyfile(BASE/'harness/inputs/SOURCE-R10-FRAGMENT.yml',inputs/'SOURCE-R10-R2-FRAGMENT.yml')
driver=(ROOT/'harness/tools/materialize_candidate_r14.py').read_bytes()
assert identity(driver)['git_blob']=='cfe319279641b124bcd724437857686f36d1aa07'
local=(BASE/'run_local_generation_r10.py').read_text()
for old,new in [('v92-union-r10','v92-union-r10-r2'),
 ('2213cb5040a82231698838895d528d6a118e7ae0',identity(new_plan)['git_blob']),
 ('MATERIALIZATION-R10.json','MATERIALIZATION-R10-R2.json'),
 ('AUTHORING-R10.json','AUTHORING-R10-R2.json'),
 ('all_60_source_packets_checked','all_61_source_packets_checked')]:
    assert local.count(old)==1,(old,local.count(old))
    local=local.replace(old,new)
(ROOT/'run_local_generation_r10_r2.py').write_text(local)
report={'schema':'hia.r10-r2.archive-repair-preparation.v1','status':'PREPARED_NOT_QUALIFIED',
    'plan':identity(new_plan),'new_packet':pin,'workflow':identity(after),
    'driver':identity(driver),'total_packets':61,'authored_files':430,'explicit_overrides':166,
    'source_files':3083,'source_contract':1307,'generators':121,'selectors':228,'tests_expected':1319,
    'changed_paths_vs_r10':[NAME],'all_test_bytes_unchanged':True,
    'original_native_execution_steps_unchanged':True,'generation_executed':False,'tests_executed':0,
    'whole_native':False,'default_changed':False}
(ROOT/'PREPARATION.json').write_bytes(encode(report))
print(json.dumps(report,sort_keys=True),flush=True)

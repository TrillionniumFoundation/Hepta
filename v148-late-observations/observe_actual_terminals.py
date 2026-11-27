from pathlib import Path
import hashlib,json,stat,time
ROOT=Path('/tmp/hia-progress-v148-20261114-dda7')
R4=Path('/dev/shm/hia-u32-r8-controls-r4-dda7')
OP=Path('/tmp/hia-op13-execution-r2-dda7/attempt-r1')
def read(p):
 p=Path(p);s=p.lstat();assert stat.S_ISREG(s.st_mode) and s.st_nlink==1
 b=p.read_bytes();assert p.lstat()==s
 return json.loads(b),{'path':str(p),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'git_blob':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()}
def write(n,d):
 b=(json.dumps(d,sort_keys=True,indent=2)+'\n').encode()
 with (ROOT/n).open('xb') as f:f.write(b)
 assert (ROOT/n).read_bytes()==b
 return {'path':n,'bytes':len(b),'git_blob':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()}
overall,overall_pin=read(R4/'RESULT.json');native,native_pin=read(R4/'semantic/evidence/full-buffer-replay-r1/REPORT.json');vm,vm_pin=read(R4/'semantic/evidence/compact-vm-remaining-r1/REPORT.json');outer,outer_pin=read('/tmp/hia-r8-original-controls-r4-outer-dda7/RESULT.json')
assert overall['status']=='FAIL' and [(r['phase'],r['pass']) for r in overall['rows']]==[('public-R5-refusal',True),('native162',True),('semantic-edge-vm',True),('semantic-remaining-vm',False)]
assert vm['count']==6 and len(vm['rows'])==6 and [r['name'] for r in vm['rows'] if not r['pass']]==['root-v8-cross-target-loans']
assert sum(r['pass'] for r in vm['rows'])==5 and vm['VM_steps_per_case']==10000000
assert outer['returncode']==1 and outer['ECHILD'] and outer['process_group_absent'] and not outer['timeout']
rows=[]
for row in overall['rows']:
 o=row['owner'];assert o['qualification_seconds']==180 and o['cleanup_seconds']==3 and o['cleanup']['complete'] and o['cleanup']['observed_echild'] and not o['timed_out']
 rows.append({'phase':row['phase'],'pass':row['pass'],'owner_status':o['status'],'returncode':o['returncode'],'supervisor_returncode':o['supervisor_returncode'],'owner_180_cleanup_3_unchanged':True,'cleanup_ECHILD':True})
r4={'schema':'hia.root.actual-stage-reports-observed.v1','scope':'R8 R4 original stages','status':'FAIL','original_reports_fully_read':True,'complete_actual_raw_independent_root_readback_and_custody':'PENDING_SEPARATE_STAGE','sources':{'overall':overall_pin,'native':native_pin,'vm':vm_pin,'outer':outer_pin},'phases':rows,'original_Native162_stage_passed':True,'extra_edge_Native_calls':1,'new_Native_calls_reported':163,'VM_total_actual_calls':6,'VM_passed':5,'VM_failed':1,'VM_rows':vm['rows'],'not_started':overall['not_started'],'outer_elapsed_ns':outer['elapsed_ns'],'outer_cleanup_ECHILD':True,'all_original_limits_unchanged':True,'whole_native':False,'new_current_cold':False,'public_R5_profile_qualified':False,'production_legacy_retired':False}
actual,actual_pin=read(OP/'RESULT.json');o,o_pin=read('/tmp/hia-op13-product-outer-r2-dda7/OUTER.json')
expected=['op13-source8','build-report-six','build-inspect','build-patch']+['native-%02d'%i for i in range(1,6)]
assert actual['status']=='FAIL' and actual['actual_owner_launch_attempts']==9 and [r['label'] for r in actual['stages']]==expected
assert [r['status'] for r in actual['stages']]==['PASS']*8+['FAIL']
tests,t_pin=read(OP/'09-native-05/TESTS.json');source,s_pin=read(OP/'01-op13-source8/TESTS.json')
assert source['status']=='PASS' and source['tests_run']==8 and not source['errors'] and not source['failures']
assert tests['tests_run']==1 and len(tests['failures'])==1 and not tests['errors'] and "consume_mask" in tests['failures'][0][1]
op={'schema':'hia.root.actual-stage-reports-observed.v1','scope':'op13 stable tmp R2 original product chain','status':'FAIL','original_reports_fully_read':True,'complete_actual_raw_independent_root_readback_and_custody':'PENDING_SEPARATE_STAGE','sources':{'parent':actual_pin,'outer':o_pin,'source8_tests':s_pin,'native05_tests':t_pin},'actual_owner_stages':9,'stages':[{'label':r['label'],'status':r['status']} for r in actual['stages']],'Source_methods_passed':8,'actual_component_compilations_reported':8,'Native_methods_passed':4,'Native_methods_failed':1,'failed_id':tests['declared_ids'][0],'actual_failure':tests['failures'][0][1],'remaining_Native_methods_not_started':list(range(6,13)),'VM12_executed':False,'old_R5_witness10':'FAIL_UNCHANGED','whole_native':False,'current_cold':False,'default':False,'production_legacy_retired':False}
print(json.dumps([write('R4-OBSERVED-TERMINAL.json',r4),write('OP13-R2-OBSERVED-TERMINAL.json',op)],sort_keys=True))

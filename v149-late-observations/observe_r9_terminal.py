from pathlib import Path
import hashlib,json,os,stat
ROOT=Path('/tmp/hia-progress-v149-20261114-dda7')
R9=Path('/hia-r8-r9-controls-20261114-dda7')
R4=Path('/dev/shm/hia-u32-r8-controls-r4-dda7')
FIELDS=('st_dev','st_ino','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
def pin(b):return {'bytes':len(b),'git_blob':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest(),'sha256':hashlib.sha256(b).hexdigest()}
def read(p):
 s=p.lstat();assert stat.S_ISREG(s.st_mode);raw=p.read_bytes();assert [getattr(s,k) for k in FIELDS]==[getattr(p.lstat(),k) for k in FIELDS]
 return raw
result=json.loads(read(R9/'RESULT.json'));outer=json.loads(read(Path('/tmp/hia-r9-controls-outer-r1-dda7/RESULT.json')))
assert result['status']=='FAIL' and len(result['rows'])==4 and outer['returncode']==1 and outer['ECHILD'] and not outer['timeout']
oldp=R4/'semantic/evidence/compact-vm-remaining-r1/REPORT.json';newp=R9/'semantic/evidence/compact-vm-remaining-r1/REPORT.json'
old=json.loads(read(oldp));new=json.loads(read(newp));assert len(old['rows'])==len(new['rows'])==6
comparison=[]
for a,b in zip(old['rows'],new['rows'],strict=True):
 assert (a['group'],a['name'])==(b['group'],b['name'])
 comparison.append({'case':b['name'],'old_actual_steps':a['VM_steps'],'new_actual_steps':b['VM_steps'],'old_phase_word':a['phase_word'],'new_phase_word':b['phase_word'],'pass':b['pass'],'semantic_error_word':b['semantic_error_word'],'new_checks':b['checks']})
assert comparison[0]['old_actual_steps']==4426100 and comparison[0]['new_actual_steps']==4028084
assert sum(r['pass'] for r in comparison)==5 and comparison[-1]['new_actual_steps']==10000001
owners=[{'phase':r['phase'],'pass':r['pass'],'returncode':r['owner']['returncode'],'qualification_seconds':r['owner']['qualification_seconds'],'cleanup_seconds':r['owner']['cleanup_seconds'],'timed_out':r['owner']['timed_out'],'cleanup_complete':r['owner']['cleanup']['complete'],'ECHILD':r['owner']['cleanup']['observed_echild']} for r in result['rows']]
assert all(o['qualification_seconds']==180 and o['cleanup_seconds']==3 and not o['timed_out'] and o['cleanup_complete'] and o['ECHILD'] for o in owners)
observation={'schema':'hia.root.R9.actual-terminal-observation.v1','status':'ACTUAL_FAILURE_OBSERVED_FULL_INDEPENDENT_READBACK_PENDING','original_actual_status':'FAIL','outer':outer,'owners':owners,'original_result':pin(read(R9/'RESULT.json')),'old_R4_VM_report':pin(read(oldp)),'new_R9_VM_report':pin(read(newp)),'VM_actual_comparison':comparison,'not_started':result['not_started'],'native_calls_reported':163,'VM_calls_reported':6,'native_complete_frame_independent_validation':'pending','semantic_cross_target_failure_retained':True,'formal_old_summary_correction':{'prior_conversation_summary_value':2564426,'actual_original_report_value':4426100,'original_report_unchanged':True},'automatic_retry':False,'whole_native':False,'production_legacy_retired':False}
raw=(json.dumps(observation,sort_keys=True,indent=2)+'\n').encode()
with (ROOT/'R9-ACTUAL-TERMINAL-OBSERVATION.json').open('xb') as f:f.write(raw)
print(json.dumps({'observation':pin(raw),'owners':len(owners),'VM_pass':5,'VM_fail':1,'formal_actual_saved_steps':4426100-4028084,'cross_phase':comparison[-1]['new_phase_word']},sort_keys=True))

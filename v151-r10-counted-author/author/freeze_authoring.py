"""Stdlib-only authoring freezer. Never imports a project or runs a product."""
from pathlib import Path
import ast
import hashlib
import json
import os
import stat
from datetime import datetime,timezone

ROOT=Path('/tmp/hia-r10-cross-counted-author-r1-dda7')
OLD=Path('/tmp/hia-r10-controls-author-r1-dda7')
SOURCE=Path('/tmp/hia-r8-source-recovery-20261114-r1/source')
EVIDENCE=Path('/workspace/hia-r10-controls-r1-dda7/semantic/evidence')
NATIVE=EVIDENCE/'full-buffer-replay-r1/retained-semantic-r1/root-v8-cross-target-loans'
FAILED=EVIDENCE/'compact-vm-remaining-r1/root-v8-cross-target-loans'
OUTPUT=Path('/workspace/hia-r10-cross-counted-r1-dda7')
STAT=('st_dev','st_ino','st_mode','st_size','st_mtime_ns','st_ctime_ns','st_nlink')

def require(ok,message):
    if not ok:raise AssertionError(message)

def pin(raw,mode=None):
    result={'bytes':len(raw),'git_blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest(),
            'sha256':hashlib.sha256(raw).hexdigest()}
    if mode is not None:result.update(mode=mode,git_mode='100755' if mode&0o111 else '100644')
    return result

def read(path):
    path=Path(path);s=path.lstat();require(stat.S_ISREG(s.st_mode),'not regular: '+str(path))
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        require(all(getattr(os.fstat(fd),k)==getattr(s,k) for k in STAT),'opened inode differs')
        with os.fdopen(fd,'rb',closefd=False) as stream:raw=stream.read(s.st_size+1)
        require(len(raw)==s.st_size and all(getattr(os.fstat(fd),k)==getattr(s,k)
            and getattr(path.lstat(),k)==getattr(s,k) for k in STAT),'file changed')
    finally:os.close(fd)
    return raw,stat.S_IMODE(s.st_mode),{k:getattr(s,k) for k in STAT}

def row(path):
    raw,mode,stamp=read(path)
    return {'path':str(path),'identity':pin(raw,mode),'author_stat':stamp}

def write(path,raw):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('xb') as stream:stream.write(raw)
    path.chmod(0o644)
    require(read(path)[0]==raw,'new author file readback differs')

def dump(path,value):
    write(path,(json.dumps(value,indent=2,sort_keys=True,allow_nan=False)+'\n').encode())

def definition(raw,name):
    text=raw.decode();node=next(n for n in ast.parse(raw).body if getattr(n,'name',None)==name)
    return ''.join(text.splitlines(keepends=True)[node.lineno-1:node.end_lineno]).encode()

def main():
    require(not os.path.lexists(OUTPUT),'future one-shot output already exists')
    original_plan=json.loads(read(OLD/'EXECUTION-PLAN.json')[0])
    require(original_plan['source']['path']==str(SOURCE)
        and original_plan['source']['tree']=='4c62be4ed66ff107fa6f88c6131313a354868bd9','frozen source identity differs')
    authorities={
        'R10-plan':OLD/'EXECUTION-PLAN.json',
        'R10-source-map':OLD/'FROZEN-3180-SOURCE.json',
        'original-edge-diagnostic':OLD/'semantic/authoring/run_compact_vm_diagnostic_r1.py',
        'original-remaining-VM':OLD/'semantic/authoring/run_compact_vm_remaining_r1.py',
        'original-wrapper':OLD/'run_controls.py','original-support':OLD/'r8_common.py',
        'R10-source':Path('/workspace/hia-r10-prefix-r1-dda7/generated/file_render_checker_word64_bytes.hepta'),
        'R10-image':Path('/workspace/hia-r10-prefix-r1-dda7/size-pack/R8.u32.image.bin'),
        'R10-native-image':EVIDENCE/'compact-build-r1/checker.image.bin',
        'initial-source':NATIVE/'INPUT.hepta',
        'initial-output':NATIVE.parent/'OUTPUT-PREIMAGE.bin',
        'initial-workspace':NATIVE.parent/'WORKSPACE-PREIMAGE.bin',
        'native-observation':NATIVE/'native/OBSERVATION.json',
        'native-request':NATIVE/'native/request.json','native-child':NATIVE/'native/CHILD-REPORT.json',
        'native-stdout':NATIVE/'native/stdout.bin','native-stderr':NATIVE/'native/stderr.bin',
        'native-group-report':EVIDENCE/'full-buffer-replay-r1/REPORT.json',
        'native-owner':EVIDENCE/'full-buffer-replay-r1/OWNER.json',
        'native-owner-returned':EVIDENCE/'full-buffer-replay-r1/OWNER-RETURNED.json',
        'native-outer':EVIDENCE/'full-buffer-replay-r1/OUTER.json',
        'failed-state':FAILED/'RAW-VM-STATE.json','failed-vm-report':FAILED/'VM-REPORT.json',
        'failed-result':FAILED/'RESULT.json','failed-capture':FAILED/'CAPTURE.json',
        'failed-exception':FAILED/'EXCEPTION.txt',
        'failed-group-report':FAILED.parent/'REPORT.json','failed-owner':FAILED.parent/'OWNER.json',
        'failed-owner-returned':FAILED.parent/'OWNER-RETURNED.json','failed-outer':FAILED.parent/'OUTER.json',
        'edge-symbols':EVIDENCE/'compact-vm-diagnostic-r1/INPUTS.json',
    }
    for name in ('source','output','workspace'):
        authorities['native-'+name]=NATIVE/'native'/(name+'.shared')
        authorities['failed-'+name]=FAILED/(name+'.bin')
    fixed={name:row(path) for name,path in authorities.items()}
    require(fixed['R10-source']['identity']['git_blob']=='dcf7ab874951a9e0742b8cc17138095cd2af0973'
        and fixed['R10-image']['identity']['git_blob']=='78b32200cc4843860a6e60a9870d6ac306ae76d7','actual R10 changed')
    expected_failure=json.loads(read(FAILED/'RAW-VM-STATE.json')[0])
    require(expected_failure=={'error':{'code':'steps','message':'E_HIA_BUDGET_STEPS: finite step limit reached',
        'type':'HIAProgramBudgetExceeded'},'status':'budget_exceeded','steps':10000001,'values':[]},'unexpected old failure')
    for name,code in (('native',0),('failed',1)):
        raw=read(authorities[name+'-owner'])[0];old=json.loads(raw)
        returned=json.loads(read(authorities[name+'-owner-returned'])[0])
        require(returned==dict(old,supervisor_returncode=code,receipt_sha256=pin(raw)['sha256']),
                'actual old raw/returned owner differs')
        outer=json.loads(read(authorities[name+'-outer'])[0])
        require(outer['owner']==outer['terminal']==returned,'actual old outer differs')
    original_edge=read(authorities['original-edge-diagnostic'])[0]
    original_support=read(authorities['original-support'])[0]
    counted=read(ROOT/'counted_machine.py')[0];support=read(ROOT/'counted_support.py')[0]
    require(definition(counted,'CountedMachine')==definition(original_edge,'CountedMachine'),'Counted whole text differs')
    inverse={}
    for name in ('require','pin','read_regular','write','dump'):
        a=definition(support,name);b=definition(original_support,name)
        require(a==b,'original safe helper text differs: '+name)
        inverse[name]={'whole_bytes_equal':True,'identity':pin(a)}
    require(read(ROOT/'FROZEN-3180-SOURCE.json')[0]==read(authorities['R10-source-map'])[0],'source map copy differs')
    original_map=json.loads(read(ROOT/'FROZEN-3180-SOURCE.json')[0]);require(len(original_map)==3180,'source count differs')
    source_files=('hepta/hia_program_runtime.py','hepta/hia_agent_assembly.py','hepta/hia_program.py',
                  'hepta/hia_opcodes.py','tools/hia_selfhost_process_owner.py')
    for relative in source_files:
        raw,mode,_=read(SOURCE/relative);require(pin(raw,mode)==original_map[relative],'implementation source changed')
        write(ROOT/'original-source'/relative,raw)
    for name in ('original-edge-diagnostic','original-remaining-VM','original-wrapper','original-support'):
        write(ROOT/'original-source'/(name+'.py'),read(authorities[name])[0])
    controls={}
    for name in ('counted_machine.py','counted_support.py','run_cross_counted.py','FROZEN-3180-SOURCE.json'):
        value=row(ROOT/name);value.pop('path');controls[name]=value
    exe=Path('/tmp/hia-runtime-artifact-recovery-20261114-dda7/runtime-data/bin/python3.14')
    lib=exe.parent.parent/'lib/libpython3.14.so.1.0'
    runtime={'executable':row(exe),'library':row(lib),'version':[3,14,4],
        'environment':{'HOME':str(OUTPUT),'LANG':'C.UTF-8','LC_ALL':'C.UTF-8',
            'LD_LIBRARY_PATH':str(lib.parent),'PATH':'/usr/local/bin:/usr/bin:/bin',
            'PYTHONDONTWRITEBYTECODE':'1','TZ':'UTC'}}
    require(runtime['executable']['identity']['sha256']=='b135f1ae69c99912bc4b035f60255094103c7ee1c4659491ae61385ad5dd09a5'
        and runtime['library']['identity']['sha256']=='0cceb109e9b44702a0b5ab3b822c110e8d1c112fdb69ef97f1fef633f37850e0',
        'original recovered runtime differs')
    plan={'schema':'hepta.r10.cross-target-counted-execution-plan.v1','status':'AUTHORED_NOT_EXECUTED',
        'author_root':str(ROOT),'output':str(OUTPUT),'source':{'path':str(SOURCE),
            'files':3180,'tree':original_plan['source']['tree'],'map':'FROZEN-3180-SOURCE.json'},
        'runtime':runtime,'fixed_inputs':fixed,'controls':controls,
        'output_ancestors':{path:{k:getattr(Path(path).lstat(),k)
            for k in ('st_dev','st_ino','st_mode')} for path in ('/','/workspace')},
        'budgets':{'VM_steps':10000000,'VM_heap_bytes':1048576,'VM_call_depth':128,
            'qualification_seconds':180,'cleanup_seconds':3},'minimum_free_bytes':3221225472,
        'original_native_limits':json.loads(read(authorities['native-child'])[0])['limits'],
        'expected_failure':expected_failure,
        'expected_old_checks':json.loads(read(authorities['failed-result'])[0])['checks'],
        'expected_process_exit':1,'expected_owner_status':'QUALIFICATION_FAILED',
        'max_VM_invocations':1,'native_invocations':0,'generator_invocations':0,'compile_invocations':0,
        'public_qualification':False,'matching_current_cold':False,'R10_candidate_changed':False,
        'retry':False,'source_fresh_full_reads':['parent-before','child-before','child-finally','parent-finally'],
        'frame_contract':'six actual arrays; full original-failed partial equality; no oracle-written observation',
        'symbol_map':'fixed actual edge INPUTS.json, same actual R10 HIA/image; no new source_program call',
        'output_upper_estimate_bytes':67108864,
        'estimate_is_not_a_quota_or_budget_change':True,
        'authorization':'Only Root may authorize one execution; this author freeze is not an execution receipt'}
    material=(json.dumps(plan,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
    plan['authorization_pin']=pin(material)['sha256']
    dump(ROOT/'EXECUTION-PLAN.json',plan)
    command=[str(exe),'-B',str(ROOT/'run_cross_counted.py'),'--plan-sha256',plan['authorization_pin']]
    dump(ROOT/'LAUNCH.json',{'schema':'hepta.r10.cross-target-counted-launch.v1','status':'NOT_EXECUTED',
        'command':command,'cwd':str(SOURCE),'environment':runtime['environment'],
        'plan':row(ROOT/'EXECUTION-PLAN.json'),'expected_exit':1,'expected_original_product_outcome':'FAIL',
        'not_qualification':True,'new_native_calls':0,'max_new_VM_calls':1,
        'owner_seconds':180,'cleanup_seconds':3,'outer_stdout_stderr_exit_must_be_saved':True})
    tree=ast.parse(read(ROOT/'run_cross_counted.py')[0])
    require(len([n for n in ast.walk(tree) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute)
            and isinstance(n.func.value,ast.Name) and n.func.value.id=='machine' and n.func.attr=='invoke'])==1,
            'machine call denominator changed')
    require(len([n for n in ast.walk(tree) if isinstance(n,ast.Call) and isinstance(n.func,ast.Name)
            and n.func.id=='run_owned'])==1,'owner call denominator changed')
    counted_tree=ast.parse(counted)
    actual_class=next(n for n in counted_tree.body if isinstance(n,ast.ClassDef))
    require([n.name for n in actual_class.body if isinstance(n,ast.FunctionDef)]==['__init__','invoke'],
            'Counted may not alter tick/operation semantics')
    proof={'schema':'hepta.r10.cross-target-counted-authoring-proof.v1','status':'STATIC_ONLY',
        'product_executions':0,'project_imports':0,'future_output_absent':not os.path.lexists(OUTPUT),
        'Counted_class_full_bytes_equal':True,'Counted_class_identity':pin(definition(counted,'CountedMachine')),
        'Counted_class_AST_equal':ast.dump(ast.parse(definition(counted,'CountedMachine')),include_attributes=False)
            ==ast.dump(ast.parse(definition(original_edge,'CountedMachine')),include_attributes=False),
        'unmodified_original_safe_helpers':inverse,'runtime_method_overrides':['__init__','invoke'],
        'one_root_VM_call_site':True,'one_process_owner_call_site':True,'original_Machine_source':original_map['hepta/hia_program_runtime.py'],
        'full_frozen_source_count':3180,'actual_R10_partial_buffer_binding':{n:fixed['failed-'+n]
            for n in ('source','output','workspace')},
        'plan_identity':row(ROOT/'EXECUTION-PLAN.json'),'launch_identity':row(ROOT/'LAUNCH.json'),
        'all_new_Python_AST_parse_only':['counted_machine.py','counted_support.py','run_cross_counted.py','freeze_authoring.py','project_authoring.py'],
        'R9_to_R10_whole_inverse':json.loads(read(ROOT/'EXACT-INVERSE.json')[0]),
        'runtime_guard_scope':'only executable and libpython two-file closure; not all2496 runtime files',
        'output_ancestor_keys':['st_dev','st_ino','st_mode'],
        'output_space_floor_from_held_directory':True,
        'not_performance_measurement':True,'not_semantic_or_cold_pass':True,
        'created_utc':datetime.now(timezone.utc).isoformat()}
    for name in proof['all_new_Python_AST_parse_only']:ast.parse(read(ROOT/name)[0],filename=name)
    dump(ROOT/'STATIC-PROOF.json',proof)
    print(json.dumps({'status':'AUTHORING_FROZEN_NO_PRODUCT','plan':row(ROOT/'EXECUTION-PLAN.json'),
        'launch':row(ROOT/'LAUNCH.json'),'fixed_inputs':len(fixed),'future_output_absent':not os.path.lexists(OUTPUT)},indent=2))

if __name__=='__main__':main()

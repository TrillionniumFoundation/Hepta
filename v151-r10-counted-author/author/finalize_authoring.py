"""Freeze explanatory metadata around the already-authored plan; zero products."""
from pathlib import Path
import hashlib,json,os,stat
ROOT=Path(__file__).resolve().parent
def pin(b):return {'bytes':len(b),'git_blob':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest(),'sha256':hashlib.sha256(b).hexdigest()}
def enc(x):return (json.dumps(x,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def put(n,b):
    with (ROOT/n).open('xb') as f:f.write(b)
    (ROOT/n).chmod(0o644);assert (ROOT/n).read_bytes()==b
    return pin(b)
old=json.loads((ROOT/'before/EXECUTION-PLAN.json').read_bytes());plan=json.loads((ROOT/'EXECUTION-PLAN.json').read_bytes());launch=json.loads((ROOT/'LAUNCH.json').read_bytes());material=dict(plan);auth=material.pop('authorization_pin')
assert pin(enc(material))['sha256']==auth==launch['command'][-1]
assert old['budgets']==plan['budgets'] and old['minimum_free_bytes']==plan['minimum_free_bytes']==3221225472
assert old['source']==plan['source'] and len(plan['fixed_inputs'])==37
assert old['runtime']['executable']==plan['runtime']['executable'] and old['runtime']['library']==plan['runtime']['library']
before_env=dict(old['runtime']['environment']);after_env=dict(plan['runtime']['environment']);assert before_env.pop('HOME')!=after_env.pop('HOME') and before_env==after_env
changes=[]
def diff(a,b,path=''):
    if type(a)is not type(b):changes.append({'pointer':path,'before':a,'after':b});return
    if isinstance(a,dict):
        for k in sorted(a.keys()|b.keys()):
            q=path+'/'+str(k).replace('~','~0').replace('/','~1')
            if k not in a:changes.append({'pointer':q,'before_absent':True,'after':b[k]})
            elif k not in b:changes.append({'pointer':q,'before':a[k],'after_absent':True})
            else:diff(a[k],b[k],q)
    elif isinstance(a,list) and len(a)==len(b):
        for i,(x,y) in enumerate(zip(a,b)):diff(x,y,path+'/'+str(i))
    elif a!=b:changes.append({'pointer':path,'before':a,'after':b})
diff(old,plan)
put('PLAN-DIFFERENCES.json',enc({'status':'STATIC_BINDING_ONLY','before':pin((ROOT/'before/EXECUTION-PLAN.json').read_bytes()),'after':pin((ROOT/'EXECUTION-PLAN.json').read_bytes()),'differences':changes,'all_original_budgets_equal':True,'source_domain_equal':True,'Counted_implementation_whole_equal':True,'products':0}))
put('PLAN-PIN-ROLES.json',enc({'full_plan':pin((ROOT/'EXECUTION-PLAN.json').read_bytes()),'canonical_material_without_authorization_pin':pin(enc(material)),'command_plan_sha256':auth,'consumed_rule':'load_plan removes only authorization_pin, then canonical sorted indent2 LF SHA256; normal full guards also bind complete serialized plan bytes and seven stats.','products':0}))
summary={'status':'ACTUAL_R10_FAILURE_INPUTS_BOUND_NOT_EXECUTED','HIA':plan['fixed_inputs']['R10-source'],'image':plan['fixed_inputs']['R10-image'],'original_Core':[107,1456,6299],'failed_state':plan['expected_failure'],'expected_checks':plan['expected_old_checks'],'initial':{n:plan['fixed_inputs']['initial-'+n] for n in ('source','output','workspace')},'failed_partial':{n:plan['fixed_inputs']['failed-'+n] for n in ('source','output','workspace')},'source_files':3180,'runtime_file_count':2,'runtime_distribution2496_not_claimed':True,'products':0}
put('ACTUAL-INPUT-SUMMARY.json',enc(summary))
contract='''# R10 cross-target Counted diagnostic — authoring R1

AUTHORED_NOT_EXECUTED. Root alone may run LAUNCH.json once, after its independent terminal readback and static admission. This observes the actual R10 root-v8-cross-target-loans original fuel failure. No product source changes, generation, compile, Native call, qualification retry or new optimization are included.

## Exact actual inputs

Actual R10 assembly is 397114 B, Git dcf7ab874951a9e0742b8cc17138095cd2af0973; actual R10 machine image is 544696 B, Git 78b32200cc4843860a6e60a9870d6ac306ae76d7. The child checks 107 ordered functions, 1456 blocks, 6299 operations and the original failed VM report's full Core identity. Host source remains the frozen 3180-file tree 4c62be4ed66ff107fa6f88c6131313a354868bd9. Parent and child fully read that domain before and after. This older development scope does not become current/default/cold integration.

All 37 fixed inputs retain the actual Native-used image, 19089-byte input, complete 1MiB A5 output/zero workspace preimages, original Native request/child/observation/physical F/O/W and canaries, retained162 report/owner, failed six-case report/owner, capture/raw state/VM report/exception/full failed partial F/O/W, and same-source/image edge symbol record. R9 partial buffers are never substituted.

## Original invocation, full observations and limits

CountedMachine is whole-byte identical to the previously executed R9/R8/edge class. It delegates original invoke accounting to the original _Machine; tick/operation/report/resource semantics are untouched. There is exactly one f0 call using CountedMachine(checked,10000000,1048576,None,128). All setup, full source/fixed reads, assembly, observation, comparison and final guards remain within one original 180+3 owner. There is no split, warmup, retry or larger fuel run.

All three real live arrays are written/read before entry and immediately after return/exception. Incomplete before observation forbids entry. Every after-frame, exception, raw state, resource report, VM report and count write is independently attempted. All six buffers must exactly match the R10 preimages and R10 failed partials; saved raw status/error/steps/values and complete VM report must also match. Native comparison stays [true,true,false], return equality false, and complete spare-tail equality remains checked. Expected phase is 1 and semantic error is 0. No missing frame is fabricated from an oracle.

Even exact observation deliberately returns process 1/status FAIL and QUALIFICATION_FAILED; it must preserve child/supervisor exit 1, cleanup and ECHILD. diagnostic_observation_complete proves only faithful observation of the existing 5PASS/1FAIL logical VM group. Exclusive costs partition charged steps; inclusive costs overlap; instrumented elapsed time is not a performance comparison.

## Output/runtime guards and inverse

New output /workspace/hia-r10-cross-counted-r1-dda7 must be absent, including symlinks. Existing exact held/named / and /workspace dev/inode/mode checks, held-parent mkdir, and original 3221225472-byte fstatvfs floor are unchanged. The 64MiB output estimate is neither a reservation nor a quota. Fixed files keep full byte/mode/seven-stat guards. Runtime binds only the real recovered CPython3.14.4 executable and libpython two-file closure, not all 2496 runtime files. Original -B flags and exact environment remain; HOME alone changes to the new output.

before/ preserves complete R9 authors. EXACT-INVERSE proves whole-byte/AST reversal of the R10 labels, explicit actual input paths/pins and 6347-to-6299 Core denominator; Counted file, source map, five safe helpers, owner/cleanup and every original call/limit are unchanged. PLAN-DIFFERENCES enumerates actual JSON binding changes. The command SHA binds canonical plan JSON with only authorization_pin removed; LAUNCH separately records the full serialized plan identity. Root must preserve its real outer stdout/stderr/exit and complete actual owner/frames. This package authorizes no execution by itself.
'''
put('CONTRACT.md',contract.encode())
assert not os.path.lexists(plan['output'])
files={str(p.relative_to(ROOT)):pin(p.read_bytes()) for p in sorted(ROOT.rglob('*')) if p.is_file()}
handoff={'schema':'hepta.r10.cross-counted-authoring-handoff.v1','status':'AUTHORED_NOT_EXECUTED','root':str(ROOT),'files':files,'exact_launch':launch,'budgets':plan['budgets'],'fixed_inputs':37,'full_source_files':3180,'Counted_whole_file_unchanged':True,'original_expected_IR':[107,1456,6299],'runtime_files_guarded':2,'full_runtime2496_claim':False,'minimum_free_bytes':3221225472,'output':plan['output'],'expected_process_exit':1,'expected_product_status':'FAIL','expected_diagnostic':'exact prior R10 partial and raw report equality','only_Root_may_authorize_execution':True,'product_executions':0,'not_a_qualification':True}
ident=put('HANDOFF.json',enc(handoff));print(json.dumps({'handoff':ident,'plan':pin((ROOT/'EXECUTION-PLAN.json').read_bytes()),'launch':pin((ROOT/'LAUNCH.json').read_bytes()),'authorization_pin':auth,'files':len(files),'products':0},sort_keys=True))

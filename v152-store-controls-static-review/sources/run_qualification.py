"""Root-launched typed codec development controls, each under its original owner.

Only the two compile stages create executable images. Every following group
uses its exact actual image. First failure stops the chain without a retry.
No result admits a Store backend, an FD adapter or a durable transaction.
"""
from __future__ import annotations
import argparse
import os
from pathlib import Path
import sys
import time
import traceback
sys.path.insert(0,str(Path(__file__).absolute().parent))
import qualification_support as S
from head_cases import GROUPS as HEAD_GROUPS
from catalog_cases import GROUPS as CATALOG_GROUPS

STAGES=('compile-head','compile-catalog',*HEAD_GROUPS,*CATALOG_GROUPS)

def run_stage(plan,plan_row,generation,stage,prior,builds,env,runtime,owner,result):
    before=S.guard(plan,generation,runtime.guard_runtime_context)
    S.prior_readback(prior)
    S.require(S.G.decode(S.fixed(plan_row))==plan,'frozen plan changed before stage')
    free=S.G.floor(Path(plan['attempt']))
    component=stage[8:] if stage.startswith('compile-') else stage.split('-',1)[0]
    build=None if stage.startswith('compile-') else builds[component]
    if build is not None:S.image_guard(plan,build)
    directory=Path(plan['attempt'])/('%02d-'%(STAGES.index(stage)+1)+stage)
    directory.mkdir(mode=0o700)
    request=dict(schema=S.SCHEMA+'.request',plan=plan_row,limits=plan['limits'],stage=stage,
        directory=str(directory),prior_inventories=prior,build=build)
    S.write(directory/'REQUEST.json',request);request_row=S.G.capture(directory/'REQUEST.json')
    command=[plan['runtime']['launch_executable'],'-I','-B',plan['controls']['run_child.py']['path'],
        '--request',request_row['path'],'--sha256',request_row['pin']['sha256']]
    S.write(directory/'COMMAND.json',dict(command=command,cwd=plan['source'],environment=env,
        supervisor_environment=env,qualification_seconds=180,cleanup_seconds=3,free_bytes_before=free))
    observed=dict(stage=stage,status='FAIL',directory=str(directory),full_before=before,
        started_ns=time.monotonic_ns(),owner_returned=None,terminal_errors=[])
    result['stages'].append(observed);S.write(directory/'STAGE-INTENT.json',observed)
    child=None
    try:
        result['owner_launch_attempts']+=1
        returned=owner.run_owned(command,cwd=plan['source'],env=env,supervisor_env=env,
            stdout_path=directory/'stdout.raw',stderr_path=directory/'stderr.raw',
            receipt_path=directory/'OWNER.json',qualification_seconds=180,cleanup_seconds=3)
        observed['owner_returned']=returned;S.write(directory/'OWNER-RETURNED.json',returned)
        actual=S.G.admit_owner(returned,directory,command,env,plan)
        S.require(actual['status']=='OWNED_PROCESS_COMPLETED' and actual['returncode']==0
            and actual['timed_out'] is False and actual['exit_observed_before_deadline'] is True,
            'original owner failure or budget exceeded')
        child=S.read(directory/'CHILD-RESULT.json')
        S.require(child['schema']==S.SCHEMA+'.child' and child['status']=='PASS'
            and child['stage']==stage and child['request']==request_row and child['errors']==[]
            and child['actual_runtime']==plan['runtime'],'complete actual child result required')
        S.equal(child['full_before'],child['full_after'])
        if stage.startswith('compile-'):
            S.require(child['compile_calls']==1 and child['Native_calls']==child['VM_calls']==0,
                'one compiler call and no semantic calls required')
            build=child['build'];S.image_guard(plan,build)
            S.require(S.read(directory/'compile/BUILD.json')==build,'exact actual BUILD record required')
            builds[component]=build
            observed['build']=build
        else:
            S.require(child['compile_calls']==0 and child['Native_calls']==child['VM_calls']>0,
                'semantic groups require paired real calls without compilation')
            audited=S.frames(directory,plan,component,build)
            S.require(audited==child['frames'] and audited['calls']==child['Native_calls']
                and audited['cases']==child['cases']['cases']==plan['groups'][stage]['cases']
                and audited['calls']==plan['groups'][stage]['paired_calls'] and child['cases']['group']==stage,
                'parent complete physical/full-frame and independent case admission differs')
            S.image_guard(plan,build);observed['frames']=audited
        observed.update(status='PASS',child=S.G.capture(directory/'CHILD-RESULT.json'),
            compile_calls=child['compile_calls'],Native_calls=child['Native_calls'],VM_calls=child['VM_calls'])
    except BaseException:observed['error']=traceback.format_exc()
    finally:
        try:
            S.require(S.G.decode(S.fixed(plan_row))==plan,'frozen plan changed after stage')
            S.prior_readback(prior)
            observed['full_after']=S.guard(plan,generation,runtime.guard_runtime_context)
            S.equal(before,observed['full_after'])
        except BaseException:
            observed['status']='FAIL';observed['terminal_errors'].append(traceback.format_exc())
        observed['finished_ns']=time.monotonic_ns();S.write(directory/'STAGE.json',observed)
    S.require(observed['status']=='PASS','first incomplete child, full-frame, guard or owner failure stops the chain')
    return S.publish_artifacts(directory,S.G.stage_artifacts(directory))

def execute(path,sha):
    plan_row,plan,generation=S.load(path,sha)
    S.require(plan['stages']==list(STAGES) and len(STAGES)==27 and len(HEAD_GROUPS)==12
        and len(CATALOG_GROUPS)==13,'fixed two compiles and all 25 typed/state groups required')
    S.require(Path(__file__).absolute()==Path(plan['controls']['run_qualification.py']['path']),
        'exact frozen parent required')
    scope=Path(plan['scope']);attempt=Path(plan['attempt'])
    S.require(attempt==scope/'attempt-r1' and not os.path.lexists(scope),'one absent explicit independent scope required')
    before=S.guard(plan,generation)
    runtime,owner=S.G.import_runtime(plan)
    runtime.guard_runtime_context(plan['runtime']);actual_runtime=runtime.capture_runtime_context()
    S.require(actual_runtime==plan['runtime'],'whole original runtime context required')
    free=S.G.floor(scope.parent)
    scope.mkdir(mode=0o700);attempt.mkdir(mode=0o700);(attempt/'tmp').mkdir(mode=0o700)
    env=S.G.environment(plan);S.require(env==plan['environment'],'explicit fixed environment differs')
    S.write(attempt/'PLAN-USED.json',plan);S.write(attempt/'RUNTIME.json',actual_runtime)
    S.write(attempt/'ENVIRONMENT.json',env)
    S.write(attempt/'SOURCE-STATE-BEFORE.json',S.G.metadata(Path(plan['source'])))
    S.write(attempt/'RUNTIME-STATE-BEFORE.json',S.G.metadata(Path(plan['runtime']['base_prefix'])))
    result=dict(schema=S.SCHEMA+'.result',status='FAIL',plan=plan_row,started_ns=time.monotonic_ns(),
        free_bytes_before=free,full_before=before,stages=[],owner_launch_attempts=0,
        terminal_errors=[],automatic_retry=False,default_activated=False,durability_qualified=False,
        sqlite_backend_replaced=False,catalogue_graph_verified=False,transaction_row_semantics_verified=False,
        filesystem_adapter_executed=False,current_cold=False,whole=False)
    prior=S.publish_artifacts(attempt,[S.G.capture(p) for p in sorted(attempt.iterdir()) if p.is_file()]);builds={}
    try:
        for stage in STAGES:prior+=run_stage(plan,plan_row,generation,stage,prior,builds,env,runtime,owner,result)
        S.require(len(result['stages'])==result['owner_launch_attempts']==27,'all original owners required')
        S.prior_readback(prior);S.G.floor(attempt)
        result.update(status='PASS_TYPED_NATIVE_VM_HEAD_AND_CATALOG_CONTROLS_ONLY',
            actual_compilations=sum(x['compile_calls'] for x in result['stages']),
            actual_Native_calls=sum(x['Native_calls'] for x in result['stages']),
            actual_VM_calls=sum(x['VM_calls'] for x in result['stages']),actual_builds=builds)
    except BaseException:result['error']=traceback.format_exc()
    finally:
        try:
            S.prior_readback(prior)
            S.require(S.G.decode(S.fixed(plan_row))==plan,'terminal fixed author plan changed')
            result['full_after']=S.guard(plan,generation,runtime.guard_runtime_context)
            S.equal(before,result['full_after'])
            S.write(attempt/'SOURCE-STATE-AFTER.json',S.G.metadata(Path(plan['source'])))
            S.write(attempt/'RUNTIME-STATE-AFTER.json',S.G.metadata(Path(plan['runtime']['base_prefix'])))
        except BaseException:result['status']='FAIL';result['terminal_errors'].append(traceback.format_exc())
        result['actual_stage_order']=[s['stage'] for s in result['stages']]
        result['unstarted_stages']=list(STAGES[len(result['stages']):]);result['finished_ns']=time.monotonic_ns()
        S.write(attempt/'RESULT.json',result)
    return 0 if result['status']=='PASS_TYPED_NATIVE_VM_HEAD_AND_CATALOG_CONTROLS_ONLY' else 1

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--plan',required=True);p.add_argument('--sha256',required=True)
    a=p.parse_args();raise SystemExit(execute(a.plan,a.sha256))

"""Fail-stopping Source8, eight actual builds and twelve owned Native methods.

Every child keeps 180+3. Complete parent admission/readback is separately
stated; it grants no historical, default, cold or whole qualification.
"""
from __future__ import annotations
import argparse
import time
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).absolute().parent))
from execution_support import *


def native_guard(inputs,bundle):
    if bundle is not None:checked(bundle)
    for row in inputs.values():
        for item in row.values():checked(item)


def context_for(plan,directory,phase,group,native,bundle):
    current=decode(checked(plan['source_map']))
    cfg={'schema':'hepta.hia.patch-cli.control-context.v3','phase':phase,'source':plan['source'],
        'controls_output':str(directory/'controls'),
        'adapter_files':{name:current[name]for name in ('hepta/hia_cli_inspect_native.py',
            'hepta/hia_inspect_cli_operand.py','hepta/hia_inspect_cli_records.py')},
        'new_production':{name:{k:current[name][k]for k in ('bytes','sha256','git_blob')}
            for name in ('hepta/hia_cli_patch_result_native.py','hepta/hia_patch_cli_records.py')},
        'authority_files':{name:{'path':plan['controls'][key]['path'],'pin':plan['controls'][key]['pin'],
            'posix_mode':stat.S_IMODE(plan['controls'][key]['stat']['st_mode'])}
            for name,key in plan['authority_names'].items()}}
    for name,key in (('retained_support','inspect_cli_control_support.py'),('original_observer','inspect_exec_support.py')):
        row=plan['controls'][key];cfg[name]={'path':row['path'],'pin':row['pin'],
            'posix_mode':stat.S_IMODE(row['stat']['st_mode'])}
    if phase=='native':
        require(set(native)==set(COMPONENTS)and bundle is not None,'all eight actual builds required')
        cfg.update(report_manifest=bundle['path'],inspect_manifest=native['inspect']['manifest']['path'],
            patch_manifest=native['patch']['manifest']['path'],signature_native=group['signature_native'])
    return cfg


def take_build(plan,directory,label,actual):
    manifest=Path(actual['build']['manifest']);require(manifest.is_relative_to(directory),'build escaped stage')
    inputs={};bundle=None
    if label=='build-report-six':
        bundle=capture(manifest);value=decode(checked(bundle))
        for name in COMPONENTS[:6]:
            relative=value[name+'_manifest']
            require(type(relative)is str and not Path(relative).is_absolute()
                    and all(p not in ('','.', '..')for p in relative.split('/')),'bundle child traversal')
            row=component_binding(manifest.parent/relative,Path(plan['source'])/plan['component_sources'][name],
                                  plan['compiler'],directory)
            require(row['manifest']['pin']['sha256']==value[name+'_manifest_sha256'],'child manifest hash differs')
            inputs[name]=row
        require(actual['build']['six_real_compilations']is True and
                actual['build']['matching_current_cold']is False,'six-component scope differs')
    else:
        name='inspect'if label=='build-inspect'else'patch'
        inputs[name]=component_binding(manifest,Path(plan['source'])/plan['component_sources'][name],
                                      plan['compiler'],directory)
        require(actual['build']['matching_current_cold']is False,'development scope differs')
    artifacts=[]
    for path in sorted(directory.rglob('*')):
        info=path.lstat();require(stat.S_ISDIR(info.st_mode)or stat.S_ISREG(info.st_mode),'unknown build member')
        if stat.S_ISREG(info.st_mode):artifacts.append(capture(path))
    return inputs,bundle,artifacts


def execute(plan_path,expected_sha,binding_path,binding_sha):
    raw=checked(capture(Path(plan_path),maximum=16<<20));plan=decode(raw)
    require(hashlib.sha256(raw).hexdigest()==expected_sha and plan['schema']==SCHEMA
            and plan['state']=='BOUND_AWAITING_ROOT_AUTHORIZATION','exact bound plan required')
    binding_raw=checked(capture(Path(binding_path),maximum=16<<20));binding=decode(binding_raw)
    require(hashlib.sha256(binding_raw).hexdigest()==binding_sha and binding['status']=='BOUND_NOT_EXECUTED'
            and binding['products_executed']==0 and checked(binding['plan'])==raw
            and Path(__file__).absolute()==Path(plan['controls']['run_execution.py']['path']),
            'actual binding or executing runner differs')
    template=decode(checked(plan['template']));matrix=decode(checked(plan['controls']['CONTROL-MATRIX.json']))
    labels=['op13-source8','build-report-six','build-inspect','build-patch']+[r['group']for r in matrix['native_groups']]
    require(template['new_group_order']==labels and len(labels)==16 and len(matrix['source_ids'])==8
            and len(matrix['native_groups'])==12 and template['child_limits']==LIMITS,'original stages/IDs/limits differ')
    require(sys.implementation.name=='cpython'and sys.version_info[:3]==(3,14,4)
            and sys.flags.isolated and sys.flags.dont_write_bytecode,'actual3.14.4 -I -B required')
    all_guards(plan);runtime,owner=import_runtime(plan);runtime.guard_runtime_context(plan['runtime'])
    attempt=Path(plan['attempt']);require(not os.path.lexists(attempt),'exclusive attempt exists')
    free=floor(attempt.parent);attempt.mkdir(mode=0o700);(attempt/'tmp').mkdir(mode=0o700)
    publish(attempt/'PLAN-USED.json',plan)
    result={'schema':SCHEMA+'.result','status':'FAIL','plan_pin':pin(raw),'binding_pin':pin(binding_raw),
        'started_ns':time.monotonic_ns(),'free_bytes_before':free,'stages':[],'actual_owner_launch_attempts':0,
        'new_build_calls_required':8,'all_frames_retired':False,'compile_full_workspaces_observed':False,
        'current_cold':False,'default':False,'whole':False,'original_R5_witness10':'FAIL_UNCHANGED_NOT_REQUALIFIED',
        'future_vm12_executed':False}
    native={};bundle=None;build_artifacts=[]
    try:
        env=environment(plan);publish(attempt/'ENVIRONMENT.json',env);publish(attempt/'RUNTIME.json',plan['runtime'])
        for index,label in enumerate(labels):
            all_guards(plan,runtime.guard_runtime_context);free=floor(attempt)
            require(checked(binding['plan'])==raw,'plan changed before stage')
            for item in build_artifacts:checked(item)
            native_guard(native,bundle)
            directory=attempt/('%02d-'%(index+1)+label);directory.mkdir(mode=0o700)
            is_build=label.startswith('build-');is_source=label=='op13-source8'
            if is_build:
                request={'schema':SCHEMA+'.build-request','plan':capture(Path(plan_path)),
                    'group':label,'directory':str(directory),'limits':LIMITS}
                child=plan['controls']['run_build_child.py']['path'];ids=[]
            else:
                phase='source'if is_source else'native'
                group={}if is_source else next(r for r in matrix['native_groups']if r['group']==label)
                ids=matrix['source_ids']if is_source else[group['id']]
                request={'schema':'hepta.hia.patch-cli.bound-child.v3','state':'BOUND_AWAITING_ROOT_AUTHORIZATION',
                    'limits':LIMITS,'source':plan['source'],'source_map':plan['source_map'],
                    'source_state':plan['source_state'],'controls':plan['controls'],'runtime':plan['runtime'],
                    'phase':phase,'group':'source8'if is_source else label,'ids':ids,'directory':str(directory),
                    'context':context_for(plan,directory,phase,group,native,bundle)}
                if not is_source:request.update(native_inputs=native,report_bundle=bundle)
                child=plan['controls']['run_control_child.py']['path']
            request_path=directory/'REQUEST.json';publish(request_path,request)
            request_raw=checked(capture(request_path));require(len(request_raw)<=8<<20,'request exceeds8MiB')
            command=[plan['runtime']['launch_executable'],'-I','-B',child,'--request',str(request_path),
                '--request-sha256',hashlib.sha256(request_raw).hexdigest()]
            publish(directory/'COMMAND.json',{'command':command,'cwd':plan['source'],'environment':env,
                'supervisor_environment':env,'qualification_seconds':180,'cleanup_seconds':3,'free_bytes_before':free})
            stage={'label':label,'directory':str(directory),'ids':ids,'status':'FAIL',
                   'started_ns':time.monotonic_ns(),'owner_returned':None}
            result['stages'].append(stage);actual=None;pending_build=None
            try:
                result['actual_owner_launch_attempts']+=1
                returned=owner.run_owned(command,cwd=plan['source'],env=env,supervisor_env=env,
                    stdout_path=directory/'stdout.raw',stderr_path=directory/'stderr.raw',
                    receipt_path=directory/'OWNER.json',qualification_seconds=180,cleanup_seconds=3)
                stage['owner_returned']=returned;publish(directory/'OWNER-RETURNED.json',returned)
                admit_owner(returned,directory,command,env,plan)
                actual=decode(checked(capture(directory/'RESULT.json')))
                require(actual['status']=='PASS'and actual['request_pin']==pin(request_raw)
                        and not actual.get('terminal_guard_errors')and actual['source_after']==actual['source_before'],
                        'actual child failed or drifted')
                if is_build:
                    pending_build=take_build(plan,directory,label,actual)
                else:
                    tests=decode(checked(capture(directory/'TESTS.json')))
                    require(actual['tests']==tests,'raw tests differ');admit_tests(tests,ids)
                stage['status']='PASS'
            except BaseException:
                stage['error']=traceback.format_exc();result['halted_after_first_failure']=True
            finally:
                errors=[]
                for name in ('actual-child','frames','guards'):
                    try:
                        if name=='actual-child'and(directory/'RESULT.json').is_file():
                            stage['actual_child']=capture(directory/'RESULT.json')
                        elif name=='frames'and not is_build:
                            frames=audit_frames(directory);publish(directory/'FRAME-READBACK.json',frames)
                            stage['frame_readback']=capture(directory/'FRAME-READBACK.json')
                            if stage['status']=='PASS':require(frames['all_observed_frames_complete'],'incomplete actual frame')
                        elif name=='guards':
                            stage['source_after']=all_guards(plan,runtime.guard_runtime_context)
                            native_guard(native,bundle)
                            for item in build_artifacts:checked(item)
                    except BaseException:errors.append({'kind':name,'traceback':traceback.format_exc()})
                if errors:stage.update(status='FAIL',terminal_errors=errors)
                stage['finished_ns']=time.monotonic_ns();publish(directory/'STAGE.json',stage)
            require(stage['status']=='PASS','first failure stops all later stages; no retry')
            if is_build:
                require(pending_build is not None,'missing admitted actual build')
                new,new_bundle,artifacts=pending_build
                artifacts.append(capture(directory/'STAGE.json'))
                require(not(set(new)&set(native)),'component repeated')
                native.update(new);bundle=new_bundle if new_bundle is not None else bundle
                build_artifacts.extend(artifacts)
                publish(directory/'ACTUAL-COMPONENTS.json',{'components':new,'bundle':new_bundle})
                build_artifacts.append(capture(directory/'ACTUAL-COMPONENTS.json'))
        require(set(native)==set(COMPONENTS)and len(result['stages'])==16,'stage chain incomplete')
        all_guards(plan,runtime.guard_runtime_context);native_guard(native,bundle)
        for row in build_artifacts:checked(row)
        result.update(status='DEVELOPMENT_OP13_SOURCE8_BUILD8_NATIVE12_PASS',native_inputs=native,
                      report_bundle=bundle,original_retained_groups_rerun=False)
    except BaseException:result.update(error=traceback.format_exc(),halted_after_first_failure=True)
    finally:
        result['finished_ns']=time.monotonic_ns()
        try:
            result['source_after']=all_guards(plan,runtime.guard_runtime_context);native_guard(native,bundle)
        except BaseException:result.update(status='FAIL',terminal_guard_error=traceback.format_exc())
        publish(attempt/'RESULT.json',result)
    return 0 if result['status']=='DEVELOPMENT_OP13_SOURCE8_BUILD8_NATIVE12_PASS'else 1


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--plan',required=True)
    parser.add_argument('--plan-sha256',required=True);parser.add_argument('--binding',required=True)
    parser.add_argument('--binding-sha256',required=True);a=parser.parse_args()
    raise SystemExit(execute(a.plan,a.plan_sha256,a.binding,a.binding_sha256))

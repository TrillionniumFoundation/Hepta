"""One explicitly authorized actual-R10 Counted diagnostic. Expected exit: 1.

This observes the existing fuel failure. It never upgrades a qualification,
executes Native, changes HIA, or retries a timed out/failed observation.
"""
from pathlib import Path
import argparse
import json
import os
import stat
import sys
import time
import traceback
import counted_support as S


def attempt(errors,label,action):
    try:
        return action()
    except BaseException as error:
        errors.append({'where':label,'type':type(error).__name__,'traceback':traceback.format_exc()})
        return None


def note_exception(errors,label,error):
    errors.append({'where':label,'type':type(error).__name__,'traceback':traceback.format_exc()})


def capture_frames(folder,phase,roots,errors):
    rows={}
    for name,owner in zip(('source','output','workspace'),roots):
        def save(name=name,owner=owner):
            # This is the actual live array, never an oracle-derived buffer.
            raw=bytes(owner.data)
            path=folder/(name+'.'+phase+'.bin')
            S.write(path,raw)
            saved,mode,stamp=S.read_regular(path)
            S.require(saved==raw,'actual array write/readback differs')
            return {'path':str(path),'identity':S.pin(saved,mode),'stat':stamp,
                    'owner_ident':owner.ident,'owner_active':owner.active}
        row=attempt(errors,'capture-'+phase+'-'+name,save)
        if row is not None:rows[name]=row
    attempt(errors,'capture-'+phase+'-manifest',lambda:S.dump(folder/(phase.upper()+'-FRAMES.json'),rows))
    return rows


def final_guard(root,plan,plan_state,folder,before,bindings,errors):
    def source():
        observed=S.source_snapshot(root,plan)
        S.dump(folder/'FULL-SOURCE-AFTER.json',observed)
        S.require(before is not None and observed==before,'complete source/inode state differs or was not observed')
    def fixed():
        observed=S.guards(root,plan,plan_state)
        S.dump(folder/'BINDINGS-AFTER.json',observed)
        S.require(bindings is not None and observed==bindings,'complete bindings differ or were not observed')
    attempt(errors,'final-source',source)
    attempt(errors,'final-bindings',fixed)


def child(root,plan,plan_state):
    folder=Path(plan['output'])/'diagnostic'
    errors=[];before=None;bindings=None;roots=None;machine=None;authority=None
    values=[];status='not_started';error=None;exception_text=None;calls_attempted=0
    state=None;observed=None;costs=None;comparisons=None
    before_rows={};after_rows={};started=None;stopped=None
    report={'schema':'hepta.r10.cross-target-counted-diagnostic.v1','status':'FAIL',
            'qualification_pass':False,'matching_current_cold':False,'whole':False,
            'expected_original_outcome':'budget_exceeded','expected_process_exit':1,
            'new_native_calls':0,'generator_calls':0,'compile_calls':0,'automatic_retry':False}
    try:
        S.require(stat.S_ISDIR(folder.lstat().st_mode),'parent did not create a real evidence directory')
        parent=json.loads(S.read_regular(Path(plan['output'])/'LAUNCH.json')[0])
        S.require(parent['command']==[plan['runtime']['executable']['path'],'-B',str(root/'run_cross_counted.py'),
            '--plan-sha256',plan['authorization_pin'],'--child']
            and parent['environment']==plan['runtime']['environment']
            and parent['qualification_seconds']==180 and parent['cleanup_seconds']==3,
            'actual parent launch binding differs')
        bindings=S.guards(root,plan,plan_state);S.dump(folder/'BINDINGS-BEFORE.json',bindings)
        before=S.source_snapshot(root,plan);S.dump(folder/'FULL-SOURCE-BEFORE.json',before)
        authority=S.prior_authority(plan)
        S.dump(folder/'INPUT-ADMISSION.json',{'status':'ACTUAL_ORIGINAL_INPUTS_READ',
            'source':plan['source'],'HIA':S.pin(authority['program']),'image':S.pin(authority['image']),
            'initial':{n:S.pin(v) for n,v in zip(('source','output','workspace'),authority['initial'])},
            'old_partial':{n:S.pin(v) for n,v in zip(('source','output','workspace'),authority['failed'])},
            'symbol_order':authority['symbol_order'],'old_VM_status':'FAIL','new_native_calls':0})
        sys.path.insert(0,plan['source']['path'])
        from hepta.hia_agent_assembly import assemble_program
        from hepta.hia_program_runtime import _Machine, _Owner, _View, HIAProgramBudgetExceeded, HIAProgramTrap
        from counted_machine import CountedMachine
        S.require(CountedMachine.__bases__==(_Machine,),'Counted base is not the original _Machine')
        checked=assemble_program(authority['program'])
        functions=checked.as_dict()['functions']
        S.require([fn['name'] for fn in functions]==['f'+str(i) for i in range(107)],'actual function ordering differs')
        S.require(sum(len(fn['blocks']) for fn in functions)==1456
            and sum(len(b['ops']) for fn in functions for b in fn['blocks'])==6299,
            'actual original R10 IR denominator differs')
        S.require(checked.sha256==authority['vm_report']['program_sha256'],'actual original Core identity differs')
        roots=tuple(_Owner(-(i+1),bytearray(value)) for i,value in enumerate(authority['initial']))
        machine=CountedMachine(checked,10000000,1048576,None,128)
        before_rows=capture_frames(folder,'before',roots,errors)
        S.require(len(before_rows)==3 and not errors,'before observation incomplete; no invocation allowed')
        # All setup, assembly, custody, and teardown remain inside this one
        # original 180-second owner; the original machine fuel is unchanged.
        started=time.monotonic_ns();calls_attempted=1;status='returned'
        try:
            values=machine.invoke(machine.functions['f0'],
                [_View(roots[0],False),_View(roots[1],True),_View(roots[2],True)])
        except (HIAProgramBudgetExceeded,HIAProgramTrap) as exc:
            error=exc;status='budget_exceeded' if isinstance(exc,HIAProgramBudgetExceeded) else 'trapped'
            exception_text=traceback.format_exc()
        except BaseException as exc:
            error=exc;status='unexpected_error';exception_text=traceback.format_exc()
            note_exception(errors,'machine-unexpected',exc)
        finally:
            stopped=time.monotonic_ns()
            # Attempt every actual after frame before report/comparison code.
            after_rows=capture_frames(folder,'after',roots,errors)
            state={'steps':machine.steps,'status':status,'values':values,
                'error':None if error is None else {'type':type(error).__name__,
                    'code':getattr(error,'code',None),'message':str(error)}}
            attempt(errors,'raw-machine-state',lambda:S.dump(folder/'RAW-VM-STATE.json',state))
            attempt(errors,'machine-resources',lambda:S.dump(folder/'RESOURCES.json',machine.resources()))
            if exception_text is not None:
                attempt(errors,'original-exception',lambda:S.write(folder/'EXCEPTION.txt',exception_text.encode()))
            if status in ('returned','budget_exceeded','trapped'):
                def machine_report():
                    value=machine.report('f0',status,values,error=error,external_roots=roots)
                    S.dump(folder/'VM-REPORT.json',value)
                    return value
                observed=attempt(errors,'original-machine-report',machine_report)
            def save_counts():
                rows=[dict(function=fn,source_function=authority['symbol_order'][fn],**value)
                      for fn,value in machine.call_costs.items()]
                rows.sort(key=lambda row:(-row['exclusive_steps'],row['function']))
                S.dump(folder/'STEP-COUNTS.json',{'rows':rows,'frames_after_unwind':machine.frames,
                    'exclusive_step_sum':sum(r['exclusive_steps'] for r in rows),
                    'actual_machine_steps':machine.steps,'invoke_started_ns':started,'invoke_stopped_ns':stopped,
                    'timing_is_instrumented_and_not_a_performance_comparison':True})
                return rows
            costs=attempt(errors,'step-counts',save_counts)
        def compare():
            # Fresh complete old oracle reads and actual newly saved frames.
            prior=S.prior_authority(plan)
            initial=tuple(S.read_regular(folder/(n+'.before.bin'))[0] for n in ('source','output','workspace'))
            final=tuple(S.read_regular(folder/(n+'.after.bin'))[0] for n in ('source','output','workspace'))
            value={'initial_complete_bytes_equal':[a==b for a,b in zip(initial,prior['initial'])],
                'old_failed_partial_complete_bytes_equal':[a==b for a,b in zip(final,prior['failed'])],
                'old_raw_state_equal':state==prior['state'],
                'old_VM_report_equal':observed==prior['vm_report'],
                'native_complete_bytes_equal':[a==b for a,b in zip(final,prior['native'])],
                'native_return_equal':status=='returned' and values==[prior['native_return']],
                'original_limit_retained':machine.max_steps==10000000 and machine.max_heap_bytes==1048576
                    and machine.max_call_depth==128 and machine.allocation_fail_at is None,
                'root_calls':machine.call_costs.get('f0',{}).get('calls'),
                'all_counted_frames_unwound':machine.frames==[],
                'exclusive_step_sum_equal':costs is not None and sum(r['exclusive_steps'] for r in costs)==machine.steps,
                'source_mutable':False,'output_mutable':True,'workspace_mutable':True,
                'phase_word':int.from_bytes(final[2][48:56],'little'),
                'semantic_error_word':int.from_bytes(final[2][40:48],'little'),
                'spare_tail_unchanged':final[2][1047040:]==initial[2][1047040:]}
            S.dump(folder/'COMPARISONS.json',value)
            S.require(value['initial_complete_bytes_equal']==[True]*3
                and value['old_failed_partial_complete_bytes_equal']==[True]*3
                and value['old_raw_state_equal'] and value['old_VM_report_equal']
                and value['native_complete_bytes_equal']==[True,True,False]
                and value['native_return_equal']is False and value['original_limit_retained']
                and value['root_calls']==1 and value['all_counted_frames_unwound']
                and value['exclusive_step_sum_equal'] and value['spare_tail_unchanged'],
                'diagnostic did not exactly reproduce the original failure')
            return value
        comparisons=attempt(errors,'complete-byte-comparison',compare)
    except BaseException as exc:
        note_exception(errors,'child-setup-or-observation',exc)
    finally:
        final_guard(root,plan,plan_state,folder,before,bindings,errors)
        actual_calls=0 if machine is None else machine.call_costs.get('f0',{}).get('calls',0)
        report.update(diagnostic_observation_complete=(comparisons is not None and not errors),
            original_fuel_failure_reproduced=(comparisons is not None),
            diagnostic_status='COMPLETE_ORIGINAL_FUEL_FAILURE' if comparisons is not None and not errors else 'INCOMPLETE_OR_DIFFERENT_OBSERVATION',
            actual_new_VM_calls=actual_calls,VM_invocation_attempts=calls_attempted,observed_outcome=status,
            VM_steps=None if machine is None else machine.steps,
            before_frame_count=len(before_rows),after_frame_count=len(after_rows),
            comparisons=comparisons,errors=errors,
            historical_VM6_status='5 PASS / 1 fuel FAIL; unchanged',
            missing_after_on_hard_timeout='unobserved; never fabricated from oracle')
        attempt(errors,'final-report',lambda:S.dump(folder/'REPORT.json',report))
        # This diagnostic ALWAYS retains a failing product exit, even when
        # every original failed byte has been observed and compared exactly.
        try:print(json.dumps({'status':'FAIL','diagnostic_observation_complete':report['diagnostic_observation_complete'],
                    'actual_new_VM_calls':actual_calls,'errors':errors},sort_keys=True),flush=True)
        except BaseException:
            try:sys.stderr.write(traceback.format_exc());sys.stderr.flush()
            except BaseException:pass
    return 1


def validate_child(root,plan,folder):
    report=json.loads(S.read_regular(folder/'REPORT.json')[0])
    S.require(report['status']=='FAIL' and report['qualification_pass']is False
        and report['diagnostic_observation_complete']is True and report['errors']==[]
        and report['actual_new_VM_calls']==1 and report['new_native_calls']==0
        and report['VM_steps']==10000001,'child diagnostic incomplete or different')
    prior=S.prior_authority(plan)
    frames={}
    for phase,expected in (('before',prior['initial']),('after',prior['failed'])):
        manifest=json.loads(S.read_regular(folder/(phase.upper()+'-FRAMES.json'))[0])
        S.require(set(manifest)=={'source','output','workspace'},'frame manifest count differs')
        for name,value in zip(('source','output','workspace'),expected):
            path=folder/(name+'.'+phase+'.bin');raw,mode,stamp=S.read_regular(path)
            row=manifest[name]
            S.require(raw==value and row=={'path':str(path),'identity':S.pin(raw,mode),'stat':stamp,
                'owner_ident':-1-('source','output','workspace').index(name),'owner_active':True},
                'complete actual frame or recorded identity differs: '+str(path))
            frames[path.name]={'identity':S.pin(raw,mode),'stat':stamp}
    S.require(json.loads(S.read_regular(folder/'RAW-VM-STATE.json')[0])==prior['state']
        and json.loads(S.read_regular(folder/'VM-REPORT.json')[0])==prior['vm_report'],'saved VM state differs')
    costs=json.loads(S.read_regular(folder/'STEP-COUNTS.json')[0])
    S.require(costs['exclusive_step_sum']==costs['actual_machine_steps']==10000001
        and costs['frames_after_unwind']==[] and sum(r['exclusive_steps'] for r in costs['rows'])==10000001,
        'saved Counted exclusive accounting differs')
    S.require(len({r['function'] for r in costs['rows']})==len(costs['rows'])
        and all(r['source_function']==prior['symbol_order'][r['function']] and r['calls']>0
            and 0<=r['exclusive_steps']<=r['inclusive_steps'] for r in costs['rows'])
        and next(r for r in costs['rows'] if r['function']=='f0')['calls']==1,'saved Counted symbols/calls differ')
    return {'status':'EXACT_ORIGINAL_FAILURE_OBSERVED','qualification_pass':False,'frames':frames,
            'report_identity':S.pin(S.read_regular(folder/'REPORT.json')[0]),
            'step_counts_identity':S.pin(S.read_regular(folder/'STEP-COUNTS.json')[0])}


def driver(root,plan,plan_state):
    output=Path(plan['output']);errors=[];before=None;bindings=None;returned=None;observed=None
    launched=False;created=False
    # Refuse an existing path, including a dangling symlink. No retries.
    S.require(output.is_absolute() and output.parent==Path('/workspace') and not os.path.lexists(output),'one-shot output exists or differs')
    parent_fd=S.open_output_parent(plan)
    try:
        free=os.fstatvfs(parent_fd);S.require(free.f_bavail*free.f_frsize>=plan['minimum_free_bytes'],'original 3GiB floor not met')
        os.mkdir(output.name,mode=0o700,dir_fd=parent_fd);created=True
        S.output_parent_snapshot(plan)
    finally:
        os.close(parent_fd)
    folder=output/'diagnostic';folder.mkdir(mode=0o700)
    try:
        bindings=S.guards(root,plan,plan_state);S.dump(output/'BINDINGS-BEFORE.json',bindings)
        before=S.source_snapshot(root,plan);S.dump(output/'FULL-SOURCE-BEFORE.json',before)
        S.prior_authority(plan)
        command=[plan['runtime']['executable']['path'],'-B',str(root/'run_cross_counted.py'),
                 '--plan-sha256',plan['authorization_pin'],'--child']
        env=dict(plan['runtime']['environment'])
        S.dump(output/'LAUNCH.json',{'command':command,'environment':env,'cwd':plan['source']['path'],
            'qualification_seconds':180,'cleanup_seconds':3,'automatic_retry':False,'expected_exit':1})
        sys.path.insert(0,plan['source']['path'])
        from tools.hia_selfhost_process_owner import run_owned
        launched=True
        returned=run_owned(command,cwd=plan['source']['path'],env=env,supervisor_env=env,
            qualification_seconds=180,cleanup_seconds=3,receipt_path=output/'OWNER.json',
            stdout_path=output/'child.stdout.bin',stderr_path=output/'child.stderr.bin')
        S.dump(output/'OWNER-RETURNED.json',returned)
        raw=S.read_regular(output/'OWNER.json')[0]
        owner=S.owner_protocol(raw,returned)
        request_raw=S.read_regular(output/'OWNER.json.request.json')[0];request=json.loads(request_raw)
        S.require(request['command']==command and request['cwd']==plan['source']['path'] and request['env']==env
            and request['qualification_seconds']==180 and request['cleanup_seconds']==3
            and request['implementation_sha256']==before['files']['tools/hia_selfhost_process_owner.py']['sha256']
            and owner['request_sha256']==S.pin(request_raw)['sha256']
            and owner['implementation_sha256']==request['implementation_sha256'],'actual request or owner code differs')
        S.require(S.clean_owner(returned,1),'owner did not cleanly preserve the expected failed product exit')
        observed=validate_child(root,plan,folder)
        S.dump(output/'COMPLETE-READBACK.json',observed)
    except BaseException as exc:
        note_exception(errors,'parent-observation',exc)
    finally:
        if created:
            final_guard(root,plan,plan_state,output,before,bindings,errors)
            result={'schema':'hepta.r10.cross-target-counted-owner.v1','status':'FAIL','expected_exit':1,
                'diagnostic_observation_complete':observed is not None and not errors,
                'owner_call_attempted':launched,'owner':returned,'errors':errors,
                'new_native_calls':0,'generator_calls':0,'compile_calls':0,'max_new_VM_calls':1,
                'automatic_retry':False,'qualification_pass':False,'matching_current_cold':False,'whole':False,
                'original_R10_VM6':'5 PASS / 1 fuel FAIL; unchanged'}
            attempt(errors,'outer-record',lambda:S.dump(output/'OUTER.json',result))
            attempt(errors,'final-record',lambda:S.dump(output/'RESULT.json',result))
            try:print(json.dumps({'status':'FAIL','diagnostic_observation_complete':result['diagnostic_observation_complete'],
                      'owner_status':None if returned is None else returned.get('status'),'errors':errors},sort_keys=True),flush=True)
            except BaseException:
                try:sys.stderr.write(traceback.format_exc());sys.stderr.flush()
                except BaseException:pass
    return 1


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan-sha256',required=True)
    parser.add_argument('--child',action='store_true')
    args=parser.parse_args()
    root,plan,state=S.load_plan(args.plan_sha256)
    raise SystemExit(child(root,plan,state) if args.child else driver(root,plan,state))

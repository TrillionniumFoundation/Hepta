"""One additional private-helper VM owner; no compiler or Native execution."""
from pathlib import Path
import argparse,json,os,stat,sys,time,traceback
sys.path.insert(0,str(Path(__file__).resolve().parent))
import helper_support as S

def attempt(errors,name,action):
    try:return action()
    except BaseException as error:
        errors.append({'where':name,'type':type(error).__name__,'traceback':traceback.format_exc()})
        return None

def final_guards(folder,source_before,controls_before,errors):
    def source():
        observed=S.snapshot(folder/'FULL-FRESH-AFTER.json')
        S.require(source_before is not None and observed==source_before,'complete fresh domain changed or was not observed')
    def controls():
        observed=S.controls_guard();S.dump(folder/'CONTROLS-AFTER.json',observed)
        S.require(controls_before is not None and observed==controls_before,'helper input/control closure drift')
    attempt(errors,'final-complete-fresh',source)
    attempt(errors,'final-controls',controls)
    attempt(errors,'final-runtime',lambda:S.dump(folder/'RUNTIME-AFTER.json',S.runtime_guard()))

def observe(checked,case,label,folder,errors,attempts):
    from hepta.hia_program_runtime import _Machine,_Owner,_View,HIAProgramTrap,HIAProgramBudgetExceeded
    from hepta.hia_program import HIAProgramRejected
    from trace_machine import TraceMachine
    S.require(TraceMachine.__bases__==(_Machine,),'observer base is not original Machine')
    root=_Owner(-1,bytearray.fromhex(case['initial_hex']))
    view=_View(root,case['view']!='readonly')
    if case['view']=='expired_view':view.active=False
    if case['view']=='expired_owner':root.active=False
    machine=TraceMachine(checked,10000000,1048576,None,128)
    target=folder/label;S.mkdir(target)
    actual_before=bytes(root.data);S.write(target/'buffer.before.bin',actual_before)
    S.require(S.read(target/'buffer.before.bin')[0]==actual_before,'before witness not readable; do not invoke')
    arguments=[view,case['offset']]
    if case['function'] not in ('f23','f25'):arguments.append(case['value'])
    request={'case':case,'program_sha256':checked.sha256,'program_input_sha256':checked.input_sha256,
        'function':case['function'],'scalar_arguments':arguments[1:],
        'actual_initial_buffer':S.pin(actual_before),'view_state':{'mutable':view.mutable,'active':view.active,'owner_active':root.active},
        'limits':{'max_steps':10000000,'max_heap_bytes':1048576,'max_call_depth':128,'allocation_fail_at':None},
        'one_actual_borrowed_buffer_ABI':True,'synthetic_source_output_buffers':False}
    S.dump(target/'REQUEST.json',request)
    values=[];status='not_started';error=None;exception=None;calls=0;started=time.monotonic_ns()
    after=None;state=None
    marker={'id':case['id'],'version':label,'steps':None,'after_captured':False}
    try:
        S.dump(target/'CALL-INTENT.json',{'id':case['id'],'version':label,'one_invocation':True})
        attempts.append(marker)
        calls=1;status='returned'
        values=machine.invoke(machine.functions[case['function']],arguments)
    except (HIAProgramTrap,HIAProgramRejected,HIAProgramBudgetExceeded) as exc:
        status='trapped' if isinstance(exc,HIAProgramTrap) else 'budget_exceeded' if isinstance(exc,HIAProgramBudgetExceeded) else 'rejected'
        error={'type':type(exc).__name__,'code':exc.code,'message':str(exc)};exception=traceback.format_exc()
    except BaseException as exc:
        status='unexpected_error';error={'type':type(exc).__name__,'code':getattr(exc,'code',None),'message':str(exc)}
        exception=traceback.format_exc()
    finally:
        stopped=time.monotonic_ns()
        def capture_after():
            raw=bytes(root.data);S.write(target/'buffer.after.bin',raw)
            S.require(S.read(target/'buffer.after.bin')[0]==raw,'actual after buffer readback differs')
            return raw
        after=attempt(errors,label+'-capture-after',capture_after)
        marker.update(steps=machine.steps,after_captured=after is not None)
        state={'status':status,'values':values,'error':error,'events':machine.byte_events,
            'operation_events':machine.operation_events,'byte_event_op_indices':machine.byte_event_op_indices,
            'steps':machine.steps,'resources':machine.resources(),'call_attempts':calls,
            'actual_before':S.pin(actual_before),'actual_after':None if after is None else S.pin(after),
            'owner_active':root.active,'view_active':view.active,'view_mutable':view.mutable,
            'started_ns':started,'stopped_ns':stopped,'elapsed_ns':stopped-started,
            'observation_only_VM':True,'Native_calls':0,'compile_calls':0}
        attempt(errors,label+'-write-state',lambda:S.dump(target/'OBSERVATION.json',state))
        if exception is not None:attempt(errors,label+'-write-exception',lambda:S.write(target/'EXCEPTION.txt',exception.encode()))
    S.require(after is not None and not errors,'complete helper observation missing')
    S.require(S.read(target/'buffer.before.bin')[0]==actual_before and S.read(target/'buffer.after.bin')[0]==after,'saved helper buffers differ')
    S.require(json.loads(S.read(target/'OBSERVATION.json')[0])==state,'saved helper state differs')
    return state,after

def child():
    folder=S.EXEC/'helper-controls';errors=[];before=None;controls=None;all_cases=[];attempts=[]
    result={'schema':'hia.R10.helper-boundary-result.v1','status':'FAIL','case_pairs':[],
        'Native_calls':0,'compile_calls':0,'generation_calls':0,'semantic_f0_calls':0,
        'whole_native':False,'matching_current_cold':False,'errors':errors}
    try:
        S.dump(folder/'RUNTIME-BEFORE.json',S.runtime_guard())
        controls=S.controls_guard();S.dump(folder/'CONTROLS-BEFORE.json',controls)
        before=S.snapshot(folder/'FULL-FRESH-BEFORE.json')
        root_proof=json.loads(S.fixed(S.PLAN['fixed_controls']['actual_Root_prefix_proof'])[0])
        S.require(root_proof['status']=='PASS_INDEPENDENT_R10_PREFIX_TERMINAL_ONLY'
            and root_proof['exact_scalar_editpaths']==9 and root_proof['word64_then_scalar_proof_chain'],
            'actual R10 prefix independent predecessor is not closed')
        from boundary_cases import cases,oracle
        all_cases=cases()
        S.require(all_cases==json.loads(S.read(S.AUTHOR/'CASES.json')[0]),'complete frozen helper cases/order differ')
        sys.path.insert(0,str(S.SOURCE))
        from hepta.hia_agent_assembly import assemble_program
        old_raw=S.fixed(S.PLAN['fixed_controls']['R10-author:before/file_render_checker_word64.hepta'])[0]
        new_raw=S.fixed(S.PLAN['fixed_controls']['actual_R10_source'])[0]
        checked={'R9':assemble_program(old_raw),'R10':assemble_program(new_raw)}
        for label,ops in (('R9',6347),('R10',6299)):
            doc=checked[label].as_dict()
            S.require([fn['name'] for fn in doc['functions']]==['f'+str(i) for i in range(107)]
                and sum(len(fn['blocks']) for fn in doc['functions'])==1456
                and sum(len(block['ops']) for fn in doc['functions'] for block in fn['blocks'])==ops,
                'complete actual helper program shape differs')
        reports=json.loads(S.fixed(S.PLAN['fixed_controls']['actual_R10_generation_report'])[0])
        q=reports['generated']['scalar_byte_projection']
        S.require(checked['R9'].sha256==q['original_core_sha256'] and checked['R10'].sha256==q['after_core_sha256'],
            'real reparsed full Core does not equal the actual generation double proof')
        S.dump(folder/'ACTUAL-PROGRAMS.json',{label:{'Core_sha256':program.sha256,'input_sha256':program.input_sha256}
            for label,program in checked.items()})
        for index,case in enumerate(all_cases):
            case_folder=folder/'cases'/str(index).zfill(4);S.mkdir(case_folder)
            S.dump(case_folder/'CASE.json',case);expected=oracle(case);S.dump(case_folder/'ORACLE.json',expected)
            pair={'id':case['id'],'group':case['group'],'status':'FAIL','versions':{}}
            result['case_pairs'].append(pair)
            for label in ('R9','R10'):
                state,after=observe(checked[label],case,label,case_folder,errors,attempts)
                comparison={'outcome_equal':all(state[k]==expected[k] for k in ('status','values','error','events')),
                    'complete_actual_buffer_equal':after==bytes.fromhex(expected['after_hex']),
                    'before_exact':S.read(case_folder/label/'buffer.before.bin')[0]==bytes.fromhex(case['initial_hex']),
                    'original_limit':state['steps']<=10000000,'one_invocation':state['call_attempts']==1,
                    'no_Native_or_compile':state['Native_calls']==state['compile_calls']==0}
                pair['versions'][label]={'observation':S.identity(case_folder/label/'OBSERVATION.json'),'comparison':comparison}
                S.dump(case_folder/(label+'-COMPARISON.json'),comparison)
                S.require(all(comparison.values()),'real helper result differs from independent oracle: '+case['id']+'/'+label)
                if label=='R9':prior_state=state;prior_after=after
                else:
                    S.require(prior_after==after and prior_state['resources']==state['resources']
                        and all(prior_state[k]==state[k] for k in ('status','values','error','events','owner_active','view_active','view_mutable')),
                        'actual R9/R10 complete outcome, effects, state or resources differ')
                    if state['byte_event_op_indices']:
                        tail=state['operation_events'][state['byte_event_op_indices'][-1]+1:]
                        S.require(all(event['op']!='int.add.wrap' for event in tail),
                            'candidate added an address increment after its final byte access')
            pair['status']='PASS';S.dump(case_folder/'PAIR.json',pair)
        result['status']='PASS_ADDITIONAL_PRIVATE_HELPERS_ONLY'
    except BaseException as error:
        errors.append({'where':'helper-child','type':type(error).__name__,'traceback':traceback.format_exc()})
    finally:
        final_guards(folder,before,controls,errors)
        if errors:result['status']='FAIL'
        result.update(declared_cases=len(all_cases),completed_pairs=sum(r['status']=='PASS' for r in result['case_pairs']),
            attempted_cases=len(result['case_pairs']),not_started=[c['id'] for c in all_cases[len(result['case_pairs']):]],
            actual_VM_calls=sum(r['steps'] is not None and r['steps']>0 for r in attempts),
            VM_invocation_attempts=len(attempts),invocations=attempts,
            missing_frames_policy='Failure retained, never filled from expected bytes',
            original_eight_groups_executed=0)
        attempt(errors,'write-child-result',lambda:S.dump(folder/'RESULT.json',result))
        if errors:result['status']='FAIL'
        print(json.dumps({'status':result['status'],'completed_pairs':result['completed_pairs'],'errors':errors},sort_keys=True),flush=True)
    return 0 if result['status']=='PASS_ADDITIONAL_PRIVATE_HELPERS_ONLY' and not errors else 1

def driver():
    S.runtime_guard();S.require(not os.path.lexists(S.EXEC),'unique helper output already exists')
    parent_fd=S.open_output_parent(S.PLAN)
    try:
        free=os.fstatvfs(parent_fd);S.require(free.f_bavail*free.f_frsize>=3221225472,'original 3 GiB floor unavailable')
        os.mkdir(S.EXEC.name,mode=0o700,dir_fd=parent_fd);S.output_parent_snapshot(S.PLAN)
    finally:os.close(parent_fd)
    folder=S.EXEC/'helper-controls';S.mkdir(folder)
    errors=[];before=None;controls=None;owner=None;observed=None;attempted=0
    try:
        S.dump(S.EXEC/'RUNTIME-BEFORE.json',S.runtime_guard())
        controls=S.controls_guard();S.dump(S.EXEC/'CONTROLS-BEFORE.json',controls)
        before=S.snapshot(S.EXEC/'FULL-FRESH-BEFORE.json')
        command=[S.PLAN['runtime']['executable']['path'],'-I','-S','-B',str(S.AUTHOR/'run_helper_gate.py'),
            '--plan-sha256',S.PLAN['authorization_pin'],'--child']
        env=S.PLAN['environment']
        S.dump(S.EXEC/'LAUNCH.json',{'command':command,'cwd':str(S.SOURCE),'env':env,'supervisor_env':env,
            'qualification_seconds':180,'cleanup_seconds':3,'automatic_retry':False})
        sys.path.insert(0,str(S.SOURCE))
        from tools.hia_selfhost_process_owner import run_owned
        attempted=1
        owner=run_owned(command,cwd=S.SOURCE,env=env,supervisor_env=env,qualification_seconds=180,cleanup_seconds=3,
            receipt_path=S.EXEC/'OWNER.json',stdout_path=S.EXEC/'stdout.bin',stderr_path=S.EXEC/'stderr.bin')
        S.dump(S.EXEC/'OWNER-RETURNED.json',owner);S.owner_record(S.EXEC/'OWNER.json',owner);S.complete_owner(owner)
        S.require(owner['qualification_started']is True and owner['event_overflow']is False
            and owner['interrupted_signals']==[] and owner['subreaper_enabled']is True
            and owner['cleanup']['remaining_direct_children']==[], 'owner terminal detail differs')
        request_raw=S.read(S.EXEC/'OWNER.json.request.json')[0];request=json.loads(request_raw)
        S.require(request['command']==command and request['cwd']==str(S.SOURCE) and request['env']==env
            and request['qualification_seconds']==180 and request['cleanup_seconds']==3
            and request['implementation_sha256']==S.PLAN['fixed_controls']['owner_source']['identity']['sha256']
            and owner['request_sha256']==S.pin(request_raw)['sha256'],'actual helper owner request differs')
        observed=json.loads(S.read(folder/'RESULT.json')[0])
        S.require(observed['status']=='PASS_ADDITIONAL_PRIVATE_HELPERS_ONLY' and observed['errors']==[]
            and observed['completed_pairs']==observed['declared_cases']==S.PLAN['case_count']
            and observed['actual_VM_calls']==2*S.PLAN['case_count'] and observed['not_started']==[],
            'helper child did not complete exact frozen cases')
    except BaseException as error:
        errors.append({'where':'helper-owner','type':type(error).__name__,'traceback':traceback.format_exc()})
    finally:
        final_guards(S.EXEC,before,controls,errors)
        result={'schema':'hia.R10.helper-boundary-owner.v1','status':'PASS_ADDITIONAL_PRIVATE_HELPERS_ONLY' if observed is not None and not errors else 'FAIL',
            'owner_attempts':attempted,'owner':owner,'actual_child_result':observed,'errors':errors,
            'Native_calls':0,'compile_calls':0,'original_eight_groups_executed':0,'whole_native':False,'matching_current_cold':False,'retry':False}
        attempt(errors,'write-owner-result',lambda:S.dump(S.EXEC/'RESULT.json',result))
        if errors:result['status']='FAIL'
        print(json.dumps({'status':result['status'],'owner_attempts':attempted,'errors':errors},sort_keys=True),flush=True)
    return 0 if result['status']=='PASS_ADDITIONAL_PRIVATE_HELPERS_ONLY' and not errors else 1

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--plan-sha256',required=True);parser.add_argument('--child',action='store_true')
    args=parser.parse_args();material=dict(S.PLAN);claimed=material.pop('authorization_pin')
    S.require(S.pin(S.encode(material))['sha256']==claimed==args.plan_sha256,'exact helper plan authorization differs')
    raise SystemExit(child() if args.child else driver())

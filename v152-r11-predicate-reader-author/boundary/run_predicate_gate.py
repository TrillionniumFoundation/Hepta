"""One real R10/R11 predicate and full-function VM owner; no Native."""
from pathlib import Path
import argparse,json,os,stat,sys,time,traceback
sys.path.insert(0,str(Path(__file__).resolve().parent))
import predicate_support as S

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
    from trace_machine import PredicateTraceMachine
    from predicate_logic import physical_state
    S.require(PredicateTraceMachine.__bases__==(_Machine,), 'observer does not inherit the original Machine')
    target=folder/label;S.mkdir(target)
    owners={};views={};before={};after={}
    if case['kind']=='function':
        source=bytes.fromhex(case['source_hex']);workspace=bytes.fromhex(case['workspace_hex'])
        if case['same_physical_owner']:
            S.require(source==workspace,'shared-owner fixture does not describe one physical preimage')
            common=_Owner(-1,bytearray(source));owners={'source':common,'workspace':common}
        else:
            owners={'source':_Owner(-1,bytearray(source)),'workspace':_Owner(-2,bytearray(workspace))}
        for role in ('source','workspace'):
            mode=case[role+'_view'];view=_View(owners[role],mode=='mutable')
            if mode=='expired_view':view.active=False
            if mode=='expired_owner':owners[role].active=False
            views[role]=view
        arguments=[views['source'],views['workspace']];function=case['function']
        output='v134' if function=='f16' else 'v88'
    else:
        S.require(case['kind']=='scalar','unknown actual case kind')
        arguments=[case['character']]
        if case['predicate']=='identifier_invalid':arguments.append(case['index'])
        function='predicate';output='v134' if case['predicate']=='delimiter' else 'v88'
    for role,owner in owners.items():
        raw=bytes(owner.data);S.write(target/(role+'.before.bin'),raw)
        S.require(S.read(target/(role+'.before.bin'))[0]==raw,'before witness is not readable; do not invoke')
        before[role]=raw
    machine=PredicateTraceMachine(checked,10000000,1048576,None,128)
    machine.observed_views=views;machine.predicate_output=output
    request={'case':case,'program_sha256':checked.sha256,'program_input_sha256':checked.input_sha256,
        'function':function,'scalar_arguments':arguments if not views else [],
        'actual_initial_buffers':{name:S.pin(raw) for name,raw in before.items()},
        'view_state':physical_state(owners,views),'physical_owner_count':len({id(o) for o in owners.values()}),
        'limits':{'max_steps':10000000,'max_heap_bytes':1048576,'max_call_depth':128,'allocation_fail_at':None},
        'synthetic_source_output_buffers':False,'scalar_fragment_has_zero_buffers':case['kind']=='scalar'}
    S.dump(target/'REQUEST.json',request)
    values=[];status='not_started';error=None;exception=None;calls=0;started=time.monotonic_ns()
    marker={'id':case['id'],'version':label,'steps':None,'after_captured':False}
    state=None
    try:
        S.dump(target/'CALL-INTENT.json',{'id':case['id'],'version':label,'one_invocation':True})
        attempts.append(marker);calls=1;status='returned'
        values=machine.invoke(machine.functions[function],arguments)
    except (HIAProgramTrap,HIAProgramRejected,HIAProgramBudgetExceeded) as exc:
        status='trapped' if isinstance(exc,HIAProgramTrap) else 'budget_exceeded' if isinstance(exc,HIAProgramBudgetExceeded) else 'rejected'
        error={'type':type(exc).__name__,'code':exc.code,'message':str(exc)};exception=traceback.format_exc()
    except BaseException as exc:
        status='unexpected_error';error={'type':type(exc).__name__,'code':getattr(exc,'code',None),'message':str(exc)}
        exception=traceback.format_exc()
    finally:
        stopped=time.monotonic_ns()
        for role,owner in owners.items():
            def capture_after(role=role,owner=owner):
                raw=bytes(owner.data);S.write(target/(role+'.after.bin'),raw)
                S.require(S.read(target/(role+'.after.bin'))[0]==raw,'actual after-buffer readback differs')
                return raw
            raw=attempt(errors,label+'-'+role+'-capture-after',capture_after)
            if raw is not None:after[role]=raw
        complete=set(after)==set(before)
        marker.update(steps=machine.steps,after_captured=complete)
        state={'status':status,'values':values,'error':error,'effects':machine.effects,
            'operation_events':machine.operation_events,'predicate_values':machine.predicate_values,
            'steps':machine.steps,'resources':machine.resources(),'call_attempts':calls,
            'actual_before':{name:S.pin(raw) for name,raw in before.items()},
            'actual_after':{name:S.pin(raw) for name,raw in after.items()},
            'physical_state':physical_state(owners,views),
            'physical_owner_count':len({id(o) for o in owners.values()}),
            'started_ns':started,'stopped_ns':stopped,'elapsed_ns':stopped-started,
            'observation_only_VM':True,'Native_calls':0,'compile_calls':0}
        attempt(errors,label+'-write-state',lambda:S.dump(target/'OBSERVATION.json',state))
        if exception is not None:attempt(errors,label+'-write-exception',lambda:S.write(target/'EXCEPTION.txt',exception.encode()))
    S.require(set(after)==set(before) and not errors,'complete actual observation missing')
    for role in before:
        S.require(S.read(target/(role+'.before.bin'))[0]==before[role]
            and S.read(target/(role+'.after.bin'))[0]==after[role], 'saved physical buffers differ')
    S.require(json.loads(S.read(target/'OBSERVATION.json')[0])==state,'saved actual state differs')
    return state,before,after

def child():
    folder=S.EXEC/'predicate-controls';errors=[];before=None;controls=None;all_cases=[];attempts=[]
    result={'schema':'hia.R11.predicate-boundary-result.v1','status':'FAIL','case_pairs':[],
        'Native_calls':0,'compile_calls':0,'generation_calls':0,'semantic_f0_calls':0,
        'whole_native':False,'matching_current_cold':False,'errors':errors}
    try:
        S.dump(folder/'RUNTIME-BEFORE.json',S.runtime_guard())
        controls=S.controls_guard();S.dump(folder/'CONTROLS-BEFORE.json',controls)
        before=S.snapshot(folder/'FULL-FRESH-BEFORE.json')
        root_proof=json.loads(S.fixed(S.PLAN['fixed_controls']['actual_Root_prefix_proof'])[0])
        S.require(root_proof['status']=='PASS_INDEPENDENT_R11_PREFIX_TERMINAL_ONLY'
            and root_proof['exact_scalar_editpaths']==9 and root_proof['exact_ascii_editpaths']==2
            and root_proof['word64_then_scalar_proof_chain']
            and root_proof['word64_then_scalar_then_ascii_proof_chain'],
            'actual independent R11 prefix predecessor is not closed')
        from boundary_cases import cases,scalar_oracle
        from predicate_logic import derive_fragments,untouched_bytes
        all_cases=cases()
        S.require(all_cases==json.loads(S.read(S.AUTHOR/'CASES.json')[0]),
            'complete frozen predicate cases/order differ')
        sys.path.insert(0,str(S.SOURCE))
        from hepta.hia_agent_assembly import assemble_program
        old_raw=S.fixed(S.PLAN['fixed_controls']['actual_R10_source'])[0]
        new_raw=S.fixed(S.PLAN['fixed_controls']['actual_R11_source'])[0]
        checked={'R10':assemble_program(old_raw),'R11':assemble_program(new_raw)}
        generated=json.loads(S.fixed(S.PLAN['fixed_controls']['actual_R11_generation_report'])[0])['generated']
        fragments=derive_fragments(checked,generated['ascii_predicate_projection'],folder,S)
        for index,case in enumerate(all_cases):
            case_folder=folder/'cases'/str(index).zfill(4);S.mkdir(case_folder)
            S.dump(case_folder/'CASE.json',case)
            expected=scalar_oracle(case) if case['kind']=='scalar' else None
            if case['kind']=='scalar':S.dump(case_folder/'SCALAR-ORACLE.json',{'value':expected})
            pair={'id':case['id'],'group':case['group'],'kind':case['kind'],
                'status':'FAIL','versions':{}}
            result['case_pairs'].append(pair)
            for label in ('R10','R11'):
                program=fragments[label][case['predicate']] if case['kind']=='scalar' else checked[label]
                state,initial,after=observe(program,case,label,case_folder,errors,attempts)
                comparison={'one_actual_invocation':state['call_attempts']==1,
                    'original_limit':0<state['steps']<=10000000,
                    'expected_outcome_class':state['status'] in ('returned','trapped','rejected'),
                    'no_Native_or_compile':state['Native_calls']==state['compile_calls']==0}
                if case['kind']=='scalar':
                    comparison.update(real_scalar_result=state['status']=='returned' and state['error'] is None
                        and state['values']==[expected] and state['predicate_values']==[expected],
                        no_scalar_buffers_or_effects=initial==after=={} and state['effects']==[])
                else:
                    exact_initial={'source':bytes.fromhex(case['source_hex']),
                        'workspace':bytes.fromhex(case['workspace_hex'])}
                    canaries=untouched_bytes(initial,after,state['effects'],case['same_physical_owner'])
                    comparison.update(complete_initial_buffers=initial==exact_initial,
                        complete_final_extents=all(len(after[name])==len(raw) for name,raw in initial.items()),
                        all_untouched_bytes=all(canaries.values()),
                        source_unchanged_or_explicit_alias=case['same_physical_owner'] or initial['source']==after['source'],
                        shared_owner_consistent=not case['same_physical_owner'] or after['source']==after['workspace'])
                    S.dump(case_folder/(label+'-UNTOUCHED.json'),canaries)
                pair['versions'][label]={'observation':S.identity(case_folder/label/'OBSERVATION.json'),
                    'comparison':comparison}
                S.dump(case_folder/(label+'-COMPARISON.json'),comparison)
                S.require(all(comparison.values()),'actual boundary comparison failed: '+case['id']+'/'+label)
                if label=='R10':prior_state=state;prior_initial=initial;prior_after=after
                else:
                    equal=prior_initial==initial and prior_after==after and all(
                        prior_state[key]==state[key] for key in ('status','values','error','effects',
                        'resources','physical_state','physical_owner_count','predicate_values'))
                    S.dump(case_folder/'PAIR-COMPARISON.json',{'all_actual_buffers_outcomes_effects_resources_equal':equal})
                    S.require(equal,'actual R10/R11 outcome, ordered effects, buffers, or resources differ')
            pair['status']='PASS';S.dump(case_folder/'PAIR.json',pair)
        result['status']='PASS_ADDITIONAL_PRIVATE_PREDICATES_ONLY'
    except BaseException as error:
        errors.append({'where':'predicate-child','type':type(error).__name__,'traceback':traceback.format_exc()})
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
    return 0 if result['status']=='PASS_ADDITIONAL_PRIVATE_PREDICATES_ONLY' and not errors else 1


def driver():
    S.runtime_guard();S.require(not os.path.lexists(S.EXEC),'unique helper output already exists')
    parent_fd=S.open_output_parent(S.PLAN)
    try:
        free=os.fstatvfs(parent_fd);S.require(free.f_bavail*free.f_frsize>=3221225472,'original 3 GiB floor unavailable')
        os.mkdir(S.EXEC.name,mode=0o700,dir_fd=parent_fd);S.output_parent_snapshot(S.PLAN)
    finally:os.close(parent_fd)
    folder=S.EXEC/'predicate-controls';S.mkdir(folder)
    errors=[];before=None;controls=None;owner=None;observed=None;attempted=0
    try:
        S.dump(S.EXEC/'RUNTIME-BEFORE.json',S.runtime_guard())
        controls=S.controls_guard();S.dump(S.EXEC/'CONTROLS-BEFORE.json',controls)
        before=S.snapshot(S.EXEC/'FULL-FRESH-BEFORE.json')
        command=[S.PLAN['runtime']['executable']['path'],'-I','-S','-B',str(S.AUTHOR/'run_predicate_gate.py'),
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
        S.require(observed['status']=='PASS_ADDITIONAL_PRIVATE_PREDICATES_ONLY' and observed['errors']==[]
            and observed['completed_pairs']==observed['declared_cases']==S.PLAN['case_count']
            and observed['actual_VM_calls']==2*S.PLAN['case_count'] and observed['not_started']==[],
            'helper child did not complete exact frozen cases')
    except BaseException as error:
        errors.append({'where':'helper-owner','type':type(error).__name__,'traceback':traceback.format_exc()})
    finally:
        final_guards(S.EXEC,before,controls,errors)
        result={'schema':'hia.R11.predicate-boundary-owner.v1','status':'PASS_ADDITIONAL_PRIVATE_PREDICATES_ONLY' if observed is not None and not errors else 'FAIL',
            'owner_attempts':attempted,'owner':owner,'actual_child_result':observed,'errors':errors,
            'Native_calls':0,'compile_calls':0,'original_eight_groups_executed':0,'whole_native':False,'matching_current_cold':False,'retry':False}
        attempt(errors,'write-owner-result',lambda:S.dump(S.EXEC/'RESULT.json',result))
        if errors:result['status']='FAIL'
        print(json.dumps({'status':result['status'],'owner_attempts':attempted,'errors':errors},sort_keys=True),flush=True)
    return 0 if result['status']=='PASS_ADDITIONAL_PRIVATE_PREDICATES_ONLY' and not errors else 1


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--plan-sha256',required=True);parser.add_argument('--child',action='store_true')
    args=parser.parse_args();material=dict(S.PLAN);claimed=material.pop('authorization_pin')
    S.require(S.pin(S.encode(material))['sha256']==claimed==args.plan_sha256,'exact helper plan authorization differs')
    raise SystemExit(child() if args.child else driver())

#!/usr/bin/env python3
"""Bounded paired native controls against an immutable HIA source checkout.

This entry-side harness calls the existing run_cell API without patching HIA.
Its proposal provider is authored Python, including an explicit private teacher;
there is no model invocation, real-Agent task or economic-benefit claim.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
from hashlib import sha256
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import resource
import subprocess
import sys
import tempfile
import time
import traceback

SOURCE_SHA = 'd1c97d22d503b395ba9b0dfaa87e5a1c1b208fe6'
SCHEMA = 'hepta.hia.paired-native-control.v1'
CELL_BUDGET = {'wall_ns': 30_000_000_000, 'model_tokens': 32768}
PAIR_ORDER = [('ordinary','ndu'),('ndu','ordinary'),('ndu','ordinary'),('ordinary','ndu')]


def wire(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()


def digest(value):
    return sha256(wire(value)).hexdigest()


def require(ok, message):
    if not ok:
        raise ValueError(message)


def write_new(path, value):
    with Path(path).open('xb') as stream:
        stream.write(wire(value) + b'\n')


def git(source, *args):
    return subprocess.check_output(['git','-C',str(source),*args],text=True).strip()


def cpu_snapshot():
    return {name:round((r.ru_utime+r.ru_stime)*1e9)
        for name,r in ((name,resource.getrusage(kind)) for name,kind in
            (('parent',resource.RUSAGE_SELF),('children',resource.RUSAGE_CHILDREN)))}


def unstable_cleanup(value):
    if isinstance(value,dict):
        if any(value.get(k) is False for k in ('termination_confirmed','cleanup_confirmed')):
            return True
        return any(unstable_cleanup(v) for v in value.values())
    return isinstance(value,list) and any(unstable_cleanup(v) for v in value)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',required=True,type=Path)
    parser.add_argument('--registration',required=True,type=Path)
    parser.add_argument('--native-binary',required=True,type=Path)
    parser.add_argument('--native-build-receipt',required=True,type=Path)
    parser.add_argument('--output',required=True,type=Path)
    args=parser.parse_args()
    started=time.monotonic_ns(); cpu_before=cpu_snapshot()
    source=args.source.resolve(strict=True)
    require(sys.platform=='linux','actual native control requires Linux')
    require(git(source,'rev-parse','HEAD')==SOURCE_SHA,'unexpected immutable HIA source HEAD')
    require(not git(source,'status','--porcelain','--untracked-files=all'),'HIA source is not clean')
    sys.path.insert(0,str(source))
    from hepta.hia_agent_contract import installation_manifest
    from hepta.hia_agent_macro_policy import ledger_totals
    from hepta.hia_ndu_optimizer import _bridge_identity
    from hepta.hia_ndu_scalar_selection import resolve_scalar_selection
    from tools.qualify_hia_macro_campaign import Evidence, _native_result_correct
    from tools.qualify_hia_macro_multistep import run_cell, source_identity, checked_pool_selection

    bridge={'binary':str(args.native_binary.resolve(strict=True)),
            'build_receipt':str(args.native_build_receipt.resolve(strict=True))}
    _,bridge_identity=_bridge_identity(bridge)
    before=source_identity()
    registration_raw=args.registration.read_bytes()
    task_registration=json.loads(registration_raw)
    task=next(row for row in task_registration['tasks'] if row['purpose']=='calibration')
    documents={}
    for name in ('public','hidden'):
        raw=(args.registration.parent/task[name]['path']).read_bytes()
        require(sha256(raw).hexdigest()==task[name]['sha256'],'registered task bytes differ')
        documents[name]=json.loads(raw)
    public,hidden=documents['public'],documents['hidden']
    require('block entry(value:u8)' in public['baseline_assembly'],'registered malformed proposal precondition')
    evidence=Evidence(args.output)
    task_sha=evidence.put({'public':public,'oracle':hidden['cases'],
        'fixture_teacher_sha256':hidden['feasibility_core_sha256']})
    qualification=evidence.put({'kind':'authored_no_model_control','real_agent':False,
        'private_teacher_used':True,'heldout_or_blind_task_claim':False})
    item={'input_sha256':task_sha,'qualification_receipt_sha256':qualification}
    objective={'schema':'hepta.hia.agent.objective.v1','metric':'artifact_bytes',
        'required_claims':['core_admission','behavior_equivalence','encoding_check'],
        'allow_unchanged':False,'min_improvement_ratio':0.0}
    cell_registration={'budget':deepcopy(CELL_BUDGET),'installation':installation_manifest(),
        'tool_objective':objective,'objective_sha256':evidence.put(objective)}
    schedule=[{'pair':pair,'position':position,'arm':arm,'cell_id':f'pair.{pair}.{arm}'}
        for pair,order in enumerate(PAIR_ORDER,1) for position,arm in enumerate(order,1)]
    plan={'schema':SCHEMA,'kind':'preregistered_authored_no_model_control',
        'source_sha':SOURCE_SHA,'source_tree':git(source,'rev-parse','HEAD^{tree}'),
        'source_identity':before,'entry_harness_sha256':sha256(Path(__file__).read_bytes()).hexdigest(),
        'registration_sha256':sha256(registration_raw).hexdigest(),'task_id':public['id'],
        'public_task_sha256':task['public']['sha256'],'hidden_task_sha256':task['hidden']['sha256'],
        'schedule':schedule,'per_cell_budget':CELL_BUDGET,'maximum_cells':8,
        'sum_cell_wall_allowances_ns':8*CELL_BUDGET['wall_ns'],
        'maximum_scripted_proposals_per_cell':3,'maximum_real_model_invocations':0,
        'proposal_policy':'first original malformed entry block, then the same two private-feasibility assemblies',
        'calibration_policy':'empty calibration in every cell; original registered estimate, no fitting or tuning',
        'failure_policy':'retain all attempts; no retry, replacement, budget increase, or regeneration; stop later cells if cleanup is unsettled',
        'bridge_identity':bridge_identity,'counterbalanced_order':True,
        'real_user_tasks':0,'formal_mcp_calls':0,'private_teacher_used':True,
        'claim_scope':'native task mechanism and descriptive paired costs on one authored task',
        'p1_acceptance':'HOLD','economic_benefit_established':False,
        'stable_total_benefit_established':False,'full_cost_complete':False,'model_cost':None}
    plan_identity=evidence.put(plan)
    evidence.named('PLAN.json',plan)
    results=[]; halted=None; audits_wall_ns=0

    class AuthoredFixture:
        blocked_reason=None
        def __init__(self):
            self.calls=0
        def invoke(self,request,evidence,output,**budgets):
            self.calls+=1
            require(self.calls<=3,'scripted proposal budget exceeded')
            assembly=(public['baseline_assembly'].replace('block entry(value:u8)','block entry(other:u8)')
                if self.calls==1 else hidden['feasibility_assembly'])
            return {'status':'completed','charged_model_tokens':0,'answer':{'assembly':assembly},
                'driver_kind':'authored_no_model_control','model_invocations':0,'provider_usage':None,
                'original_budget':budgets,'request_sha256':evidence.put(request)}

    def raw_object(key):
        raw=(evidence.root/'objects'/key).read_bytes()
        require(sha256(raw).hexdigest()==key,'original object hash differs')
        return raw

    def obj(key):
        return json.loads(raw_object(key))

    for scheduled in schedule:
        if halted is not None:
            results.append({**scheduled,'executed':False,'not_started_reason':halted,
                'wrapper_cell_wall_ns':None,'observed_ledger_wall_ns':None,'completed':False})
            continue
        fixture=AuthoredFixture(); observed=None; summary=None; launch_error=None
        cell_started=time.monotonic_ns(); cell_cpu_before=cpu_snapshot()
        try:
            with tempfile.TemporaryDirectory(prefix=scheduled['cell_id']+'-',dir=evidence.root) as state:
                observed,summary=run_cell(evidence,public,hidden,item,scheduled['arm'],cell_registration,
                    provider=fixture,bridge=bridge,state_parent=Path(state),calibration=[])
        except BaseException as error:
            launch_error={'type':type(error).__name__,'message':str(error),'traceback':traceback.format_exc()}
            halted='unexpected orchestration exception; remaining registered cells not started'
        wrapper_wall=time.monotonic_ns()-cell_started; cell_cpu_after=cpu_snapshot()
        row={**scheduled,'executed':True,'wrapper_cell_wall_ns':wrapper_wall,
            'cpu_ns':{name:cell_cpu_after[name]-cell_cpu_before[name] for name in cell_cpu_before},
            'original_budget':CELL_BUDGET,'scripted_proposal_calls':fixture.calls,'model_invocations':0,
            'observed_row':observed,'original_summary':summary,'orchestration_error':launch_error,
            'completed':False,'audit_passed':False,'audit_error':None,'native_observation_count':None}
        audit_start=time.monotonic_ns()
        try:
            if launch_error is not None:
                raise ValueError('original cell did not return a settled row')
            detail=obj(observed['result_receipt_sha256'])
            costs=ledger_totals(observed['ledger']); events=[]; cursor=0
            for entry in observed['ledger']:
                event=obj(entry['receipt_sha256']);events.append(event)
                require(all(event[key]==entry[key] for key in ('id','phase','status','wall_ns','model_tokens')),
                    'event differs from original ledger')
                require(event['start_offset_ns']==cursor and event['wall_ns']>=0
                    and event['end_offset_ns']==cursor+event['wall_ns']
                    and cursor<=event['operation_start_offset_ns']<=event['end_offset_ns'],
                    'noncontiguous original ledger')
                cursor=event['end_offset_ns']
            require(cursor==costs['observed_wall_ns']==detail['measurement_endpoint_ns'],'original cost endpoint differs')
            require(wrapper_wall>=cursor,'outer cell interval excludes original ledger time')
            require(detail['original_budget']==CELL_BUDGET and detail['arm']==scheduled['arm'],'budget/arm binding differs')
            require(detail['task_id']==public['id'],'task differs from registered pair')
            model_events=[e for e in events if e['phase']=='model']
            require(all(e['output'] is not None and e['output']['driver_kind']=='authored_no_model_control'
                and e['output']['model_invocations']==0 and e['output']['provider_usage'] is None
                and e['model_tokens']==0 for e in model_events),'a scripted proposal was confused with provider usage')
            first_rejected=bool(detail['rounds'] and detail['rounds'][0]['feedback']['status']=='rejected')
            decision=detail['decision']; natives=[obj(k) for k in detail['native_original_observations']]
            row['native_observation_count']=len(natives)
            native_completed=False; matched_choice=None
            if decision is not None:
                require(decision['pool']==detail['pool'] and decision['selected_id']==detail['selected_id'],
                    'original pool or final choice differs from advice')
                ranks=[e for e in events if e['label']=='rank identical quality-qualified proposal pool']
                require(len(ranks)==1 and ranks[0]['output']==decision
                    and max(0,CELL_BUDGET['wall_ns']-ranks[0]['end_offset_ns'])
                        <=decision['remaining_wall_ns']
                        <=max(0,CELL_BUDGET['wall_ns']-ranks[0]['operation_start_offset_ns']),
                    'original advice allowance is not bound to actual controller interval')
                expected=checked_pool_selection('ordinary',detail['pool'],
                    remaining_wall_ns=decision['remaining_wall_ns'],bridge=None,
                    objective_sha256=cell_registration['objective_sha256'],generation=1)
                matched_choice=expected['selected_id']==decision['selected_id']
                require(matched_choice,'native/controller choice differs from same-table strong ordinary result')
            if scheduled['arm']=='ordinary':
                require(not natives and not observed['native_ndu_receipts'],'ordinary arm claimed a native evaluator call')
            elif decision is not None and decision['native_ndu_evaluated']:
                require(len(natives)==1,'native original observation absent or duplicated')
                native=natives[0];pump=native['pump']
                require(native['response_admitted'] is True and native['native_identity']==bridge_identity,
                    'native response lacks admitted source/image identity')
                require(pump is not None and all(pump[key] is True for key in
                    ('cleanup_confirmed','streams_complete'))
                    and pump['returncode']==0 and pump['error'] is None,'native output incomplete or unsettled')
                require(obj(native['stdin_sha256'])==decision['native_request']
                    and obj(pump['stdout_sha256'])==decision['native_response'],'original native wire differs')
                require(decision['selection_resolution']==resolve_scalar_selection(
                    decision['native_request'],decision['native_response']),'caller selection receipt differs')
                resolved=decision['selection_resolution']['selected_id']
                projected=decision['feasible_incumbent_id'] if resolved=='abstain' else resolved
                require(projected==decision['selected_id'],'caller receipt does not map to original selected artifact')
                native_completed=True
                row.update(native_raw_recommendation=decision['native_response']['advisory_recommendation'],
                    native_disposition=decision['native_response']['disposition'],
                    native_pareto_frontier=decision['native_response']['pareto_frontier'],
                    caller_tie_policy_applied=decision['selection_resolution']['caller_tie_policy_applied'],
                    caller_selection_source=decision['selection_resolution']['selection_source'],
                    native_selection_resolution=decision['selection_resolution'],
                    successful_original_callback_observations=len(natives))
            selected=next((p for p in detail['pool'] if p['id']==detail['selected_id']),None)
            consumer_ok=(selected is not None and type(detail['final_use']) is dict
                and _native_result_correct(detail['final_use'],
                {'workload':{'cases':hidden['cases']}},selected['artifact_sha256']))
            strict_size=(selected is not None and selected['artifact_bytes']<detail['baseline_bytes']
                and len(raw_object(selected['artifact_sha256']))==selected['artifact_bytes'])
            transitions={phase:[e for e in events if e['phase']==phase and e['status']=='completed']
                for phase in ('adoption','future_use','rollback')}
            transition_ok=all(len(value)==1 for value in transitions.values())
            if transition_ok:
                adoption=transitions['adoption'][0]['output']; rollback=transitions['rollback'][0]['output']
                transition_ok=(adoption==detail['adoption'] and transitions['future_use'][0]['output']==detail['final_use']
                    and rollback['previous']==adoption['current']
                    and rollback['current']['generation']==adoption['previous']['generation'])
            completed=(observed['correct'] is True and detail['quality_complete'] is True
                and detail['within_original_budget'] is True and costs['complete'] is True
                and cursor<=CELL_BUDGET['wall_ns'] and fixture.calls==3 and first_rejected
                and consumer_ok and strict_size and transition_ok
                and (scheduled['arm']=='ordinary' or native_completed))
            row.update(completed=completed,audit_passed=True,observed_ledger_wall_ns=cursor,
                phases=costs['phases'],event_count=len(events),
                failed_or_rejected_events=sum(e['status']!='completed' for e in events),
                failed_or_rejected_wall_ns=sum(e['wall_ns'] for e in events if e['status']!='completed'),
                first_round_rejection_retained=first_rejected,actual_native_ndu_completed=native_completed,
                same_table_ordinary_choice_matches=matched_choice,actual_consumer_all_256_correct=bool(consumer_ok),
                actual_strict_size_improvement=bool(strict_size),adoption_use_rollback_complete=transition_ok,
                selected_artifact_sha256=selected['artifact_sha256'] if selected else None,
                original_failure=detail['failure'])
            if fixture.blocked_reason is not None or unstable_cleanup(natives) or unstable_cleanup(events):
                halted='original native/provider cleanup or settlement was not confirmed; no later cell launched'
        except BaseException as error:
            row['audit_error']={'type':type(error).__name__,'message':str(error),'traceback':traceback.format_exc()}
            halted=halted or 'original evidence audit failed; no later cell launched'
        row['external_audit_wall_ns']=time.monotonic_ns()-audit_start
        audits_wall_ns+=row['external_audit_wall_ns']
        results.append(row)
        evidence.named(scheduled['cell_id']+'.json',row)
        print(json.dumps({k:row.get(k) for k in ('cell_id','arm','completed','wrapper_cell_wall_ns',
            'observed_ledger_wall_ns','failed_or_rejected_events','actual_native_ndu_completed','audit_error')}),flush=True)

    integrity=[]
    for entry in sorted(evidence.inventory.values(),key=lambda row:row['sha256']):
        raw=raw_object(entry['sha256'])
        require(len(raw)==entry['byte_size'],'original object length differs')
        integrity.append(entry)
    after=source_identity()
    require(before==after and not git(source,'status','--porcelain','--untracked-files=all'),'immutable source changed')
    require(git(source,'rev-parse','HEAD')==SOURCE_SHA,'immutable source HEAD changed')
    _,bridge_after=_bridge_identity(bridge)
    require(bridge_after==bridge_identity,'native image/build identity changed')
    paired=[]
    for pair in range(1,len(PAIR_ORDER)+1):
        arms={r['arm']:r for r in results if r['pair']==pair}
        complete=all(arms[arm]['completed'] for arm in ('ordinary','ndu'))
        paired.append({'pair':pair,'order':list(PAIR_ORDER[pair-1]),'both_completed':complete,
            'observed_wrapper_ordinary_minus_ndu_ns':(arms['ordinary']['wrapper_cell_wall_ns']-arms['ndu']['wrapper_cell_wall_ns'])
                if all(arms[a]['executed'] for a in arms) else None,
            'completed_ledger_ordinary_minus_ndu_ns':(arms['ordinary']['observed_ledger_wall_ns']-arms['ndu']['observed_ledger_wall_ns']) if complete else None,
            'scope':'descriptive same-task/script/budget pair; arm-specific native measurements differ; not stable or causal economic benefit'})
    executed=[r for r in results if r['executed']]
    complete=all(r['completed'] for r in results)
    native_count=sum(r.get('actual_native_ndu_completed') is True for r in results)
    tie_count=sum(r.get('caller_tie_policy_applied') is True for r in results)
    cpu_after=cpu_snapshot(); ended=time.monotonic_ns()
    cell_wall=sum(r['wrapper_cell_wall_ns'] for r in executed)
    summary={'schema':SCHEMA,'status':'MECHANISM_COMPLETE' if complete else 'INCOMPLETE',
        'source_sha':SOURCE_SHA,'entry_harness_sha256':plan['entry_harness_sha256'],
        'plan_sha256':plan_identity,'plan_file_sha256':sha256((evidence.root/'PLAN.json').read_bytes()).hexdigest(),
        'registration_sha256':plan['registration_sha256'],
        'planned_cells':8,'executed_cells':len(executed),'completed_cells':sum(r['completed'] for r in results),
        'results':results,'paired_costs':paired,'bridge_identity':bridge_identity,
        'actual_native_evaluations':native_count,'caller_tie_resolutions':tie_count,
        'retained_native_observation_count':(sum(r['native_observation_count'] for r in executed)
            if all(r.get('native_observation_count') is not None for r in executed) else None),
        'known_subset_native_observation_count':sum(r['native_observation_count'] for r in executed
            if r.get('native_observation_count') is not None),
        'actual_native_null_recommendations':sum(r.get('actual_native_ndu_completed') is True
            and r.get('native_raw_recommendation') is None for r in results),
        'tie_exercised_in_this_comparison':tie_count>0,
        'tie_scope':('actual task-cost rows triggered the caller tie policy' if tie_count else
            'no tie exercised in these measured task rows; separate actual-native integration probe covers the repair'),
        'source_unchanged':True,'native_identity_unchanged':True,'original_objects':integrity,
        'objects_hash_verified':len(integrity),'halted_reason':halted,
        'measurement':{'outer_wall_ns_to_summary_preparation':ended-started,
            'wrapper_cell_wall_ns':cell_wall,'external_audit_wall_ns':audits_wall_ns,
            'setup_export_audit_cleanup_wall_ns':ended-started-cell_wall,
            'original_ledger_wall_ns':(sum(r['observed_ledger_wall_ns'] for r in executed)
                if all(r.get('observed_ledger_wall_ns') is not None for r in executed) else None),
            'known_subset_original_ledger_wall_ns':sum(r['observed_ledger_wall_ns'] for r in executed
                if r.get('observed_ledger_wall_ns') is not None),
            'original_ledger_total_complete':all(r.get('observed_ledger_wall_ns') is not None for r in executed),
            'cpu_ns':{k:cpu_after[k]-cpu_before[k] for k in cpu_before},
            'nested_wall_added_again':False,'final_summary_write_included':False,
            'prior_source_acquisition_dependencies_and_native_build_included':False},
        'environment':{'python':sys.version,'platform':platform.platform(),
            'packages':{name:importlib.metadata.version(name) for name in ('jsonschema','z3-solver')}},
        'real_model_invocations':0,'provider_cli_sessions':0,'formal_mcp_calls':0,'real_user_tasks':0,
        'scripted_provider_is_a_model':False,'private_teacher_used':True,'learner_success':False,
        'money':None,'chatgpt_authoring_model_usage':None,'chatgpt_authoring_fees':None,
        'global_full_cost_complete':False,'p1_acceptance':'HOLD','qualified_total_ndu_saving_ns':None,
        'stable_total_benefit_established':False,'economic_benefit_established':False,
        'scope':'eight scheduled native control cells for one synthetic teacher-derived task; descriptive costs only'}
    require(summary['measurement']['setup_export_audit_cleanup_wall_ns']>=audits_wall_ns,'outer cost intervals overlap')
    evidence.named('SUMMARY.json',summary)
    return 0 if complete else 2


if __name__=='__main__':
    raise SystemExit(main())

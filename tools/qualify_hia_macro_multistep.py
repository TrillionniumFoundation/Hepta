#!/usr/bin/env python3
"""Quality-gated, matched three-round synthetic four-arm study (v2).

This is a new experiment, not a rewrite of the v1 campaign. Preparation only
freezes identities. Running requires an explicit invocation with that plan.
All model failures and native costs remain in the original cell allowance.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import resource
import statistics
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hepta.hia_agent_assembly import assemble_program
from hepta.hia_agent_contract import installation_manifest
from hepta.hia_agent_macro_policy import COMPARISON_SCHEMA, assess_macro_comparison, digest, ledger_totals, wire
from hepta.hia_agent_runner import run_native_batch
from hepta.hia_agent_service import HIAAgentService
from hepta.hia_ndu_optimizer import _bridge_identity, _native_rank, ns_to_ms_q32
from tools.hia_agent_native_qualification import ToolClient
from tools.hia_macro_multistep_provider import StructuredProvider, request_document, verify_receipt
from tools.qualify_hia_macro_campaign import (ARM_ORDER, CampaignRejected, CapturingSession,
    Evidence, Journal, _json, _native_result_correct, _new_file, _read_regular)

SCHEMA = 'hepta.hia.agent.macro-multistep.v2'
PROTOCOL_PATH = ROOT / 'benchmarks/hia_macro_multistep/PROTOCOL.json'
SOURCES = ('tools/qualify_hia_macro_multistep.py', 'tools/hia_macro_multistep_provider.py',
    'tools/qualify_hia_macro_campaign.py', 'tools/hia_macro_codex_provider.py',
    'tools/hia_agent_codex_transport.py', 'tools/hia_agent_native_qualification.py',
    'tools/prepare_hia_followup_tasks.py', 'benchmarks/hia_macro_multistep/PROTOCOL.json',
    'tools/qualify_hia_followup_tasks.py',
    'tools/hia_macro_exec_adapter.py', 'tools/prepare_hia_macro_launcher.py',
    'docs/HIA_AGENT_MACRO_MULTISTEP.md',
    'docs/HIA_AGENT_ASSEMBLY.md', 'docs/HIA_AGENT_NATIVE_TOOL_CATALOG.json')


def require(ok, message):
    if not ok:
        raise CampaignRejected('E_HIA_MULTISTEP: ' + message)


def source_identity():
    names = set(SOURCES)
    names.update(str(p.relative_to(ROOT)) for p in (ROOT / 'hepta').rglob('*.py'))
    return {name: sha256(_read_regular(ROOT / name)).hexdigest() for name in sorted(names)}


def protocol():
    value = _json(_read_regular(PROTOCOL_PATH))
    require(value['schema'] == 'hepta.hia.agent.macro-multistep-protocol.v2'
        and value['arms'] == list(ARM_ORDER) and value['calibration_tasks'] == 2
        and value['heldout_tasks'] == 4
        and value['per_cell'] == {'wall_ns': 180_000_000_000, 'model_tokens': 32768,
            'max_provider_turns': 3, 'max_candidates': 3, 'native_wall_ms': 10000,
            'memory_bytes': 536870912}, 'registered protocol/budget differs')
    return value


def prepare(registration_path, output, *, binary, model, bridge, feasibility_path, launcher_binding_path, warnings=()):
    registration_path = Path(registration_path).absolute()
    registration_raw = _read_regular(registration_path)
    registration = _json(registration_raw)
    require(registration['schema'] == 'hepta.hia.agent.followup-preregistration.v2', 'task registration schema')
    tasks = [row for row in registration['tasks'] if row['purpose'] != 'firstuse']
    require([row['purpose'] for row in tasks] == ['calibration'] * 2 + ['heldout'] * 4,
            'exact two calibration and four heldout tasks required')
    for row in tasks:
        for scope in ('public', 'hidden'):
            raw = _read_regular(registration_path.parent / row[scope]['path'])
            require(len(raw) == row[scope]['bytes'] and sha256(raw).hexdigest() == row[scope]['sha256'],
                    'task bytes differ from preregistration')
    feasibility_path = Path(feasibility_path).absolute()
    feasibility_raw = _read_regular(feasibility_path)
    feasibility = _json(feasibility_raw)
    require(feasibility['schema'] == 'hepta.hia.agent.private-native-feasibility.v2'
        and feasibility['passed'] is True and feasibility['registration_sha256'] == sha256(registration_raw).hexdigest()
        and feasibility['installation'] == installation_manifest() and feasibility['model_calls'] == 0
        and feasibility['private_teacher_is_learner_input'] is False
        and feasibility.get('linkage_profile') == 'GNU ld, matching HIAAgentService._compile; canonical codegen with no machine plan',
        'every task needs native strict-size feasibility on the exact current source/linkage before model admission')
    qualified = {row['task_id']:row for row in feasibility['tasks']}
    require(all(row['id'] in qualified and qualified[row['id']]['passed'] is True
        and qualified[row['id']]['strictly_smaller'] is True and qualified[row['id']]['native_cases'] == 512
        and qualified[row['id']]['public_sha256'] == row['public']['sha256'] for row in tasks),
        'unqualified task in frozen matrix')
    for record in feasibility['files']:
        raw = _read_regular(feasibility_path.parent / record['path'])
        require(len(raw) == record['bytes'] and sha256(raw).hexdigest() == record['sha256'],
                'native feasibility original changed')
    _, native_identity = _bridge_identity(bridge)  # identity only: no native invocation
    launcher_binding = _json(_read_regular(launcher_binding_path))
    require(launcher_binding['configuration']['registration_sha256'] == sha256(registration_raw).hexdigest()
        and launcher_binding['configuration']['task_ids'] == [row['id'] for row in tasks],
        'launcher is not bound to this registered task matrix')
    provider = StructuredProvider(binary, model, warnings=warnings,launcher_binding=launcher_binding)
    started = time.time_ns()
    plan = {'schema': SCHEMA, 'prepared_unix_ns': started,
        'registration_path': str(registration_path), 'registration_sha256': sha256(registration_raw).hexdigest(),
        'feasibility_path': str(feasibility_path), 'feasibility_sha256': sha256(feasibility_raw).hexdigest(),
        'protocol': protocol(), 'tasks': tasks, 'source_identity': source_identity(),
        'installation': installation_manifest(), 'provider': provider.description(),
        'bridge': bridge, 'native_identity': native_identity,
        'max_provider_sessions': 72, 'model_calls_at_preparation': 0,
        'max_cell_wall_allowances_seconds': 4320, 'monetary_cost': None,
        'isolation_admission': 'coordinator must independently freeze effective CLI configuration/launcher; no capability absence is inferred from an executable hash',
        'scope': 'local domain service plus real provider if explicitly run; not formal MCP first use',
        'economic_benefit_established': False, 'p1_acceptance': 'HOLD'}
    _new_file(output, wire(plan) + b'\n')
    return plan


def checked_pool_selection(arm, pool, *, remaining_wall_ns, bridge, objective_sha256, generation,
                           observer=None):
    """Same task-quality predicate and complete-cost rows for all four arms.

    The task baseline is not an admissible completed task. The first actual
    quality-qualified proposal is the feasible selection incumbent. Native
    abstain means retain that proposal, as required by its unchanged ABI;
    it never means silently deliver the unimproved task baseline. No eligible
    proposal means no task delivery and no native call with a fake incumbent.
    """
    require(arm in ARM_ORDER and type(remaining_wall_ns) is int, 'controller input')
    require(len(pool) <= 3 and len({row['id'] for row in pool}) == len(pool), 'candidate pool bound')
    eligible = []
    candidate_rows = []
    for item in pool:
        require(set(item) == {'id','quality_complete','immediate_ns','remaining_cost_ns','uncertainty_ns',
            'support_sha256','artifact_sha256','artifact_bytes'}, 'closed cost row required')
        require(type(item['quality_complete']) is bool and all(type(item[k]) is int and item[k] >= 0
            for k in ('immediate_ns','remaining_cost_ns','uncertainty_ns','artifact_bytes')), 'known nonnegative cost row')
        robust = item['remaining_cost_ns'] + item['uncertainty_ns']
        feasible = item['quality_complete'] and robust <= remaining_wall_ns
        if feasible:
            eligible.append(item)
        candidate_rows.append({'id': item['id'], 'cost_q32': ns_to_ms_q32(robust), 'uncertainty_q32': 0,
            'resource_q32': ns_to_ms_q32(robust), 'hard_violation': not feasible,
            'support_sha256': item['support_sha256']})
    incumbent = eligible[0]['id'] if eligible else None
    rows = []
    if incumbent is not None:
        incumbent_row = next(row for row in candidate_rows if row['id'] == incumbent)
        rows = [{**incumbent_row, 'id':'abstain'}] + [row for row in candidate_rows if row['id'] != incumbent]
    request = {'schema': 'hepta.hia.ndu-request.v1', 'objective_sha256': objective_sha256,
        'generation': generation, 'resource_cap_q32': ns_to_ms_q32(max(remaining_wall_ns, 0)),
        'candidates': rows}
    selected, response, native_identity = None, None, None
    if arm == 'fixed':
        selected = eligible[0]['id'] if eligible else None
    elif arm == 'greedy':
        selected = min(eligible, key=lambda row:(row['immediate_ns'],row['id']))['id'] if eligible else None
    elif arm == 'ordinary':
        # Enumerate all rows, using the same integer robust cost disclosed to
        # the native evaluator, with deterministic ID ties.
        selected = min(eligible, key=lambda row:(ns_to_ms_q32(row['remaining_cost_ns'] + row['uncertainty_ns']),
            row['id'] != incumbent, row['id']))['id'] if eligible else None
    elif eligible and remaining_wall_ns > 0:
        require(bridge is not None, 'native NDU cannot use a Python stand-in')
        options = {} if observer is None else {'observer':observer}
        response, native_identity = _native_rank(bridge, request,
            timeout_s=min(1_000_000_000, remaining_wall_ns) / 1e9, **options)
        recommendation = response['advisory_recommendation']
        selected = incumbent if recommendation in (None,'abstain') else recommendation
        require(selected is None or selected in {row['id'] for row in eligible}, 'native selected ineligible task')
    return {'schema': 'hepta.hia.agent.quality-pool-advice.v2', 'arm': arm,
        'pool': deepcopy(pool), 'remaining_wall_ns': remaining_wall_ns,
        'native_request': request if arm == 'ndu' and eligible else None,
        'native_response': response, 'native_identity': native_identity,
        'native_ndu_evaluated': response is not None, 'selected_id': selected,
        'feasible_incumbent_id': incumbent,
        'native_abstain_semantics': 'retain first quality-qualified actual proposal from this cell; not the original task baseline',
        'selection_scope': 'explicitly checked proposal pool after matched feedback rounds; no learned search dynamics',
        'baseline_delivers_maintenance_goal': False, 'authority': 'DENY_ALL',
        'forecast_is_observed_benefit': False, 'net_benefit_established': False}


def calibration_forecast(prior):
    require(len(prior) <= 2, 'at most two own-arm calibration tasks')
    observations = [row['adoption_and_rollback_wall_ns'] for row in prior
                    if row.get('quality_complete') is True]
    require(all(type(x) is int and x >= 0 for x in observations), 'calibration cost must be observed')
    return {'transition_ns': int(statistics.median(observations)) if observations else 2_000_000,
        'uncertainty_ns': max(observations) - min(observations) + 1_000_000 if observations else 10_000_000,
        'basis': 'own preceding calibration receipts only; empty basis uses a registered two-ms transition prior and ten-ms uncertainty, neither asserted as an observation',
        'observations': observations, 'forecast_is_observation': False}


def run_cell(evidence, public, hidden, item, arm, registration, *, provider, bridge, state_parent, calibration):
    budget = registration['budget']
    journal = Journal(evidence, arm, public['id'], budget)
    service, selected, final_use, decision = None, None, None, None
    rounds, pool, builds, native_receipts, native_observations = [], [], {}, [], []
    baseline_build, baseline_bytes, failure, adopted = None, None, None, None
    unsafe_stop = False
    workload = {'schema': 'hepta.hia.agent.workload.v1', 'cases': hidden['cases'],
                'warmup_iterations': 0, 'repetitions': 1}
    task_view = {'workload': workload}
    quality = False

    def remaining():
        return max(0, budget['wall_ns'] - (time.monotonic_ns() - journal.origin))

    def cost_state():
        observed = ledger_totals(journal.entries)
        return {'original': budget, 'observed': observed, 'remaining_wall_ns': remaining(),
                'remaining_tokens': budget['model_tokens'] - observed['observed_model_tokens']}

    def execute(build):
        return run_native_batch(journal.session.read(build['native_artifact']),
            {'transform': {'params':['u8'],'returns':['u8']}}, hidden['cases'],
            timeout_ms=min(10000, remaining() // 1_000_000), memory_bytes=536870912)

    def retain_native(value):
        record = deepcopy(value)
        record['stdin_sha256'] = evidence.put(record.pop('stdin'), binary=True)
        if record['pump'] is not None:
            for stream in ('stdout','stderr'):
                raw = record['pump'].pop(stream)
                record['pump'][stream + '_sha256'] = evidence.put(raw, binary=True)
                record['pump'][stream + '_bytes'] = len(raw)
        native_observations.append(evidence.put(record))

    try:
        require(getattr(provider, 'blocked_reason', None) is None,
                'provider frozen by an earlier unsettled process/protocol outcome; no new cell execution')
        def setup():
            nonlocal service
            service = HIAAgentService(state_parent / (public['id'] + '-' + arm))
            require(service.identities == registration['installation'], 'worker changed since plan freeze')
            journal.client = ToolClient(service.call)
            return {'installation': service.identities}
        journal.run('setup', 'initialize isolated local domain worker', setup)
        def discover():
            journal.session = CapturingSession(journal.client, evidence,
                prefix='macro-v2/' + public['id'] + '/' + arm)
            return journal.session.discovery
        journal.run('discovery', 'exact contract and profiles', discover)
        session = journal.session
        journal.run('setup', 'initial context for baseline import', lambda: session.freeze(workload,
            budget={'max_total_wall_ms': max(1, remaining() // 1_000_000), 'max_candidates': 4,
                    'max_model_tokens': budget['model_tokens']}))
        baseline = journal.run('search', 'import frozen public baseline', lambda: session.import_program(public['baseline']))
        journal.run('setup', 'freeze strict maintenance objective', lambda: session.freeze(workload, baseline=baseline,
            objective=registration['tool_objective'], budget={'max_total_wall_ms': max(1, remaining() // 1_000_000),
                'max_candidates': 3, 'max_model_tokens': budget['model_tokens']}))
        base_check = journal.run('verification', 'baseline admission', lambda: session.verify(baseline))
        baseline_build = journal.run('emission', 'canonical baseline shared artifact',
            lambda: session.emit(baseline, receipts=[base_check['verification_receipt']]))
        baseline_raw = session.read(baseline_build['native_artifact'])
        baseline_bytes = len(baseline_raw)
        base_use = journal.run('evaluation', 'baseline independent complete-domain observation', lambda: execute(baseline_build))
        require(_native_result_correct(base_use, task_view, baseline_build['native_artifact']['sha256']),
                'baseline fails independent mathematical oracle')
        forecast = calibration_forecast(calibration)
        for round_index in range(3):
            costs = cost_state()
            if not costs['observed']['complete'] or costs['remaining_wall_ns'] <= 0 or costs['remaining_tokens'] <= 0:
                break
            request = request_document(public, rounds, costs, calibration=calibration)
            receipt, assembled, generated = None, None, None
            current = {'round': round_index + 1, 'request_sha256': evidence.put(request),
                       'assembly': None, 'feedback': None}
            try:
                def invoke():
                    nonlocal receipt
                    receipt = provider.invoke(request, evidence,
                        evidence.root / ('provider-' + public['id'] + '-' + arm + '-' + str(round_index + 1)),
                        remaining_wall_ns=costs['remaining_wall_ns'], remaining_tokens=costs['remaining_tokens'])
                    return receipt
                generated = journal.run('model', 'scheduled proposal round ' + str(round_index + 1), invoke, model=True)
                current['assembly'] = generated['answer']['assembly']
                assembled = journal.run('search', 'strict assembly and complete Core admission',
                    lambda: assemble_program(current['assembly']).as_dict())
                candidate = journal.run('search', 'import original model proposal', lambda: session.import_program(assembled))
                proof = journal.run('verification', 'complete baseline behavior equivalence', lambda: session.verify(candidate,
                    base=baseline, claims=['core_admission','behavior_equivalence']))
                require(all(row['status'] == 'proved' for row in proof['checks']), 'candidate proof incomplete')
                build = journal.run('emission', 'canonical candidate shared artifact',
                    lambda: session.emit(candidate, receipts=[proof['verification_receipt']]))
                encoding = journal.run('verification', 'complete emitted encoding check', lambda: session.encoding(candidate, build))
                receipts = [proof['verification_receipt'], encoding['verification_receipt']]
                evaluation = journal.run('evaluation', 'frozen full-domain and size objective',
                    lambda: session.evaluate(baseline_build, build, receipts=receipts))
                probe = journal.run('evaluation', 'independent candidate full-domain observation', lambda: execute(build))
                if probe.get('termination_confirmed') is not True:
                    unsafe_stop = True
                    raise CampaignRejected('original native outcome unsettled; no further model or native execution')
                require(type(probe.get('report')) is dict and
                    type(probe['report'].get('total_native_ns')) is str
                    and probe['report']['total_native_ns'].isdigit(), 'native immediate time unknown')
                size = len(session.read(build['native_artifact']))
                complete = (size < baseline_bytes and evaluation['planned_workload_complete'] is True
                    and evaluation['outcome'] == 'improved'
                    and _native_result_correct(probe, task_view, build['native_artifact']['sha256']))
                name = 'candidate.' + str(round_index + 1)
                support = evidence.put({'build':build,'proof':proof,'encoding':encoding,'evaluation':evaluation,
                    'probe':probe,'program':candidate,'assembly_sha256':sha256(current['assembly'].encode()).hexdigest(),
                    'baseline_bytes':baseline_bytes,'artifact_bytes':size,'quality_complete':complete})
                pool.append({'id':name,'quality_complete':complete,
                    'immediate_ns':int(probe['report']['total_native_ns']),
                    'remaining_cost_ns':int(probe['wall_ns']) + forecast['transition_ns'],
                    'uncertainty_ns':forecast['uncertainty_ns'],'support_sha256':support,
                    'artifact_sha256':build['native_artifact']['sha256'],'artifact_bytes':size})
                builds[name] = (build, receipts, evaluation)
                current['feedback'] = {'status':'quality_complete' if complete else 'task_not_delivered',
                    'baseline_bytes':baseline_bytes,'candidate_bytes':size,'all_256_correct':
                        _native_result_correct(probe,task_view,build['native_artifact']['sha256']),
                    'observed_native_call_ns':(probe.get('report') or {}).get('total_native_ns'),
                    'observed_probe_wall_ns':probe['wall_ns'], 'support_sha256':support}
            except Exception as exc:
                current['feedback'] = {'status':'rejected','diagnostic':str(exc)[:2048],
                    'source':'actual original parser/checker/tool/observer result',
                    'event_receipt_sha256':journal.entries[-1]['receipt_sha256']}
                if unsafe_stop or receipt is None or (receipt.get('status') != 'completed'
                        and receipt.get('recoverable_content_rejection') is not True):
                    unsafe_stop = True
                    rounds.append(current)
                    break
            rounds.append(current)
        require(not unsafe_stop, 'original provider/native attempt lacks qualified settlement; cell stopped')
        decision = journal.run('controller', 'rank identical quality-qualified proposal pool', lambda:
            checked_pool_selection(arm, pool, remaining_wall_ns=remaining(), bridge=bridge,
                objective_sha256=registration['objective_sha256'], generation=1, observer=retain_native))
        if decision['native_ndu_evaluated']:
            native_receipts.append(evidence.put(decision))
        selected = decision['selected_id']
        if selected is not None:
            build, receipts, evaluation = builds[selected]
            adopted = journal.run('adoption', 'conditionally adopt selected checked candidate', lambda:
                session.client.result('hia_adopt', session.arguments(target_slot='macro-v2',
                    expected_current={'generation':'0','epoch':'0'}, candidate_artifact=build['native_artifact'],
                    evaluation_receipt=evaluation['evaluation_receipt'], verification_receipts=receipts)))
            final_use = journal.run('future_use', 'actual selected artifact on all 256 oracle inputs', lambda: execute(build))
            quality = (_native_result_correct(final_use, task_view, build['native_artifact']['sha256'])
                       and len(session.read(build['native_artifact'])) < baseline_bytes)
            journal.run('rollback', 'restore baseline after final observation', lambda:
                session.client.result('hia_rollback', session.arguments(target_slot='macro-v2',
                    expected_current=adopted['current'], retained_generation=adopted['previous']['generation'],
                    reason='registered local v2 comparison complete')), cleanup=True)
    except Exception as exc:
        failure = {'type':type(exc).__name__,'message':str(exc)[:2048]}
        quality = False
    finally:
        try:
            journal.session = None
            journal.close(service.close if service else lambda: None)
        except Exception as exc:
            quality = False
            failure = {'type':type(exc).__name__,'message':str(exc)[:2048]}
    costs = ledger_totals(journal.entries)
    within_budget = costs['complete'] and costs['observed_wall_ns'] <= budget['wall_ns'] \
        and costs['observed_model_tokens'] <= budget['model_tokens']
    quality = quality and within_budget
    result = {'schema':SCHEMA,'arm':arm,'task_id':public['id'],'rounds':rounds,'pool':pool,
        'selected_id':selected,'decision':decision,'final_use':final_use,'quality_complete':quality,
        'baseline_build':baseline_build,'baseline_bytes':baseline_bytes,'adoption':adopted,
        'native_original_observations':native_observations,
        'failure':failure,'within_original_budget':within_budget,'calibration':deepcopy(calibration),
        'measurement_endpoint_ns':journal.cursor-journal.origin,'original_budget':budget,
        'teacher_used_by_provider':False,'transport':'local_domain_service','formal_mcp_first_use':False,
        'p1_acceptance':'HOLD','economic_benefit_established':False}
    row = {'task_id':public['id'],'input_sha256':item['input_sha256'],
        'qualification_receipt_sha256':item['qualification_receipt_sha256'],
        'status':'completed' if quality else 'failed','correct':quality,
        'result_receipt_sha256':evidence.put(result),'ledger':journal.entries,
        'phase_inventory':journal.phase_inventory(),'native_ndu_receipts':native_receipts}
    summary = {'task_id':public['id'],'quality_complete':quality,
        'adoption_and_rollback_wall_ns':sum(entry['wall_ns'] for entry in journal.entries
            if entry['phase'] in {'adoption','rollback'}),
        'result_receipt_sha256':row['result_receipt_sha256']}
    return row, summary


def run(plan_path, output):
    started = time.monotonic_ns()
    cpu_before = [resource.getrusage(kind) for kind in (resource.RUSAGE_SELF,resource.RUSAGE_CHILDREN)]
    plan = _json(_read_regular(plan_path))
    require(plan['schema'] == SCHEMA and plan['source_identity'] == source_identity()
        and plan['installation'] == installation_manifest() and plan['protocol'] == protocol(), 'frozen source drift')
    reg_path = Path(plan['registration_path'])
    require(sha256(_read_regular(reg_path)).hexdigest() == plan['registration_sha256'], 'registration drift')
    require(sha256(_read_regular(plan['feasibility_path'])).hexdigest() == plan['feasibility_sha256'],
            'native task feasibility receipt drift')
    descriptor = plan['provider']
    provider = StructuredProvider(descriptor['invocation_path'],descriptor['requested_model'],
        warnings=descriptor['registered_startup_warnings'],reasoning_effort=descriptor['reasoning_effort'],
        launcher_binding=descriptor['launcher_binding'])
    require(provider.description() == descriptor, 'provider identity drift')
    require(str(Path(output).absolute()) == descriptor['launcher_binding']['configuration']['campaign_root'],
            'output differs from the one frozen launcher campaign')
    _, native_identity = _bridge_identity(plan['bridge'])
    require(native_identity == plan['native_identity'], 'native bridge drift')
    evidence = Evidence(output)
    plan_sha = evidence.put(plan)
    evidence.put(_read_regular(plan['feasibility_path']), binary=True)
    evidence.put(_read_regular(reg_path), binary=True)
    driver = {'schema':SCHEMA,'provider':descriptor,'source_identity':plan['source_identity'],
        'controls':plan['protocol']['controllers'],'matched_opportunities':plan['protocol']['matched_opportunities'],
        'proposal_policy':plan['protocol']['turn_policy'],'kind':'codex_cli',
        'original_response_model_identity_attested':False,'monetary_cost':None}
    driver_sha = evidence.put(driver)
    objective = {'schema':'hepta.hia.agent.objective.v1','metric':'artifact_bytes',
        'required_claims':['core_admission','behavior_equivalence','encoding_check'],
        'allow_unchanged':False,'min_improvement_ratio':0.0}
    objective_sha = evidence.put({'tool_objective':objective,'quality':plan['protocol']['quality'],
        'comparison':'all registered tasks must be delivered before cost advantage is eligible'})
    prepared, inventory = [], []
    for row in plan['tasks']:
        documents = {}
        for scope in ('public','hidden'):
            raw = _read_regular(reg_path.parent / row[scope]['path'])
            require(sha256(raw).hexdigest() == row[scope]['sha256'] and len(raw) == row[scope]['bytes'], 'task changed')
            documents[scope] = _json(raw)
        task_sha = evidence.put({'public':documents['public'],'hidden_oracle':{
            k:documents['hidden'][k] for k in ('id','cases','oracle','oracle_method')},'purpose':row['purpose']})
        qualification = evidence.put({'schema':SCHEMA,'task_id':row['id'],'input_sha256':task_sha,
            'kind':'synthetic_fixture','real_user_demand':False,'independent_task_judge':
            'Python mathematical oracle; actual native bytes checked on complete u8 domain'})
        item = {'id':row['id'],'input_sha256':task_sha,'qualification':'synthetic_fixture',
                'qualification_receipt_sha256':qualification}
        inventory.append(item)
        prepared.append((documents['public'],documents['hidden'],row,item))
    budget = {key:plan['protocol']['per_cell'][key] for key in ('wall_ns','model_tokens')}
    registration = {'agent_sha256':driver_sha,'objective_sha256':objective_sha,'budget':budget,
        'task_inventory':sorted(inventory,key=lambda x:x['id']),'minimum_gain_ns':1_000_000}
    registration_sha = evidence.put(registration)
    evidence.named('registration.json',registration)
    cell_registration = {**registration,'installation':plan['installation'],'tool_objective':objective}
    arms = {arm:{'strategy':arm,'agent_sha256':driver_sha,'registration_sha256':registration_sha,
        'budget':budget,'observations':[]} for arm in ARM_ORDER}
    calibrations = {arm:[] for arm in ARM_ORDER}
    order = []
    with tempfile.TemporaryDirectory(prefix='v2-workers-',dir=evidence.root) as temporary:
        for index,(public,hidden,row,item) in enumerate(prepared):
            for arm in ARM_ORDER[index%4:] + ARM_ORDER[:index%4]:
                order.append({'task_id':public['id'],'arm':arm,'purpose':row['purpose']})
                observed, summary = run_cell(evidence,public,hidden,item,arm,cell_registration,
                    provider=provider,bridge=plan['bridge'],state_parent=Path(temporary),calibration=calibrations[arm])
                arms[arm]['observations'].append(observed)
                if row['purpose'] == 'calibration':
                    calibrations[arm].append(summary)
                print(json.dumps({'task':public['id'],'arm':arm,'status':observed['status'],
                    'quality_complete':observed['correct'],
                    'wall_ns':ledger_totals(observed['ledger'])['observed_wall_ns']}),flush=True)
    require(plan['source_identity'] == source_identity(), 'source changed during experiment')
    comparison = {'schema':COMPARISON_SCHEMA,**registration,'registration_sha256':registration_sha,
                  'arms':[arms[arm] for arm in ARM_ORDER]}
    comparison_sha = evidence.put(comparison)
    ended = time.monotonic_ns()
    cpu = {}
    for name,kind,before in zip(('parent','children'),(resource.RUSAGE_SELF,resource.RUSAGE_CHILDREN),cpu_before):
        after = resource.getrusage(kind)
        cpu[name] = round((after.ru_utime+after.ru_stime-before.ru_utime-before.ru_stime)*1e9)
    manifest = {'schema':SCHEMA,'plan_sha256':plan_sha,'driver_sha256':driver_sha,
        'registration_sha256':registration_sha,'comparison_sha256':comparison_sha,'execution_order':order,
        'objects':sorted(evidence.inventory.values(),key=lambda row:row['sha256']),
        'measurement':{'outer_wall_ns_to_manifest':ended-started,'cpu_ns':cpu,
            'charged_cells_wall_ns':sum(ledger_totals(row['ledger'])['observed_wall_ns']
                for arm in arms.values() for row in arm['observations']),
            'nested_durations_added_again':False,'final_manifest_and_verifier_export_included':False,
            'module_imports_before_run_clock_included':False,
            'bridge_build':'historical source-bound build; current identity checks included, historical build cost separate'},
        'transport':'in_process_HIAAgentService','provider_http_request_count':None,'monetary_cost':None,
        'p1_acceptance':'HOLD','economic_benefit_established':False,'source_identity_after':source_identity()}
    evidence.named('campaign.json',manifest)
    result = verify(evidence.root)
    evidence.named('verdict.json',result)
    return result


def verify(root):
    """Offline original-byte/causal checks. Never re-execute a provider or image."""
    root = Path(root)
    manifest = _json(_read_regular(root / 'campaign.json'))
    require(manifest['schema'] == SCHEMA and manifest['p1_acceptance'] == 'HOLD'
        and manifest['economic_benefit_established'] is False and manifest['monetary_cost'] is None
        and manifest['provider_http_request_count'] is None, 'claims exceed original evidence')
    records = manifest['objects']
    require(type(records) is list and len(records) <= 16384
        and len({r['sha256'] for r in records}) == len(records), 'bounded unique object inventory')
    originals, byte_total = {}, 0
    for record in records:
        key = record['sha256']
        require(type(key) is str and len(key) == 64 and all(c in '0123456789abcdef' for c in key), 'object name')
        raw = _read_regular(root / 'objects' / key)
        require(len(raw) == record['byte_size'] and sha256(raw).hexdigest() == key, 'changed original object')
        originals[key] = raw
        byte_total += len(raw)
    require(byte_total <= 256 * 1024 * 1024, 'bundle bound')

    def obj(key):
        require(key in originals, 'missing referenced original')
        return _json(originals[key])

    plan = obj(manifest['plan_sha256'])
    private_registration = obj(plan['registration_sha256'])
    feasibility = obj(plan['feasibility_sha256'])
    require(feasibility['passed'] is True and feasibility['installation'] == plan['installation']
        and feasibility['registration_sha256'] == plan['registration_sha256']
        and plan['tasks'] == [r for r in private_registration['tasks'] if r['purpose'] != 'firstuse'],
        'preregistered task feasibility/source identity differs')
    qualified_tasks = {r['task_id']:r for r in feasibility['tasks']}
    driver = obj(manifest['driver_sha256'])
    registration = obj(manifest['registration_sha256'])
    comparison = obj(manifest['comparison_sha256'])
    require(plan['schema'] == SCHEMA and plan['protocol'] == protocol()
        and plan['source_identity'] == manifest['source_identity_after'] == driver['source_identity'],
        'source or protocol identity drift')
    require(driver['provider'] == plan['provider']
        and driver['matched_opportunities'] == plan['protocol']['matched_opportunities']
        and driver['controls'] == plan['protocol']['controllers'], 'unmatched agent/controller opportunities')
    require(comparison['registration_sha256'] == manifest['registration_sha256']
        and all(comparison[k] == v for k,v in registration.items()), 'registered comparison changed')
    require(registration == _json(_read_regular(root / 'registration.json')), 'named registration differs')
    require(registration['budget'] == {k:plan['protocol']['per_cell'][k] for k in ('wall_ns','model_tokens')},
            'original cell budget changed')
    tasks = {row['id']:row for row in registration['task_inventory']}
    ordered = []
    for index,task in enumerate(plan['tasks']):
        for arm in ARM_ORDER[index%4:] + ARM_ORDER[:index%4]:
            ordered.append({'task_id':task['id'],'arm':arm,'purpose':task['purpose']})
    require(manifest['execution_order'] == ordered and len(ordered) == 24, 'registered order/matrix differs')
    usage = {name:0 for name in ('input_tokens','cached_input_tokens','cache_write_input_tokens',
                               'output_tokens','reasoning_output_tokens')}
    counters = {'provider_cli_sessions':0,'provider_receipts':0,'content_rejections':0,
                'native_ndu_evaluations':0,'actual_completed_quality_cells':0,'events':0}
    by_arm = {}
    for arm in comparison['arms']:
        require(arm['strategy'] in ARM_ORDER, 'unknown arm')
        expected_calibration = []
        arm_rows = []
        require([row['task_id'] for row in arm['observations']] == [row['id'] for row in plan['tasks']],
                'arm omitted/reordered a registered task')
        for row,task_plan in zip(arm['observations'],plan['tasks']):
            task = obj(tasks[row['task_id']]['input_sha256'])
            public, hidden = task['public'], task['hidden_oracle']
            require(public['id'] == hidden['id'] == row['task_id'] and len(hidden['cases']) == 256
                and hidden['cases'] == [{'function':'transform','arguments':[x],
                    'expected':{'status':'returned','values':[y]}} for x,y in enumerate(hidden['oracle'])]
                and len(hidden['oracle']) == 256
                and digest(hidden['oracle']) == qualified_tasks[row['task_id']]['oracle_sha256']
                and qualified_tasks[row['task_id']]['hidden_sha256'] == task_plan['hidden']['sha256'],
                'full u8 oracle differs from independently preregistered feasibility')
            require(sha256(wire(public) + b'\n').hexdigest() == task_plan['public']['sha256'],
                    'public input differs from frozen private registration')
            result = obj(row['result_receipt_sha256'])
            require(result['schema'] == SCHEMA and result['task_id'] == row['task_id']
                and result['arm'] == arm['strategy'] and result['original_budget'] == registration['budget']
                and result['calibration'] == expected_calibration and result['teacher_used_by_provider'] is False,
                'cell task/budget/calibration binding differs')
            events, cursor, model_events, prefix_ledger = [], 0, [], []
            for ledger in row['ledger']:
                event = obj(ledger['receipt_sha256'])
                require(all(event[k] == ledger[k] for k in ('id','phase','status','wall_ns','model_tokens'))
                    and event['arm'] == arm['strategy'] and event['task_id'] == row['task_id']
                    and event['start_offset_ns'] == cursor
                    and cursor <= event['operation_start_offset_ns'] <= event['end_offset_ns']
                    and event['wall_ns'] == event['end_offset_ns'] - cursor
                    and event['nested_tool_costs_charged_separately'] is False, 'original event/contiguous cost differs')
                cursor = event['end_offset_ns']
                events.append(event)
                counters['events'] += 1
                if event['phase'] == 'model':
                    counters['provider_receipts'] += 1
                    model_events.append(event)
                    receipt = event['output']
                    if receipt is not None:
                        request = verify_receipt(receipt, originals, plan['provider'])
                        offered = request['original_budget_and_observed_costs']
                        prior_costs = ledger_totals(prefix_ledger)
                        require(offered['original'] == registration['budget']
                            and offered['observed'] == prior_costs
                            and offered['remaining_tokens'] == registration['budget']['model_tokens'] - prior_costs['observed_model_tokens']
                            and max(0,registration['budget']['wall_ns'] - event['operation_start_offset_ns'])
                                <= offered['remaining_wall_ns']
                                <= max(0,registration['budget']['wall_ns'] - event['start_offset_ns'])
                            and receipt['remaining_tokens'] == offered['remaining_tokens']
                            and receipt['remaining_wall_ns'] == offered['remaining_wall_ns']
                            and event['model_tokens'] == receipt['charged_model_tokens'],
                            'model round renewed budget or omitted previous actual cost')
                        round_index = len(model_events) - 1
                        require(round_index < 3 and request == request_document(public,
                            result['rounds'][:round_index],request['original_budget_and_observed_costs'],
                            calibration=expected_calibration), 'provider prompt has unregistered/hidden/future input')
                        require(result['rounds'][round_index]['request_sha256'] == receipt['request_sha256'],
                                'scheduled round/request mismatch')
                        if receipt['process'] is not None:
                            counters['provider_cli_sessions'] += 1
                        if receipt.get('recoverable_content_rejection'):
                            counters['content_rejections'] += 1
                        if receipt.get('usage') is not None:
                            for key in usage:
                                usage[key] += receipt['usage'][key]
                        if receipt.get('status') == 'completed' and receipt.get('answer') is not None:
                            require(result['rounds'][round_index]['assembly'] == receipt['answer']['assembly'],
                                    'candidate text not the actual model output')
                prefix_ledger.append(ledger)
            for phase,summary in row['phase_inventory'].items():
                phase_receipt = obj(summary['receipt_sha256'])
                expected_receipts = [e['receipt_sha256'] for e in row['ledger'] if e['phase'] == phase]
                require(phase_receipt['arm'] == arm['strategy'] and phase_receipt['task_id'] == row['task_id']
                    and phase_receipt['phase'] == phase and phase_receipt['event_receipts'] == expected_receipts
                    and summary['performed'] == bool(expected_receipts), 'phase receipts differ from actual ledger')
            require(cursor == result['measurement_endpoint_ns'] and len(model_events) <= 3
                and len(result['rounds']) == len(model_events), 'cell endpoint or scheduled round count differs')
            costs = ledger_totals(row['ledger'])
            require(costs['observed_wall_ns'] == cursor, 'sunk costs not fully charged')
            within = costs['complete'] and cursor <= registration['budget']['wall_ns'] \
                and costs['observed_model_tokens'] <= registration['budget']['model_tokens']
            require(result['within_original_budget'] == within, 'budget verdict differs')
            baseline = result['baseline_build']
            if baseline is not None:
                require(len(originals[baseline['native_artifact']['sha256']]) == result['baseline_bytes'],
                        'baseline original image size differs')
            forecast = calibration_forecast(expected_calibration)
            for item in result['pool']:
                support = obj(item['support_sha256'])
                index = int(item['id'].split('.')[1]) - 1
                require(0 <= index < len(result['rounds']), 'candidate not a scheduled model round')
                assembly = result['rounds'][index]['assembly']
                require(type(assembly) is str and sha256(assembly.encode()).hexdigest() == support['assembly_sha256'],
                        'candidate source is not actual model text')
                program = assemble_program(assembly)
                require(obj(support['program']['sha256']) == program.as_dict(), 'retained Core differs from actual assembly')
                build = support['build']
                artifact = build['native_artifact']
                require(artifact['sha256'] == item['artifact_sha256']
                    and len(originals[artifact['sha256']]) == item['artifact_bytes'] == support['artifact_bytes'],
                    'candidate original image differs')
                proof, encoding = support['proof'],support['encoding']
                require(proof['candidate'] == support['program'] and encoding['candidate'] == support['program']
                    and all(c['status'] == 'proved' for c in proof['checks'] + encoding['checks']),
                    'candidate proof/encoding missing')
                proof_original = obj(proof['verification_receipt']['sha256'])
                encoding_original = obj(encoding['verification_receipt']['sha256'])
                require(proof_original['candidate'] == encoding_original['candidate'] == support['program']
                    and encoding_original['subject']['native_artifact'] == artifact
                    and encoding_original['subject']['build_receipt'] == build['build_receipt'],
                    'original verification bindings differ')
                evaluation = support['evaluation']
                evaluation_original = obj(evaluation['evaluation_receipt']['sha256'])
                require(evaluation_original['candidate_artifact'] == artifact
                    and evaluation_original['baseline_artifact'] == baseline['native_artifact']
                    and evaluation['candidate_artifact'] == artifact
                    and evaluation_original['outcome'] == evaluation['outcome'], 'evaluation bound to different images')
                complete = (item['artifact_bytes'] < result['baseline_bytes']
                    and evaluation['planned_workload_complete'] is True and evaluation['outcome'] == 'improved'
                    and _native_result_correct(support['probe'],{'workload':{'cases':hidden['cases']}},artifact['sha256']))
                require(item['quality_complete'] == support['quality_complete'] == complete,
                        'cheap incorrect or unchanged artifact promoted as completed task')
                require(item['immediate_ns'] == int(support['probe']['report']['total_native_ns'])
                    and item['remaining_cost_ns'] == int(support['probe']['wall_ns']) + forecast['transition_ns']
                    and item['uncertainty_ns'] == forecast['uncertainty_ns'], 'controller cost/forecast differs')
            decision = result['decision']
            observations = [obj(k) for k in result['native_original_observations']]
            require(len(observations) <= 1 and (arm['strategy'] == 'ndu' or observations == []),
                    'unexpected native evaluator execution')
            for native in observations:
                require(native['schema'] == 'hepta.hia.ndu-native-observation.v1'
                    and native['native_identity'] in (None,plan['native_identity']), 'native original identity differs')
                pump = native['pump']
                if pump is not None:
                    require(all(len(originals[pump[s+'_sha256']]) == pump[s+'_bytes']
                        and pump[s+'_bytes'] <= 1024*1024+4096 for s in ('stdout','stderr')),
                        'bounded original native output differs')
                    require(pump['streams_complete'] == all(pump['eof'].values()), 'native partial output mislabeled')
                if native['response_admitted']:
                    require(decision is not None and native['error'] is None and pump is not None
                        and pump['streams_complete'] is True and pump['cleanup_confirmed'] is True
                        and pump['returncode'] == 0 and pump['error'] is None
                        and obj(native['stdin_sha256']) == decision['native_request']
                        and obj(pump['stdout_sha256']) == decision['native_response'],
                        'native admitted response differs from original bytes')
                else:
                    require(result['failure'] is not None and result['quality_complete'] is False,
                            'native rejection became a delivered task')
            if decision is not None:
                require(decision['pool'] == result['pool'] and decision['arm'] == arm['strategy'], 'controller pool differs')
                ranks = [e for e in events if e['label'] == 'rank identical quality-qualified proposal pool']
                require(len(ranks) == 1 and ranks[0]['output'] == decision
                    and max(0,registration['budget']['wall_ns']-ranks[0]['end_offset_ns'])
                        <= decision['remaining_wall_ns']
                        <= max(0,registration['budget']['wall_ns']-ranks[0]['operation_start_offset_ns']),
                        'controller advice not tied to actual remaining cost interval')
                if arm['strategy'] != 'ndu':
                    expected = checked_pool_selection(arm['strategy'],result['pool'],
                        remaining_wall_ns=decision['remaining_wall_ns'], bridge=None,
                        objective_sha256=registration['objective_sha256'],generation=1)
                    require(expected == decision, 'ordinary/fixed/greedy selection not its frozen rule')
                    require(row['native_ndu_receipts'] == [], 'control claimed native NDU')
                else:
                    request,response = decision['native_request'],decision['native_response']
                    expected_candidates,eligible = [],[]
                    for item in result['pool']:
                        robust = item['remaining_cost_ns'] + item['uncertainty_ns']
                        feasible = item['quality_complete'] and robust <= decision['remaining_wall_ns']
                        if feasible:
                            eligible.append(item['id'])
                        expected_candidates.append({'id':item['id'],'cost_q32':ns_to_ms_q32(robust),'uncertainty_q32':0,
                            'resource_q32':ns_to_ms_q32(robust),'hard_violation':not feasible,
                            'support_sha256':item['support_sha256']})
                    incumbent = eligible[0] if eligible else None
                    require(decision['feasible_incumbent_id'] == incumbent, 'incumbent was not an actual qualified cell proposal')
                    if incumbent is None:
                        require(request is None and response is None and decision['native_identity'] is None
                            and decision['native_ndu_evaluated'] is False and decision['selected_id'] is None
                            and row['native_ndu_receipts'] == [], 'no feasible incumbent must remain an uncompleted task')
                    else:
                        expected_rows = [{**next(r for r in expected_candidates if r['id']==incumbent),'id':'abstain'}] \
                            + [r for r in expected_candidates if r['id']!=incumbent]
                        require(decision['native_ndu_evaluated'] is True and response is not None
                            and decision['native_identity'] == plan['native_identity']
                            and len(observations) == 1 and observations[0]['response_admitted'] is True,
                            'native NDU original identity/output missing')
                        recommendation = response['advisory_recommendation']
                        selected = incumbent if recommendation in (None,'abstain') else recommendation
                        require(response['request_sha256'] == digest(request)
                            and response['objective_sha256'] == request['objective_sha256'] == registration['objective_sha256']
                            and response['generation'] == request['generation'] == 1
                            and response['authority'] == 'ADVISORY_ONLY' and selected == decision['selected_id']
                            and selected in eligible, 'native response/request binding')
                        require(request['candidates'] == expected_rows
                            and request['resource_cap_q32'] == ns_to_ms_q32(max(decision['remaining_wall_ns'],0)),
                            'native received a different quality/cost/resource table')
                        require(row['native_ndu_receipts'] == [digest(decision)], 'native receipt missing')
                        counters['native_ndu_evaluations'] += 1
                require(result['selected_id'] == decision['selected_id'], 'selection differs from original advice')
            completed = False
            if result['selected_id'] is not None:
                chosen = next(item for item in result['pool'] if item['id'] == result['selected_id'])
                completed = chosen['quality_complete'] and within and result['failure'] is None \
                    and result['adoption'] is not None and _native_result_correct(result['final_use'],
                        {'workload':{'cases':hidden['cases']}}, chosen['artifact_sha256'])
                require(any(e['phase'] == 'rollback' and e['status'] == 'completed' for e in events)
                    or not result['quality_complete'], 'successful cell lacks original rollback receipt')
                if completed:
                    support = obj(chosen['support_sha256'])
                    adoption = result['adoption']
                    transition = obj(adoption['adoption_receipt']['sha256'])
                    require(adoption['active_artifact'] == support['build']['native_artifact']
                        and all(transition[k] == adoption[k] for k in ('active_artifact','current','previous','target_slot'))
                        and transition['evaluation_receipt'] == support['evaluation']['evaluation_receipt']
                        and transition['retained_baseline'] == baseline['native_artifact']
                        and transition['verification_receipts'] == [support['proof']['verification_receipt'],
                            support['encoding']['verification_receipt']], 'selected adoption chain differs')
                    uses = [e for e in events if e['phase'] == 'future_use' and e['status'] == 'completed']
                    adopts = [e for e in events if e['phase'] == 'adoption' and e['status'] == 'completed']
                    rollbacks = [e for e in events if e['phase'] == 'rollback' and e['status'] == 'completed']
                    require(len(adopts) == len(rollbacks) == len(uses) == 1
                        and adopts[0]['output'] == adoption and uses[0]['output'] == result['final_use'],
                        'final adoption/use/rollback not actual recorded outputs')
                    rollback = rollbacks[0]['output']
                    rollback_original = obj(rollback['rollback_receipt']['sha256'])
                    require(rollback['active_artifact'] == baseline['native_artifact']
                        and rollback['previous'] == adoption['current']
                        and rollback['current']['generation'] == adoption['previous']['generation']
                        and all(rollback_original[k] == rollback[k] for k in ('active_artifact','current','previous','target_slot')),
                        'rollback did not restore original retained generation')
                    for event,tool in ((adopts[0],'hia_adopt'),(rollbacks[0],'hia_rollback')):
                        calls = [c for c in event['tool_records'] if c['tool'] == tool]
                        require(len(calls) == 1 and calls[0]['response']['status'] == 'completed'
                            and calls[0]['response']['result'] == event['output'], 'transition lacks actual tool receipt')
            require(result['quality_complete'] == row['correct'] == completed
                and row['status'] == ('completed' if completed else 'failed'), 'task completion verdict differs')
            counters['actual_completed_quality_cells'] += int(completed)
            arm_rows.append({'task_id':row['task_id'],'purpose':task_plan['purpose'],
                'quality_complete':completed,'wall_ns':cursor,'model_tokens':costs['observed_model_tokens'],
                'provider_rounds':len(model_events)})
            if task_plan['purpose'] == 'calibration':
                expected_calibration.append({'task_id':row['task_id'],'quality_complete':completed,
                    'adoption_and_rollback_wall_ns':sum(e['wall_ns'] for e in events if e['phase'] in {'adoption','rollback'}),
                    'result_receipt_sha256':row['result_receipt_sha256']})
        by_arm[arm['strategy']] = {'completed':sum(r['quality_complete'] for r in arm_rows),
            'planned':6,'wall_ns':sum(r['wall_ns'] for r in arm_rows),
            'calibration_wall_ns':sum(r['wall_ns'] for r in arm_rows if r['purpose'] == 'calibration'),
            'heldout_wall_ns':sum(r['wall_ns'] for r in arm_rows if r['purpose'] == 'heldout'),'rows':arm_rows}
    require(counters['provider_cli_sessions'] <= 72, 'provider count exceeds frozen total')
    require(manifest['measurement']['charged_cells_wall_ns'] == sum(a['wall_ns'] for a in by_arm.values())
        and manifest['measurement']['outer_wall_ns_to_manifest'] >= manifest['measurement']['charged_cells_wall_ns']
        and manifest['measurement']['nested_durations_added_again'] is False, 'outer/nested cost accounting differs')
    assessed = assess_macro_comparison(wire(comparison))
    return {'schema':SCHEMA,'original_byte_integrity':True,'planned_cells':24,'counters':counters,
        'arm_quality_and_wall':by_arm,'original_usage_counters':usage,
        'input_plus_output_tokens':usage['input_tokens'] + usage['output_tokens'],
        'source_conservative_charged_tokens':usage['input_tokens'] + usage['output_tokens'] + usage['reasoning_output_tokens'],
        'completed_comparison':assessed['completed_comparison'],
        'ndu_saving_ns':assessed['completed_comparison']['ndu_saving_ns'],
        'raw_ndu_wall_difference_ns':assessed['raw_ndu_wall_difference_ns'],
        'comparison':assessed,'measurement':manifest['measurement'],'objects_verified':len(originals),
        'monetary_cost':None,'provider_http_request_count':None,'p1_acceptance':'HOLD',
        'economic_benefit_established':False,'scope':'source-bound synthetic local domain study; original-byte causal/accounting integrity, not provider authentication, formal MCP first-use or generalized acceleration'}


def run_control(registration_path, output, *, bridge):
    """Two explicitly scripted local cells; no model/CLI provider is invoked."""
    started = time.monotonic_ns()
    source = source_identity()
    registration_path = Path(registration_path)
    task_registration = _json(_read_regular(registration_path))
    row = next(row for row in task_registration['tasks'] if row['purpose'] == 'calibration')
    documents = {}
    for scope in ('public','hidden'):
        raw = _read_regular(registration_path.parent / row[scope]['path'])
        require(sha256(raw).hexdigest() == row[scope]['sha256'], 'control task differs')
        documents[scope] = _json(raw)
    public, hidden = documents['public'],documents['hidden']
    _, bridge_identity = _bridge_identity(bridge)
    evidence = Evidence(output)
    task_sha = evidence.put({'public':public,'oracle':hidden['cases'],
        'fixture_teacher_sha256':hidden['feasibility_core_sha256']})
    qualification = evidence.put({'kind':'authored_no_model_control','real_agent':False})
    item = {'input_sha256':task_sha,'qualification_receipt_sha256':qualification}
    objective = {'schema':'hepta.hia.agent.objective.v1','metric':'artifact_bytes',
        'required_claims':['core_admission','behavior_equivalence','encoding_check'],
        'allow_unchanged':False,'min_improvement_ratio':0.0}
    cell_registration = {'budget':{'wall_ns':180_000_000_000,'model_tokens':32768},
        'installation':installation_manifest(),'tool_objective':objective,
        'objective_sha256':evidence.put(objective)}

    class AuthoredFixture:
        blocked_reason = None
        def __init__(self):
            self.calls = 0
        def invoke(self, request, evidence, output, **budgets):
            self.calls += 1
            # A real checker rejection, then two authored feasibility proposals.
            # This is never represented as a model response or real usage.
            assembly = (public['baseline_assembly'].replace('block entry(value:u8)',
                'block entry(other:u8)') if self.calls == 1 else hidden['feasibility_assembly'])
            return {'status':'completed','charged_model_tokens':0,'answer':{'assembly':assembly},
                'driver_kind':'authored_no_model_control','model_invocations':0,'provider_usage':None,
                'original_budget':budgets,'request_sha256':evidence.put(request)}

    results = {}
    with tempfile.TemporaryDirectory(prefix='controls-',dir=evidence.root) as state:
        for arm in ('ordinary','ndu'):
            fixture = AuthoredFixture()
            observed, summary = run_cell(evidence,public,hidden,item,arm,cell_registration,
                provider=fixture,bridge=bridge,state_parent=Path(state),calibration=[])
            detail = _json((evidence.root / 'objects' / observed['result_receipt_sha256']).read_bytes())
            results[arm] = {'row':observed,'summary':summary,'fixture_proposal_calls':fixture.calls,
                'first_round_rejected':bool(detail['rounds'] and detail['rounds'][0]['feedback']['status'] == 'rejected'),
                'selected_artifact':next((p for p in detail['pool'] if p['id'] == detail['selected_id']),None),
                'baseline_bytes':detail['baseline_bytes'],'failure':detail['failure']}
    require(source == source_identity(), 'source changed during control')
    passed = all(item['row']['correct'] and item['fixture_proposal_calls'] == 3
                 and item['first_round_rejected'] for item in results.values())
    receipt = {'schema':SCHEMA,'kind':'authored_no_model_native_control','passed':passed,
        'model_calls':0,'provider_cli_sessions':0,'formal_mcp_calls':0,'source_identity':source,
        'registration_sha256':sha256(_read_regular(registration_path)).hexdigest(),
        'bridge_identity':bridge_identity,'results':results,'wall_ns':time.monotonic_ns()-started,
        'objects':sorted(evidence.inventory.values(),key=lambda x:x['sha256']),
        'hidden_teacher_used_only_by_explicit_control':True,'learner_success':False,
        'p1_acceptance':'HOLD','economic_benefit_established':False}
    evidence.named('CONTROL.json',receipt)
    return receipt


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command',required=True)
    prep = sub.add_parser('prepare')
    prep.add_argument('--registration',required=True)
    prep.add_argument('--output',required=True)
    prep.add_argument('--codex',required=True)
    prep.add_argument('--model',required=True)
    prep.add_argument('--native-binary',required=True)
    prep.add_argument('--native-build-receipt',required=True)
    prep.add_argument('--registered-warnings')
    prep.add_argument('--feasibility',required=True)
    prep.add_argument('--launcher-binding',required=True)
    execute = sub.add_parser('run')
    execute.add_argument('--plan',required=True)
    execute.add_argument('--output',required=True)
    check = sub.add_parser('verify')
    check.add_argument('--bundle',required=True)
    control = sub.add_parser('control')
    control.add_argument('--registration',required=True)
    control.add_argument('--output',required=True)
    control.add_argument('--native-binary',required=True)
    control.add_argument('--native-build-receipt',required=True)
    args = parser.parse_args(argv)
    if args.command == 'prepare':
        result = prepare(args.registration,args.output,binary=args.codex,model=args.model,
            bridge={'binary':args.native_binary,'build_receipt':args.native_build_receipt},
            feasibility_path=args.feasibility,
            launcher_binding_path=args.launcher_binding,
            warnings=_json(_read_regular(args.registered_warnings)) if args.registered_warnings else [])
        print(json.dumps({'schema':result['schema'],'status':'PREPARED_ONLY','model_calls':0,
                          'max_cli_sessions':result['max_provider_sessions']}))
    elif args.command == 'control':
        result = run_control(args.registration,args.output,
            bridge={'binary':args.native_binary,'build_receipt':args.native_build_receipt})
        print(json.dumps({'schema':result['schema'],'passed':result['passed'],
            'model_calls':0,'p1_acceptance':'HOLD'}))
        return 0 if result['passed'] else 2
    else:
        result = run(args.plan,args.output) if args.command == 'run' else verify(args.bundle)
        print(json.dumps({key:result[key] for key in ('schema','planned_cells','counters',
            'completed_comparison','ndu_saving_ns','p1_acceptance','economic_benefit_established')},indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

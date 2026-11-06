"""Read-only independent audit of the frozen v1 evidence; no controller runs."""
from collections import Counter, defaultdict
from functools import lru_cache
from fractions import Fraction
from hashlib import sha256
from pathlib import Path
import json
import math
import random
import statistics
import subprocess
import time

BASE = Path('/workspace/scratch/3f3fcd2808a5')
DATA = BASE/'feedback-final-v1'
REPO = BASE/'hepta-ndu-work'
OUT = BASE/'independent-feedback-review.json'
Q = 1 << 32
LIMIT = 1000000*Q
UPSTREAM = '8e52e1187f47f6d4edc8d942fc7cb7eca4bc447d'
EXPECTED_COMMIT = 'b1746d3e436f001ea5c69d154d766fadf7231136'
EXPECTED_TREE = '92f3241ee7b5452d49947129a3a462765ada034e'
checks = Counter()
failed_checks = Counter()
failures = []
counts = Counter()
started = time.perf_counter_ns()

def check(name, ok, context=None):
    checks[name] += 1
    if not ok:
        failed_checks[name] += 1
        if len(failures) < 100:
            failures.append({'check': name, 'context': context})

def load(path):
    return json.loads(Path(path).read_text())

def wire(x):
    return json.dumps(x,sort_keys=True,separators=(',',':'),allow_nan=False).encode()

def digest(x):
    return sha256(wire(x)).hexdigest()

def rawhash(x):
    return sha256(x).hexdigest()

def signed(n):
    return n.to_bytes(8,'big',signed=True)

def unsigned(n,width=8):
    return n.to_bytes(width,'big')

def rounded(n,d=1):
    if isinstance(n,Fraction):
        n,d=n.numerator,n.denominator
    mag,rem=divmod(abs(n),d)
    mag += rem*2>d or rem*2==d and mag%2==1
    return -mag if n<0 else mag

def mul(a,b):
    return rounded(a*b,Q)

def file_identity(path):
    p=Path(path).resolve()
    b=p.read_bytes()
    return {'path':str(p),'bytes':len(b),'sha256':rawhash(b)}

registration=load(DATA/'REGISTRATION.json')
p=registration['protocol']
report=load(DATA/'RESULT.json')
planned=load(DATA/'PLANNED.json')
scenarios=load(DATA/'SCENARIOS.json')
outer=load(BASE/'feedback-final-v1.receipt.json')
check('registration_copy_exact',registration==load(BASE/'feedback-registration-v1.json'))
check('source_commit_tree',registration['source']['commit']==EXPECTED_COMMIT and registration['source']['tree']==EXPECTED_TREE)
check('protocol_frozen_object',p==load(REPO/'benchmarks/hia_ndu_feedback/PROTOCOL.json'))
check('protocol_frozen_hash',rawhash((REPO/'benchmarks/hia_ndu_feedback/PROTOCOL.json').read_bytes())==registration['protocol_sha256'])
check('registered_scenarios',scenarios['model']==registration['scenarios'])
source_names=list(registration['source']['files'])
batch_input=''.join(EXPECTED_COMMIT+':'+name+'\n' for name in source_names).encode()
source_blobs=subprocess.check_output(['git','--no-replace-objects','cat-file','--batch'],cwd=REPO,input=batch_input)
offset=0;worktree_differences=[]
for name in source_names:
    newline=source_blobs.index(b'\n',offset)
    header=source_blobs[offset:newline].decode().split();length=int(header[2])
    blob=source_blobs[newline+1:newline+1+length];offset=newline+1+length+1
    value=registration['source']['files'][name]
    check('frozen_commit_source_file_hash',header[1]=='blob' and rawhash(blob)==value,name)
    current=rawhash((REPO/name).read_bytes()) if (REPO/name).is_file() else None
    if current!=value:
        worktree_differences.append({'path':name,'frozen_sha256':value,'current_sha256':current})
check('frozen_commit_tree',subprocess.check_output(['git','--no-replace-objects','rev-parse',EXPECTED_COMMIT+'^{tree}'],cwd=REPO,text=True).strip()==EXPECTED_TREE)
for name,info in registration['inputs'].items():
    check('input_file_identity',file_identity(info['path'])==info,name)
for kind,receipt in registration['build_receipts'].items():
    check('build_receipt_identity',receipt==load(registration['inputs'][kind+'_manifest']['path']),kind)
    check('build_binary_binding',receipt['binary_sha256']==registration['inputs'][kind+'_binary']['sha256'],kind)
    check('original_source_build_claims',receipt.get('upstream',{}).get('commit')==UPSTREAM
          and receipt.get('original_rust_sources_unchanged') is True
          and receipt.get('all_original_non_manifest_inputs_unchanged') is True,kind)
    adapter=REPO/('rust/hia-ndu-value' if kind=='value' else 'rust/hia-ndu-dynamic-model')
    actual={str(f.relative_to(adapter)):rawhash(f.read_bytes()) for f in adapter.rglob('*') if f.is_file()}
    check('adapter_source_inventory',actual==receipt['adapter_files'],kind)
ledger=registration['build_attempt_ledger']
check('build_ledger_identity',file_identity(ledger['identity']['path'])==ledger['identity'])
check('build_ledger_content',load(ledger['identity']['path'])==ledger['content'])
seen=set(); build_total=0; failed_build_total=0
for item in ledger['content']['attempts']:
    info=item['receipt']; cost=load(info['path'])['build_cost']
    check('build_attempt_identity',file_identity(info['path'])==info,info['path'])
    check('build_attempt_cost_bound',cost==item['build_cost'] and type(cost['wall_ns']) is int and cost['wall_ns']>=0,info['path'])
    check('build_attempt_unique',info['sha256'] not in seen,info['path']);seen.add(info['sha256'])
    build_total+=cost['wall_ns'];failed_build_total+=cost['wall_ns']*int(not cost['completed'])
check('admitted_value_build_in_ledger',registration['inputs']['value_manifest']['sha256'] in seen)
check('build_attempt_total',report['offline_costs']['value_all_build_attempts_wall_ns']==build_total)

arms=p['arms']+[p['additional_diagnostic_arm']]
expected={(native,env,n,seed,rep,arm) for native in (False,True) for env in p['environments']
          for n in (p['native_dimensions'] if native else [0]) for seed in p['holdout_seeds']
          for rep in range(p['native_repetitions'] if native else 1) for arm in arms}
def cell_tuple(row,planned_row=False):
    if planned_row:
        return tuple(row[k] for k in ('native','environment','n','seed','repeat','arm'))
    return tuple(row[k] for k in ('native_workload','scenario','dimension','seed','repetition','arm'))
check('planned_inventory',len(planned)==len(expected) and set(map(lambda x:cell_tuple(x,True),planned))==expected)
episodes=[];audits=[]
for index,cell in enumerate(planned):
    directory=DATA/'episodes'/f'{index:04d}'
    result=load(directory/'RESULT.json');audit=load(directory/'ORACLE_AUDIT.json')
    check('episode_cell_binding',result['cell_index']==index and cell_tuple(result)==cell_tuple(cell,True),index)
    check('episode_delivery',result['status']=='completed' and result['delivered']==result['planned_requests']==p['horizon']
          and result['missing_requests']==0 and len(result['steps'])==p['horizon'] and not result['errors'],index)
    check('audit_episode_binding',audit['cell_index']==index and audit['arm']==result['arm'] and audit['scenario']==result['scenario']
          and len(audit['rows'])==len(result['steps']) and audit['online_controller_access'] is False,index)
    check('episode_authority',result['authority']=='DENY_ALL' and result['production_activation'] is False,index)
    episodes.append(result);audits.append(audit)
observed=list(map(cell_tuple,episodes))
check('complete_unique_result_inventory',len(observed)==len(expected) and len(set(observed))==len(observed) and set(observed)==expected)
check('result_denominator',report['planned_episode_count']==report['retained_episode_count']==len(expected))

scenario_map={(False,name,0):s for name,s in scenarios['model'].items()}
scenario_map.update({(True,item['environment'],item['n']):item['scenario'] for item in scenarios['native']})
def sc_for(e):return scenario_map[e['native_workload'],e['scenario'],e['dimension']]
def state_price(sc,obs):
    slack=min(obs['budget'],obs['deadline']); rem=sc['horizon']-obs['step']
    scarcity=max(Fraction(0),1-Fraction(slack,max(sc['cost_unit'],rem*sc['direct_cost']))) if sc['dynamic_preferences'] else Fraction(0)
    return {'price_q32':rounded((1+scarcity)*Q),'discount_q32':sc['discount_q32'],
            'risk_q32':min(Q,sc['risk_aversion_q32']+rounded(scarcity*Q/4)),
            'scarcity_num':scarcity.numerator,'scarcity_den':scarcity.denominator}

def make_reference(sc):
    @lru_cache(None)
    def solver(t,req,ready,budget,deadline,bnum,bden):
        slack=min(budget,deadline); remaining=sc['horizon']-t
        scarcity=max(Fraction(0),1-Fraction(slack,max(sc['cost_unit'],remaining*sc['direct_cost']))) if sc['dynamic_preferences'] else Fraction(0)
        price=rounded((1+scarcity)*Q); risk=min(Q,sc['risk_aversion_q32']+rounded(scarcity*Q/4))
        output={};eligible={}
        for resident,label in ((-1,'direct'),(0,'cache-0'),(1,'cache-1')):
            cost=(sc['hot_cost'] if resident==req else sc['direct_cost'])+sc['load_cost']*int(resident>=0 and resident!=ready)+sc['retire_cost']*int(ready>=0 and resident!=ready)+sc['holding_cost']*int(resident>=0)
            eligible[label]=cost<=slack
            children=[]
            if eligible[label] and remaining>1:
                for current in (0,1):
                    for signal in (0,1):
                        joint=[]
                        for latent in (0,1):
                            weight=Fraction(bnum,bden) if latent==0 else 1-Fraction(bnum,bden)
                            reqp=Fraction(sc[f'request_p0_z{latent}_num'],sc[f'request_p0_z{latent}_den'])
                            sigp=Fraction(sc['signal_correct_num'],sc['signal_correct_den'])
                            if latent: sigp=1-sigp
                            joint.append(weight*(reqp if current==0 else 1-reqp)*(sigp if signal==0 else 1-sigp))
                        probability=sum(joint)
                        if probability:
                            belief=joint[0]/probability
                            best=solver(t+1,current,resident,budget-cost,deadline-cost,belief.numerator,belief.denominator)[0]
                            children.append((probability,best))
            mean=sum((probability*v for probability,v in children),Fraction())
            downside=sum((probability*max(Fraction(),mean-v) for probability,v in children),Fraction())
            continuation=rounded(mean-Fraction(risk,Q)*downside)
            immediate=sc['completion_reward_q32']-mul(price,rounded(cost*Q,sc['cost_unit']))
            output[label]=immediate+mul(sc['discount_q32'],continuation)
        output['abstain']=-sc['miss_penalty_q32']*remaining;eligible['abstain']=True
        best=max(v for k,v in output.items() if eligible[k])
        return best,output,eligible,tuple(sorted(k for k,v in output.items() if eligible[k] and v==best))
    return solver

references={k:make_reference(v) for k,v in scenario_map.items()}
histories=defaultdict(set)
preferences_seen=defaultdict(set)
action_sequences=defaultdict(dict)
gate_rows=[]
same_objective_verified=0
ablation_numeric=0;ablation_actions=0;ablation_count=0
oracle_regrets=defaultdict(list)
for e,audit in zip(episodes,audits):
    idx=e['cell_index'];sc=sc_for(e);obs_prev=None;outcome_prev=None
    key=(e['native_workload'],e['scenario'],e['dimension'])
    solver=references[key];past_belief=Fraction(sc['prior0_num'],sc['prior0_den'])
    realized=0
    for step_number,(row,arow) in enumerate(zip(e['steps'],audit['rows'])):
        decision=row['decision'];obs=decision['observation'];outcome=row['outcome']
        prefix=(idx,step_number)
        check('decision_observation_shape',set(obs)=={'step','request','signal','resident','budget','deadline','belief_num','belief_den'} and obs['step']==step_number,prefix)
        check('decision_state_digest',decision['state_digest']==digest(obs)==arow['state_digest'],prefix)
        check('selected_executed_binding',decision['action']==outcome['action']==outcome['executed_action']==outcome['resident_after']
              and outcome['delivered'] and outcome['status']=='delivered' and outcome['observation']==obs,prefix)
        prior_terms=[]
        for z in (0,1):
            weight=past_belief if z==0 else 1-past_belief
            reqp=Fraction(sc[f'request_p0_z{z}_num'],sc[f'request_p0_z{z}_den'])
            sigp=Fraction(sc['signal_correct_num'],sc['signal_correct_den'])
            if z: sigp=1-sigp
            prior_terms.append(weight*(reqp if obs['request']==0 else 1-reqp)*(sigp if obs['signal']==0 else 1-sigp))
        past_belief=prior_terms[0]/sum(prior_terms)
        check('causal_bayes_update',past_belief==Fraction(obs['belief_num'],obs['belief_den']),prefix)
        if step_number==0:
            check('initial_observation_binding',obs['budget']==sc['initial_budget'] and obs['deadline']==sc['initial_deadline'] and obs['resident']==sc['initial_resident'],prefix)
        else:
            check('real_feedback_state_update',obs['budget']==outcome_prev['remaining_budget'] and obs['deadline']==outcome_prev['remaining_deadline'] and obs['resident']==outcome_prev['resident_after'],prefix)
        check('actual_cost_budget_update',outcome['remaining_budget']==max(0,obs['budget']-outcome['cost']) and outcome['remaining_deadline']==max(0,obs['deadline']-outcome['cost']),prefix)
        pref=state_price(sc,obs)
        check('external_numeric_preference',outcome['preference']==pref,prefix)
        check('external_actual_cost_reward',outcome['reward_q32']==sc['completion_reward_q32']-mul(pref['price_q32'],rounded(outcome['cost']*Q,sc['cost_unit'])) and outcome['discount_q32']==pref['discount_q32'],prefix)
        preferences_seen[(e['native_workload'],e['scenario'],e['arm'])].add(tuple(decision['preference'][k] for k in ('price_q32','discount_q32','risk_q32')))
        best,vals,eligible,winners=solver(obs['step'],obs['request'],obs['resident'],obs['budget'],obs['deadline'],obs['belief_num'],obs['belief_den'])
        selected=decision['selected_action']
        check('all_postexecution_oracle_values',arow['oracle_value_q32']==best and arow['oracle_action']==winners[0],prefix)
        regret=best-vals[selected]
        check('all_postexecution_regrets',arow['selected_conditional_regret_q32']==regret,prefix)
        oracle_regrets[(e['native_workload'],e['scenario'],e['arm'])].append(regret)
        if e['arm'] in ('same-objective','dynamic-ndu','dynamic-ndu-gated','exact-oracle'):
            same_objective_verified+=1
            check('same_objective_independent_recompute',eligible[selected] and selected in winners and decision['value_q32']==best and arow['same_objective_agrees'] is True,prefix)
        ablation=arow.get('fixed_preference_ablation')
        if ablation is not None:
            ablation_count+=1
            initial_scarcity=max(Fraction(0),1-Fraction(min(sc['initial_budget'],sc['initial_deadline']),max(sc['cost_unit'],sc['horizon']*sc['direct_cost']))) if sc['dynamic_preferences'] else Fraction()
            fixed_pref={'price_q32':rounded((1+initial_scarcity)*Q),'discount_q32':sc['discount_q32'],'risk_q32':min(Q,sc['risk_aversion_q32']+rounded(initial_scarcity*Q/4)),'scarcity_num':initial_scarcity.numerator,'scarcity_den':initial_scarcity.denominator}
            differs=fixed_pref!=decision['preference']
            check('numeric_preference_ablation_flag',ablation['numeric_preferences_change']==differs,prefix)
            check('numeric_preference_ablation_action_flag',ablation['action_changes']==(ablation['action']!=selected),prefix)
            check('numeric_preference_ablation_external_value',ablation['fixed_selected_external_value_q32']==vals[ablation['action']],prefix)
            ablation_numeric+=int(differs);ablation_actions+=int(ablation['action_changes'])
        gate=decision.get('compute_gate')
        if gate:
            check('compute_gate_upper_bound',gate['optimal_value_upper_q32']>=best and gate['incumbent_policy_value_q32']<=best,prefix)
            if not gate['invoke']:
                check('compute_gate_zero_gap',gate['gross_gain_upper_q32']==0 and decision['value_q32']==best and not decision['native_backend_used'] and decision['search']['backend_calls']==0,prefix)
            gate_rows.append({'native':e['native_workload'],'environment':e['scenario'],'step':step_number,'invoke':gate['invoke'],'reason':gate['reason'],'gate_wall_ns':gate['total_gate_wall_ns'],'gate_transitions':gate['search_transitions']})
        check('decision_transition_budget',0<=decision['search']['transitions']<=p['max_transitions_per_decision'],prefix)
        outcome_prev=outcome
    for row in reversed(e['steps']):
        out=row['outcome'];realized=out['reward_q32']+mul(out['discount_q32'],realized)
    check('realized_utility_recompute',realized==e['realized_discounted_utility_q32'],idx)
    check('actual_cost_aggregation',e['actual_cost']==sum(s['outcome']['cost'] for s in e['steps']),idx)
    check('search_work_aggregation',e['search_transitions']==sum(s['decision']['search']['transitions'] for s in e['steps']),idx)
    check('backend_work_aggregation',e['backend_calls']==sum(s['decision']['search']['backend_calls'] for s in e['steps']),idx)
    check('outer_time_contains_online',e['episode_wall_ns']>=e['online_wall_ns']>=0,idx)
    if e['native_workload']:
        check('native_online_cost_partition',e['online_wall_ns']==e['actual_cost']+e['online_cost_outside_outcome_records_ns'],idx)
    histories[(e['scenario'],e['seed'])].add(tuple((r['decision']['observation']['request'],r['decision']['observation']['signal']) for r in e['steps']))
    action_sequences[(e['native_workload'],e['scenario'],e['seed'],e['repetition'])][e['arm']]=tuple(r['decision']['action'] for r in e['steps'])
for k,v in histories.items(): check('common_random_history_all_arms',len(v)==1,k)

def recursive_digest(req,raw_request,index,c,value):
    request=sha256(raw_request).digest()
    context=[bytes.fromhex(req['objective_digest']),sha256(bytes.fromhex(req['state_digest'])+c['id'].encode()).digest(),
             sha256(b'hia.value.backup.original.scalar.v1').digest(),
             sha256(b'hia.value.scalar.q32.v1;instant-and-continuation-same-units;no-normalization').digest(),request]
    stream=b'hepta.ndu.recursive-utility.scalar.q32.v1'+b''.join(context)
    stream+=signed(c['terminal_q32'])+signed(-LIMIT)+signed(LIMIT)+unsigned(1)+unsigned(1)
    stream+=sha256(request+unsigned(index)).digest()+bytes.fromhex(req['preference_digest'])
    stream+=signed(c['instant_q32'])+signed(c['discount_q32'])+signed(value)+signed(c['terminal_q32'])+unsigned(0,4)
    return rawhash(stream)

value_log_frames={};workload_log_frames={}
for log in sorted(DATA.rglob('*.jsonl')):
    lines=[json.loads(line) for line in log.read_text().splitlines()]
    label=str(log.relative_to(DATA));check('raw_session_event_boundaries',lines[0]['event']=='hello' and lines[-1]['event']=='close',label)
    hello=lines[0];close=lines[-1];exchanges=[r for r in lines if r['event']=='exchange'];validation=[r for r in lines if r['event']=='validated']
    counts['all_raw_sessions']+=1;counts['raw_exchange_frames']+=len(exchanges)
    check('raw_session_clean_close',close['returncode']==0 and close['reaped'] is True and not close['stderr'] and close['stderr_over_bound'] is False,label)
    check('raw_session_no_failure_events',all(r['event'] in {'hello','exchange','validated','close'} for r in lines),label)
    check('raw_session_call_count',close['calls']==len(exchanges),label)
    is_value='raw_response' in hello
    kind='value' if is_value else 'workload'
    counts[kind+'_sessions']+=1;counts[kind+'_exchange_frames']+=len(exchanges)
    check('raw_session_binary_binding',hello['binary_sha256']==registration['inputs'][kind+'_binary']['sha256'],label)
    if is_value:
        check('value_hello_hash',rawhash(hello['raw_response'].encode())==hello['response_sha256'],label)
        check('value_hello_manifest_binding',hello['manifest_sha256']==registration['inputs']['value_manifest']['sha256'],label)
        check('value_hello_upstream',json.loads(hello['raw_response'])['identity']['upstream_commit']==UPSTREAM,label)
        check('value_no_missing_validation',len(validation)==len(exchanges),label)
        check('value_validated_time_sum',sum(v['outer_call_ns'] for v in validation)==close['total_call_ns'],label)
        bound=[]
    else:
        check('workload_hello_upstream',hello['response']['upstream_commit']==UPSTREAM and hello['response']['role']=='--workload-stream',label)
        n=None;quota=None;seed_map={};epochs=[];ready=set();allocations=retirements=executions=reuses=0;bound=[]
    for index,exchange in enumerate(exchanges,1):
        request_text=exchange['request'].encode();response_text=exchange['response'].encode()
        req=json.loads(request_text);res=json.loads(response_text);ctx=(label,index)
        check('raw_frame_hashes',rawhash(request_text)==exchange['request_sha256'] and rawhash(response_text)==exchange['response_sha256'],ctx)
        check('raw_exchange_sequence',exchange.get('sequence',exchange.get('index'))==index,ctx)
        check('raw_wire_nonnegative_integer',type(exchange['wire_roundtrip_ns']) is int and exchange['wire_roundtrip_ns']>=0,ctx)
        if is_value:
            check('value_request_response_binding',req['sequence']==index and all(res[k]==req[k] for k in ('sequence','generation','state_digest','preference_digest','objective_digest')) and res['request_sha256']==exchange['request_sha256'],ctx)
            check('value_request_closed_fields',set(req)=={'schema','sequence','generation','state_digest','preference_digest','objective_digest','resource_budget_q32','risk_ceiling_q32','candidates'},ctx)
            check('value_original_native_authority',res['upstream_commit']==UPSTREAM and res['projection_count']==0 and res['authority']=='DENY_ALL' and not res['execution_authorized'] and not res['safety_certificate'] and res['entry_points']==['codex_hepta_ndu::evaluate_recursive_utility','codex_hepta_ndu::evaluate_candidates_with_policy'],ctx)
            values={};eligible={}
            for ci,c in enumerate(req['candidates']):
                val=c['instant_q32']+mul(c['discount_q32'],c['terminal_q32'])
                values[c['id']]=val;eligible[c['id']]=c['feasible'] and c['resource_q32']<=req['resource_budget_q32'] and c['risk_q32']<=req['risk_ceiling_q32']
                check('original_recursive_digest_recomputed',res['path_receipts'][ci]=={'id':c['id'],'recursive_evidence_digest':recursive_digest(req,request_text,ci,c,val)},(label,index,c['id']))
                counts['value_candidates_recomputed']+=1
            best=max(v for k,v in values.items() if eligible[k]);winners=sorted(k for k,v in values.items() if eligible[k] and v==best)
            check('native_all_numeric_values_recomputed',res['values_q32']==values,ctx)
            check('native_all_eligibility_winners_recomputed',res['eligible']==eligible and res['winners']==winners and res['chosen_id']==winners[0]
                  and sorted(r['id'] for r in res['rejected'])==sorted(k for k,v in eligible.items() if not v),ctx)
            v=validation[index-1]
            check('native_validated_frame_binding',v['sequence']==index and v['values_q32']==values and v['winners']==winners and v['outer_call_ns']>=exchange['wire_roundtrip_ns'],ctx)
            bound.append((req,res,exchange))
        else:
            check('workload_response_schema',res['schema']=='hepta.hia.ndu.dynamic-cache.workload.response.v1' and res['native_rust_experiment'] is True and res['hia_compiler_qualification'] is False,ctx)
            body=res['result'];state=res['state'];command=req['command']
            if command=='init':
                n=req['n'];quota=req['quota_bytes'];epochs=[1]*req['count'];seed_map={i:(req['seed']+101*i)&0xffffffff for i in range(req['count'])}
                check('workload_init_one_slot',req['count']==2 and quota==n*n*4,ctx)
            elif command=='prepare':
                check('physical_prepare_receipt',req['epoch']==epochs[req['id']] and body['prepared']==req['id'] and body['reused']==(req['id'] in ready),ctx)
                if req['id'] in ready:reuses+=1
                else:ready.add(req['id']);allocations+=1
            elif command=='retire':
                check('physical_retire_receipt',body['retired']==req['id'] and body['existed']==(req['id'] in ready),ctx)
                if req['id'] in ready:ready.remove(req['id']);retirements+=1
            elif command=='run':
                executions+=1
                check('physical_execution_receipt',body['matrix']==req['id'] and body['epoch']==epochs[req['id']] and body['dispatch']==req['dispatch'] and body['repeats']==req['repeats'] and body['all_outputs_checked']==n,ctx)
                check('packed_cache_legal',req['dispatch']=='direct' or req['id'] in ready,ctx)
                vector=[((req['vector_seed']+13*i)&0xffffffff)%65521 for i in range(n)]
                sumv=sum(vector)&0xffffffff;sumiv=sum((i+1)*v for i,v in enumerate(vector))&0xffffffff
                base=(seed_map[req['id']]*sumv+17*sumiv)&0xffffffff
                checksum=0xcbf29ce484222325
                for j in range(n):
                    answer=(base+31*(j+1)*sumv)&0xffffffff
                    checksum=((checksum^answer)*0x100000001b3)&0xffffffffffffffff
                check('physical_output_checksum_independent',body['checksum']==checksum,ctx)
                check('kernel_oracle_service_nested',0<=body['kernel_ns']+body['oracle_ns']<=res['service_ns']<=exchange['wire_roundtrip_ns'],ctx)
                counts['physical_run_outputs']+=1;counts['physical_output_elements_recomputed']+=n
            elif command=='close':
                retirements+=len(ready);ready.clear()
                check('physical_close_flag',body['closed'] is True and state['closed'] is True,ctx)
            else:check('registered_physical_commands',False,ctx)
            check('physical_state_replay',state['n']==n and state['quota_bytes']==quota and state['resident_bytes']==len(ready)*n*n*4<=quota
                  and state['ready']==sorted(ready) and state['epochs']==epochs and state['allocations']==allocations and state['retirements']==retirements
                  and state['executions']==executions and state['reuses']==reuses and state['baseline_bytes']==(0 if command=='close' else len(epochs)*n*n*4),ctx)
            bound.append((req,res,exchange))
    if is_value:value_log_frames[log]=bound
    else:
        check('physical_full_cleanup',not ready and allocations==retirements and bound[-1][0]['command']=='close',label)
        workload_log_frames[log]=bound

for e in episodes:
    idx=e['cell_index'];directory=DATA/'episodes'/f'{idx:04d}';sc=sc_for(e)
    if e['native_workload']:
        frames=workload_log_frames[directory/'workload.jsonl']
        init=frames[0][0]
        check('native_episode_input_identity',init['seed']==e['seed'] and init['n']==e['dimension'],idx)
        attempts=e['workload_attempts'];check('native_attempt_count',len(attempts)==len(e['steps']),idx)
        frame_pos=1+int(sc['initial_resident']>=0)
        for sn,(step,attempt) in enumerate(zip(e['steps'],attempts)):
            prefix=(idx,sn)
            check('native_step_attempt_exact',step['native_execution']==attempt and attempt['status']=='success' and attempt['pending_command'] is None,prefix)
            check('native_attempt_state_digest',attempt['before_digest']==digest({'generation':sn,'state':attempt['before']}) and attempt['after_digest']==digest({'generation':sn+1,'state':attempt['after']}),prefix)
            check('native_attempt_selected_executed',attempt['generation']==sn+1 and attempt['selected_resident']==attempt['executed_resident']==step['decision']['action'] and attempt['target']==step['decision']['observation']['request'],prefix)
            before_raw=frames[frame_pos-1][1]['state'];check('native_before_state_bound',attempt['before']==before_raw,prefix)
            for command in attempt['commands']:
                req,res,raw=frames[frame_pos]
                check('native_command_to_raw_binding',command['command']==req and command['result']==res and command['wire_ns']==raw['wire_roundtrip_ns'],(idx,sn,frame_pos))
                frame_pos+=1
            last=frames[frame_pos-1]
            check('native_output_to_delivery_binding',last[0]['command']=='run' and attempt['checksum']==last[1]['result']['checksum'] and attempt['after']==last[1]['state']
                  and last[0]['vector_seed']==(e['seed']*131+sn*17)&0xffffffff and last[0]['repeats']==p['native_kernel_repeats'],prefix)
            check('native_attempt_service_sum',attempt['native_service_ns']==sum(c['result']['service_ns'] for c in attempt['commands']) and attempt['workload_wall_ns']>=sum(c['wire_ns'] for c in attempt['commands']),prefix)
            check('decision_and_workload_inside_actual_cost',step['observed_decision_wall_ns']+attempt['workload_wall_ns']<=step['outcome']['cost'],prefix)
        check('native_all_commands_consumed',frame_pos==len(frames)-1 and frames[-1][0]['command']=='close',idx)
        check('native_close_state_binding',e['workload_close']['final_state']==frames[-1][1]['state'] and e['workload_close']['returncode']==0 and e['workload_close']['error'] is None,idx)
        check('native_workload_wall_all_attempts',e['workload_wall_ns']==sum(r['workload_wall_ns'] for r in attempts),idx)
    else:check('model_has_no_physical_work',not (directory/'workload.jsonl').exists() and e['workload_wall_ns']==0,idx)
    frames=value_log_frames.get(directory/'values.jsonl',[]);pos=0
    for sn,step in enumerate(e['steps']):
        d=step['decision']
        if not d.get('native_backend_used'):
            check('non_native_decision_no_backend_calls',d['search']['backend_calls']==0,(idx,sn));continue
        trace=d['search_trace']
        check('native_trace_count',len(trace)==d['search']['backend_calls'],(idx,sn))
        for node in trace:
            req,res,raw=frames[pos];pos+=1
            check('native_values_drive_search_trace',req['state_digest']==node['state_digest'] and req['preference_digest']==digest(node['preference'])
                  and req['objective_digest']==digest({'rule':'state-price-plus-discounted-mean-downside-v1','scenario':sc})
                  and res['values_q32']==node['values_q32'] and res['chosen_id']==node['selected']
                  and [c['id'] for c in req['candidates']]==node['candidate_ids'],(idx,sn,pos))
        root_req,root_res,_=frames[pos-1]
        obs=d['observation']
        check('native_root_consumed_numeric_budget',root_req['resource_budget_q32']==rounded(min(obs['budget'],obs['deadline'])*Q,sc['cost_unit'])
              and root_req['candidates']==d['candidates'] and root_res['values_q32']==d['candidate_values_q32'] and root_res['chosen_id']==d['selected_action'],(idx,sn))
    check('native_all_search_frames_consumed',pos==len(frames)==e['backend_calls'],idx)

# Rebuild the published tables and paired bootstrap without importing runner.
tables={};pair_summary=[]
for native in (False,True):
    kind='native' if native else 'model';tables[kind]={}
    for env in p['environments']:
        tables[kind][env]={}
        for arm in arms:
            rows=[e for e in episodes if e['native_workload']==native and e['scenario']==env and e['arm']==arm]
            fields={key:sum(e[key] for e in rows) for key in ('planned_requests','delivered','episode_wall_ns','workload_wall_ns','actual_cost','search_transitions','backend_calls')}
            fields['episodes']=len(rows)
            for name,value in fields.items():check('published_table_aggregation',report['tables'][kind][env][arm][name]==value,(kind,env,arm,name))
            fields['realized_path_utility_q32']=sum(e['realized_discounted_utility_q32'] for e in rows)
            check('published_path_utility_aggregation',report['tables'][kind][env][arm]['realized_path_utility_q32']==fields['realized_path_utility_q32'],(kind,env,arm))
            tables[kind][env][arm]=fields
        if native:
            for arm in p['arms']:
                if arm in ('dynamic-ndu','exact-oracle'):continue
                deltas=[]
                for seed in p['holdout_seeds']:
                    a=[e['episode_wall_ns'] for e in episodes if e['native_workload'] and e['scenario']==env and e['seed']==seed and e['arm']=='dynamic-ndu']
                    b=[e['episode_wall_ns'] for e in episodes if e['native_workload'] and e['scenario']==env and e['seed']==seed and e['arm']==arm]
                    deltas.append(statistics.mean(a)-statistics.mean(b))
                rng=random.Random(530771)
                boot=sorted(statistics.mean(rng.choices(deltas,k=len(deltas))) for _ in range(2000))
                published=next(c for c in report['paired_comparisons'] if c['environment']==env and c['dynamic_minus_control']==arm)
                gain=tables['native'][env][arm]['episode_wall_ns']-tables['native'][env]['dynamic-ndu']['episode_wall_ns']
                check('paired_interval_recomputed',published['paired_mean_difference_ns']==statistics.mean(deltas) and published['exploratory_bootstrap_95_ns']==[boot[49],boot[1949]] and published['independent_seed_count']==len(p['holdout_seeds']),(env,arm))
                allocated=0 if arm=='fixed-preference-ndu' else build_total
                check('paired_gain_recomputed',published['observed_online_gain_ns']==gain and published['allocated_additional_build_ns']==allocated and all(published['observed_lifecycle_gain_by_deployments_ns'][str(n)]==gain*n-allocated for n in p['deployment_counts']),(env,arm))
                pair_summary.append({'environment':env,'control':arm,'dynamic_minus_control_mean_ns':statistics.mean(deltas),'bootstrap_95_ns':[boot[49],boot[1949]],'online_gain_dynamic_ns':gain,
                                     'allocated_additional_build_ns':allocated,'positive_lifecycle_deployment_counts':[n for n in p['deployment_counts'] if gain*n-allocated>0]})

check('numeric_ablation_counts',report['numeric_preference_contribution']['offline_observations']==ablation_count and report['numeric_preference_contribution']['numeric_changes']==ablation_numeric and report['numeric_preference_contribution']['action_changes']==ablation_actions)
gates=load(DATA/'GATES.json')
check('wiring_probes',gates['wiring']['all_passed'] and all(r['passed'] for r in gates['wiring']['retention']+gates['wiring']['numeric_preference']))
check('degeneration_probe',gates['degeneration']['all_passed'] and all(r['passed'] for r in gates['degeneration']['rows']))
for row in gates['wiring']['retention']:
    p_b=Fraction(row['next_b_probability']);costs={'cache-1':11-4*p_b,'cache-0':6+4*p_b}
    expected_action=min(costs,key=costs.get)
    check('manual_retention_expected',row['expected_action']==row['native']['selected_action']==row['oracle']['selected_action']==expected_action,row['next_b_probability'])
for row in gates['wiring']['numeric_preference']:
    lam=Fraction(row['lambda']);values={'A':Fraction(4,5)-lam,'B':1-3*lam};expected_action=max(values,key=values.get)
    check('manual_numeric_preference_expected',row['result']['winners']==[expected_action],row['lambda'])

diagnostics=load(DATA/'MODEL_DIAGNOSTICS.json')
diagrows=diagnostics['episodes']
diagexpected={(env,seed,arm) for env in p['environments'] for seed in p['holdout_seeds'] for arm in p['model_diagnostic_arms']}
check('model_diagnostic_inventory',len(diagrows)==len(diagexpected) and {(r['scenario'],r['seed'],r['arm']) for r in diagrows}==diagexpected)
diagstats={}
for env in p['environments']:
    diagstats[env]={}
    for arm in p['model_diagnostic_arms']:
        erows=[r for r in diagrows if r['scenario']==env and r['arm']==arm]
        diagstats[env][arm]={'episodes':len(erows),'delivered':sum(r['delivered'] for r in erows),'planned_requests':sum(r['planned_requests'] for r in erows),
                           'actual_model_cost':sum(r['actual_cost'] for r in erows),'regret_q32':sum(x['selected_conditional_regret_q32'] for r in erows for x in r['post_execution_audit']['rows'])}
check('gradient_claim_absent',diagnostics['U_or_Z_used_as_gradient'] is False and diagnostics['gradient_updates']==0)

control_action_differences=[]
for native in (False,True):
    for env in p['environments']:
        for other in ('fixed','state-greedy','ordinary-mpc','same-objective','fixed-preference-ndu','exact-oracle','dynamic-ndu-gated'):
            pairs=[d for (isnative,family,seed,repeat),d in action_sequences.items() if isnative==native and family==env]
            control_action_differences.append({'native':native,'environment':env,'control':other,'paired_episodes':len(pairs),
                                               'different_episode_action_sequences':sum(d['dynamic-ndu']!=d[other] for d in pairs),
                                               'different_step_actions':sum(a!=b for d in pairs for a,b in zip(d['dynamic-ndu'],d[other]))})

gate_stats={'total_decisions':len(gate_rows),'skips':sum(not g['invoke'] for g in gate_rows),'invocations':sum(g['invoke'] for g in gate_rows),
            'skips_by_step':dict(Counter(g['step'] for g in gate_rows if not g['invoke'])),'skips_by_environment':dict(Counter(g['environment'] for g in gate_rows if not g['invoke'])),
            'total_gate_wall_ns':sum(g['gate_wall_ns'] for g in gate_rows),'total_gate_transitions':sum(g['gate_transitions'] for g in gate_rows)}
known_campaign=sum(e['episode_wall_ns'] for e in episodes)+sum(report['offline_costs'][k] for k in ('calibration_wall_ns','fixed_selection_wall_ns','mechanism_gates_wall_ns','oracle_audit_wall_ns','model_error_diagnostics_wall_ns'))
check('outer_receipt_complete',outer['exit_code']==0 and outer['source']==EXPECTED_COMMIT and outer['outer_wall_ns']>=report['wall_before_report_ns']>=known_campaign)
check('no_advantage_claim',report['checks']['independent_net_gain'] is False and report['no_go_for_advantage_claim'] is True and report['full_lifecycle_cost_known'] is False and report['production_activation'] is False)

raw_manifest={str(f.relative_to(DATA)):{'bytes':f.stat().st_size,'sha256':rawhash(f.read_bytes())} for f in sorted(DATA.rglob('*')) if f.is_file()}
review={
    'schema':'hepta.hia.ndu.feedback-independent-review.v1',
    'reviewer':'independent_gates agent; independent arithmetic, oracle and raw-log readback',
    'source':{'commit':EXPECTED_COMMIT,'tree':EXPECTED_TREE},
    'post_measurement_worktree_differences':worktree_differences,
    'source_audit_scope':'Every registered file is checked against the immutable b1746d3 commit blob. Later working-tree edits are listed separately and do not alter v1 evidence or pass as v1-qualified source.',
    'scope':'Read-only frozen v1 evidence audit; no rerun, native execution, retraining, threshold change or protocol mutation.',
    'evidence_directory':str(DATA),'registration':file_identity(DATA/'REGISTRATION.json'),'campaign_result':file_identity(DATA/'RESULT.json'),'outer_receipt':file_identity(BASE/'feedback-final-v1.receipt.json'),
    'audit_source':file_identity(Path(__file__)),
    'status':'PASS_INTEGRITY_WITH_NO_ADVANTAGE' if not failures else 'FAIL_INTEGRITY',
    'check_counts':dict(checks),'failed_check_counts':dict(failed_checks),'failures':failures,
    'inventory':{'episodes':len(episodes),'model_episodes':sum(not e['native_workload'] for e in episodes),'native_episodes':sum(e['native_workload'] for e in episodes),
                 'planned_requests':sum(e['planned_requests'] for e in episodes),'delivered_requests':sum(e['delivered'] for e in episodes),'same_objective_root_decisions_independently_recomputed':same_objective_verified,
                 'all_root_decisions_independently_recomputed':sum(len(e['steps']) for e in episodes),**counts},
    'numeric_preferences':{'counterfactual_observations':ablation_count,'numeric_changes':ablation_numeric,'action_changes':ablation_actions,
                           'dynamic_observed_preferences':{'native' if native else 'model':{env:sorted(preferences_seen[native,env,'dynamic-ndu']) for env in p['environments']} for native in (False,True)},
                           'conclusion':'Hand-computed price and belief reversals establish numerical wiring. In this registered primary cohort all dynamic numeric preferences remain constant; the causal API and native numeric consumption do not establish exercised preference adaptation or its benefit.'},
    'compute_gate':gate_stats,
    'action_differences':control_action_differences,
    'tables':tables,'paired_comparisons':pair_summary,'model_error_diagnostics':diagstats,
    'costs':{'whole_campaign_outer_wall_ns':outer['outer_wall_ns'],'nested_accounted_campaign_ns':known_campaign,'primary_episode_wall_ns':sum(e['episode_wall_ns'] for e in episodes),
             'recorded_value_build_attempt_count':len(ledger['content']['attempts']),'all_value_build_attempts_wall_ns':build_total,'failed_value_build_attempts_wall_ns':failed_build_total,
             'note':'Outer/online/service/kernel costs are nested. Build receipts exclude imports/final receipt writes as disclosed; unknown historical engineering, human review, monetary fees and energy remain unknown.'},
    'limitations':['A deterministic finite belief model and synthetic affine CPU workloads are not production workload qualification.',
                   'A known sensor reliability of 0.2 is modeled anti-correlation, not unknown distribution drift.',
                   'Whole-episode wall and source/frame binding support observed execution; a digest is not external attestation of hardware execution.',
                   'Python causal observation separation is not a malicious-controller memory sandbox.',
                   'Primary realized path utilities are not unbiased samples of the nested conditional downside objective.',
                   'Four independent holdout seeds and shared-host timings support exploratory intervals only.',
                   'Native value build is conservatively allocated in full versus non-native controls; the frozen comparison correctly cancels it versus fixed-preference NDU.',
                   'No parameter gradient training or U/Z-as-gradient claim is established.'],
    'raw_evidence_manifest':raw_manifest,
    'audit_wall_ns':time.perf_counter_ns()-started,
}
OUT.write_text(json.dumps(review,sort_keys=True,indent=2)+'\n')
print(json.dumps({k:review[k] for k in ('status','failed_check_counts','inventory','numeric_preferences','compute_gate','costs','audit_wall_ns')},indent=2))
if failures:print(json.dumps(failures[:20],indent=2))

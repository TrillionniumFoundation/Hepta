"""Independent read-only compute-price audit; never executes campaign/native workers.

Numerical/source/frame verification is independent of production model/runner
imports. Raw-byte encoder and physical checksum replay are retained from the
previous independently written reviewer, without running or modifying v1.
"""
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

BASE=Path('/workspace/scratch/3f3fcd2808a5')
DATA=BASE/'compute-price-final-v1'
REPO=BASE/'hepta-ndu-work'
OUT=BASE/'independent-compute-price-review.json'
Q=1<<32
LIMIT=1000000*Q
UPSTREAM='8e52e1187f47f6d4edc8d942fc7cb7eca4bc447d'
EXPECTED_COMMIT='78c0b951adc08b02be60d64b386620c5ac9faf99'
EXPECTED_TREE='a96e501429fa0482330c7d5d477f8549a132bd52'
EXPECTED_CALIBRATION='f66e61d8686069881057e15451037c61389f280c61cfe96100e4b71a3252f148'
checks=Counter();failed_checks=Counter();failures=[];counts=Counter()
started=time.perf_counter_ns()

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

def audit_raw_sessions():
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
    return value_log_frames,workload_log_frames

def bind_episode_raw(e):
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
                  and last[0]['vector_seed']==(e['seed']*131+sn*17)&0xffffffff and last[0]['repeats']==p['kernel_repeats'],prefix)
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


def observation_args(obs):
    return tuple(obs[k] for k in ('step','request','resident','budget','deadline','belief_num','belief_den'))


def costs(sc,obs):
    return {label:(sc['hot_cost'] if a==obs['request'] else sc['direct_cost'])
            +sc['load_cost']*int(a>=0 and a!=obs['resident'])
            +sc['retire_cost']*int(obs['resident']>=0 and a!=obs['resident'])
            +sc['holding_cost']*int(a>=0)
            for a,label in ((-1,'direct'),(0,'cache-0'),(1,'cache-1'))}


def root_greedy(sc,obs):
    price=state_price(sc,obs)['price_q32']; physical=costs(sc,obs)
    vals={k:sc['completion_reward_q32']-mul(price,rounded(v*Q,sc['cost_unit'])) for k,v in physical.items()}
    vals['abstain']=-sc['miss_penalty_q32']*(sc['horizon']-obs['step'])
    feasible={k:v<=min(obs['budget'],obs['deadline']) for k,v in physical.items()};feasible['abstain']=True
    best=max(v for k,v in vals.items() if feasible[k])
    return best,vals,feasible,sorted(k for k,v in vals.items() if feasible[k] and v==best)[0]


def make_greedy_policy_reference(sc,fee=0):
    """Independently enumerate the entire greedy policy, including later stops.

    Fee is a constant hypothetical charge in utility at future decisions; as in
    the declared gate model, it does not claim realized physical feasibility.
    """
    @lru_cache(None)
    def solve(t,req,ready,budget,deadline,bnum,bden,charge):
        obs={'step':t,'request':req,'resident':ready,'budget':budget,'deadline':deadline,
             'belief_num':bnum,'belief_den':bden}
        immediate,_,_,chosen=root_greedy(sc,obs);pref=state_price(sc,obs)
        value=immediate-(mul(pref['price_q32'],rounded(fee*Q,sc['cost_unit'])) if charge else 0)
        if chosen=='abstain' or t+1==sc['horizon']:return value
        action={'direct':-1,'cache-0':0,'cache-1':1}[chosen];spent=costs(sc,obs)[chosen]
        children=[]
        for request in (0,1):
            for signal in (0,1):
                weights=[]
                for latent in (0,1):
                    prior=Fraction(bnum,bden) if latent==0 else 1-Fraction(bnum,bden)
                    rp=Fraction(sc[f'request_p0_z{latent}_num'],sc[f'request_p0_z{latent}_den'])
                    sp=Fraction(sc['signal_correct_num'],sc['signal_correct_den'])
                    if latent:sp=1-sp
                    weights.append(prior*(rp if request==0 else 1-rp)*(sp if signal==0 else 1-sp))
                probability=sum(weights)
                if probability:
                    belief=weights[0]/probability
                    children.append((probability,solve(t+1,request,action,budget-spent,deadline-spent,
                                                       belief.numerator,belief.denominator,True)))
        mean=sum(probability*v for probability,v in children)
        downside=sum(probability*max(Fraction(0),mean-v) for probability,v in children)
        return value+mul(sc['discount_q32'],rounded(mean-Fraction(pref['risk_q32'],Q)*downside))
    return solve


def generated_events(sc,seed):
    rng=random.Random(seed)
    hidden=int(rng.random()>=float(Fraction(sc['prior0_num'],sc['prior0_den'])))
    rp=Fraction(sc[f'request_p0_z{hidden}_num'],sc[f'request_p0_z{hidden}_den'])
    sp=Fraction(sc['signal_correct_num'],sc['signal_correct_den'])
    if hidden:sp=1-sp
    belief=Fraction(sc['prior0_num'],sc['prior0_den']);events=[]
    for _ in range(sc['horizon']):
        request=int(rng.random()>=float(rp));signal=int(rng.random()>=float(sp));weights=[]
        for z in (0,1):
            rq=Fraction(sc[f'request_p0_z{z}_num'],sc[f'request_p0_z{z}_den'])
            sq=Fraction(sc['signal_correct_num'],sc['signal_correct_den'])
            if z:sq=1-sq
            weights.append((belief if z==0 else 1-belief)*(rq if request==0 else 1-rq)*(sq if signal==0 else 1-sq))
        belief=weights[0]/sum(weights)
        events.append((request,signal,belief.numerator,belief.denominator))
    return events


registration=load(DATA/'REGISTRATION.json');p=registration['protocol']
report=load(DATA/'RESULT.json');planned=load(DATA/'PLANNED.json')
scenarios=load(DATA/'SCENARIOS.json');outer=load(BASE/'compute-price-final-v1.receipt.json')
training=load(DATA/'TRAINING_PRICES.json');freeze=load(DATA/'PRICE_FREEZE.json')
prior=load(registration['prior_registration']['path']);calibration=load(registration['calibration']['path'])
check('registration_copy_exact',registration==load(BASE/'compute-price-registration-v1.json'))
check('source_commit_tree',registration['source']['commit']==EXPECTED_COMMIT and registration['source']['tree']==EXPECTED_TREE)
check('reported_source_exact',report['source']==registration['source'])
check('authority_and_no_advantage_claim',registration['authority']==report['authority']=='DENY_ALL'
      and report['production_activation'] is False and report['unique_NDU_advantage_claim'] is False)
check('frozen_calibration_anchor',registration['calibration']['sha256']==p['original_calibration_sha256']==EXPECTED_CALIBRATION)
for info in [*registration['inputs'].values(),registration['prior_registration'],registration['calibration']]:
    check('frozen_input_identity',file_identity(info['path'])==info,info['path'])
check('historical_native_inputs_unchanged',registration['inputs']==prior['inputs'])
check('split_disjoint',not set(p['holdout_seeds'])&(set(p['training_seeds'])|set(prior['protocol']['holdout_seeds'])))
check('new_final_dimension',p['dimension'] not in calibration['training_dimensions']+prior['protocol']['native_dimensions'])
check('training_origin',p['training_seeds']==calibration['training_seeds']==prior['protocol']['training_seeds']
      and calibration['training_dimensions']==[192,640] and calibration['future_measurement_access'] is False)

names=list(registration['source']['files']);frozen_blobs={};worktree_differences=[]
raw=subprocess.check_output(['git','--no-replace-objects','cat-file','--batch'],cwd=REPO,
    input=''.join(EXPECTED_COMMIT+':'+name+'\n' for name in names).encode());offset=0
for name in names:
    newline=raw.index(b'\n',offset);header=raw[offset:newline].decode().split();length=int(header[2])
    blob=raw[newline+1:newline+1+length];offset=newline+1+length+1;frozen_blobs[name]=blob
    expected_hash=registration['source']['files'][name]
    check('frozen_commit_source_hash',header[1]=='blob' and rawhash(blob)==expected_hash,name)
    current=rawhash((REPO/name).read_bytes()) if (REPO/name).is_file() else None
    if current!=expected_hash:worktree_differences.append({'path':name,'frozen_sha256':expected_hash,'current_sha256':current})
check('source_tree',subprocess.check_output(['git','--no-replace-objects','rev-parse',EXPECTED_COMMIT+'^{tree}'],cwd=REPO,text=True).strip()==EXPECTED_TREE)
check('protocol_commit_binding',json.loads(frozen_blobs['benchmarks/hia_ndu_feedback/COMPUTE_PRICE_PROTOCOL.json'])==p)
check('runner_commit_binding',rawhash(frozen_blobs['tools/qualify_hia_ndu_compute_price.py'])==registration['source']['compute_runner_sha256'])

for name,sc in scenarios.items():
    n=p['dimension'];lo,hi=calibration['training_dimensions'];fraction=Fraction(n-lo,hi-lo)
    expected={}
    for label,key in (('direct','direct_cost'),('packed','hot_cost'),('prepare','load_cost')):
        a=Fraction(calibration['models'][str(lo)][label+'_ns'],lo*lo)
        b=Fraction(calibration['models'][str(hi)][label+'_ns'],hi*hi)
        expected[key]=max(1,round((a+(b-a)*fraction)*n*n))
    expected['retire_cost']=round(statistics.median(m['retire_ns'] for m in calibration['models'].values()))
    expected['cost_unit']=max(1,expected['direct_cost']//6)
    check('scenario_forecast_recomputed_rational',all(sc[k]==v for k,v in expected.items()),name)
    check('scenario_budget_protocol_binding',sc['horizon']==p['horizon'] and sc['initial_budget']==sc['initial_deadline']==p['episode_budget_ns'],name)
    original=prior['scenarios'][name]
    changed=set(expected)|{'initial_budget','initial_deadline','cost_unit_label'}
    check('scenario_other_fields_unmodified',all(sc[k]==v for k,v in original.items() if k not in changed),name)

expected={(name,seed,rep,arm) for name in p['environments'] for seed in p['holdout_seeds']
          for rep in range(p['repetitions']) for arm in p['arms']}
expected_order=[]
for fi,name in enumerate(p['environments']):
    for si,seed in enumerate(p['holdout_seeds']):
        for rep in range(p['repetitions']):
            rotation=(fi+si+rep)%len(p['arms']);order=p['arms'][rotation:]+p['arms'][:rotation]
            if (si+rep)%2:order=list(reversed(order))
            expected_order.extend({'environment':name,'seed':seed,'repeat':rep,'arm':arm} for arm in order)
check('planned_inventory_and_order',planned==expected_order and len(planned)==len(expected)==120)
episodes=[];audits=[]
for index,cell in enumerate(planned):
    directory=DATA/'episodes'/f'{index:04d}';e=load(directory/'RESULT.json');a=load(directory/'ORACLE_AUDIT.json')
    check('episode_identity_binding',(e['scenario'],e['seed'],e['repetition'],e['arm'])==tuple(cell[k] for k in ('environment','seed','repeat','arm'))
          and e['cell_index']==index and e['dimension']==p['dimension'] and e['native_workload'] is True,index)
    check('complete_actual_delivery',e['status']=='completed' and e['delivered']==e['planned_requests']==len(e['steps'])==p['horizon']
          and e['missing_requests']==0 and not e['errors'] and e['failed_search_transitions']==0,index)
    check('audit_root_count_and_scope',len(a['rows'])==len(e['steps']) and a['online_controller_access'] is False,index)
    episodes.append(e);audits.append(a)
actual=[(e['scenario'],e['seed'],e['repetition'],e['arm']) for e in episodes]
check('unique_complete_observed_inventory',len(actual)==len(set(actual))==len(expected) and set(actual)==expected)
check('fixed_denominators',report['planned_episode_count']==report['retained_episode_count']==120
      and report['planned_request_count']==report['delivered_request_count']==360 and not report['not_run_cells'])

references={name:make_reference(sc) for name,sc in scenarios.items()}
policy_references={}
def sc_for(e):return scenarios[e['scenario']]
def policy_value(name,obs,fee=0):
    key=(name,fee)
    if key not in policy_references:policy_references[key]=make_greedy_policy_reference(scenarios[name],fee)
    return policy_references[key](*observation_args(obs),False)

check('training_completed_without_holdout',training['status']=='completed' and not training['errors'] and training['holdout_used'] is False
      and training['price_is_physical_guarantee'] is False)
check('training_file_frozen',freeze['training']==file_identity(DATA/'TRAINING_PRICES.json')==report['training_identity']
      and freeze['prices']==training['prices'] and freeze['before_any_final_execution'] is True)
check('price_freeze_file_identity',report['price_freeze']==file_identity(DATA/'PRICE_FREEZE.json'))
trial_keys=[];groups=defaultdict(list);training_wall_by_arm=Counter();training_transitions=Counter();training_backend_calls=0
for trial in training['all_trials']:
    name=trial['environment'];sc=scenarios[name];obs=trial['observation'];d=trial['decision'];arm=trial['arm'];ctx=(name,trial['seed'],obs['step'],arm)
    trial_keys.append(ctx);groups[name,trial['seed'],obs['step']].append(trial)
    training_wall_by_arm[arm]+=trial['wall_ns'];training_transitions[arm]+=trial['search_transitions']
    training_backend_calls+=d['search']['backend_calls']
    check('training_trial_complete',trial['status']=='completed' and trial['wall_ns']>=d['controller_wall_ns']>=0
          and trial['search_transitions']==d['search']['transitions'],ctx)
    check('training_trial_observation_binding',obs==d['observation'] and d['state_digest']==digest(obs),ctx)
    check('training_current_preference',d['preference']==state_price(sc,obs),ctx)
    if arm=='state-greedy':best,vals,elig,winner=root_greedy(sc,obs)
    else:best,vals,elig,winners=references[name](*observation_args(obs));winner=winners[0]
    check('training_planner_independent_recompute',d['value_q32']==best and d['selected_action']==winner and d['candidate_values_q32']==vals,ctx)
expected_trials={(name,seed,t,arm) for name in p['environments'] for seed in p['training_seeds'] for t in range(p['horizon'])
                 for arm in ('state-greedy','same-objective','dynamic-ndu')}
check('training_trial_inventory',len(trial_keys)==len(set(trial_keys))==len(expected_trials)==108 and set(trial_keys)==expected_trials)
for (name,seed,t),rows in groups.items():
    check('equal_training_observations',len(rows)==3 and all(r['observation']==rows[0]['observation'] for r in rows),(name,seed,t))
for name in p['environments']:
    sc=scenarios[name]
    for seed in p['training_seeds']:
        ready=sc['initial_resident'];budget=sc['initial_budget'];deadline=sc['initial_deadline']
        for t,event in enumerate(generated_events(sc,seed)):
            req,sig,bnum,bden=event;expected_obs={'step':t,'request':req,'signal':sig,'resident':ready,
                'budget':budget,'deadline':deadline,'belief_num':bnum,'belief_den':bden}
            rows=groups[name,seed,t];check('greedy_behavior_training_history',all(r['observation']==expected_obs for r in rows),(name,seed,t))
            chosen=root_greedy(sc,expected_obs)[3];spent=costs(sc,expected_obs)[chosen]
            ready={'direct':-1,'cache-0':0,'cache-1':1}[chosen];budget-=spent;deadline-=spent
    for arm in ('state-greedy','same-objective','dynamic-ndu'):
        for depth in range(1,p['horizon']+1):
            samples=[r['wall_ns'] for r in training['all_trials'] if r['environment']==name and r['arm']==arm and p['horizon']-r['observation']['step']==depth]
            check('price_exact_retained_trial_median',len(samples)==len(p['training_seeds']) and training['prices'][name][arm][str(depth)]==round(statistics.median(samples)),(name,arm,depth))
check('training_transition_ledgers',dict(training_transitions)==training['transition_ledgers'])
check('training_whole_wall_contains_all_trials',training['wall_ns']>=sum(training_wall_by_arm.values())+training['native_close']['close_ns'])
check('training_native_close_count',training['native_close']['started'] is True and training['native_close']['returncode']==0
      and training['native_close']['calls']==training_backend_calls)

preferences_seen=defaultdict(set);regrets=defaultdict(list);gates=[];actions=defaultdict(dict);root_recomputations=Counter()
for e,a in zip(episodes,audits):
    name=e['scenario'];sc=scenarios[name];previous=None;events=generated_events(sc,e['seed'])
    for t,(step,arow) in enumerate(zip(e['steps'],a['rows'])):
        d=step['decision'];obs=d['observation'];out=step['outcome'];ctx=(e['cell_index'],t)
        expected_state={'step':t,'request':events[t][0],'signal':events[t][1],
                        'belief_num':events[t][2],'belief_den':events[t][3],
                        'resident':sc['initial_resident'] if previous is None else previous['resident_after'],
                        'budget':sc['initial_budget'] if previous is None else previous['remaining_budget'],
                        'deadline':sc['initial_deadline'] if previous is None else previous['remaining_deadline']}
        check('complete_causal_observation_recomputed',obs==expected_state,ctx)
        check('decision_and_audit_digest_binding',d['state_digest']==digest(obs)==arow['state_digest'],ctx)
        check('actual_action_consumption',out['observation']==obs and d['action']==out['action']==out['executed_action']==out['resident_after']
              and out['delivered'] is True and out['status']=='delivered',ctx)
        pref=state_price(sc,obs);preferences_seen[name,e['arm']].add(tuple(pref[k] for k in ('price_q32','discount_q32','risk_q32')))
        check('numeric_preferences_actual_consumed',d['preference']==out['preference']==pref,ctx)
        check('actual_feedback_budget',out['remaining_budget']==max(0,obs['budget']-out['cost'])
              and out['remaining_deadline']==max(0,obs['deadline']-out['cost']),ctx)
        check('observed_reward_and_discount',out['reward_q32']==sc['completion_reward_q32']-mul(pref['price_q32'],rounded(out['cost']*Q,sc['cost_unit']))
              and out['discount_q32']==pref['discount_q32'],ctx)
        best,vals,eligible,winners=references[name](*observation_args(obs));greedy,gvals,geligible,gaction=root_greedy(sc,obs)
        regret=best-vals[d['selected_action']];regrets[name,e['arm']].append(regret)
        root_recomputations['all_final_roots']+=1
        check('independent_exact_postexecution_values',arow['oracle_value_q32']==best and arow['oracle_action']==winners[0],ctx)
        check('independent_postexecution_regret',arow['selected_conditional_regret_q32']==regret and regret>=0,ctx)
        g=d.get('compute_gate');full=e['arm'] in ('same-objective','dynamic-ndu') or bool(g and g['invoke'])
        if full:
            root_recomputations['full_planner_roots']+=1
            check('full_planner_values_actions_exact',d['value_q32']==best and d['candidate_values_q32']==vals and d['selected_action']==winners[0]
                  and arow['same_objective_required'] is True and arow['same_objective_agrees'] is True,ctx)
        else:
            root_recomputations['greedy_roots']+=1
            check('greedy_values_actions_exact',d['value_q32']==greedy and d['candidate_values_q32']==gvals and d['selected_action']==gaction,ctx)
        if g:
            underlying=e['arm'].removesuffix('-priced');depth=p['horizon']-t
            frozen_price=training['prices'][name][underlying][str(depth)]
            greedy_price=max(training['prices'][name]['state-greedy'][str(k)] for k in range(1,depth+1))
            penalty=mul(pref['price_q32'],rounded(frozen_price*Q,sc['cost_unit']))
            check('gate_price_frozen_training_lookup',g['forecast_control_ns']==frozen_price and g['greedy_forecast_ns']==greedy_price,ctx)
            check('gate_compute_cost_unit_conversion',g['forecast_compute_penalty_q32']==g['compute_penalty_q32']==penalty
                  and g['current_price_q32']==pref['price_q32'] and g['cost_unit_ns']==sc['cost_unit'],ctx)
            check('gate_price_identity',g['forecast_identity']==digest({'planner_arm':underlying,'forecast_control_ns':frozen_price,
                  'greedy_forecast_ns':greedy_price,'cost_unit_ns':sc['cost_unit']}),ctx)
            true_greedy=policy_value(name,obs);true_costed=policy_value(name,obs,greedy_price)
            check('gate_upper_lower_against_independent_full_policies',g['incumbent_gross_lower_q32']<=true_greedy<=best<=g['optimal_upper_q32']
                  and g['incumbent_costed_lower_q32']<=true_costed<=true_greedy,ctx)
            gross=g['optimal_upper_q32']-g['incumbent_gross_lower_q32'];priced_gap=g['optimal_upper_q32']-g['incumbent_costed_lower_q32']
            check('gate_opportunity_subtraction',g['gross_gain_upper_q32']==gross and g['priced_gain_upper_q32']==priced_gap,ctx)
            services=any(v for k,v in geligible.items() if k!='abstain')
            should_invoke=depth>1 and services and gross>0 and priced_gap>penalty
            check('gate_admission_rule',g['invoke'] is should_invoke and g['incumbent_action']==gaction and g['planner_arm']==underlying,ctx)
            check('gate_current_greedy_sunk_not_credited',g['current_greedy_fee_is_sunk'] is True
                  and g['current_greedy_forecast_fee_q32']==mul(pref['price_q32'],rounded(greedy_price*Q,sc['cost_unit'])),ctx)
            gate_work=4 if depth==1 or not services else 4+3*(depth-1)+4
            check('gate_linear_work_and_shared_allowance',g['gate_transitions']==gate_work<=g['maximum_gate_transitions']==3*depth+5
                  and g['future_state_enumerations']==0 and d['search']['gate_transitions']==gate_work
                  and d['search']['transitions']==gate_work+d['search']['planner_transitions']
                  and g['planner_allowance']==p['max_transitions_per_decision']-gate_work,ctx)
            check('gate_bound_audit_true',arow['priced_optimal_upper_valid'] is True,ctx)
            if not g['invoke']:
                check('skip_has_no_native_or_planner_work',not d['native_backend_used'] and d['search']['backend_calls']==0
                      and d['search']['planner_transitions']==0 and g['planner_wall_ns']==0
                      and arow['priced_incumbent_agrees'] is True,ctx)
            check('gate_wall_retained_nested',step['observed_decision_wall_ns']>=d['controller_wall_ns']>=g['total_gate_wall_ns']+g['planner_wall_ns']
                  and g['total_gate_wall_ns']>=g['incumbent_root_wall_ns']+g['bound_calculation_wall_ns'],ctx)
            check('gate_scope_no_physical_or_gain_guarantee',g['cost_threshold_is_observed_guarantee'] is False
                  and g['positive_net_benefit_claim'] is False,ctx)
            gates.append({'cell_index':e['cell_index'],'environment':name,'arm':e['arm'],'step':t,'invoke':g['invoke'],
                'reason':g['reason'],'forecast_control_ns':frozen_price,'greedy_forecast_ns':greedy_price,
                'gate_wall_ns':g['total_gate_wall_ns'],'gate_transitions':gate_work,'selected_regret_q32':regret,
                'optimal_value_q32':best,'greedy_policy_value_q32':true_greedy,'costed_greedy_policy_value_q32':true_costed,
                'optimal_upper_q32':g['optimal_upper_q32'],'incumbent_gross_lower_q32':g['incumbent_gross_lower_q32'],
                'incumbent_costed_lower_q32':g['incumbent_costed_lower_q32']})
        check('decision_budget_bound',0<=d['search']['transitions']<=p['max_transitions_per_decision'],ctx)
        previous=out
    utility=0
    for step in reversed(e['steps']):utility=step['outcome']['reward_q32']+mul(step['outcome']['discount_q32'],utility)
    check('episode_path_utility',utility==e['realized_discounted_utility_q32'],e['cell_index'])
    check('episode_cost_partition',e['episode_wall_ns']>=e['online_wall_ns']==e['actual_cost']+e['online_cost_outside_outcome_records_ns']
          and e['actual_cost']==e['cost_with_outcome_record_ns']==sum(s['outcome']['cost'] for s in e['steps']),e['cell_index'])
    check('episode_search_counts',e['search_transitions']==sum(s['decision']['search']['transitions'] for s in e['steps'])
          and e['backend_calls']==sum(s['decision']['search']['backend_calls'] for s in e['steps']),e['cell_index'])
    actions[name,e['seed'],e['repetition']][e['arm']]=[s['decision']['selected_action'] for s in e['steps']]

value_log_frames,workload_log_frames=audit_raw_sessions()
for e in episodes:bind_episode_raw(e)
training_frames=value_log_frames[DATA/'training-values.jsonl'];pos=0
for row in training['all_trials']:
    if row['arm']!='dynamic-ndu':continue
    d=row['decision'];sc=scenarios[row['environment']];context=(row['environment'],row['seed'],row['observation']['step'])
    check('training_native_trace_length',len(d['search_trace'])==d['search']['backend_calls'],context)
    for trace in d['search_trace']:
        req,res,raw=training_frames[pos];pos+=1
        check('training_native_trace_binding',req['state_digest']==trace['state_digest'] and req['preference_digest']==digest(trace['preference'])
              and req['objective_digest']==digest({'rule':'state-price-plus-discounted-mean-downside-v1','scenario':sc})
              and res['values_q32']==trace['values_q32'] and res['chosen_id']==trace['selected'],context)
    root,answer,_=training_frames[pos-1];obs=d['observation']
    check('training_native_root_consumed',root['candidates']==d['candidates'] and answer['values_q32']==d['candidate_values_q32']
          and answer['chosen_id']==d['selected_action'] and root['resource_budget_q32']==rounded(min(obs['budget'],obs['deadline'])*Q,sc['cost_unit']),context)
check('training_all_native_frames_consumed',pos==len(training_frames)==training_backend_calls)

tables={};comparisons=[];action_differences=[]
for name in p['environments']:
    tables[name]={}
    for arm in p['arms']:
        rows=[e for e in episodes if e['scenario']==name and e['arm']==arm]
        stats={'planned_episodes':len(p['holdout_seeds'])*p['repetitions'],'observed_episodes':len(rows),
               'planned_requests':len(p['holdout_seeds'])*p['repetitions']*p['horizon'],
               **{key:sum(e[key] for e in rows) for key in ('delivered','episode_wall_ns','workload_wall_ns','backend_calls','search_transitions')},
               'gate_skips':sum(not s['decision'].get('compute_gate',{}).get('invoke',True) for e in rows for s in e['steps'])}
        check('published_table_recomputed',stats==report['tables'][name][arm],(name,arm))
        values=regrets[name,arm]
        stats.update(positive_regret_decisions=sum(v>0 for v in values),regret_sum_q32=sum(values),
                     regret_max_q32=max(values),regret_mean_q32=statistics.mean(values),
                     actual_online_ns=sum(e['actual_cost'] for e in rows),
                     realized_path_utility_q32=sum(e['realized_discounted_utility_q32'] for e in rows))
        tables[name][arm]=stats
    for priced_arm in ('same-objective-priced','dynamic-ndu-priced'):
        for control in (priced_arm.removesuffix('-priced'),'state-greedy'):
            differences=[]
            for seed in p['holdout_seeds']:
                paired=[]
                for rep in range(p['repetitions']):
                    pair={e['arm']:e for e in episodes if e['scenario']==name and e['seed']==seed and e['repetition']==rep}
                    paired.append(pair[priced_arm]['episode_wall_ns']-pair[control]['episode_wall_ns'])
                differences.append(statistics.mean(paired))
            rng=random.Random(530771);boot=sorted(statistics.mean(rng.choices(differences,k=len(differences))) for _ in range(2000))
            rebuilt={'paired_mean_difference_ns':statistics.mean(differences),'exploratory_bootstrap_95_ns':[boot[49],boot[1949]],
                     'independent_seed_count':len(differences)}
            published=next(c for c in report['paired_comparisons'] if c['environment']==name and c['priced_arm']==priced_arm and c['control']==control)
            check('seed_level_paired_bootstrap_recomputed',all(published['paired'][k]==v for k,v in rebuilt.items()),(name,priced_arm,control))
            comparisons.append({'environment':name,'priced_arm':priced_arm,'control':control,'seed_mean_differences_ns':differences,
                                **rebuilt,'priced_observed_episode_saving_ns':tables[name][control]['episode_wall_ns']-tables[name][priced_arm]['episode_wall_ns']})
            pairs=[seq for (env,_,_),seq in actions.items() if env==name]
            action_differences.append({'environment':name,'priced_arm':priced_arm,'control':control,'paired_episodes':len(pairs),
                'different_episode_sequences':sum(a[priced_arm]!=a[control] for a in pairs),
                'different_step_actions':sum(x!=y for a in pairs for x,y in zip(a[priced_arm],a[control]))})
for arm in p['arms']:
    spent=training_transitions[arm.removesuffix('-priced')]+sum(e['search_transitions'] for e in episodes if e['arm']==arm)
    check('whole_lifecycle_transition_ledger',report['transition_ledgers'][arm]==spent<=p['max_transitions_per_arm'],arm)
check('formal_result_checks_honest',report['status']=='completed' and all(report['checks'].values())
      and not report['fatal_error'] and not report['postflight_errors'] and not report['audit_errors'])
audit_wall=sum(a['wall_ns'] for a in audits);episode_wall=sum(e['episode_wall_ns'] for e in episodes)
known=training['wall_ns']+audit_wall+episode_wall
check('total_wall_nested',outer['returncode']==0 and outer['source']==EXPECTED_COMMIT
      and outer['wall_ns']>=report['wall_before_report_ns']>=known)
check('offline_audit_training_cost_retained',report['training_wall_ns']==training['wall_ns'] and report['post_execution_audit_wall_ns']==audit_wall)
build_total=0;build_failed=0
for item in prior['build_attempt_ledger']['content']['attempts']:
    check('historical_build_attempt_identity',file_identity(item['receipt']['path'])==item['receipt'])
    cost=load(item['receipt']['path'])['build_cost'];check('historical_build_attempt_cost',cost==item['build_cost'])
    build_total+=cost['wall_ns'];build_failed+=cost['wall_ns']*int(not cost['completed'])
totals_by_arm={arm:sum(tables[name][arm]['episode_wall_ns'] for name in p['environments']) for arm in p['arms']}
native_saving=totals_by_arm['dynamic-ndu']-totals_by_arm['dynamic-ndu-priced']
greedy_saving=totals_by_arm['state-greedy']-totals_by_arm['dynamic-ndu-priced']
gate_stats={arm:{'decisions':len([g for g in gates if g['arm']==arm]),
    'invocations':sum(g['invoke'] for g in gates if g['arm']==arm),
    'skips':sum(not g['invoke'] for g in gates if g['arm']==arm),
    'skips_by_step':dict(Counter(g['step'] for g in gates if g['arm']==arm and not g['invoke'])),
    'invocations_by_step':dict(Counter(g['step'] for g in gates if g['arm']==arm and g['invoke'])),
    'total_gate_wall_ns':sum(g['gate_wall_ns'] for g in gates if g['arm']==arm),
    'total_gate_transitions':sum(g['gate_transitions'] for g in gates if g['arm']==arm)}
    for arm in ('same-objective-priced','dynamic-ndu-priced')}
raw_manifest={str(f.relative_to(DATA)):{'bytes':f.stat().st_size,'sha256':rawhash(f.read_bytes())}
              for f in sorted(DATA.rglob('*')) if f.is_file()}
review={
 'schema':'hepta.hia.ndu.compute-price-independent-review.v1',
 'reviewer':'independent_gates; independent Fraction model/policy enumeration and raw byte readback',
 'source':{'commit':EXPECTED_COMMIT,'tree':EXPECTED_TREE},'post_measurement_worktree_differences':worktree_differences,
 'scope':'Read-only frozen compute-price cohort; no native execution, campaign rerun, retraining, parameter choice or original-data changes.',
 'status':'PASS_INTEGRITY_WITH_COST_CONTROL_NO_GREEDY_ADVANTAGE' if not failures else 'FAIL_INTEGRITY',
 'audit_source':file_identity(Path(__file__)),'evidence_directory':str(DATA),
 'registration':file_identity(DATA/'REGISTRATION.json'),'campaign_result':file_identity(DATA/'RESULT.json'),
 'outer_receipt':file_identity(BASE/'compute-price-final-v1.receipt.json'),
 'check_counts':dict(checks),'failed_check_counts':dict(failed_checks),'failures':failures,
 'inventory':{'episodes':len(episodes),'planned_requests':120*p['horizon'],'delivered_requests':sum(e['delivered'] for e in episodes),
              'training_trials':len(training['all_trials']),**root_recomputations,**counts},
 'training':{'prices':training['prices'],'trial_whole_wall_by_arm_ns':dict(training_wall_by_arm),
             'transition_ledgers':dict(training_transitions),'whole_wall_ns':training['wall_ns'],
             'native_close':training['native_close'],'original_calibration_sha256':EXPECTED_CALIBRATION,
             'causal_scope':'Every price uses only four registered training seeds. All three planners see identical greedy-behavior observations. The exact training bytes are frozen before dispatch. Future greedy fees use maximum frozen median among remaining depths.'},
 'gate_statistics':gate_stats,'gate_independent_policy_certificates':gates,'tables':tables,
 'paired_comparisons':comparisons,'action_differences':action_differences,
 'observed_numeric_preferences':{name:{arm:sorted(preferences_seen[name,arm]) for arm in p['arms']} for name in p['environments']},
 'costs':{'whole_campaign_outer_wall_ns':outer['wall_ns'],'accounted_nested_campaign_ns':known,
          'training_wall_ns':training['wall_ns'],'primary_episode_wall_ns':episode_wall,'post_execution_audit_wall_ns':audit_wall,
          'sum_episode_wall_by_arm_ns':totals_by_arm,'priced_native_online_saving_vs_ungated_native_ns':native_saving,
          'priced_native_online_saving_vs_greedy_ns':greedy_saving,
          'priced_native_saving_vs_ungated_after_charging_entire_shared_training_ns':native_saving-training['wall_ns'],
          'priced_native_saving_vs_greedy_after_charging_entire_shared_training_ns':greedy_saving-training['wall_ns'],
          'historical_value_build_attempts_wall_ns':build_total,'historical_failed_build_wall_ns':build_failed,
          'allocation_scope':'The full training debit is an explicit conservative comparison for this 24-episode-per-arm cohort, not marginal deployment training or full engineering lifecycle cost. Historical native builds cancel versus the same ungated native dependency; they cannot be silently erased versus greedy. Campaign audit/measurement costs are separately retained, not silently amortized into a production claim.',
          'nesting':'episode/online/workload/native-service/kernel costs overlap; never add nested layers.'},
 'findings':[
   'The trained native price gate skips all 72 formal decisions and emits no formal native value calls; it executes the same action sequence as state-greedy in every paired episode.',
   'Ordinary same-objective planning receives the same gate. Its frozen lower computation price admits 24 middle-step invocations; all invoked values/actions and skipped immediate greedy answers were independently verified.',
   'Skipping trades away positive gross task-model value in adaptive and misleading states. Exact conditional regrets are retained; they are not evidence of defective wiring or an observed throughput failure.',
   'The large native-runtime saving is relative to unnecessarily running the expensive native planner. It does not establish an advantage over the simple greedy controller.',
   'Adaptive and misleading priced-native-minus-greedy exploratory intervals include zero. Fixed is strictly slower in this sample. Shared-host timing and four seeds do not support a general performance guarantee.',
   'Numerical preferences remain constant in this cohort. Actual native preference-update coverage belongs to the separately registered state-coverage study.',
 ],
 'limitations':[
   'Independent recomputation verifies finite-model and byte consistency; logs are not external hardware attestation.',
   'Q32 policy bounds refer to modeled workload resource transitions. Future computation charges are a frozen utility-price model, not guarantees about actual budgets, deadlines or elapsed wall.',
   'Training medians mostly measure a warm native process; actual final initialization and cleanup remain in whole episode cost.',
   'Gross conditional action regret is computed at each observed state assuming optimal future continuation; summing it is descriptive, not pathwise or unbiased nested-risk regret.',
   'The known anti-correlated sensor is not an unknown distribution shift.',
   'The observation object is a causal interface, not a malicious-process sandbox.',
   'Unknown prior engineering effort, human review, energy and monetary costs remain unknown. This is not production activation or NDU-exclusive net benefit.',
 ],
 'raw_evidence_manifest':raw_manifest,'audit_wall_ns':time.perf_counter_ns()-started,
}
OUT.write_text(json.dumps(review,sort_keys=True,indent=2)+'\n')
print(json.dumps({k:review[k] for k in ('status','failed_check_counts','inventory','gate_statistics','costs','audit_wall_ns')},indent=2))
if failures:print(json.dumps(failures[:30],indent=2))
raise SystemExit(bool(failures))

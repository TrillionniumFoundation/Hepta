"""Independent complete state/native-frame/physical-witness qualification audit.

Reads frozen artifacts and computes arithmetic/model answers itself. It never
imports production planners, launches native workers, alters the original data,
re-registers a grid, samples a favorable subset or reruns a campaign.
"""
from collections import Counter,defaultdict
from functools import lru_cache
from fractions import Fraction
from hashlib import sha256
from pathlib import Path
import itertools
import json
import subprocess
import time

BASE=Path('/workspace/scratch/3f3fcd2808a5')
COVERAGE=BASE/'state-coverage-final-v1'
WITNESS=BASE/'physical-witness-final-v1'
REPO=BASE/'hepta-ndu-work'
OUT=BASE/'independent-state-coverage-review.json'
Q=1<<32
LIMIT=1000000*Q
UPSTREAM='8e52e1187f47f6d4edc8d942fc7cb7eca4bc447d'
EXPECTED_COMMIT='78c0b951adc08b02be60d64b386620c5ac9faf99'
EXPECTED_TREE='a96e501429fa0482330c7d5d477f8549a132bd52'
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

def state_price(sc,obs):
    slack=min(obs['budget'],obs['deadline']); rem=sc['horizon']-obs['step']
    scarcity=max(Fraction(0),1-Fraction(slack,max(sc['cost_unit'],rem*sc['direct_cost']))) if sc['dynamic_preferences'] else Fraction(0)
    return {'price_q32':rounded((1+scarcity)*Q),'discount_q32':sc['discount_q32'],
            'risk_q32':min(Q,sc['risk_aversion_q32']+rounded(scarcity*Q/4)),
            'scarcity_num':scarcity.numerator,'scarcity_den':scarcity.denominator}

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

def observation_args(obs):
    return tuple(obs[k] for k in ('step','request','resident','budget','deadline','belief_num','belief_den'))

def costs(sc,obs):
    return {label:(sc['hot_cost'] if a==obs['request'] else sc['direct_cost'])
            +sc['load_cost']*int(a>=0 and a!=obs['resident'])
            +sc['retire_cost']*int(obs['resident']>=0 and a!=obs['resident'])
            +sc['holding_cost']*int(a>=0)
            for a,label in ((-1,'direct'),(0,'cache-0'),(1,'cache-1'))}


def file_identity(path):
    p=Path(path).resolve();h=sha256();length=0
    with p.open('rb') as stream:
        while block:=stream.read(1024*1024):h.update(block);length+=len(block)
    return {'path':str(p),'bytes':length,'sha256':h.hexdigest()}


def posterior(sc,belief,request,signal):
    weights=[]
    for z in (0,1):
        rp=Fraction(sc[f'request_p0_z{z}_num'],sc[f'request_p0_z{z}_den'])
        sp=Fraction(sc['signal_correct_num'],sc['signal_correct_den'])
        if z:sp=1-sp
        weights.append((belief if z==0 else 1-belief)*(rp if request==0 else 1-rp)*(sp if signal==0 else 1-sp))
    return sum(weights),weights[0]/sum(weights) if sum(weights) else None


def branches(sc,obs):
    belief=Fraction(obs['belief_num'],obs['belief_den'])
    for request,signal in itertools.product((0,1),repeat=2):
        probability,next_belief=posterior(sc,belief,request,signal)
        if probability:yield probability,request,signal,next_belief


def fixed_preference(sc):
    initial={'step':0,'budget':sc['initial_budget'],'deadline':sc['initial_deadline']}
    return state_price(sc,initial)


scenario_objects={}
def scenario_key(sc):
    key=digest(sc);scenario_objects.setdefault(key,sc);return key


@lru_cache(None)
def solve(key,t,request,ready,budget,deadline,bnum,bden,mode):
    """Independent Bellman/fixed-policy evaluator; no production helper calls."""
    sc=scenario_objects[key]
    obs={'step':t,'request':request,'resident':ready,'budget':budget,'deadline':deadline,
         'belief_num':bnum,'belief_den':bden}
    pref=fixed_preference(sc) if mode=='fixedpref' else state_price(sc,obs)
    if mode=='additive':pref={'price_q32':Q,'discount_q32':Q,'risk_q32':0,'scarcity_num':0,'scarcity_den':1}
    values={};eligible={};candidates=[];physical=costs(sc,obs);remaining=sc['horizon']-t
    for action,label in ((-1,'direct'),(0,'cache-0'),(1,'cache-1')):
        cost=physical[label];eligible[label]=cost<=min(budget,deadline);children=[]
        if eligible[label] and remaining>1 and mode!='greedy':
            for probability,req,sig,belief in branches(sc,obs):
                child=solve(key,t+1,req,action,budget-cost,deadline-cost,belief.numerator,belief.denominator,mode)
                children.append((probability,child['value']))
        mean=sum((probability*v for probability,v in children),Fraction())
        downside=sum((probability*max(Fraction(),mean-v) for probability,v in children),Fraction())
        terminal=rounded(mean-Fraction(pref['risk_q32'],Q)*downside)
        raw_cost=rounded(cost*Q,sc['cost_unit'])
        instant=-raw_cost if mode=='additive' else sc['completion_reward_q32']-mul(pref['price_q32'],raw_cost)
        values[label]=instant+mul(pref['discount_q32'],terminal)
        candidates.append({'id':label,'instant_q32':instant,'terminal_q32':terminal,
            'discount_q32':pref['discount_q32'],'feasible':eligible[label],'resource_q32':raw_cost,'risk_q32':0})
    values['abstain']=-sc['miss_penalty_q32']*remaining;eligible['abstain']=True
    candidates.append({'id':'abstain','instant_q32':values['abstain'],'terminal_q32':0,
        'discount_q32':Q,'feasible':True,'resource_q32':0,'risk_q32':0})
    best=max(v for k,v in values.items() if eligible[k]);winner=min(k for k,v in values.items() if eligible[k] and v==best)
    if mode=='fixedpolicy':
        winner='cache-0' if eligible['cache-0'] else min((k for k in physical if eligible[k]),key=lambda k:(physical[k],k),default='abstain')
        best=values[winner]
    return {'value':best,'values':values,'eligible':eligible,'winner':winner,'preference':pref,'candidates':candidates}


def reference(sc,obs,arm='dynamic-ndu'):
    copy=dict(obs);mode='dynamic'
    if arm in ('fixed-preference-ndu','no-adaptation'):mode='fixedpref'
    if arm=='no-adaptation':copy.update(belief_num=sc['prior0_num'],belief_den=sc['prior0_den'])
    if arm=='wrong-forecast':copy['belief_num']=copy['belief_den']-copy['belief_num']
    if arm=='ordinary-mpc':mode='additive'
    if arm=='state-greedy':mode='greedy'
    if arm=='fixed-policy-value':mode='fixedpolicy'
    return solve(scenario_key(sc),*observation_args(copy),mode)


def node_order(sc,obs):
    """Public states of every feasible recursive backup, in dependency order."""
    seen=set();nodes=[]
    def visit(state):
        key=wire(state)
        if key in seen:return
        if state['step']+1<sc['horizon']:
            for action,label in ((-1,'direct'),(0,'cache-0'),(1,'cache-1')):
                spent=costs(sc,state)[label]
                if spent>min(state['budget'],state['deadline']):continue
                for probability,request,signal,belief in branches(sc,state):
                    child={'step':state['step']+1,'request':request,'signal':signal,'resident':action,
                        'budget':state['budget']-spent,'deadline':state['deadline']-spent,
                        'belief_num':belief.numerator,'belief_den':belief.denominator}
                    visit(child)
        seen.add(key);nodes.append(state)
    visit(obs);return nodes


registry=load(COVERAGE/'REGISTRATION.json');coverage=load(COVERAGE/'RESULT.json');p=registry['protocol']
wreg=load(WITNESS/'REGISTRATION.json');wresult=load(WITNESS/'RESULT.json');wp=wreg['protocol']
prior=load(wreg['prior_registration']['path']);base_scenarios=prior['scenarios']
check('registry_canonical_digest',registry['registration_sha256']==digest({k:v for k,v in registry.items() if k!='registration_sha256'}))
check('registry_protocol_digest',registry['protocol_sha256']==digest(p))
check('coverage_registry_binding',coverage['registration_sha256']==registry['registration_sha256'] and coverage['source']==registry['source'])
for source in (registry['source'],wreg['source']):
    check('source_commit_tree',source['commit']==EXPECTED_COMMIT and source['tree']==EXPECTED_TREE)
check('coverage_source_clean',registry['source']['clean'] is True)
source_map={};post_measurement_differences=[]
for source in (registry['source'],wreg['source']):
    for name,value in source['files'].items():
        if name in source_map:check('shared_source_hash_binding',source_map[name]==value,name)
        source_map[name]=value
batch=subprocess.check_output(['git','--no-replace-objects','cat-file','--batch'],cwd=REPO,
    input=''.join(EXPECTED_COMMIT+':'+name+'\n' for name in source_map).encode());position=0;blobs={}
for name,expected in source_map.items():
    end=batch.index(b'\n',position);parts=batch[position:end].decode().split();size=int(parts[2])
    value=batch[end+1:end+1+size];position=end+size+2;blobs[name]=value
    check('source_immutable_git_blob',parts[1]=='blob' and rawhash(value)==expected,name)
    current=file_identity(REPO/name)['sha256'] if (REPO/name).is_file() else None
    if current!=expected:post_measurement_differences.append({'path':name,'frozen_sha256':expected,'current_sha256':current})
check('git_tree_binding',subprocess.check_output(['git','--no-replace-objects','rev-parse',EXPECTED_COMMIT+'^{tree}'],cwd=REPO,text=True).strip()==EXPECTED_TREE)
check('coverage_protocol_commit_binding',json.loads(blobs['benchmarks/hia_ndu_feedback_state_coverage/PROTOCOL.json'])==p)
check('witness_protocol_commit_binding',json.loads(blobs['benchmarks/hia_ndu_feedback_state_coverage/WITNESS_PROTOCOL.json'])==wp)
check('base_model_unchanged',rawhash(blobs['experiments/hia_ndu_feedback_20261106/model.py'])==p['base_model_sha256'])
for info in [*registry['native_inputs'].values(),*wreg['inputs'].values(),wreg['coverage'],wreg['prior_registration']]:
    check('frozen_native_and_evidence_identity',file_identity(info['path'])==info,info['path'])
check('witness_bound_complete_coverage',wreg['coverage']==file_identity(COVERAGE/'RESULT.json') and wreg['before_any_physical_measurement'] is True)
check('same_admitted_native_inputs',registry['native_inputs']['binary']==wreg['inputs']['value_binary']
      and registry['native_inputs']['manifest']==wreg['inputs']['value_manifest'] and wreg['inputs']==prior['inputs'])

expected_states={};expected_memberships=[];expected_tapes=[];expected_profiles=[];owner_states=set()
def add_state(sc,obs,membership):
    identity=digest({'scenario':sc,'observation':obs})
    expected_states.setdefault(identity,{'id':identity,'scenario':sc,'observation':obs,'families':[]})
    if membership['family'] not in expected_states[identity]['families']:expected_states[identity]['families'].append(membership['family'])
    expected_memberships.append({**membership,'state_id':identity});return identity

grid=p['supplied_grid'];boundary=p['boundary_grid'];natural=p['natural_support']
for i,(name,request,ready,belief,resources,horizon,load_cost) in enumerate(itertools.product(p['environments'],grid['current_requests'],grid['residents'],
        grid['beliefs'],grid['remaining_resources'],grid['horizons'],grid['load_costs'])):
    sc={**base_scenarios[name],'horizon':horizon,'load_cost':load_cost,
        'initial_budget':grid['initial_resources'][0],'initial_deadline':grid['initial_resources'][1]};b=Fraction(*belief)
    obs={'step':0,'request':request,'signal':0,'resident':ready,'budget':resources[0],'deadline':resources[1],
         'belief_num':b.numerator,'belief_den':b.denominator}
    add_state(sc,obs,{'id':f'grid-{i:04}','family':'supplied-grid','environment':name,'natural_posterior_claim':False})
for i,(name,request,numerator,budget) in enumerate(itertools.product(p['environments'],boundary['current_requests'],boundary['belief_numerators'],boundary['remaining_budgets'])):
    sc={**base_scenarios[name],'horizon':boundary['horizon'],'load_cost':boundary['load_cost'],
        'initial_budget':boundary['initial_resources'][0],'initial_deadline':boundary['initial_resources'][1]};b=Fraction(numerator,boundary['belief_denominator'])
    obs={'step':0,'request':request,'signal':0,'resident':1-request,'budget':budget,'deadline':boundary['remaining_deadline'],
         'belief_num':b.numerator,'belief_den':b.denominator}
    add_state(sc,obs,{'id':f'boundary-{i:04}','family':'supplied-boundary','environment':name,'natural_posterior_claim':False})
for i,(name,ready,resources,load_cost) in enumerate(itertools.product(p['environments'],natural['initial_residents'],natural['initial_resource_pairs'],natural['load_costs'])):
    profile_id=f'natural-profile-{i:02}'
    sc={**base_scenarios[name],'horizon':natural['horizon'],'load_cost':load_cost,'initial_resident':ready,
        'initial_budget':resources[0],'initial_deadline':resources[1]};mass=Fraction()
    for ti,tape in enumerate(itertools.product(natural['alphabet'],repeat=sc['horizon'])):
        ident=f'{profile_id}/tape-{ti:02}';belief=Fraction(sc['prior0_num'],sc['prior0_den']);probability=Fraction(1)
        for request,signal in tape:
            conditional,belief=posterior(sc,belief,request,signal);probability*=conditional
        mass+=probability;belief=Fraction(sc['prior0_num'],sc['prior0_den']);res=ready;budget,deadline=resources;steps=[];spent_total=0
        for t,(request,signal) in enumerate(tape):
            _,belief=posterior(sc,belief,request,signal)
            obs={'step':t,'request':request,'signal':signal,'resident':res,'budget':budget,'deadline':deadline,
                 'belief_num':belief.numerator,'belief_den':belief.denominator}
            answer=reference(sc,obs);label=answer['winner'];action={'direct':-1,'cache-0':0,'cache-1':1,'abstain':None}[label]
            stateid=add_state(sc,obs,{'id':ident+f'/step-{t}','family':'natural-support','environment':name,
                'natural_posterior_claim':True,'profile':profile_id,'prefix':[list(e) for e in tape[:t+1]]});owner_states.add(stateid)
            row={'observation':obs,'action':action,'selected_action':label,'state_digest':digest(obs),'coverage_state_id':stateid}
            if action is None:
                row.update(status='abstained',predicted_cost=0,delivered=False);steps.append(row);break
            spent=costs(sc,obs)[label];res=action;budget-=spent;deadline-=spent;spent_total+=spent
            row.update(status='delivered',predicted_cost=spent,delivered=True,resident_after=res,remaining_budget=budget,remaining_deadline=deadline);steps.append(row)
        delivered=sum(row['delivered'] for row in steps)
        expected_tapes.append({'id':ident,'profile':profile_id,'environment':name,'tape':[list(e) for e in tape],
            'probability':[probability.numerator,probability.denominator],'steps':steps,'planned_requests':sc['horizon'],
            'delivered':delivered,'missing_requests':sc['horizon']-delivered,'modeled_cost':spent_total})
    check('natural_profile_probability_mass',mass==1,profile_id)
    expected_profiles.append({'id':profile_id,'scenario':sc,'tapes':64,'probability_sum':[1,1],'all_tapes_preserved':True})
for state in expected_states.values():state['families'].sort()
check('complete_exact_registered_state_inventory',registry['states']==[expected_states[k] for k in sorted(expected_states)] and len(expected_states)==5736)
check('all_supplied_and_natural_memberships',registry['memberships']==expected_memberships)
check('whole_profile_inventory',registry['natural_profiles']==expected_profiles and len(expected_profiles)==54)
check('whole_tape_inventory',len(expected_tapes)==len(registry['natural_tapes'])==3456)
for observed,expected in zip(registry['natural_tapes'],expected_tapes):
    check('complete_tape_prefix_posterior_action_and_denominator',all(observed.get(k)==v for k,v in expected.items()),expected['id'])
check('registration_natural_owner_count',registry['preparation']['owner_distinct_states']==len(owner_states)==2716
      and registry['preparation']['native_calls']==0)
print(json.dumps({'audit_progress':'complete registered inventory independently rebuilt','distinct_states':len(expected_states),'natural_states':len(owner_states)}),flush=True)

native_stream=(COVERAGE/'values.jsonl').open();hello=json.loads(next(native_stream));native_sequence=0;validation_wall=0;native_wire_wall=0
check('coverage_native_hello',hello['event']=='hello' and hello['binary_sha256']==registry['native_inputs']['binary']['sha256']
      and hello['manifest_sha256']==registry['native_inputs']['manifest']['sha256']
      and rawhash(hello['raw_response'].encode())==hello['response_sha256']
      and json.loads(hello['raw_response'])['identity']['upstream_commit']==UPSTREAM)

def consume_native(sc,obs,arm,context):
    global native_sequence,validation_wall,native_wire_wall
    exchange=json.loads(next(native_stream));validated=json.loads(next(native_stream));native_sequence+=1
    raw_req=exchange['request'].encode();raw_res=exchange['response'].encode();req=json.loads(raw_req);res=json.loads(raw_res)
    expected=reference(sc,obs,arm);values=expected['values'];eligible=expected['eligible']
    winners=sorted(k for k,v in values.items() if eligible[k] and v==expected['value'])
    check('coverage_raw_frame_hashes',exchange['event']=='exchange' and rawhash(raw_req)==exchange['request_sha256']
          and rawhash(raw_res)==exchange['response_sha256'],context)
    check('coverage_raw_frame_sequence',exchange['sequence']==req['sequence']==res['sequence']==native_sequence,context)
    check('coverage_request_closed_schema',set(req)=={'schema','sequence','generation','state_digest','preference_digest','objective_digest',
          'resource_budget_q32','risk_ceiling_q32','candidates'},context)
    check('coverage_every_backup_state_preferences_budget',req['state_digest']==digest(obs)
          and req['preference_digest']==digest(expected['preference'])
          and req['objective_digest']==digest({'rule':'state-price-plus-discounted-mean-downside-v1','scenario':sc})
          and req['resource_budget_q32']==rounded(min(obs['budget'],obs['deadline'])*Q,sc['cost_unit'])
          and req['risk_ceiling_q32']==Q and req['candidates']==expected['candidates'],context)
    check('coverage_native_response_identity',all(req[k]==res[k] for k in ('generation','state_digest','preference_digest','objective_digest'))
          and res['request_sha256']==exchange['request_sha256'] and res['upstream_commit']==UPSTREAM,context)
    check('coverage_native_authority_and_entrypoints',res['projection_count']==0 and res['authority']=='DENY_ALL'
          and res['execution_authorized'] is False and res['safety_certificate'] is False
          and res['entry_points']==['codex_hepta_ndu::evaluate_recursive_utility','codex_hepta_ndu::evaluate_candidates_with_policy'],context)
    check('coverage_every_backup_values_and_choice_exact',res['values_q32']==values and res['eligible']==eligible
          and res['winners']==winners and res['chosen_id']==winners[0]
          and sorted(r['id'] for r in res['rejected'])==sorted(k for k,v in eligible.items() if not v),context)
    for i,candidate in enumerate(req['candidates']):
        value=candidate['instant_q32']+mul(candidate['discount_q32'],candidate['terminal_q32'])
        check('coverage_original_recursive_digest',res['path_receipts'][i]=={'id':candidate['id'],
            'recursive_evidence_digest':recursive_digest(req,raw_req,i,candidate,value)},context)
        counts['coverage_native_candidates']+=1
    check('coverage_transport_validation_binding',validated['event']=='validated' and validated['sequence']==native_sequence
          and validated['values_q32']==values and validated['winners']==winners
          and validated['outer_call_ns']>=exchange['wire_roundtrip_ns']>=0,context)
    validation_wall+=validated['outer_call_ns'];native_wire_wall+=exchange['wire_roundtrip_ns']

rows=coverage['rows'];states=registry['states'];by_id={r['id']:r for r in rows};work=Counter();strict_states=[]
check('complete_state_results_order',len(rows)==len(states)==5736 and [r['id'] for r in rows]==[s['id'] for s in states])
checkpoint=(COVERAGE/'RESULT.states.jsonl').open()
arm_order=('same-objective','ordinary-mpc','state-greedy','wrong-forecast','no-adaptation','exact-oracle','dynamic-ndu','fixed-preference-ndu')
for index,(row,state) in enumerate(zip(rows,states)):
    sc=state['scenario'];obs=state['observation'];identifier=state['id'];context=(index,identifier)
    check('state_checkpoint_retained_exact',json.loads(next(checkpoint))==row,context)
    check('state_result_identity',all(row[k]==state[k] for k in ('id','scenario','observation','families'))
          and row['environment']==sc['name'],context)
    check('state_qualification_original_native',row['status']=='passed' and row['original_native_executed'] is True
          and row['qualification_type']=='original-native' and row['authority']=='DENY_ALL',context)
    check('state_complete_arm_inventory',set(row['answers'])==set(arm_order)
          and tuple(a['arm'] for a in row['attempts'])==(*arm_order,'fixed-policy-value'),context)
    exact=reference(sc,obs);regret={};refs={}
    for arm,answer in row['answers'].items():
        expected=reference(sc,obs,arm);refs[arm]=expected
        check('all_arms_independent_values_actions_preferences',answer['value_q32']==expected['value']
              and answer['candidate_values_q32']==expected['values'] and answer['selected_action']==expected['winner']
              and answer['action']=={'direct':-1,'cache-0':0,'cache-1':1,'abstain':None}[expected['winner']]
              and answer['preference']==expected['preference'],(index,arm))
        regret[arm]=exact['value']-exact['values'][answer['selected_action']]
        check('all_arms_external_feasibility',exact['eligible'][answer['selected_action']],(index,arm))
    check('all_arms_external_regret_recomputed',regret==row['external_conditional_regret_q32'],context)
    fixed=reference(sc,obs,'fixed-policy-value')
    check('fixed_whole_policy_value_independent',row['fixed_policy']['value_q32']==fixed['value']<=exact['value']
          and row['fixed_policy']['fixed_action']==p['registered_fixed_action'],context)
    dynamic=refs['dynamic-ndu'];fixed_pref=refs['fixed-preference-ndu']
    flags={'same_objective_exact':refs['same-objective']['values']==dynamic['values']==exact['values'],
        'same_feasibility':dynamic['eligible']==fixed_pref['eligible'],
        'root_preference_numeric_change':any(dynamic['preference'][k]!=fixed_pref['preference'][k] for k in ('price_q32','discount_q32','risk_q32')),
        'recursive_numeric_change':dynamic['values']!=fixed_pref['values'],
        'preference_action_change':dynamic['winner']!=fixed_pref['winner'],
        'preference_external_gain':regret['fixed-preference-ndu']>0,
        'preference_both_deliver':dynamic['winner']!='abstain' and fixed_pref['winner']!='abstain',
        'state_information_value':regret['no-adaptation']>0,
        'planning_value_over_greedy':regret['state-greedy']>0,
        'misleading_belief_cost':regret['wrong-forecast']>0,
        'fixed_policy_sufficient':fixed['value']==exact['value']}
    flags['strict_preference_action_reversal']=all(flags[k] for k in ('same_objective_exact','same_feasibility','preference_action_change','preference_external_gain','preference_both_deliver'))
    check('all_mechanism_flags_recomputed',row['flags']==flags,context)
    if flags['strict_preference_action_reversal']:
        strict_states.append({'state_id':identifier,'environment':sc['name'],'families':state['families'],'observation':obs,
            'dynamic_action':dynamic['winner'],'fixed_preference_action':fixed_pref['winner'],
            'dynamic_preference':dynamic['preference'],'fixed_preference':fixed_pref['preference'],
            'dynamic_candidate_values_q32':dynamic['values'],'fixed_preference_candidate_values_q32':fixed_pref['values'],
            'fixed_preference_external_regret_q32':regret['fixed-preference-ndu']})
    for attempt in row['attempts']:
        arm=attempt['arm'];stats=attempt['search'];work[arm]+=stats['transitions']
        check('all_attempts_cost_and_budget_retained',attempt['status']=='completed' and attempt['wall_ns']>=0
              and 0<=stats['transitions']<=p['per_decision_transition_cap'],(index,arm))
        if arm!='fixed-policy-value':
            check('attempt_answer_search_binding',stats==row['answers'][arm]['search']
                  and attempt['wall_ns']>=row['answers'][arm]['controller_wall_ns'],(index,arm))
        else:check('fixed_policy_search_binding',stats['transitions']==row['fixed_policy']['transitions'] and attempt['wall_ns']>=row['fixed_policy']['wall_ns'],index)
    check('state_whole_wall_contains_attempts',row['wall_ns']>=sum(a['wall_ns'] for a in row['attempts']),index)
    first=native_sequence+1;nodes=node_order(sc,obs)
    for arm in ('dynamic-ndu','fixed-preference-ndu'):
        stats=row['answers'][arm]['search']
        check('native_full_search_topology_counts',stats['backend_calls']==stats['backups']==stats['states']==len(nodes)
              and stats['transitions']==4*len(nodes), (index,arm))
        for node in nodes:consume_native(sc,node,arm,(index,arm,native_sequence+1))
    check('native_request_range_contiguous',row['native_request_range']==[first,native_sequence],index)
    if (index+1)%1000==0:print(json.dumps({'audit_progress':'independent state models and all native frames','states':index+1,'native_frames':native_sequence}),flush=True)
check('checkpoint_exact_end',next(checkpoint,None) is None);checkpoint.close()
close=json.loads(next(native_stream));check('coverage_native_exact_log_end',next(native_stream,None) is None);native_stream.close()
check('coverage_native_clean_close',close['event']=='close' and close['calls']==native_sequence==coverage['native_calls']==167976
      and close['returncode']==0 and close['reaped'] is True and not close['stderr'] and close['stderr_over_bound'] is False)
check('coverage_native_cost_sums',close['total_call_ns']==validation_wall==coverage['native_close']['call_wall_ns']
      and validation_wall>=native_wire_wall>=0)
check('coverage_work_ledger',dict(work)==coverage['work'] and all(v<=p['per_arm_transition_cap'] for v in work.values()) and not coverage['unknown_work_counters'])
check('coverage_no_hidden_failure_or_dropped_denominator',coverage['status']=='passed' and coverage['all_states_original_native_qualified'] is True
      and coverage['completed_states']==coverage['planned_distinct_states']==5736
      and coverage['failed_states']==coverage['not_run_states']==0 and not coverage['errors']
      and coverage['planned_supplied_memberships']==3030 and coverage['planned_natural_tapes']==3456)

summary=coverage['summary'];flags_to_count=('root_preference_numeric_change','recursive_numeric_change','preference_action_change',
    'preference_external_gain','state_information_value','planning_value_over_greedy','misleading_belief_cost','fixed_policy_sufficient','strict_preference_action_reversal')
summary_counts={};logical_witnesses={}
for family in ('all-distinct','supplied-grid','supplied-boundary','natural-support'):
    summary_counts[family]={}
    for name in p['environments']:
        selected=[r for r in rows if r['environment']==name and (family=='all-distinct' or family in r['families'])]
        table={'distinct_states':len(selected),'passed':sum(r['status']=='passed' for r in selected),
               **{flag:sum(r['flags'][flag] for r in selected) for flag in flags_to_count}}
        summary_counts[family][name]=table;key=family+'/'+name;logical_witnesses[key]={}
        for flag in flags_to_count:
            matches=sorted(r['id'] for r in selected if r['flags'][flag])
            logical_witnesses[key][flag]={'all_state_ids':matches,'first_state_id':matches[0] if matches else None}
check('all_summary_counts_recomputed',summary_counts==summary['counts'])
check('all_logical_witnesses_lexicographic',logical_witnesses==summary['witnesses'])
natural_profile_stats=[]
for profile in registry['natural_profiles']:
    tapes=[t for t in expected_tapes if t['profile']==profile['id']];event_counts=Counter();masses={f:Fraction() for f in flags_to_count}
    expected_missing=sum(Fraction(*t['probability'])*t['missing_requests'] for t in tapes)
    for tape in tapes:
        state_rows=[by_id[s['coverage_state_id']] for s in tape['steps']]
        for flag in flags_to_count:
            has=any(s['flags'][flag] for s in state_rows);event_counts[flag]+=has
            if has:masses[flag]+=Fraction(*tape['probability'])
    stat={'id':profile['id'],'environment':profile['scenario']['name'],'tapes':len(tapes),'probability_sum':[1,1],
        'unqualified_state_references':0,'expected_missing_requests':[expected_missing.numerator,expected_missing.denominator],
        'tape_event_counts':dict(event_counts),'tape_event_probability':{f:[v.numerator,v.denominator] for f,v in masses.items()}}
    published=next(r for r in summary['natural_profile_coverage'] if r['id']==profile['id'])
    check('exact_natural_profile_counts_and_probabilities',all(published[k]==v for k,v in stat.items()),profile['id'])
    natural_profile_stats.append(stat)
check('summary_scientific_claim_boundaries',summary['net_benefit_established'] is False and summary['ndu_exclusive_advantage_established'] is False)
coverage_native_counts={'sessions':1,'native_value_calls':native_sequence,'candidate_recursive_digests':counts['coverage_native_candidates'],
                        'exact_full_root_answers':len(rows)*len(arm_order),'fixed_full_policies':len(rows)}
print(json.dumps({'audit_progress':'complete coverage arithmetic, native chain and summary verified','failures':sum(failed_checks.values()),**coverage_native_counts}),flush=True)

# Selection uses the frozen source's JSON member order for stable annotations;
# every qualifying match and every empty group is independently recomputed.
wp=json.loads(blobs['benchmarks/hia_ndu_feedback_state_coverage/WITNESS_PROTOCOL.json'])
selected_cells={};memberships=[]
for family in wp['families']:
    for name in wp['environments']:
        for mechanism,definition in wp['mechanisms'].items():
            matches=sorted((r for r in rows if r['status']=='passed' and r['environment']==name
                and (family=='all-distinct' or family in r['families']) and all(r['flags'][f] for f in definition['flags'])),key=lambda r:r['id'])
            state=matches[0] if matches else None
            membership={'family':family,'environment':name,'mechanism':mechanism,'matching_state_count':len(matches),
                        'selected_state_id':state['id'] if state else None};memberships.append(membership)
            if state is not None:
                for arm in ('dynamic-ndu','same-objective',definition['comparison_arm']):
                    selected_cells.setdefault((state['id'],arm),{'state_id':state['id'],'arm':arm,'scenario':state['scenario'],
                        'observation':state['observation'],'coverage_action':state['answers'].get(arm,{}).get('action'),'memberships':[]})['memberships'].append(membership)
cells=[selected_cells[k] for k in sorted(selected_cells)]
selection={'memberships':memberships,'cells':cells}
check('witness_complete_lexicographic_selection',wreg['selection']==selection and len(memberships)==24 and len(cells)==43)
check('witness_empty_groups_retained',wresult['memberships']==memberships)
DATA=WITNESS;registration=wreg
value_log_frames,workload_log_frames=audit_raw_sessions();witness_rows=[];preference_physical=defaultdict(dict)
for index,cell in enumerate(cells):
    directory=WITNESS/'cells'/f'{index:03d}';row=load(directory/'RESULT.json');sc=cell['scenario'];obs=cell['observation'];d=row['decision']
    check('witness_exact_cell_identity',all(row[k]==v for k,v in cell.items()) and row['cell_index']==index,index)
    check('witness_complete_actual_execution',row['status']=='passed' and row['physically_executed'] is True and not row['errors']
          and row['authority']=='DENY_ALL' and d['authority']=='DENY_ALL' and d['production_activation'] is False,index)
    expected=reference(sc,obs,'state-greedy' if cell['arm']=='fixed' else cell['arm'])
    if cell['arm']=='fixed':
        physical=costs(sc,obs);eligible=expected['eligible']
        label='cache-0' if eligible['cache-0'] else min((k for k in physical if eligible[k]),key=lambda k:(physical[k],k),default='abstain')
        expected={**expected,'winner':label,'value':expected['values'][label]}
    check('witness_independent_decision',d['observation']==obs and d['state_digest']==digest(obs)
          and d['value_q32']==expected['value'] and d['candidate_values_q32']==expected['values']
          and d['selected_action']==expected['winner'] and d['preference']==expected['preference'],index)
    if cell['arm']!='fixed':check('witness_coverage_action_preserved',d['action']==cell['coverage_action'],index)
    frames=workload_log_frames[directory/'workload.jsonl'];init=frames[0][0]
    check('witness_matrix_and_quota_binding',init['seed']==wp['matrix_seed'] and init['n']==wp['dimension'],index)
    offset=1+int(obs['resident']>=0)
    check('witness_initial_residency',frames[offset-1][1]['state']['ready']==([] if obs['resident']==-1 else [obs['resident']]),index)
    outcome=row['physical_outcome'];check('witness_attempt_exactly_retained',row['workload_attempts']==[outcome]
        and outcome['status']=='success' and outcome['pending_command'] is None,index)
    check('witness_state_generation_digests',outcome['generation']==1 and outcome['before_digest']==digest({'generation':0,'state':outcome['before']})
          and outcome['after_digest']==digest({'generation':1,'state':outcome['after']})
          and outcome['before']==frames[offset-1][1]['state'],index)
    for command in outcome['commands']:
        req,res,raw=frames[offset];offset+=1
        check('witness_command_raw_binding',command['command']==req and command['result']==res and command['wire_ns']==raw['wire_roundtrip_ns'],(index,offset))
    req,res,_=frames[offset-1]
    check('witness_output_action_consumption',req['command']=='run' and req['id']==obs['request']
          and req['vector_seed']==wp['vector_seed'] and req['repeats']==wp['kernel_repeats']
          and outcome['checksum']==res['result']['checksum'] and outcome['after']==res['state']
          and outcome['selected_resident']==outcome['executed_resident']==d['action']
          and outcome['after']['ready']==([] if d['action']==-1 else [d['action']]),index)
    check('witness_all_physical_commands_consumed',offset==len(frames)-1 and frames[-1][0]['command']=='close',index)
    check('witness_clean_costed_close',row['workload_close']['final_state']==frames[-1][1]['state']
          and row['workload_close']['returncode']==0 and row['workload_close']['error'] is None,index)
    check('witness_whole_actual_cost_nesting',row['workload_wall_ns']==outcome['workload_wall_ns']
          and row['wall_ns']>=d['controller_wall_ns']+row['workload_wall_ns']
          and outcome['workload_wall_ns']>=sum(c['wire_ns'] for c in outcome['commands'])
          and outcome['native_service_ns']==sum(c['result']['service_ns'] for c in outcome['commands']),index)
    vframes=value_log_frames.get(directory/'values.jsonl',[])
    if cell['arm'] in ('dynamic-ndu','fixed-preference-ndu'):
        nodes=node_order(sc,obs)
        check('witness_native_all_backup_counts',len(nodes)==len(vframes)==d['search']['backend_calls']==len(d['search_trace']),index)
        for ni,(node,(req,res,raw)) in enumerate(zip(nodes,vframes)):
            ref=reference(sc,node,cell['arm']);trace=d['search_trace'][ni]
            check('witness_native_independent_all_backup_values',req['state_digest']==digest(node)==trace['state_digest']
                  and req['preference_digest']==digest(ref['preference']) and req['candidates']==ref['candidates']
                  and req['resource_budget_q32']==rounded(min(node['budget'],node['deadline'])*Q,sc['cost_unit'])
                  and res['values_q32']==ref['values']==trace['values_q32'] and res['chosen_id']==ref['winner']==trace['selected'],(index,ni))
        check('witness_native_root_consumed',vframes[-1][1]['chosen_id']==d['selected_action']
              and vframes[-1][0]['candidates']==d['candidates'] and vframes[-1][1]['values_q32']==d['candidate_values_q32'],index)
    else:check('ordinary_witness_no_native_values',not vframes and d['search']['backend_calls']==0,index)
    if any(m['mechanism']=='numeric_preference' for m in row['memberships']):
        preference_physical[row['state_id']][row['arm']]={'cell_index':index,'action':d['selected_action'],
            'preference':d['preference'],'checksum':outcome['checksum'],'dispatch':outcome['dispatch'],
            'actual_workload_wall_ns':row['workload_wall_ns'],'abstract_budget':obs['budget'],
            'abstract_deadline':obs['deadline'],'observation':obs}
    witness_rows.append(row)
for identity,by_arm in preference_physical.items():
    check('physical_numeric_action_reversal',by_arm['dynamic-ndu']['action']==by_arm['same-objective']['action']
          and by_arm['dynamic-ndu']['action']!=by_arm['fixed-preference-ndu']['action'],identity)
    check('physical_candidate_outputs_equal_despite_dispatch_change',len({r['checksum'] for r in by_arm.values()})==1,identity)
check('witness_summary_denominator_and_cost',wresult['planned_cells']==wresult['retained_cells']==wresult['physical_actions']==len(witness_rows)==43
      and wresult['explicit_abstentions']==0 and wresult['total_cell_wall_ns']==sum(r['wall_ns'] for r in witness_rows)
      and all(wresult['checks'].values()) and not wresult['fatal_error'] and not wresult['postflight_errors'])
check('witness_claim_boundary',wresult['production_activation'] is False and wresult['unique_NDU_advantage_claim'] is False)

freeze_receipt=load(COVERAGE/'freeze.receipt.json');coverage_receipt=load(COVERAGE/'qualification.receipt.json')
witness_receipt=load(BASE/'physical-witness-final-v1.receipt.json')
for receipt in (freeze_receipt,coverage_receipt,witness_receipt):
    check('outer_process_receipts',receipt['returncode']==0 and receipt['source']==EXPECTED_COMMIT and receipt['authority']=='DENY_ALL')
check('coverage_registration_preparation_cost_retained',freeze_receipt['wall_ns']>=registry['preparation']['wall_ns']>=0)
check('coverage_qualification_cost_nesting',coverage_receipt['wall_ns']>=coverage['outer_wall_ns']>=coverage['qualification_wall_ns']
      >=sum(r['wall_ns'] for r in rows)+coverage['preflight_wall_ns']+coverage['postflight_wall_ns'])
check('witness_cost_nesting',witness_receipt['wall_ns']>=wresult['wall_before_report_ns']>=sum(r['wall_ns'] for r in witness_rows))
known_files=[COVERAGE/name for name in ('REGISTRATION.json','RESULT.json','RESULT.states.jsonl','values.jsonl',
    'freeze.receipt.json','qualification.receipt.json','freeze.stdout','freeze.stderr','qualification.stdout','qualification.stderr')]
known_files.extend(f for f in WITNESS.rglob('*') if f.is_file())
manifests={str(f.relative_to(BASE)):file_identity(f) for f in sorted(known_files)}
review={
 'schema':'hepta.hia.ndu.state-coverage-independent-review.v1',
 'status':'PASS_INTEGRITY_FINITE_MECHANISM_WITH_NATURAL_PREFERENCE_GAP' if not failures else 'FAIL_INTEGRITY',
 'reviewer':'independent_gates; separately encoded full state/arm/policy arithmetic and every original native frame',
 'source':{'commit':EXPECTED_COMMIT,'tree':EXPECTED_TREE},'post_measurement_worktree_differences':post_measurement_differences,
 'scope':'Read-only complete registry, state checkpoint, native value stream and physical witness audit; no controller/native rerun, retuning or original artifact mutation.',
 'audit_source':file_identity(Path(__file__)),'coverage_registration':file_identity(COVERAGE/'REGISTRATION.json'),
 'coverage_result':file_identity(COVERAGE/'RESULT.json'),'witness_registration':file_identity(WITNESS/'REGISTRATION.json'),
 'witness_result':file_identity(WITNESS/'RESULT.json'),
 'check_counts':dict(checks),'failed_check_counts':dict(failed_checks),'failures':failures,
 'inventory':{'distinct_states':len(rows),'supplied_memberships':3030,'natural_distinct_states':len(owner_states),
              'natural_profiles':len(expected_profiles),'natural_tapes':len(expected_tapes),
              'natural_planned_requests':sum(t['planned_requests'] for t in expected_tapes),
              'natural_delivered_model_requests':sum(t['delivered'] for t in expected_tapes),
              'natural_missing_model_requests':sum(t['missing_requests'] for t in expected_tapes),
              'natural_tapes_with_missing_requests':sum(t['missing_requests']>0 for t in expected_tapes),
              'physical_groups':len(memberships),'empty_physical_groups':sum(m['selected_state_id'] is None for m in memberships),
              'physical_cells':len(witness_rows),'physical_actual_dispatches':sum(r['physically_executed'] for r in witness_rows)},
 'coverage_native':coverage_native_counts,
 'witness_native_and_workload':{k:v for k,v in counts.items() if not k.startswith('coverage_')},
 'counts':summary_counts,'strict_preference_states':strict_states,'natural_profile_coverage':natural_profile_stats,
 'physical_witness_memberships':memberships,'physical_numeric_preference_triplets':dict(preference_physical),
 'costs':{'registration_outer_wall_ns':freeze_receipt['wall_ns'],'registration_model_preparation_wall_ns':registry['preparation']['wall_ns'],
          'qualification_outer_wall_ns':coverage_receipt['wall_ns'],'qualification_internal_outer_wall_ns':coverage['outer_wall_ns'],
          'qualification_state_attempt_wall_ns':sum(r['wall_ns'] for r in rows),'native_value_transport_validation_wall_ns':validation_wall,
          'native_wire_roundtrip_wall_ns':native_wire_wall,'native_close':coverage['native_close'],
          'witness_outer_wall_ns':witness_receipt['wall_ns'],'witness_cell_wall_ns':sum(r['wall_ns'] for r in witness_rows),
          'witness_workload_wall_ns':sum(r['workload_wall_ns'] for r in witness_rows),
          'scope':'These are qualification costs, not a deployment gain estimate. Native/service/controller costs are nested; do not add them to their enclosing wall clocks.'},
 'work_ledger':dict(work),
 'findings':[
   'All 5736 distinct states, all eight comparison-arm answers, and all fixed complete-policy values match an independent evaluator. The ordinary same-objective controller and original-native dynamic NDU agree everywhere.',
   'Every one of the 167976 original-native value exchanges is independently bound to its reconstructed internal search observation, numeric preference, budget, candidate continuation values and winner. All 671904 original recursive digests are recomputed.',
   'There are 24 strict numerical-preference action reversals, twelve each in adaptive and misleading environments. All occur in the separately supplied boundary mesh; ordinary same-objective planning produces the same improved actions.',
   'Complete natural-support coverage has 2716 distinct reachable owner-policy states and zero numerical-preference action reversals or strict external gains. Numeric values do change there; this is an exercised no-action-change result, not absent native consumption.',
   'Natural-support model prediction interventions have 164 positive-regret states and planning beats current-state greedy at 138 states. These are generic model and planning contributions; no NDU-exclusive advantage follows.',
   'All 24 prospectively defined physical witness groups are retained, including empty groups. The 43 deduplicated selected cells perform real dispatch with independently recomputed output checksums. Two numerical-preference state triplets physically execute opposite choices with unchanged valid output.',
   'Witness resource quantities remain abstract model units. Physical residency is recreated and the current action is consumed; witness nanoseconds do not create a naturally reached physical history or prove a latency benefit.'
 ],
 'limitations':[
   'Boundary-grid development was disclosed before the native qualification; this finite complete mesh is mechanism testing, not an independent random performance holdout.',
   'Natural support is all event tapes under a registered ordinary owner policy, not the reachable state union of every possible policy. Distinct states and correlated prefixes are not IID samples.',
   'Supplied posterior/resource states are valid interface inputs but are not asserted to arise from the natural-support initial prior and histories.',
   'Fixed-policy sufficiency is conditional on each current public state and registered feasibility fallback; the environment label fixed does not guarantee fixed sufficiency in every supplied boundary state.',
   'Frame/source/checksum consistency is strong execution evidence, not external hardware attestation or a malicious-process sandbox.',
   'Neither this coverage suite nor its physical witnesses establish full lifecycle net benefit, learned gradients, general workload performance, or NDU-exclusive advantage.',
 ],
 'raw_evidence_manifest':manifests,'audit_wall_ns':time.perf_counter_ns()-started,
}
OUT.write_text(json.dumps(review,sort_keys=True,indent=2)+'\n')
print(json.dumps({k:review[k] for k in ('status','failed_check_counts','inventory','coverage_native','witness_native_and_workload','costs','audit_wall_ns')},indent=2))
if failures:print(json.dumps(failures[:30],indent=2))
raise SystemExit(bool(failures))

#!/usr/bin/env python3
"""Descriptive aggregation only; independent arithmetic review is a separate file."""
import gzip
import hashlib
import json
from collections import Counter, defaultdict
from decimal import Decimal
from pathlib import Path

ROOT = Path('/workspace/scratch/22f6defbc03d')
RUN = ROOT / 'policy-final-v1'
Q32 = 1 << 32

def read(path):
    with (gzip.open if path.suffix == '.gz' else open)(path, 'rt') as f:
        return json.load(f)

def units(value):
    return str(Decimal(value) / Q32)

def sign(value):
    return 'positive' if value > 0 else 'negative' if value < 0 else 'zero'

def identity(path):
    data = path.read_bytes()
    return {'path': str(path), 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}

def main():
    result = read(RUN / 'RESULT.json')
    assert result['status'] == 'passed', result['status']
    assert result['planned_states'] == result['retained_states'] == 10224
    assert result['planned_cells'] == 122688
    profiles = defaultdict(list)
    state_stats = defaultdict(lambda: defaultdict(Counter))
    state_factorial = defaultdict(lambda: defaultdict(Counter))
    counts = Counter()
    native = defaultdict(Counter)
    examples = {}
    for p in result['profiles']:
        env = p['scenario']['name']
        profiles[env].append(p)
        rows = read(RUN / p['id'] / 'STATE_RESULTS.json.gz')
        counts[env] += len(rows)
        for arm, cost in p['costs'].items():
            if cost['native_close'] is not None:
                close = cost['native_close']
                native[arm]['calls'] += close['calls']
                native[arm]['processes'] += int(close['started'])
                native[arm]['clean_process_exits'] += int(close['returncode'] == 0)
            native[arm]['planning_wall_including_cleanup_ns'] += cost['planning_wall_including_native_cleanup_ns']
            native[arm]['policy_evaluation_wall_ns'] += cost['policy_evaluation_wall_ns']
        for row in rows:
            arms = row['arms']
            oracle = arms['exact-oracle']
            for arm, cell in arms.items():
                c = state_stats[env][arm]
                c['states'] += 1
                c['completed'] += cell['status'] == 'completed'
                c['action_differs_from_oracle'] += cell['action'] != oracle['action']
                c['first_action_positive_regret'] += cell['first_action_conditional_regret_q32'] > 0
                c['whole_policy_positive_regret'] += cell['whole_policy_regret_q32'] > 0
                c['first_action_zero_whole_policy_positive'] += cell['first_action_conditional_regret_q32'] == 0 and cell['whole_policy_regret_q32'] > 0
                c['candidate_values_differ_from_oracle'] += cell['candidate_values_q32'] != oracle['candidate_values_q32']
                c['preference_differs_from_dynamic'] += cell['preference'] != arms['dynamic-ndu']['preference']
                if cell['first_action_conditional_regret_q32'] == 0 and cell['whole_policy_regret_q32'] > 0:
                    examples.setdefault('zero_first_action_positive_whole_policy', {'profile':p['id'],'state_id':row['id'],'arm':arm,'observation':row['observation'],'first_action_conditional_regret_q32':0,'whole_policy_regret_q32':cell['whole_policy_regret_q32']})
            for k, v in row['whole_policy_factorial'].items():
                if k.endswith('_q32') and isinstance(v, int):
                    state_factorial[env][k][sign(v)] += 1
    environment_summaries = {}
    for env, ps in profiles.items():
        arm_summaries = {}
        for arm in result['per_arm_ledgers']:
            regrets = [p['policies']['exact-oracle']['value_q32'] - p['policies'][arm]['value_q32'] for p in ps]
            arm_summaries[arm] = {'profile_count':len(ps),'regret_signs':dict(Counter(sign(x) for x in regrets)),
                'sum_profile_regret_q32':sum(regrets),'mean_profile_regret_units':str(Decimal(sum(regrets))/len(ps)/Q32),
                'maximum_profile_regret_units':units(max(regrets)),
                'incomplete_expected_delivery_profiles':sum(p['policies'][arm]['expected_delivered'][0] < p['scenario']['horizon'] * p['policies'][arm]['expected_delivered'][1] for p in ps)}
        fixed_regrets = [p['policies']['exact-oracle']['value_q32'] - p['model_optimal_fixed']['value_q32'] for p in ps]
        factors = defaultdict(Counter)
        for p in ps:
            for k,v in p['factorial'].items():
                if k.endswith('_q32') and isinstance(v,int): factors[k][sign(v)] += 1
        environment_summaries[env] = {'profiles':len(ps),'states':counts[env],'arms':arm_summaries,
            'strongest_fixed':{'regret_signs':dict(Counter(sign(x) for x in fixed_regrets)),
                'sum_profile_regret_q32':sum(fixed_regrets),'mean_profile_regret_units':str(Decimal(sum(fixed_regrets))/len(ps)/Q32),
                'maximum_profile_regret_units':units(max(fixed_regrets)),
                'selected_arms':dict(Counter(p['model_optimal_fixed']['arm'] for p in ps))},
            'whole_profile_factorial_signs':dict(factors)}
    output = {'schema':'hepta.hia.ndu.policy-descriptive-summary.v1','source':result['source'],
        'result':identity(RUN/'RESULT.json'),'status':result['status'],'checks':result['checks'],
        'profiles':result['retained_profiles'],'states':result['retained_states'],'cells':result['planned_cells'],
        'cell_status_counts':dict(sum((Counter(p['cell_status_counts']) for p in result['profiles']), Counter())),
        'state_counts_by_environment':dict(counts),'environments':environment_summaries,
        'state_comparisons':state_stats,'state_factorial_signs':state_factorial,'costs_by_arm':native,
        'per_arm_ledgers':result['per_arm_ledgers'],'freeze_wall_ns':result['freeze_wall_ns'],
        'campaign_wall_before_report_ns':result['wall_before_report_ns'],'examples':examples,
        'scope':'Descriptive coverage counts, not IID observations. Same finite model, externally evaluated full policies. Audit timings are not physical deployment advantage endpoints.',
        'independent_verification':'See separate independent-policy-review.json; this script only aggregates retained results.',
        'full_lifecycle_cost_known':False,'ndu_exclusive_advantage_established':False,'production_activation':False,'authority':'DENY_ALL'}
    path=ROOT/'policy-descriptive-summary.json'
    with path.open('x') as f: json.dump(output,f,indent=2,sort_keys=True); f.write('\n')
    print(json.dumps({'output':str(path),'profiles':output['profiles'],'states':output['states'],'cells':output['cells'],'statuses':output['cell_status_counts'],'environments':environment_summaries,'native_calls':{a:c['calls'] for a,c in native.items() if c['calls']},'wall_ns':output['campaign_wall_before_report_ns']},sort_keys=True))

if __name__ == '__main__':
    main()

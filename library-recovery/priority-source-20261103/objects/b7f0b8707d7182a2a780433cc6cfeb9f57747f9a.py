#!/usr/bin/env python3
"""Finite, independent *advisory* optimization-accounting experiment.

This is a same-information fixed/greedy/DP/exhaustive control harness.
NO native hepta NDU is called; NDU and application net-benefit gates stay open.
"""
from __future__ import annotations
import itertools
from hia_probe import Rejected, identity, reject

COST_FIELDS=('compile_ns','verify_ns','measure_ns','switch_ns',
             'rollback_reserve_ns','cleanup_ns','prepare_ns')
MAX_JOBS=8
MAX_CANDIDATES=6
MAX_PLANS=100_000


def validate_experiment(record: object) -> dict:
    if type(record) is not dict or set(record)!={'schema','study_kind','frozen_source_digest','objective_digest','max_one_time_ns','jobs'}:
        reject('E_MODEL','exact experiment schema required')
    if record['schema']!='hepta.audit.net-benefit.v1' or record['study_kind'] not in ('synthetic','measured'):
        reject('E_MODEL','study type or version')
    for k in ('frozen_source_digest','objective_digest'):
        v=record[k]
        if type(v) is not str or len(v)!=64 or any(c not in '0123456789abcdef' for c in v):
            reject('E_PROVENANCE','must be fixed lowercase sha256')
    budget=record['max_one_time_ns']
    if type(budget) is not int or budget < 0 or budget > 10**15:
        reject('E_BUDGET','invalid one-time optimization budget')
    jobs=record['jobs']
    if type(jobs) is not list or not 1<=len(jobs)<=MAX_JOBS:
        reject('E_MODEL','bounded jobs only')
    ids=set()
    for job in jobs:
        if type(job) is not dict or set(job)!={'id','invocations','baseline_run_ns','candidates'}:
            reject('E_JOB','exact job schema')
        if type(job['id']) is not str or not job['id'] or job['id'] in ids:
            reject('E_JOB','unique name required')
        ids.add(job['id'])
        for key in ('invocations','baseline_run_ns'):
            if type(job[key]) is not int or not 1<=job[key]<=10**12:
                reject('E_JOB','invalid invocation or runtime')
        cs=job['candidates']
        if type(cs) is not list or len(cs)>MAX_CANDIDATES:
            reject('E_MODEL','candidate budget')
        candidate_ids=set()
        for c in cs:
            if type(c) is not dict or set(c)!={'id','run_ns','verified_core_digest',*COST_FIELDS}:
                reject('E_CANDIDATE','exact candidate schema')
            if type(c['id']) is not str or not c['id'] or c['id']=='baseline' or c['id'] in candidate_ids:
                reject('E_CANDIDATE','unique candidate IDs required')
            candidate_ids.add(c['id'])
            for key in ('run_ns',*COST_FIELDS):
                if type(c[key]) is not int or not 0<=c[key]<=10**12:
                    reject('E_COST','no unknown or negative costs permitted')
            dig=c['verified_core_digest']
            if type(dig) is not str or len(dig)!=64 or any(x not in '0123456789abcdef' for x in dig):
                reject('E_PROVENANCE','identity is evidence identity, not proof')
    return record


def score_option(job: dict, option: dict | None) -> tuple[int,int]:
    if option is None:
        return (0,0)
    prep=sum(option[k] for k in COST_FIELDS)
    saved=job['invocations'] * (job['baseline_run_ns']-option['run_ns'])-prep
    return (prep,saved)


def options(job: dict) -> list[dict|None]:
    return [None,*job['candidates']]


def _output(study: dict, label: str, selected: list[dict|None]) -> dict:
    if len(selected)!=len(study['jobs']):
        reject('E_PLAN','incomplete plan')
    one_time=0; net=0; parts=[]
    for job,choice in zip(study['jobs'],selected):
        prep,saved=score_option(job,choice)
        one_time+=prep;net+=saved
        parts.append({'job':job['id'],'variant':choice['id'] if choice else 'baseline',
                      'one_time_ns':prep,'net_savings_ns':saved})
    return {'strategy':label,'plan':parts,'one_time_ns':one_time,
            'net_savings_ns':net,'within_budget':one_time<=study['max_one_time_ns'],
            'source_digest':study['frozen_source_digest'],'objective_digest':study['objective_digest'],
            'advisory_only':True, 'authority':'DENY_ALL', 'safety_certificate':False}


def exact_exhaustive(record: object) -> dict:
    study=validate_experiment(record)
    choices=[options(j) for j in study['jobs']]
    count=1
    for group in choices:
        count*=len(group)
        if count>MAX_PLANS:
            reject('E_ENUM_BUDGET','too many candidate combinations for oracle')
    winner=_output(study,'exhaustive',[None for _ in choices])
    best_key=(0,0,tuple('baseline' for _ in choices))
    for choice in itertools.product(*choices):
        trial=_output(study,'exhaustive',list(choice))
        if not trial['within_budget']:
            continue
        # maximize net, prefer cheaper spend in ties, then stable IDs
        key=(trial['net_savings_ns'],-trial['one_time_ns'],
             tuple(p['variant'] for p in trial['plan']))
        if key[:2]>best_key[:2] or (key[:2]==best_key[:2] and key[2]<best_key[2]):
            winner=trial;best_key=key
    return winner


def exact_dp(record: object) -> dict:
    study=validate_experiment(record)
    # Sparse exact DP over actual one-time costs. One plan retained per cost.
    states:dict[int,tuple[int,tuple[int,...]]]={0:(0,())}
    for j,job in enumerate(study['jobs']):
        revised={}
        for spent,(net,selected) in states.items():
            for i,choice in enumerate(options(job)):
                prep,saved=score_option(job,choice)
                new_cost=spent+prep
                if new_cost>study['max_one_time_ns']:
                    continue
                candidate=(net+saved,selected+(i,))
                old=revised.get(new_cost)
                if old is None or candidate[0]>old[0] or (candidate[0]==old[0] and candidate[1]<old[1]):
                    revised[new_cost]=candidate
        states=revised
        if not states or len(states)>500_000:
            reject('E_DP_BUDGET','exact state budget exhausted')
    spent,(net,indices)=min(states.items(),key=lambda kv:(-kv[1][0],kv[0],kv[1][1]))
    choice=[options(j)[idx] for j,idx in zip(study['jobs'],indices)]
    return _output(study,'exact_sparse_dp',choice)


def strong_fixed(record: object) -> dict:
    study=validate_experiment(record)
    # One shared named variant across every job; if missing, cannot use it.
    ids={c['id'] for c in study['jobs'][0]['candidates']}
    for job in study['jobs'][1:]:
        ids &= {c['id'] for c in job['candidates']}
    winner=_output(study,'strong_fixed',[None]*len(study['jobs']))
    for label in sorted(ids):
        candidates=[next(c for c in j['candidates'] if c['id']==label) for j in study['jobs']]
        r=_output(study,'strong_fixed',candidates)
        if r['within_budget'] and (r['net_savings_ns']>winner['net_savings_ns'] or
            (r['net_savings_ns']==winner['net_savings_ns'] and r['one_time_ns']<winner['one_time_ns'])):
            winner=r
    return winner


def same_information_greedy(record: object) -> dict:
    study=validate_experiment(record)
    # Process in immutable user job order; choose best available feasible net move.
    budget=study['max_one_time_ns'];chosen=[]
    for job in study['jobs']:
        best=None;best_net=0
        for c in job['candidates']:
            prep,saved=score_option(job,c)
            if prep<=budget and saved>best_net:
                best=c;best_net=saved
        if best:
            budget-=score_option(job,best)[0]
        chosen.append(best)
    return _output(study,'same_information_greedy',chosen)


def comparison(record: object) -> dict:
    study=validate_experiment(record)
    outputs=[strong_fixed(study),same_information_greedy(study),exact_dp(study)]
    enum=exact_exhaustive(study)
    if (outputs[2]['one_time_ns'],outputs[2]['net_savings_ns']) != (enum['one_time_ns'],enum['net_savings_ns']):
        reject('E_ORACLE_MISMATCH','independent exhaustive solver disagrees with exact DP')
    return {'schema':'hepta.audit.same-information-control.v1',
            'study_kind':study['study_kind'], 'study_sha256':identity(study),
            'results':outputs+[enum],
            'native_ndu':{'status':'UNAVAILABLE','reason':'native bridge not executed in this offline prototype'},
            'acceptance':{'ndu_incremental_value_proved':False,'real_application_net_benefit_proved':False},
            'authority':'DENY_ALL'}

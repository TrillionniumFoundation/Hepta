"""Registered finite search controls; *not* the original Rust NDU evaluator.

This deliberately reports whether a Q32-style proxy adds decision value beyond
an exact, same-information finite DP, including actual Python controller cost.
"""
from __future__ import annotations
from itertools import product
from functools import lru_cache
from time import perf_counter_ns
from dataclasses import dataclass

# Immutable prospective synthetic workloads, NOT independent native measurements.
SYNTHETIC_COSTS_NS = (
    (1100,1000),(1050,1020),(1200,900),(850,1000),
    (1300,950),(1000,1010),(900,1050),(1250,920),
)
SWITCH_COST_NS=450
Q32=1<<32

def plan_cost(plan, costs=SYNTHETIC_COSTS_NS, switch_cost=SWITCH_COST_NS):
    if len(plan)!=len(costs) or any(action not in (0,1) for action in plan):
        raise ValueError("invalid finite plan")
    prev=0;total=0
    for action,pair in zip(plan,costs):
        total+=pair[action]+(switch_cost if action!=prev else 0)
        prev=action
    return total

def oracle_enumerate(costs=SYNTHETIC_COSTS_NS):
    return min(((plan_cost(p,costs),p) for p in product((0,1),repeat=len(costs))),
               key=lambda t:(t[0],t[1]))

def exact_dp(costs=SYNTHETIC_COSTS_NS):
    @lru_cache(None)
    def solve(i,prev):
        if i==len(costs): return 0,()
        choices=[]
        for a in (0,1):
            rest,p=solve(i+1,a)
            choices.append((costs[i][a]+(SWITCH_COST_NS if a!=prev else 0)+rest,(a,)+p))
        return min(choices,key=lambda t:(t[0],t[1]))
    return solve(0,0)

def q32_advisory_proxy(costs=SYNTHETIC_COSTS_NS):
    """Zero-authority brute-force discounted utility over disclosed finite plans.

    Distinct implementation from DP, but same exact inputs. Q32 arithmetic is
    integer-valued for this profile. No NDU native calls, FBSDE, stochastic
    model, learned coefficients or performance advantage are claimed.
    """
    winner=None
    for p in product((0,1),repeat=len(costs)):
        prior=0;value=0
        for i,action in enumerate(p):
            stage=costs[i][action]+(SWITCH_COST_NS if action!=prior else 0)
            value += -stage*Q32
            prior=action
        candidate=(-value//Q32,p)
        if winner is None or candidate<winner: winner=candidate
    return winner

def qualify_finite_planners():
    start=perf_counter_ns(); oracle=oracle_enumerate();o_ns=perf_counter_ns()-start
    start=perf_counter_ns(); dp=exact_dp();d_ns=perf_counter_ns()-start
    start=perf_counter_ns(); advisory=q32_advisory_proxy();a_ns=perf_counter_ns()-start
    fixed_base=(plan_cost((0,)*len(SYNTHETIC_COSTS_NS)),(0,)*len(SYNTHETIC_COSTS_NS))
    fixed_opt=(plan_cost((1,)*len(SYNTHETIC_COSTS_NS)),(1,)*len(SYNTHETIC_COSTS_NS))
    fixed=min([fixed_base,fixed_opt],key=lambda x:(x[0],x[1]))
    if oracle!=dp or dp!=advisory:
        raise AssertionError("finite independent plan disagreement")
    return {"status":"FINITE_SAME_INFORMATION_AGREEMENT",
        "objective":"minimize synthetic step cost + switch cost (integer ns units)",
        "synthetic_costs_ns":SYNTHETIC_COSTS_NS,"switch_cost_ns":SWITCH_COST_NS,
        "candidate_count":2**len(SYNTHETIC_COSTS_NS),
        "fixed":{"modeled_execution_ns":fixed[0],"plan":fixed[1]},
        "enumeration":{"modeled_execution_ns":oracle[0],"plan":oracle[1],"measured_controller_ns":o_ns},
        "exact_dp":{"modeled_execution_ns":dp[0],"plan":dp[1],"measured_controller_ns":d_ns},
        "q32_advisory_proxy":{"modeled_execution_ns":advisory[0],"plan":advisory[1],"measured_controller_ns":a_ns},
        "actual_native_ndu_used":False,"same_information":True,
        "NDU_additional_value_proven":False,"production_qualified":False}

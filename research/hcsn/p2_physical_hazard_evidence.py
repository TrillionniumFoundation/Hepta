"""P2 physical hazard-clock evidence; no fitted task accuracy or gate closure."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import statistics

from scipy.stats import poisson

from research.hcsn.test_p2_physical_hazard_clock import (
    KNOTS, RATES, independent_inverse, process,
)
from research.hcsn.p2_physical_hazard_clock import causal_rate


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def generate():
    paired=[]
    max_inverse=0.0
    max_refine=0.0
    for seed in (11,23,37,101,1001):
        for refractory in (0.0,.31):
            ref=independent_inverse(seed,refractory)
            baseline=process(seed,1,refractory)
            assert len(ref)==len(baseline)
            max_inverse=max(max_inverse,*(abs(a-b) for a,b in zip(ref,baseline)))
            for sub in (4,16,64):
                candidate=process(seed,sub,refractory)
                assert len(candidate)==len(baseline)
                max_refine=max(max_refine,*(abs(a-b) for a,b in zip(candidate,baseline)))
            paired.append({'seed':seed,'refractory':refractory,
                           't_event_s':baseline,'independent_quad_brentq_s':ref,
                           'counts_refined':[len(process(seed,sub,refractory)) for sub in (1,4,16,64)]})
    hold=[]
    for seed in (11,23,37):
        traces=[process(seed,sub,.2,(0.,4.),(.7,)) for sub in (4,16,64)]
        hold.append({'seed':seed,'counts':[len(t) for t in traces], 'event_times_s':traces,
                     'previous_iteration29_clock_candidate_counts':({11:[1,6,25],23:[1,6,26],37:[1,6,25]}[seed])})
    counts=[len(process(seed)) for seed in range(2000)]
    mu=sum((b-a)*lam for a,b,lam in zip(KNOTS[:-1],KNOTS[1:],RATES))
    return {'schema':'hcsn.p2-physical-hazard-renewal-iteration30.v1',
            'science_scope':'Compensator-inversion benchmark for causal ZOH intensity and absolute-time refractory. NOT continuous Brownian first-hit, original HX/A7/QVI, trained event policy or heldout MQAR gain.',
            'sources_sha256':{str(p):sha(p) for p in (
                 'research/hcsn/p2_physical_hazard_clock.py',
                 'research/hcsn/test_p2_physical_hazard_clock.py',
                 'research/hcsn/p2_physical_hazard_evidence.py')},
            'protocol':{'seeds':[11,23,37,101,1001], 'refinement':[1,4,16,64],
                        'piecewise_knots_s':KNOTS,'piecewise_held_rates_s_inverse':RATES,
                        'physical_refractory_s':[0.,.31], 'held_context_rate_s_inverse':.7,
                        'held_context_duration_s':4.,'counts_mc_seeds':2000},
            'paired_times':paired,'held_context_traces':hold,
            'max_abs_scipy_inverse_difference_s':max_inverse,
            'max_abs_refinement_difference_s':max_refine,
            'poisson_no_refractory':{'exact_mu':mu,'empirical_mean':statistics.mean(counts),
                                    'empirical_population_variance':statistics.pvariance(counts),
                                    'empirical_p_count_ge_4':sum(x>=4 for x in counts)/len(counts),
                                    'exact_p_count_ge_4':float(poisson.sf(3,mu)),
                                    'histogram':{str(i):counts.count(i) for i in range(max(counts)+1)}},
            'negative_control':{'mechanism':'per-token Bernoulli p=0.2 at same duration T=4s',
                                'sample_counts':[4,16,64], 'expected_events':[.8,3.2,12.8]},
            'positive_causal_rate_map_example':{'contexts':[-2.,0.,2.],
                                                 'rates':[causal_rate(x,.2,1.) for x in (-2.,0.,2.)],
                                                 'weights_are_trained':False},
            'matched_flops':False,'pretrained_encoders':False,'independent_attestation':False,
            'claims':'A sample-grid-invariant ZOH hazard renewal control exists under fixed exogenous intensity. This does not solve learned HCSN free-boundary or improve query accuracy.',
            'science_gates':{f'P{i}':'OPEN' for i in range(7)},'production_activation':False}


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    if a.output.exists():p.error('refusing overwrite')
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(generate(),indent=2,sort_keys=True)+'\n',encoding='utf-8')

if __name__=='__main__':main()

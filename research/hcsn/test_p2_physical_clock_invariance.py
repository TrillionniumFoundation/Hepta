"""P2 negative: token-count volatility breaks physical-time resampling invariance.

A held context carries identical information at 4, 16 or 64 observations in
4 seconds. Retrain the original task-only model without event labels, then
probe its HARD event decision at a common physical time with identical input.
Research diagnostic only. Not full stochastic QVI or P2 validation.
"""
import argparse
import hashlib
import json
import math
from pathlib import Path
import unittest

import torch
from torch.nn import functional as F
from research.hcsn.p2_no_event_dynamic_boundary import (CausalBoundary,DIM,NKEYS,samples)


def trained(seed):
    torch.set_num_threads(1)
    torch.manual_seed(seed)
    m=CausalBoundary('dynamic')
    opt=torch.optim.Adam(m.parameters(),lr=.025)
    for step in range(40):
        x,y,q,_=samples(16,64,4,seed*100000+step)
        opt.zero_grad(set_to_none=True)
        z,_,_=m.rollout(x,hard=False)
        loss=F.binary_cross_entropy_with_logits(z[q],y[q])
        loss.backward()
        torch.nn.utils.clip_grad_norm_(m.parameters(),5.)
        opt.step()
    return m


def actual(m,n):
    """Constant context 1 for T=4; common jump to 1-exp(-1)+0.78 at T+0.01."""
    st=m.initial(torch.zeros(1,DIM))
    with torch.no_grad():
        count=0
        for _ in range(n):
            x=torch.zeros(1,DIM)
            x[:,NKEYS+3]=1.
            x[:,NKEYS+4]=4./n
            st,_,hit=m.step(x,st,hard=True)
            count+=int(hit.item())
        level=float(st.level.item()); vol=float(st.volatility.item())
        bound=float(F.softplus(m.threshold+m.sensitivity*st.volatility).item())
        x=torch.zeros(1,DIM)
        x[:,NKEYS+3]=1.-math.exp(-1.)+.78
        x[:,NKEYS+4]=.01
        _,_,hit=m.step(x,st,hard=True)
    return {'samples':n,'level':level,'volatility':vol,
            'threshold':bound,'prior_hits':count,'probe_hit':bool(hit.item())}


def reference(n):
    """Independent semigroup-consistent held-context ODE reference, not QVI.

    dL/dt=(1-L)/4; dV/dt=(abs(1-L)-V)/tau, tau=-1/log(.9).
    Closed-form update integrates both fields over each physical dt.
    """
    tau=-1./math.log(.9)
    level=vol=0.
    for _ in range(n):
        dt=4./n
        el=math.exp(-dt/4.)
        ev=math.exp(-dt/tau)
        force=abs(1.-level)*ev*math.expm1(dt*(1./tau-1./4.))/(1.-tau/4.)
        vol=ev*vol+force
        level=1.+(level-1.)*el
    return {'samples':n,'level':level,'volatility':vol}


def evidence():
    cases=[]
    for seed in (11,23,37):
        model=trained(seed)
        cases.append({'seed':seed,
                      'parameters':{k:float(v.detach()) for k,v in model.named_parameters()},
                      'traces':[actual(model,n) for n in (4,16,64)]})
    return {'schema':'hcsn.p2-physical-clock-resampling-negative.v1',
            'source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'upstream_model_sha256':hashlib.sha256(Path(__file__).with_name('p2_no_event_dynamic_boundary.py').read_bytes()).hexdigest(),
            'experiment':'query-only 40-step trained model, constant observed context 1 for 4s, identical physical-time probe at 4.01s',
            'reference_assumptions':'exact deterministic held-context ODE integration; not a Brownian or QVI proof',
            'cases':cases,'independent_clock':[reference(n) for n in (4,16,64)],
            'science_gates':{f'P{i}':'OPEN' for i in range(7)},
            'production_activation':False,'full_model_validation':False}


class TestPhysicalClock(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result=evidence()

    def test_three_seed_trained_probe_counterexample(self):
        for c in self.result['cases']:
            a,b,z=c['traces']
            self.assertTrue(a['probe_hit'])
            self.assertFalse(b['probe_hit'])
            self.assertFalse(z['probe_hit'])
            self.assertLess(abs(a['level']-b['level']),1e-6)
            self.assertGreater(b['volatility']-a['volatility'],.2)
            self.assertLess(a['threshold'],.78)
            self.assertGreater(b['threshold'],.78)

    def test_exact_reference_semi_group(self):
        refs=self.result['independent_clock']
        self.assertLess(max(x['level'] for x in refs)-min(x['level'] for x in refs),1e-12)
        self.assertLess(max(x['volatility'] for x in refs)-min(x['volatility'] for x in refs),1e-12)
        self.assertAlmostEqual(refs[0]['volatility'],.2099500481453896,places=12)

    def test_gate_and_data_provenance(self):
        self.assertEqual(set(self.result['science_gates'].values()),{'OPEN'})
        self.assertFalse(self.result['production_activation'])
        self.assertEqual(self.result['upstream_model_sha256'],
                         'bff9aa7dba1b4b73ae3445fdba39a7ef115e9df4eed47548848be0f6318d23c6')


if __name__=='__main__':
    p=argparse.ArgumentParser()
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    if a.output.exists():p.error('evidence exists: overwrite refused')
    r=evidence()
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(r,indent=2,sort_keys=True)+'\n')
    print(json.dumps({'probe_pairs':[[x['probe_hit'] for x in c['traces']] for c in r['cases']],
                      'clock_reference':[x['volatility'] for x in r['independent_clock']]}))

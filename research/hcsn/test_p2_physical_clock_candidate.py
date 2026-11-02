"""Counterexample-preserving P2 clock-correction tests; science gates remain OPEN."""
from __future__ import annotations

import math
import unittest
import numpy as np
import torch
from scipy.integrate import solve_ivp
from torch.nn import functional as F

from research.hcsn.p2_no_event_dynamic_boundary import CausalBoundary, DIM, NKEYS, samples
from research.hcsn.p2_physical_clock_candidate import (ClockCorrectedBoundary,
    exact_held_context_step, LEVEL_TIME, VOL_TIME)


def scipy_independent(level,vol,context,dt):
    f=lambda t,x: [(context-x[0])/LEVEL_TIME,(abs(context-x[0])-x[1])/VOL_TIME]
    v=solve_ivp(f,[0,dt],[level,vol],rtol=2e-12,atol=2e-13,method='DOP853')
    if not v.success:
        raise ArithmeticError(v.message)
    return v.y[:,-1]


def same_physical_hold(model,n,probe=True):
    state=model.initial(torch.zeros(1,DIM))
    with torch.no_grad():
        prior_hits=0
        for _ in range(n):
            x=torch.zeros(1,DIM)
            x[:,NKEYS+3]=1.0
            x[:,NKEYS+4]=4.0/n
            state,_,event=model.step(x,state,hard=True)
            prior_hits+=int(event.item())
        level=float(state.level.item())
        vol=float(state.volatility.item())
        bound=float(F.softplus(model.threshold+model.sensitivity*state.volatility).item())
        x=torch.zeros(1,DIM)
        x[:,NKEYS+3]=1.-math.exp(-1.)+.78
        x[:,NKEYS+4]=.01
        _,_,hit=model.step(x,state,hard=True)
        return {'n':n,'level':level,'volatility':vol,'threshold':bound,
                'probe_hit':bool(hit.item()),'prior_hits':prior_hits}


class TestPhysicalClockCandidate(unittest.TestCase):
    def test_independent_scipy_reference(self):
        rng=np.random.default_rng(424242)
        for _ in range(48):
            level=float(rng.uniform(-3,3));vol=float(rng.uniform(0,4))
            ctx=float(rng.uniform(-3,3));dt=float(rng.uniform(.001,4))
            p=torch.tensor([level],dtype=torch.float64)
            q=torch.tensor([vol],dtype=torch.float64)
            r=torch.tensor([ctx],dtype=torch.float64)
            s=torch.tensor([dt],dtype=torch.float64)
            a,b=exact_held_context_step(p,q,r,s)
            e=scipy_independent(level,vol,ctx,dt)
            self.assertLess(abs(a.item()-e[0]),2e-10)
            self.assertLess(abs(b.item()-e[1]),2e-10)

    def test_semigroup_same_held_context(self):
        a=torch.tensor([.1,-.8,1.2],dtype=torch.float64)
        b=torch.tensor([.2,.5,0.],dtype=torch.float64)
        c=torch.tensor([1.5,-1.,.2],dtype=torch.float64)
        for n in (1,4,16,64,257):
            L,V=a,b
            for _ in range(n):
                L,V=exact_held_context_step(L,V,c,torch.full_like(c,4.0/n))
            A,B=exact_held_context_step(a,b,c,torch.full_like(c,4.0))
            self.assertLess(float((L-A).abs().max()),3e-12)
            self.assertLess(float((V-B).abs().max()),3e-12)

    def test_repeated_sampling_probe_candidate_and_old_negative(self):
        for cls in (ClockCorrectedBoundary,CausalBoundary):
            torch.manual_seed(77)
            model=cls() if cls is ClockCorrectedBoundary else cls('dynamic')
            with torch.no_grad():
                model.threshold.fill_(-.1959683895)
                model.sensitivity.fill_(1.0518410206)
            traces=[same_physical_hold(model,n) for n in (4,16,64)]
            if cls is ClockCorrectedBoundary:
                self.assertLess(max(z['volatility'] for z in traces)-min(z['volatility'] for z in traces),1e-6)
                self.assertEqual(len(set(z['probe_hit'] for z in traces)),1)
                self.assertAlmostEqual(traces[0]['volatility'],.2099500481453896,places=6)
            else:
                self.assertGreater(max(z['volatility'] for z in traces)-min(z['volatility'] for z in traces),.2)
                self.assertEqual([z['probe_hit'] for z in traces],[True,False,False])

    def test_repeated_event_chatter_remains_open(self):
        # Use frozen seed-11 trained scalars from iteration 28; no new training.
        # The corrected *clock state* is invariant, but firing on every
        # observation above threshold is NOT a continuous-time event law.
        model=ClockCorrectedBoundary()
        with torch.no_grad():
            model.threshold.fill_(-.1959683895111084)
            model.sensitivity.fill_(1.0518410205841064)
        traces=[same_physical_hold(model,n) for n in (4,16,64)]
        self.assertEqual(traces[0]['prior_hits'],1)
        self.assertGreaterEqual(traces[1]['prior_hits'],5)
        self.assertGreaterEqual(traces[2]['prior_hits'],20)
        self.assertEqual([z['probe_hit'] for z in traces],[True,True,True])
        self.assertLess(max(z['volatility'] for z in traces)-min(z['volatility'] for z in traces),1e-6)

    def test_chunk_equals_whole_and_causality(self):
        m=ClockCorrectedBoundary()
        x,*_=samples(3,64,4,224)
        full,ev,final=m.rollout(x,hard=True)
        _,_,st=m.rollout(x[:,:27,:],hard=True)
        rest,events,tail=m.rollout(x[:,27:,:],hard=True,state=st)
        self.assertTrue(torch.equal(full[:,27:],rest))
        self.assertTrue(torch.equal(ev[:,27:],events))
        self.assertTrue(torch.allclose(final.volatility,tail.volatility))
        altered=x.clone()
        altered[:,27:,NKEYS+3]+=1.
        early,_,_=m.rollout(altered[:,:27,:],hard=True)
        self.assertTrue(torch.equal(early,full[:,:27]))

    def test_soft_gradient_and_training_budget(self):
        torch.manual_seed(2)
        m=ClockCorrectedBoundary()
        x,y,q,_=samples(5,64,4,213)
        logits,ev,_=m.rollout(x,hard=False)
        loss=F.binary_cross_entropy_with_logits(logits[q],y[q])
        loss.backward()
        self.assertEqual(sum(v.numel() for v in m.parameters()),4)
        for p in m.parameters():
            self.assertIsNotNone(p.grad)
            self.assertTrue(torch.isfinite(p.grad).all())
        self.assertEqual(ev.dtype,torch.bool)

    def test_invalid_inputs_fail(self):
        m=ClockCorrectedBoundary()
        state=m.initial(torch.zeros(2,DIM))
        for dt in (0.,-1.,float('nan'),float('inf'),4.01):
            x=torch.zeros(2,DIM)
            x[:,NKEYS+4]=dt
            with self.assertRaises(ValueError):
                m.step(x,state,hard=True)
        with self.assertRaises(ValueError):
            exact_held_context_step(torch.zeros(2),torch.zeros(2),torch.zeros(2),torch.ones(1))

    def test_time_scale_covariance(self):
        # Scale every physical duration and *both* relaxation constants together:
        # normalized dynamics should agree. Check the independent analytic law.
        lev=.27;vol=.43;ctx=1.4;dt=3.1
        o=scipy_independent(lev,vol,ctx,dt)
        for scale in (.1,10.):
            sol=solve_ivp(lambda t,z:[(ctx-z[0])/(scale*LEVEL_TIME),
                                     (abs(ctx-z[0])-z[1])/(scale*VOL_TIME)],
                           [0,scale*dt],[lev,vol],rtol=2e-12,atol=2e-13,method='DOP853').y[:,-1]
            self.assertLess(float(np.max(np.abs(o-sol))),2e-10)


if __name__=='__main__':
    unittest.main()

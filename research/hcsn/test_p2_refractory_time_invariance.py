"""Executable independent P2 physical-time counterexample and causal invariants."""
from __future__ import annotations
import unittest
import numpy as np
try:
    from .p2_refractory_time_invariance import (
        ElapsedFilterState, elapsed_edge_refractory, token_edge_refractory,
        sampling_grid, accepted_times)
except ImportError:
    from p2_refractory_time_invariance import (
        ElapsedFilterState, elapsed_edge_refractory, token_edge_refractory,
        sampling_grid, accepted_times)


class RefractoryTimeInvariantTests(unittest.TestCase):
    def test_synthetic_same_hitting_times_refinement_breaks_token_semantics(self):
        raw_a,t_a=sampling_grid(.25)
        raw_b,t_b=sampling_grid(.125)
        a,_=elapsed_edge_refractory(raw_a,t_a,seconds=2.)
        b,_=elapsed_edge_refractory(raw_b,t_b,seconds=2.)
        self.assertEqual(accepted_times(a,t_a),[[0.,2.,4.]])
        self.assertEqual(accepted_times(b,t_b),[[0.,2.,4.]])
        ua=token_edge_refractory(raw_a,cooldown_tokens=2)
        ub=token_edge_refractory(raw_b,cooldown_tokens=2)
        self.assertEqual(accepted_times(ua,t_a),[[0.,1.,2.,3.,4.,5.]])
        self.assertEqual(accepted_times(ub,t_b),[[0.,1.,2.,3.,4.,5.]])
        # Different token policies need a tighter cooldown setting to expose
        # a resolution-dependent decision on the SAME event timestamps.
        ua=token_edge_refractory(raw_a,cooldown_tokens=5)
        ub=token_edge_refractory(raw_b,cooldown_tokens=5)
        self.assertNotEqual(accepted_times(ua,t_a),accepted_times(ub,t_b))

    def test_seconds_units_are_scaled_with_timestamp_units(self):
        raw,t=sampling_grid(.25)
        a,_=elapsed_edge_refractory(raw,t,seconds=2.)
        b,_=elapsed_edge_refractory(raw,t*1000.,seconds=2000.)
        self.assertTrue(np.array_equal(a,b))

    def test_chunked_stream_and_whole_have_identical_event_times(self):
        raw,t=sampling_grid(.125)
        whole,_=elapsed_edge_refractory(raw,t,seconds=2.)
        front,s=elapsed_edge_refractory(raw[:,:13],t[:,:13],seconds=2.)
        tail,_=elapsed_edge_refractory(raw[:,13:],t[:,13:],seconds=2.,state=s)
        self.assertTrue(np.array_equal(whole,np.concatenate((front,tail),axis=1)))

    def test_batch_independence_and_state_per_stream(self):
        raw,t=sampling_grid(.25)
        paired=np.concatenate((raw,~raw),axis=0)
        times=np.concatenate((t,t+0.01),axis=0)
        both,_=elapsed_edge_refractory(paired,times,seconds=1.1)
        for i in range(2):
            solo,_=elapsed_edge_refractory(paired[i:i+1],times[i:i+1],seconds=1.1)
            self.assertTrue(np.array_equal(both[i:i+1],solo))

    def test_exact_independent_oracle_on_randomized_traces(self):
        rng=np.random.default_rng(20261031)
        for _ in range(100):
            n=round(rng.uniform(10,100))
            raw=(rng.random(n)<.28)
            times=np.cumsum(rng.uniform(.02,1.0,size=n))
            seconds=float(rng.uniform(0,2))
            got,_=elapsed_edge_refractory(raw[None,:],times[None,:],seconds=seconds)
            expected=[];prev=False;last=float('-inf')
            for r,t in zip(raw,times):
                hit=bool(r) and not prev and (t-last>=seconds)
                expected.append(hit)
                if hit:last=float(t)
                prev=bool(r)
            self.assertEqual(got[0].tolist(),expected)

    def test_preserves_edge_semantics_under_stuck_detector(self):
        raw=np.ones((2,40),dtype=np.bool_)
        t=np.tile(np.arange(40,dtype=np.float64)[None,:],(2,1))
        hits,_=elapsed_edge_refractory(raw,t,seconds=0.)
        self.assertEqual(hits.sum(),2)
        self.assertTrue(bool(hits[:,0].all()))

    def test_rejects_invalid_time_units_and_state(self):
        raw,t=sampling_grid(.25)
        for bad in (t.astype(np.float32),t[:,:-1],np.full_like(t,np.nan),
                    np.zeros_like(t),t-1.):
            with self.assertRaises(ValueError):elapsed_edge_refractory(raw,bad)
        for bad_duration in (-1.,float('nan'),True,1e12):
            with self.assertRaises(ValueError):elapsed_edge_refractory(raw,t,seconds=bad_duration)
        with self.assertRaises(ValueError):elapsed_edge_refractory(raw.astype(np.uint8),t)
        front,s=elapsed_edge_refractory(raw,t)
        with self.assertRaises(ValueError):elapsed_edge_refractory(raw,t,state=s)
        with self.assertRaises(ValueError):elapsed_edge_refractory(raw,t,state='wrong')

    def test_not_an_end_to_end_model_or_solved_event_time_gradient(self):
        raw,t=sampling_grid(.125)
        hits,_=elapsed_edge_refractory(raw,t,seconds=2.)
        self.assertEqual(int(hits.sum()),3)
        self.assertFalse(hasattr(hits,'requires_grad'))

if __name__=='__main__':unittest.main()

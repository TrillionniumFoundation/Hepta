"""Tests of physical-clock accuracy and the *necessary* finite-state decay bound."""
import math
import unittest
import numpy as np
from p2_task_only_ctmc_retention import (
    checked_rates, checked_schedule, exact_probability, independent_ode,
    independent_expm, exact_blank_decay, bayes_balanced_accuracy,
    physical_split, train_task_only, reproduce, independent_event_path,
)

A=[(1.,1),(1.,0)]
B=[(1.,0),(1.,1)]

class RetentionReferenceTests(unittest.TestCase):
    def test_numeric_independent_matrix_and_ode(self):
        rng = np.random.default_rng(93211)
        max_error = 0
        for _ in range(40):
            rates = rng.uniform(.03, 4., size=(3,2))
            segments = [(float(rng.uniform(.05,2.)),int(rng.integers(0,3))) for _ in range(4)]
            a = exact_probability(segments, rates)
            b = independent_ode(segments, rates)
            c = independent_expm(segments, rates)
            max_error=max(max_error,abs(a-b),abs(a-c))
        self.assertLess(max_error, 4e-11)

    def test_physical_refinement_and_contiguous_blank(self):
        r = [[.1,4.],[4.,.1],[.04,.07]]
        sched = B+[(8.25,2)]
        for n in (4,16,64):
            self.assertAlmostEqual(exact_probability(sched,r),exact_probability(physical_split(sched,n),r),delta=1e-12)
        self.assertAlmostEqual(exact_probability(sched,r), exact_probability(B+[(3.,2),(5.25,2)],r),delta=1e-13)

    def test_exact_exponential_information_leak(self):
        r=[[.1,4.],[4.,.1],[.04,.07]]
        initial=abs(exact_probability(A,r)-exact_probability(B,r))
        for d in (0.,1.,4.,16.,64.,256.):
            self.assertAlmostEqual(exact_blank_decay(A,B,d,r),initial*math.exp(-.11*d),delta=2e-14)
            self.assertLessEqual(bayes_balanced_accuracy(A,B,d,r),.5+.5*math.exp(-.08*d)+1e-14)

    def test_independent_autonomous_event_simulator(self):
        rates=[[.08,3.],[3.,.08],[.12,.07]]
        sched=B+[(16.,2)]
        n=5000
        samples=[independent_event_path(sched,rates,100001+i) for i in range(n)]
        p=exact_probability(sched,rates)
        successes=sum(s for s,_ in samples)
        z=abs(successes/n-p)/math.sqrt(p*(1-p)/n)
        self.assertLess(z,4.)
        self.assertGreater(sum(events>1 for _,events in samples),n//3)

    def test_absorbing_blank_is_distinct(self):
        r=[[.1,4.],[4.,.1],[0.,0.]]
        for d in (0.,1.,16.,256.):
            self.assertAlmostEqual(exact_blank_decay(A,B,d,r),exact_blank_decay(A,B,0,r),delta=1e-14)
        self.assertAlmostEqual(exact_probability(A+[(256.,2)],r),exact_probability(A,r),delta=1e-14)

    def test_reject_malformed_input(self):
        for bad in ([],[(0.,0)],[(-1.,0)],[(float('nan'),0)],[(1.,3)],[(1.,True)]):
            with self.assertRaises(ValueError): exact_probability(bad,[[1,1]]*3)
        for bad in ([[1,1]],[[1,-1]]*3,[[math.nan,1]]*3,[[1,2,3]]*3):
            with self.assertRaises(ValueError): checked_rates(bad)
        for bad in (-1,0,1001,True):
            with self.assertRaises(ValueError): physical_split(A,bad)
        with self.assertRaises(ValueError): exact_blank_decay(A,B,-1,[[1,1]]*3)

    def test_task_only_three_seed_training_and_ood(self):
        # Narrow task fit does not close any gate. No event or state supervision.
        for seed in (11,23,37):
            result=reproduce(seed,steps=190)
            self.assertLess(result['train_final_loss'],result['train_initial_loss']-.09)
            rows=result['heldout_blank_lengths']
            self.assertGreater(rows[0]['bayes_accuracy'],.8)
            self.assertLess(rows[-1]['bayes_accuracy'],.501)
            for row in rows:
                self.assertLessEqual(row['bayes_accuracy'], row['uniform_floor_upper_bound']+1e-12)

if __name__=='__main__':
    unittest.main()

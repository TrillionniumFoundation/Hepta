"""Fixed-seed bounded 50-case original-HX numerical cross-reference stress.

Test uses PDE on original Eq. (8), not a formal all-domain bound. Frozen
PRNG produces reproducible parameter candidates independent of any training.
"""
import unittest
import numpy as np
try:
    from .hx_original import HXParams,closed_boundary,bond_price_from_log
    from .bond_fd_reference import solve_bond_pde
except ImportError:
    from hx_original import HXParams,closed_boundary,bond_price_from_log
    from bond_fd_reference import solve_bond_pde

class BondPDEStressTests(unittest.TestCase):
    def test_fifty_admissible_cases_reference_bounded_accuracy(self):
        g=np.random.default_rng(62844)
        max_rel=0.
        for i in range(50):
            p=HXParams(r=g.uniform(.055,.14),delta=g.uniform(.015,.085),
                       sigma=g.uniform(.16,.55),alpha=g.uniform(.25,.85),
                       tax=g.uniform(.06,.35),xi=g.uniform(0.,5.),
                       k=g.uniform(0.,.05),maturity=g.uniform(.4,5.),
                       coupon_total=g.uniform(3.,9.),face_total=g.uniform(40.,90.))
            vb=closed_boundary(p)
            fd=solve_bond_pde(p,vb,p.maturity,points=501,steps=1300,max_x=7.)
            for x in (.12,.3,.7,1.3,2.):
                closed=bond_price_from_log(x,p.maturity,vb,p)
                rel=abs(fd.at(x)-closed)/max(1.,abs(closed))
                max_rel=max(max_rel,rel)
                self.assertLess(rel,.001, (i,x,rel))
        self.assertLess(max_rel,.001)

if __name__=='__main__':unittest.main()

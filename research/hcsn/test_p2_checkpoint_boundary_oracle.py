"""Deterministic adversarial tests for causal input-conditioned free boundaries."""
import dataclasses
import inspect
import math
import unittest

import torch

from research.hcsn.p2_checkpoint_boundary_oracle import (
    TwoStageBrownian,first_hit_prob,killed_density,
    probability_quad,probability_torch,probability_bridge_mc,
)


class MovingBoundaryOracleTests(unittest.TestCase):
    def test_stationary_semigroup_collapse_three_drifts(self):
        for drift in (-.24, 0., .35):
            for b in (-.4, 0., .2):
                p=TwoStageBrownian(b1=b,b2_level=b,gain=0,drift=drift)
                got,_=probability_quad(p)
                exact=first_hit_prob(p.x0-b,drift,p.diffusion,p.t1+p.t2)
                self.assertLess(abs(got-exact),5e-10,(p,got,exact))

    def test_killed_density_boundary_zero_and_positive(self):
        p=TwoStageBrownian()
        self.assertEqual(killed_density(p.b1,p),0.)
        self.assertGreater(killed_density(p.b1+1e-8,p),0)
        self.assertGreater(killed_density(p.x0,p),0)

    def test_jump_up_increases_hits(self):
        low=probability_quad(TwoStageBrownian(gain=0,b2_level=-.4))[0]
        even=probability_quad(TwoStageBrownian(gain=0,b2_level=0))[0]
        high=probability_quad(TwoStageBrownian(gain=0,b2_level=.5))[0]
        self.assertLess(low,even)
        self.assertLess(even,high)

    def test_causal_feedback_changes_risk(self):
        probabilities=[probability_quad(TwoStageBrownian(gain=x))[0] for x in (-.45,0,.45)]
        self.assertGreater(max(probabilities)-min(probabilities),.001)

    def test_independent_gauss_legendre_vs_adaptive_quad(self):
        cases=[
            TwoStageBrownian(),TwoStageBrownian(gain=-.5,b2_level=-.3),
            TwoStageBrownian(gain=.55,b2_level=.60,drift=-.28),
            TwoStageBrownian(gain=.2,b2_level=-.7,drift=.35),
        ]
        for p in cases:
            q,err=probability_quad(p)
            d,tail=probability_torch(p,n=256)
            self.assertLess(abs(float(d)-q),2e-7,(p,float(d),q,err))
            self.assertLess(float(tail),1e-15)

    def test_exact_checkpoint_brownian_bridge_mc(self):
        cases=[
            TwoStageBrownian(),TwoStageBrownian(gain=-.45,b2_level=-.5),
            TwoStageBrownian(gain=.45,b2_level=.6,drift=-.18),
            TwoStageBrownian(gain=0,b2_level=.9,drift=.3),
        ]
        for i,p in enumerate(cases):
            q,_=probability_quad(p)
            m,se,_=probability_bridge_mc(p,n=160_000,seed=20261031+i)
            self.assertLess(abs(q-m),5*se+2e-4,(p,q,m,se))

    def test_signed_gradients_seven_coordinates(self):
        p=TwoStageBrownian(b1=-.18,b2_level=.42,gain=.33)
        fields=('x0','b1','b2_level','gain','drift','diffusion','t1','t2')
        vals={f:torch.tensor(getattr(p,f),dtype=torch.float64,requires_grad=True) for f in fields}
        probability,tail=probability_torch(p,n=256,**vals)
        derivatives=torch.autograd.grad(probability,list(vals.values()))
        for f,g in zip(fields,derivatives):
            h=1e-4*max(1,abs(getattr(p,f)))
            pp=dataclasses.replace(p,**{f:getattr(p,f)+h})
            pm=dataclasses.replace(p,**{f:getattr(p,f)-h})
            fd=(probability_quad(pp)[0]-probability_quad(pm)[0])/(2*h)
            self.assertTrue(math.isfinite(float(g)),(f,g))
            self.assertLess(abs(float(g)-fd),2e-5,(f,float(g),fd))
        self.assertLess(float(derivatives[0]),0) # move initial state away => fewer hits
        self.assertGreater(float(derivatives[2]),0) # raise late boundary => more hits

    def test_checkpoint_policy_is_explicitly_causal(self):
        p=TwoStageBrownian()
        self.assertEqual(list(inspect.signature(TwoStageBrownian.b2_at).parameters), ['self','y'])
        self.assertNotEqual(p.b2_at(1.2), p.b2_at(1.5))
        # The boundary policy accepts only the current checkpoint state and
        # cannot accept future Brownian increments or the final position.
        with self.assertRaises(TypeError):
            p.b2_at(1.2, future_state=12.0)

    def test_reject_invalid_and_nonnumeric(self):
        for kw in [dict(x0=0),dict(gain=1),dict(diffusion=0),dict(diffusion=math.nan),
                   dict(t1=0),dict(drift=math.inf),dict(b2_level=999),dict(t2=-1)]:
            p=dataclasses.replace(TwoStageBrownian(),**kw)
            with self.assertRaises(ValueError):
                probability_quad(p)
        p=TwoStageBrownian()
        with self.assertRaises(ValueError):
            probability_torch(p,unknown=torch.tensor(1.,dtype=torch.float64))
        with self.assertRaises(TypeError):
            probability_torch(p,x0=torch.tensor(1.,dtype=torch.float32))
        with self.assertRaises(ValueError):
            probability_torch(p,n=8)


if __name__=='__main__': unittest.main()

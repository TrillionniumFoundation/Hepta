"""Independent numerical/adversarial tests; all HCSN P0-P6 gates stay open."""
import dataclasses
import inspect
import math
import unittest

import torch

from research.hcsn.p2_moving_affine_boundary import (
    MovingTwoStage,bridge_mc,first_killed_density,fixed_barrier_hit,
    probability_quad,probability_torch,
)


class MovingAffineBoundaryTests(unittest.TestCase):
    def test_global_linear_barrier_semigroup(self):
        # Identical slopes and barrier levels make a single global moving line.
        for drift in (-.30,0.,.33):
            for slope in (-.26,0.,.22):
                p=MovingTwoStage(slope1=slope,slope2=slope,
                                 b2=slope*.75,gain=0,drift=drift)
                computed,_=probability_quad(p)
                exact=fixed_barrier_hit(p.x0-p.b1,drift-slope,p.diffusion,p.t1+p.t2)
                self.assertLess(abs(computed-exact),4e-10,(p,computed,exact))

    def test_fixed_barrier_prior_specialization(self):
        p=MovingTwoStage(slope1=0.,slope2=0.)
        risk,_=probability_quad(p)
        self.assertLess(abs(risk-.25099875),1e-7)
        tensor,tail=probability_torch(p)
        self.assertLess(abs(float(tensor)-risk),2e-7)
        self.assertLess(float(tail.detach()),1e-15)

    def test_bridge_density_obeys_first_boundary(self):
        p=MovingTwoStage()
        self.assertEqual(first_killed_density(p.stage1_end_barrier,p),0.)
        self.assertGreater(first_killed_density(p.stage1_end_barrier+1e-8,p),0.)
        self.assertGreater(first_killed_density(p.x0,p),0.)

    def test_slope_monotonicity(self):
        p=MovingTwoStage()
        first=[probability_quad(dataclasses.replace(p,slope1=v))[0] for v in (-.3,0.,.4)]
        second=[probability_quad(dataclasses.replace(p,slope2=v))[0] for v in (-.35,0.,.35)]
        self.assertTrue(first[0]<first[1]<first[2],first)
        self.assertTrue(second[0]<second[1]<second[2],second)

    def test_independent_quad_vs_torch(self):
        cases=[MovingTwoStage(),MovingTwoStage(slope1=-.23,slope2=.30,gain=-.42,b2=-.2),
               MovingTwoStage(slope1=.45,slope2=-.36,gain=.60,b2=.7,drift=-.24),
               MovingTwoStage(slope1=-.35,slope2=.17,gain=.12,b2=-.8,drift=.37)]
        for p in cases:
            reference,_=probability_quad(p)
            torch_risk,tail=probability_torch(p,order=256)
            self.assertLess(abs(float(torch_risk)-reference),4e-7,(p,reference,float(torch_risk)))
            self.assertLess(float(tail.detach()),1e-15)

    def test_exact_linear_bridge_monte_carlo(self):
        cases=[MovingTwoStage(),MovingTwoStage(slope1=-.23,slope2=.30,gain=-.42,b2=-.2),
               MovingTwoStage(slope1=.45,slope2=-.36,gain=.60,b2=.7,drift=-.24),
               MovingTwoStage(slope1=-.35,slope2=.17,gain=.12,b2=-.8,drift=.37)]
        for i,p in enumerate(cases):
            expected,_=probability_quad(p)
            empirical,se,_=bridge_mc(p,n=125_000,seed=20261031+i)
            self.assertLess(abs(empirical-expected),5*se+2e-4,(p,expected,empirical,se))

    def test_autograd_all_ten_parameter_directions(self):
        p=MovingTwoStage(b1=-.2,b2=.41,gain=.3,slope1=.17,slope2=-.13)
        vals={name:torch.tensor(value,dtype=torch.float64,requires_grad=True)
              for name,value in vars(p).items()}
        prediction,tail=probability_torch(p,order=256,**vals)
        gradient=torch.autograd.grad(prediction,tuple(vals.values()))
        self.assertLess(float(tail.detach()),1e-15)
        for (name,value),grad in zip(vals.items(),gradient):
            h=1e-4*max(1.,abs(float(value.detach())))
            plus=dataclasses.replace(p,**{name:float(value.detach())+h})
            minus=dataclasses.replace(p,**{name:float(value.detach())-h})
            fd=(probability_quad(plus)[0]-probability_quad(minus)[0])/(2*h)
            self.assertTrue(math.isfinite(float(grad)),name)
            self.assertLess(abs(float(grad)-fd),3e-5,(name,float(grad),fd))
        self.assertLess(float(gradient[0]),0) # larger initial margin reduces hits
        self.assertGreater(float(gradient[3]),0) # higher stage-2 barrier increases hits
        self.assertGreater(float(gradient[2]),0) # steeper first-stage line increases hits
        self.assertGreater(float(gradient[5]),0) # steeper second-stage line increases hits

    def test_causal_checkpoint_interface(self):
        p=MovingTwoStage()
        self.assertEqual(list(inspect.signature(MovingTwoStage.b2_at).parameters),
                         ['self','checkpoint_state','elapsed_after_checkpoint'])
        self.assertNotEqual(p.b2_at(1.2),p.b2_at(1.5))
        self.assertAlmostEqual(p.b2_at(1.2,.5)-p.b2_at(1.2),p.slope2*.5,places=14)
        with self.assertRaises(TypeError):
            p.b2_at(1.2,future_endpoint=100.)

    def test_invalid_inputs_fail_closed(self):
        for kw in (dict(x0=0.),dict(gain=1.),dict(diffusion=0),dict(diffusion=math.nan),
                   dict(slope1=2),dict(slope2=-2),dict(b1=30),dict(t1=0),
                   dict(b2=math.inf),dict(t2=-1)):
            with self.assertRaises(ValueError):
                probability_quad(dataclasses.replace(MovingTwoStage(),**kw))
        p=MovingTwoStage()
        with self.assertRaises(TypeError):
            probability_torch(p,x0=torch.tensor(1.,dtype=torch.float32))
        with self.assertRaises(ValueError):
            probability_torch(p,unknown=torch.tensor(.2,dtype=torch.float64))
        with self.assertRaises(ValueError):
            probability_quad(p,epsabs=0.)
        with self.assertRaises(ValueError):
            probability_torch(p,order=8)
        with self.assertRaises(ValueError):
            probability_torch(p,gain=torch.tensor(1.,dtype=torch.float64))


if __name__=='__main__':
    unittest.main()

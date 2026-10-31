"""Adversarial finite-grid tests for nonlocal state-dependent impulse QVI."""
import math
import unittest
import numpy as np
try:
    from .contextual_qvi import ContextualReset,solve_contextual_qvi
    from .regenerative_qvi import RegenerativeParams,reset_boundary,regenerative_value
except ImportError:
    from contextual_qvi import ContextualReset,solve_contextual_qvi
    from regenerative_qvi import RegenerativeParams,reset_boundary,regenerative_value

class ContextualQVITests(unittest.TestCase):
    def test_constant_reset_reduces_to_independent_analytical_root(self):
        p=RegenerativeParams()
        a=solve_contextual_qvi(p,ContextualReset(0.,0.))
        b=reset_boundary(p)
        self.assertLess(abs(a.estimated_trigger-b)/b,.045)
        self.assertLess(a.max_complementarity_residual,1e-8)
        for ix in range(50,len(a.v)-25,40):
            expected=regenerative_value(float(a.v[ix]),p)
            self.assertLess(abs(a.u[ix]-expected),.06*max(1.,abs(expected)))

    def test_variable_target_is_truly_nonlinear_nonlocal_obstacle(self):
        p=RegenerativeParams()
        c=ContextualReset(rho=.18,cost_slope=.02)
        a=solve_contextual_qvi(p,c)
        self.assertLess(a.max_complementarity_residual,1e-8)
        self.assertGreater(np.std(a.target),.04)
        self.assertGreater(a.iterations,0)
        self.assertTrue(np.all(a.reset_policy[:12]))
        self.assertTrue(np.all(~a.reset_policy[a.v>=p.reset_value]))
        self.assertGreater(np.ptp(a.u[:40]),.005)  # state-dependent reset value
        active=np.flatnonzero(a.reset_policy)[10:40]
        self.assertLess(np.max(np.abs(a.source_obstacle[active])),1e-8)
        self.assertLessEqual(np.max(a.source_generator[1:-1]),1e-8)

    def test_mesh_refinement_independent_no_closed_form(self):
        p=RegenerativeParams(sigma=.35,delta=.042)
        cfg=ContextualReset(rho=.13,cost_slope=.012)
        a=solve_contextual_qvi(p,cfg,h=.04,left_steps=140,right_steps=140)
        b=solve_contextual_qvi(p,cfg,h=.02,left_steps=280,right_steps=280)
        self.assertLess(abs(a.estimated_trigger-b.estimated_trigger)/b.estimated_trigger,.06)
        # Both grids represent same physical states, with reference reset at x=0.
        for k in (-60,30,70):
            va=a.u[a.v.size//2+k]
            vb=b.u[b.v.size//2+2*k]
            self.assertLess(abs(va-vb),.035*max(1.,abs(vb)))

    def test_reject_invalid_input(self):
        for kwargs in ({'rho':-.1},{'rho':.4},{'cost_slope':-.01},
                       {'rho':float('nan')},{'cost_slope':.08}):
            with self.assertRaises(ValueError):ContextualReset(**kwargs)
        with self.assertRaises(ValueError):solve_contextual_qvi(RegenerativeParams(),h=.1)

if __name__=='__main__':unittest.main()

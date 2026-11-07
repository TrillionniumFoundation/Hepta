"""Independent FD vs regenerative closed form, including mesh convergence."""
from __future__ import annotations
import unittest
import numpy as np
try:
    from .regenerative_qvi import RegenerativeParams,reset_boundary,regenerative_value
    from .qvi_fd_reference import solve_qvi_fd
except ImportError:
    from regenerative_qvi import RegenerativeParams,reset_boundary,regenerative_value
    from qvi_fd_reference import solve_qvi_fd


class IndependentQVIReferenceTests(unittest.TestCase):
    def test_discrete_complementarity_and_value(self):
        for p in [RegenerativeParams(),RegenerativeParams(sigma=.36,delta=.045,
                 reset_value=1.4,reset_cost=.16)]:
            grid=solve_qvi_fd(p)
            self.assertLess(grid.max_complementarity_residual,1e-7)
            b=reset_boundary(p)
            self.assertLess(abs(grid.estimated_boundary-b)/b,.07)
            for i in range(4,len(grid.x)-4,26):
                exact=regenerative_value(float(grid.v[i]),p)
                self.assertLess(abs(grid.u[i]-exact),.08*max(1.,abs(exact)))

    def test_refine_grid_reduces_bias(self):
        p=RegenerativeParams()
        a=solve_qvi_fd(p,h=.04,left_steps=140,right_steps=140)
        b=solve_qvi_fd(p,h=.02,left_steps=280,right_steps=280)
        true=reset_boundary(p)
        # Both grids have same geometric domain and same pinned reset node.
        # Compare errors for continuation points to avoid boundary noise.
        idxa=a.reset_index+30
        idxb=b.reset_index+60
        va=regenerative_value(float(a.v[idxa]),p)
        vb=regenerative_value(float(b.v[idxb]),p)
        self.assertLess(abs(b.u[idxb]-vb),abs(a.u[idxa]-va)+1e-5)
        self.assertLess(abs(b.estimated_boundary-true),.035*true)

    def test_invalid_inputs_refuse(self):
        with self.assertRaises(ValueError):solve_qvi_fd(RegenerativeParams(),h=.1)
        with self.assertRaises(ValueError):solve_qvi_fd(RegenerativeParams(),left_steps=2)

if __name__=='__main__':unittest.main()

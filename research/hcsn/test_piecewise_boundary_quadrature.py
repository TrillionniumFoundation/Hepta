"""Deterministic nonstationary first-hit integration; independent references."""
import math
import unittest
import numpy as np
import torch
from scipy.integrate import quad
try:
    from .piecewise_boundary_quadrature import piecewise_hitting_quadrature
    from .moving_boundary_first_passage import affine_hitting_torch, piecewise_affine_hitting_mc
except ImportError:
    from piecewise_boundary_quadrature import piecewise_hitting_quadrature
    from moving_boundary_first_passage import affine_hitting_torch, piecewise_affine_hitting_mc


def t(value, grad=False):
    return torch.tensor(value, dtype=torch.float64,requires_grad=grad)

def solve(x=.24,mu=.03,sig=.3,slopes=(.18,-.12),ds=(.8,.9),lam=.12,**kwargs):
    return piecewise_hitting_quadrature(t(x),t(mu),t(sig),t(slopes),t(ds),t(lam),**kwargs)

class PiecewiseDeterministicQuadrature(unittest.TestCase):
    def test_one_segment_matches_analytical_closed_forms(self):
        for drift,slope in [(.03,.15),(-.14,-.04),(.12,-.23)]:
            r=solve(slopes=(slope,),ds=(1.6,),mu=drift)
            exact=affine_hitting_torch(t(.24),t(1.6),t(drift),t(.3),t(slope),t(.12))
            self.assertLess(abs(float(r.probability-exact.probability)),2e-7)
            self.assertLess(abs(float(r.discounted_probability-exact.discounted_probability)),2e-7)
            self.assertLess(r.probability_mass_error,2e-7)
            self.assertLess(r.refinement_error,1e-5)

    def test_two_segment_independent_integral_reference(self):
        # A separate 1-D adaptive integral: first-interval killed density times
        # second-interval analytic hitting value, plus first hit event.
        x=.24;mu=.03;sig=.3;sl1=.18;sl2=-.12;d1=.8;d2=.9;lam=.12
        p1=affine_hitting_torch(t(x),t(d1),t(mu),t(sig),t(sl1),t(lam))
        var=sig*sig*d1
        def killed_pdf(y):
            return (math.exp(-.5*(y-x-(mu-sl1)*d1)**2/var)
                    *(-math.expm1(-2*x*y/var))/math.sqrt(2*math.pi*var))
        def next_values(y):
            return affine_hitting_torch(t(y),t(d2),t(mu),t(sig),t(sl2),t(lam))
        # Independently integrate with scipy.quad over y. This does not call
        # the spatial Gauss--Legendre matrix propagator.
        fref=float(p1.probability)+quad(lambda y:killed_pdf(y)*float(next_values(y).probability),0,4.,epsabs=1e-10)[0]
        gref=float(p1.discounted_probability)+math.exp(-lam*d1)*quad(lambda y:killed_pdf(y)*float(next_values(y).discounted_probability),0,4.,epsabs=1e-10)[0]
        ans=solve()
        self.assertLess(abs(float(ans.probability)-fref),2e-7)
        self.assertLess(abs(float(ans.discounted_probability)-gref),2e-7)

    def test_history_even_when_terminal_boundary_identical(self):
        early=solve(x=.22,mu=0.,sig=.26,slopes=(.45,-.45),ds=(.8,.8),lam=.08)
        late=solve(x=.22,mu=0.,sig=.26,slopes=(-.45,.45),ds=(.8,.8),lam=.08)
        self.assertGreater(float(early.probability-late.probability),.4)
        self.assertGreater(float(early.discounted_probability-late.discounted_probability),.35)
        for slopes,answer in [((.45,-.45),early),((-.45,.45),late)]:
            mc=piecewise_affine_hitting_mc(.22,0.,.26,slopes,[.8,.8],paths=140000,seed=425)
            self.assertLess(abs(float(answer.probability)-mc.hit_probability),6*mc.standard_error+.001)

    def test_parameter_gradients_vs_direct_centered_differences(self):
        x=t(.24,True);mu=t(.03,True);sig=t(.3,True)
        sl=t([.18,-.12],True);ds=t([.8,.9],True);lam=t(.12,True)
        res=piecewise_hitting_quadrature(x,mu,sig,sl,ds,lam)
        grad=torch.autograd.grad(res.discounted_probability,(x,mu,sig,sl,ds,lam))
        groups=[[.24],[.03],[.3],[.18,-.12],[.8,.9],[.12]]
        for g,values in enumerate(groups):
            for idx in range(len(values)):
                hi=[list(a) for a in groups];lo=[list(a) for a in groups]
                eps=1e-5; hi[g][idx]+=eps;lo[g][idx]-=eps
                def f(params):
                    args=[t(v[0]) if len(v)==1 and k not in (3,4) else t(v) for k,v in enumerate(params)]
                    return float(piecewise_hitting_quadrature(*args).discounted_probability)
                derivative=(f(hi)-f(lo))/(2*eps)
                actual=float(grad[g][idx] if len(values)>1 else grad[g])
                self.assertLess(abs(derivative-actual),4e-6,(g,idx,actual,derivative))

    def test_interval_split_invariance_and_refinement(self):
        a=solve(slopes=(.09,),ds=(2.,),lam=.1)
        b=solve(slopes=(.09,)*4,ds=(.5,)*4,lam=.1)
        self.assertLess(abs(float(a.probability-b.probability)),2e-6)
        self.assertLess(abs(float(a.discounted_probability-b.discounted_probability)),2e-6)

    def test_heldout_randomized_40_nonstationary_panels(self):
        # Independent withheld RNG, not part of fitted training samples.
        rng=np.random.default_rng(20261031)
        worst_refinement=0.
        worst_mass_error=0.
        for _ in range(40):
            ans=solve(x=float(rng.uniform(.08,.6)),
                mu=float(rng.uniform(-.12,.15)),sig=float(rng.uniform(.16,.45)),
                ds=rng.uniform(.25,1.2,size=3).tolist(),
                slopes=rng.uniform(-.23,.26,size=3).tolist(),
                lam=float(rng.uniform(.02,.22)))
            worst_refinement=max(worst_refinement,ans.refinement_error)
            worst_mass_error=max(worst_mass_error,ans.probability_mass_error)
            self.assertGreaterEqual(float(ans.probability),float(ans.discounted_probability))
        self.assertLess(worst_refinement,1e-9)
        self.assertLess(worst_mass_error,1e-9)

    def test_fail_closed_on_truncation_and_invalid_params(self):
        for kw in [dict(x_max=.3),dict(x_max=1.),dict(coarse_order=20),dict(fine_order=600),dict(tolerance=0.)]:
            with self.assertRaises((ValueError,ArithmeticError)):solve(**kw)
        with self.assertRaises(ValueError):solve(slopes=(.2,.3),ds=(.8,))
        with self.assertRaises(ValueError):solve(sig=0.)
        with self.assertRaises(ValueError):solve(slopes=(.8,),ds=(.8,))
        with self.assertRaises(ValueError):solve(ds=(.0,.3))
        with self.assertRaises(TypeError):piecewise_hitting_quadrature(t(.2).float(),t(.0),t(.3),t([.1]),t([1.]),t(.1))

if __name__=='__main__':unittest.main()

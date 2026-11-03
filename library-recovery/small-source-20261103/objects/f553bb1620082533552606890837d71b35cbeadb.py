"""Independent 90-digit boundary stress test for simplified one-shot kernel."""
import unittest,math,random
import mpmath as mp
from hcsn_p0_p6_20261031.math_kernel import PhysicalParameters, values, beta_and_boundary
class TestAdversarialBoundary(unittest.TestCase):
 def test_mpmath_randomized(self):
  mp.mp.dps=90; rng=random.Random(20261031); worst=0; tested=0
  for _ in range(70):
   p=PhysicalParameters(r=rng.uniform(.001,.3),delta=rng.uniform(.001,.2),sigma=math.exp(rng.uniform(math.log(.01),0)),k=rng.uniform(.1,10))
   beta,b=beta_and_boundary(p)
   r,d,s,k=[mp.mpf(str(x)) for x in (p.r,p.delta,p.sigma,p.k)]
   q=r-d-s*s/2; bh=(q+mp.sqrt(q*q+2*r*s*s))/(s*s); B=k*bh/(1+bh)
   for m in ['1e-3','1e-5','1e-7','1e-9']:
    v=float(B*mp.exp(mp.mpf(m)))
    if v<=b:continue
    got=values(v,p)[0]; vm=mp.mpf(v)
    expected=vm-k+(k-B)*(B/vm)**bh
    error=abs(float(expected)-got); worst=max(worst,error); tested+=1
    self.assertTrue(math.isfinite(got)); self.assertGreaterEqual(got,0)
    self.assertLess(error,2e-10)
  self.assertGreater(tested,200)
  print('ADVERSARIAL_RESULT',{'samples':tested,'worst_absolute_error':worst,'near_boundary_relative_accuracy_not_certified':True})
if __name__=='__main__':unittest.main()

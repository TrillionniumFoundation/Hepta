import unittest
import torch
try:from .p5_end_to_end_cpu import cdf_error,ndtr_approx,run_cpu_benchmark
except ImportError:from p5_end_to_end_cpu import cdf_error,ndtr_approx,run_cpu_benchmark

class P5Tests(unittest.TestCase):
 def test_approx_cdf_and_its_derivative(self):
    e=cdf_error(801)
    self.assertLess(e['cdf_max_abs_error'],1e-6)
    self.assertLess(e['derivative_max_abs_error'],1e-5)
    self.assertTrue(e['grad_finite'])
 def test_narrow_end_to_end_runs(self):
    r=run_cpu_benchmark(iterations=10,batches=(1,),lengths=(24,))
    self.assertEqual(len(r['rows']),3)
    self.assertEqual(set(z['arch'] for z in r['rows']),{'analytic','ordinary','gru'})
    self.assertFalse(r['power_measured'])
    self.assertFalse(r['p5_closed'])
    self.assertTrue(all(z['p99_forward_ms']>0 for z in r['rows']))

if __name__=='__main__':unittest.main()

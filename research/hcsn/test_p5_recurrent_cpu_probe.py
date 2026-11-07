import unittest
try:from .p5_recurrent_cpu_probe import run_cpu_probe
except ImportError:from p5_recurrent_cpu_probe import run_cpu_probe

class CPUHeadProbeTests(unittest.TestCase):
 def test_minimal_complete_head_is_cpu_only_and_not_energy(self):
    p=run_cpu_probe(n_list=(8,),lengths=(24,),repeats=10)
    self.assertEqual(len(p['results']),3)
    self.assertFalse(p['gpu'])
    self.assertIsNone(p['energy_joules'])
    self.assertFalse(p['p5_closed'])
    for z in p['results']:
        self.assertTrue(z['all_outputs_finite'])
        self.assertEqual(len(z['raw_wall_ms']),10)
        self.assertGreater(z['p99_end_to_end_head_ms'],0)

if __name__=='__main__':unittest.main()

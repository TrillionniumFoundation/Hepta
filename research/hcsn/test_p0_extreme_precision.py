import unittest
try:
 from .p0_extreme_precision import numerical_precision_panel,hx_adversarial_panel
except ImportError:
 from p0_extreme_precision import numerical_precision_panel,hx_adversarial_panel

class ExtremeP0Tests(unittest.TestCase):
 def test_bf16_reconstructs_zero_for_tiny_margin(self):
    panel=numerical_precision_panel()
    self.assertEqual(panel[-1]['bf16']['log_margin_reconstructed'],0.)
    self.assertEqual(panel[-1]['fp32']['log_margin_reconstructed'],0.)
    self.assertGreater(panel[-1]['bf16']['relative_margin_reconstruction_error'],.99)
    # A separately supplied FP32 logmargin still yields nonzero Call value.
    self.assertGreater(panel[-1]['fp32']['local_call_from_margin'],0.)
 def test_adversarial_panel_explicitly_counts_singular_a7(self):
    result=hx_adversarial_panel(9,seed=232)
    self.assertEqual(result['cases'],9)
    self.assertGreaterEqual(result['direct_a7_singular_cases'],1)
    self.assertEqual(result['cases'],result['ok']+result['refused'])

if __name__=='__main__':unittest.main()

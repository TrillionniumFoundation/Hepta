import unittest
try:from .gate_evidence import GATES,make_manifest
except ImportError:from gate_evidence import GATES,make_manifest
from pathlib import Path

class FailClosedTests(unittest.TestCase):
 def test_all_required_gates_fail_closed_without_external_evidence(self):
    m=make_manifest(Path(__file__).parent)
    self.assertEqual(set(m['gates']),set(f'P{i}' for i in range(7)))
    self.assertFalse(m['full_closure'])
    self.assertFalse(m['production_activation'])
    self.assertTrue(all(g['status']=='OPEN' and not g['production_ready']
                        for g in m['gates'].values()))

if __name__=='__main__':unittest.main(verbosity=2)

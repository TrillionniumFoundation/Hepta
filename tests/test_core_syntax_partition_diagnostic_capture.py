"""New fixed target shares the already bounded collector, never Lean proofs."""
import unittest
from tools import core_syntax_diagnostic_capture as capture
from tests import test_core_syntax_diagnostic_capture as legacy


class PartitionDiagnosticCaptureTests(unittest.TestCase):
    run_child = legacy.DiagnosticCaptureTests.run_child

    def test_part02_real_child_exact_files_and_marker(self):
        marker = dict(id='HIA_DIAG_v1_P02_000', original_offset=65, instrumented_offset=65)
        script = 'import os; os.write(1,b\'"HIA_DIAG_v1_P02_000" : String\\n\'); os.write(2,b"diagnostic")'
        result, files, launches = self.run_child(script, target='CertPart02', markers=[marker])
        self.assertEqual(result['status'], 'diagnostic_completed')
        self.assertEqual(result['marker_count'], 1)
        self.assertEqual(set(files), set(capture.target_configuration('CertPart02')[0]))
        self.assertEqual(len(launches), 1)

    def test_wrong_target_marker_never_launches(self):
        marker = dict(id='HIA_DIAG_v1_LIN_000', original_offset=65, instrumented_offset=65)
        result, _, launches = self.run_child('raise AssertionError()', target='CertPart02', markers=[marker])
        self.assertEqual(result['status'], 'diagnostic_infrastructure_failed')
        self.assertEqual(launches, [])

    def test_unrecognized_target_rejected(self):
        for target in ('../CertPart02', 'CertPart03', '', None, True):
            with self.assertRaises(ValueError): capture.target_configuration(target)

    def test_legacy_configuration_unchanged(self):
        names, prefix = capture.target_configuration('LinearTransport')
        self.assertEqual(names, capture.DIAGNOSTIC_FILES)
        self.assertEqual(prefix, 'HIA_DIAG_v1_LIN_')

    def test_part02_timeout_cleanup_preserved(self):
        result, _, launches = self.run_child('import time; time.sleep(30)', target='CertPart02')
        self.assertEqual(result['status'], 'diagnostic_timeout')
        self.assertTrue(result['leader_reaped'])
        self.assertTrue(result['group_kill_sent'])
        self.assertEqual(len(launches), 1)

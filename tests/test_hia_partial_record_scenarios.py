"""Independent executable scenarios for initialized-field and cleanup state."""
from pathlib import Path
import sys
import tempfile
import unittest

from hepta.clang_capture import CaptureRejected
from hepta.hia_program import HIAProgramRejected, verify_core
from hepta.hia_program_runtime import HIAProgramBudgetExceeded, execute_program
from tools.qualify_hia_partial_records import cases, independent_spec, program, retained_process


class PartialRecordScenarioTests(unittest.TestCase):
    def test_all_fixed_scenarios_match_independent_values_and_allocator_counts(self):
        checked = verify_core(program())
        for index, row in enumerate(cases()):
            with self.subTest(index=index, row=row):
                options = {'allocation_fail_at': row['fail_at']} if row['fail_at'] else {}
                observed = execute_program(checked, row['function'], row['arguments'], **options)
                expected = independent_spec(row)
                self.assertEqual(observed['values'], [expected['result']])
                ledger = observed['resources']
                for actual, wanted in [('allocation_attempts', 'attempts'), ('allocations', 'allocations'),
                                       ('frees', 'frees'), ('peak_bytes', 'peak_bytes'), ('live_bytes', 'live_bytes')]:
                    self.assertEqual(ledger[actual], expected[wanted])
                self.assertEqual(ledger['owners_created'], expected['logical_owners'])
                self.assertEqual(ledger['owners_dropped'], expected['logical_owners'])
                self.assertEqual(ledger['live_owners'], 0)
                self.assertEqual(ledger['live_local_loans'], 0)

    def test_pending_partial_state_is_preserved_when_evaluator_budget_stops(self):
        checked = verify_core(program())
        normalized = verify_core(checked.canonical_bytes)
        for limit in (3, 8, 15, 25, 40):
            reports = []
            for candidate in (checked, normalized):
                with self.assertRaises(HIAProgramBudgetExceeded) as stopped:
                    execute_program(candidate, 'partial_case', [0, 7, 73], max_steps=limit)
                reports.append(stopped.exception.report)
            self.assertEqual(reports[0]['steps'], reports[1]['steps'])
            self.assertEqual(reports[0]['resources'], reports[1]['resources'])
        # This stop is after the first allocation and before disposal; it
        # must not claim normal-return cleanup or destroy the partial state.
        self.assertGreater(reports[0]['resources']['live_owners'], 0)
        complete = execute_program(checked, 'partial_case', [0, 7, 73], max_steps=60)
        self.assertEqual(complete['result'], 177)
        self.assertEqual(complete['resources']['live_owners'], 0)

    def test_closing_partial_token_cannot_discard_an_initialized_owner(self):
        candidate = program()
        dispose = next(fn for fn in candidate['functions'] if fn['name'] == 'dispose_left')
        dispose['blocks'][0]['ops'] = [
            {'op': 'record.abandon', 'args': ['state'], 'out': [], 'attrs': {}}]
        with self.assertRaisesRegex(HIAProgramRejected, 'E_HIA_INIT'):
            verify_core(candidate)

    def test_borrowed_field_cannot_be_moved_out_before_loan_end(self):
        candidate = program()
        body = next(b for fn in candidate['functions'] if fn['name'] == 'partial_case'
                    for b in fn['blocks'] if b['id'] == 'replace')
        body['ops'].insert(1, {'op': 'record.borrow', 'args': ['pair'],
            'out': [{'name': 'live_loan', 'type': 'readbuf'}], 'attrs': {'field': 'first', 'mode': 'read'}})
        body['ops'].insert(3, {'op': 'loan.end', 'args': ['live_loan'], 'out': [], 'attrs': {}})
        with self.assertRaisesRegex(HIAProgramRejected, 'E_HIA_LOAN'):
            verify_core(candidate)

    def test_qualification_retains_timeout_attempt_and_both_streams(self):
        report = {'processes': []}
        script = "import os,time;os.write(1,b'partial\\x00');os.write(2,b'diagnostic');time.sleep(2)"
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(CaptureRejected) as rejected:
                retained_process(report, directory, [sys.executable, '-c', script], timeout=.4)
            self.assertEqual(rejected.exception.code, 'E_CAPTURE_TIMEOUT')
            self.assertEqual(len(report['processes']), 1)
            attempt = report['processes'][0]
            self.assertEqual(attempt['status'], 'capture_rejected')
            self.assertEqual(Path(attempt['stdout']['path']).read_bytes(), b'partial\x00')
            self.assertEqual(Path(attempt['stderr']['path']).read_bytes(), b'diagnostic')
            self.assertFalse(attempt['stdout_truncated'])
            self.assertFalse(attempt['stderr_truncated'])
            self.assertIsNotNone(attempt['returncode'])

    def test_qualification_reports_output_truncation_and_total_observed_length(self):
        report = {'processes': []}
        script = "import os;os.write(2,b'failure details');os.write(1,b'x'*4096)"
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(CaptureRejected) as rejected:
                retained_process(report, directory, [sys.executable, '-c', script], stdout_limit=32)
            self.assertEqual(rejected.exception.code, 'E_CAPTURE_OUTPUT_SIZE')
            attempt = report['processes'][0]
            self.assertEqual(Path(attempt['stdout']['path']).read_bytes(), b'x' * 32)
            self.assertEqual(attempt['stdout_total_bytes'], 4096)
            self.assertTrue(attempt['stdout_truncated'])
            self.assertEqual(Path(attempt['stderr']['path']).read_bytes(), b'failure details')


if __name__ == '__main__':
    unittest.main()

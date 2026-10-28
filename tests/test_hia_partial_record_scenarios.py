"""Independent executable scenarios for initialized-field and cleanup state."""
from pathlib import Path
import sys
import tempfile
import unittest

from hepta.clang_capture import CaptureRejected
from hepta.hia_program import HIAProgramRejected, verify_core
from hepta.hia_program_runtime import HIAProgramBudgetExceeded, execute_program
from tools.qualify_hia_partial_records import (analysis_receipts, cases, independent_spec,
                                             program, retained_process)


class PartialRecordScenarioTests(unittest.TestCase):
    def test_actual_normalized_call_graph_gets_only_its_supported_bound(self):
        checked = verify_core(program())
        analysis = analysis_receipts(checked)
        frames = analysis['call_depth']
        self.assertEqual(frames['core_sha256'], checked.sha256)
        self.assertEqual(frames['input_sha256'], checked.input_sha256)
        self.assertEqual(frames['core_schema'], 'hepta.hia.program.v7')
        bounds = {row['function']: row['max_call_depth'] for row in frames['functions']}
        self.assertEqual(bounds['partial_case'], 2)
        self.assertEqual(bounds['partial_task'], 4)
        self.assertEqual(bounds['partial_pair_task'], 4)
        self.assertFalse(frames['claims']['vm_ticks_bounded'])
        self.assertFalse(frames['claims']['process_rss_or_native_stack_bytes_bounded'])
        self.assertEqual(analysis['static_budget']['status'], 'unknown')
        self.assertEqual(analysis['static_budget']['code'], 'E_HIA_BUDGET_PROFILE')
        self.assertEqual(analysis['live_heap']['status'], 'unknown')

    def test_partial_v3_does_not_erase_a_v8_return_origin_contract(self):
        from tests.test_hia_returned_loans import helper, loan_program
        raw_v8 = loan_program('mut', 'child')
        admitted = verify_core(raw_v8)
        self.assertEqual(execute_program(admitted, 'entry_mut_child', [1, 37])['result'], 42)
        self.assertEqual(admitted.as_dict()['functions'][0]['return_loans'], ['input'])
        nominal = program()
        nominal['functions'].append(helper('mut', 'child'))
        with self.assertRaisesRegex(HIAProgramRejected, 'E_HIA_FORMAT'):
            verify_core(nominal)

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

    def test_two_payload_task_failure_stages_and_cancel_are_explicit(self):
        checked = verify_core(program())
        for mode in (0, 1, 2):
            for fail, expected, allocations in ((1, 100, 0), (2, 200, 1), (None, 3 if mode < 2 else 88, 2)):
                with self.subTest(mode=mode, fail=fail):
                    options = {} if fail is None else {'allocation_fail_at': fail}
                    result = execute_program(checked, 'partial_pair_task', [mode, 7, 73], **options)
                    self.assertEqual(result['result'], expected)
                    self.assertEqual(result['resources']['allocations'], allocations)
                    self.assertEqual(result['resources']['frees'], allocations)
                    self.assertEqual(result['resources']['live_owners'], 0)
                    self.assertEqual(result['resources']['live_bytes'], 0)

    def test_two_live_payload_budget_stop_does_not_invoke_cancellation(self):
        checked = verify_core(program())
        with self.assertRaises(HIAProgramBudgetExceeded) as stopped:
            execute_program(checked, 'partial_pair_task', [1, 7, 73], max_steps=20)
        ledger = stopped.exception.report['resources']
        self.assertEqual(ledger['allocations'], 2)
        self.assertEqual(ledger['frees'], 0)
        self.assertEqual(ledger['live_bytes'], 15)
        self.assertGreaterEqual(ledger['live_owners'], 3)

    def test_two_payload_cleanup_cannot_consume_a_still_borrowed_field(self):
        candidate = program()
        body = next(fn for fn in candidate['functions'] if fn['name'] == 'pair_poll')['blocks'][0]['ops']
        delayed = next(op for op in body if op['op'] == 'loan.end' and op['args'] == ['first_view'])
        body.remove(delayed)
        cleanup_call = next(index for index, op in enumerate(body)
                            if op['op'] == 'call' and op['attrs']['function'] == 'dispose_full')
        body.insert(cleanup_call + 1, delayed)
        with self.assertRaisesRegex(HIAProgramRejected, 'E_HIA_LOAN'):
            verify_core(candidate)

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

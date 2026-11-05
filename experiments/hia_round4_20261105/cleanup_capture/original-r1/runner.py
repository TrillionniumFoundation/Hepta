import json,sys,unittest
loader=unittest.TestLoader()
suite=loader.loadTestsFromNames(['tests.test_core_capture_terminal_deadline.CaptureTerminalDeadlineTests.test_cleanup_eof_after_deadline_is_rejected_without_renewal', 'tests.test_core_capture_terminal_deadline.CaptureTerminalDeadlineTests.test_cleanup_late_data_consumes_quota_without_persistence_or_renewal', 'tests.test_core_capture_terminal_deadline.CaptureTerminalDeadlineTests.test_cleanup_wait_returning_after_deadline_never_succeeds'])
result=unittest.TextTestRunner(verbosity=2).run(suite)
receipt={'testsRun':result.testsRun,'failures':len(result.failures),'errors':len(result.errors),'skips':len(result.skipped),'expected_failures':len(result.expectedFailures),'unexpected_successes':len(result.unexpectedSuccesses),'loader_errors':loader.errors,'expected_count':3}
print(json.dumps(receipt,sort_keys=True))
sys.exit(0 if result.wasSuccessful() and result.testsRun==3 and not loader.errors and not result.skipped and not result.expectedFailures and not result.unexpectedSuccesses else 1)

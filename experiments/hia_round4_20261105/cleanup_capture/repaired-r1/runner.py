import json,sys,unittest
loader=unittest.TestLoader()
suite=loader.loadTestsFromNames(['tests.test_core_capture_terminal_deadline', 'tests.test_core_syntax_diagnostic_capture', 'tests.test_core_seven_certificate_pending_eio'])
result=unittest.TextTestRunner(verbosity=2).run(suite)
receipt={'testsRun':result.testsRun,'failures':len(result.failures),'errors':len(result.errors),'skips':len(result.skipped),'expected_failures':len(result.expectedFailures),'unexpected_successes':len(result.unexpectedSuccesses),'loader_errors':loader.errors,'expected_count':45}
print(json.dumps(receipt,sort_keys=True))
sys.exit(0 if result.wasSuccessful() and result.testsRun==45 and not loader.errors and not result.skipped and not result.expectedFailures and not result.unexpectedSuccesses else 1)

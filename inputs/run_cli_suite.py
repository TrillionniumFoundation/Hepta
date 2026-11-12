
import json,os,pathlib,sys,unittest
names=("tests.test_hia_cli_native","tests.test_hia_cli_continuation_native")
suite=unittest.defaultTestLoader.loadTestsFromNames(names)
assert suite.countTestCases()==39,suite.countTestCases()
result=unittest.TextTestRunner(verbosity=2).run(suite)
passed=(result.wasSuccessful() and result.testsRun==39 and not result.skipped
        and not result.expectedFailures and not result.unexpectedSuccesses)
out={"expected":39,"tests_run":result.testsRun,"failures":len(result.failures),
     "errors":len(result.errors),"skips":len(result.skipped),"expected_failures":len(result.expectedFailures),
     "unexpected_successes":len(result.unexpectedSuccesses),"passed":passed}
pathlib.Path(os.environ["CLI_V77_TERMINAL"]).write_text(json.dumps(out,indent=2)+"\n")
raise SystemExit(0 if passed else 1)

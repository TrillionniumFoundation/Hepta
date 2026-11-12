"""Run the exact frozen ELF component denominator; never infer native skips."""
from pathlib import Path
import json
import sys
import time
import traceback
import unittest

source, output = Path(sys.argv[1]).resolve(strict=True), Path(sys.argv[2])
sys.path.insert(0, str(source))
expected = int(sys.argv[3])
names = sys.argv[4:]
record = {'schema': 'hia.elf.development-suite.v1', 'expected_count': expected,
          'modules': names, 'scope': 'DEVELOPMENT_ONLY', 'python': sys.version,
          'cold_qualified': False, 'whole_qualified': False}
started = time.monotonic()
try:
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromNames(names)
    def flatten(suite):
        for item in suite:
            if isinstance(item, unittest.TestSuite):
                yield from flatten(item)
            else:
                yield item
    loaded = [test.id() for test in flatten(suite)]
    record.update(loaded_ids=loaded, loader_errors=loader.errors)
    assert len(loaded) == expected and len(set(loaded)) == expected and not loader.errors
    class Result(unittest.TextTestResult):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.executed = []
        def startTest(self, test):
            self.executed.append(test.id())
            super().startTest(test)
    result = unittest.TextTestRunner(verbosity=2, resultclass=Result).run(suite)
    record.update(tests_run=result.testsRun, executed_ids=result.executed,
                  failures=[(test.id(), trace) for test, trace in result.failures],
                  errors=[(test.id(), trace) for test, trace in result.errors],
                  skips=[(test.id(), reason) for test, reason in result.skipped],
                  expected_failures=[(test.id(), trace) for test, trace in result.expectedFailures],
                  unexpected_successes=[test.id() for test in result.unexpectedSuccesses])
    record['status'] = ('PASS' if result.wasSuccessful() and result.testsRun == expected
                        and result.executed == loaded and not result.skipped
                        and not result.expectedFailures and not result.unexpectedSuccesses else 'FAIL')
except BaseException:
    record.update(status='FAIL', traceback=traceback.format_exc())
finally:
    record['seconds'] = time.monotonic() - started
    with output.open('x') as stream:
        json.dump(record, stream, sort_keys=True, indent=2)
        stream.write('\n')
print(json.dumps({'status': record['status'], 'tests_run': record.get('tests_run', 0)}), flush=True)
raise SystemExit(0 if record['status'] == 'PASS' else 1)

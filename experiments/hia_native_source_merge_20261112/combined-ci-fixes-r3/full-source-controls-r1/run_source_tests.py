"""Complete source-only gate controls plus original source-contract tests."""
from pathlib import Path
import json
import sys
import unittest

ROOT = Path('/workspace/scratch/e26ed3e2edcf/combined-ci-fixes-r3')
OUT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
expected = json.loads((OUT / 'EXPECTED-IDS.json').read_bytes())
loader = unittest.TestLoader()
suite = loader.loadTestsFromNames([
    'tests.test_hia_compiler_owner_gates.CompilerOwnerGateTests',
    'tests.test_hia_selfhost_contract.SelfhostContractTests',
    'tests.test_hia_core_only.CoreOnlyTests',
    'tests.test_hia_selfhost_names.SelfhostFunctionNameTests',
])
def ids(test):
    if isinstance(test, unittest.TestSuite):
        return [name for child in test for name in ids(child)]
    return [test.id()]
loaded, started = ids(suite), []
class Result(unittest.TextTestResult):
    def startTest(self, test):
        started.append(test.id())
        super().startTest(test)
result = unittest.TextTestRunner(verbosity=2, resultclass=Result).run(suite)
anomalies = {
    'errors': len(result.errors), 'failures': len(result.failures),
    'skipped': len(result.skipped), 'expectedFailures': len(result.expectedFailures),
    'unexpectedSuccesses': len(result.unexpectedSuccesses),
}
passed = (expected == loaded == started and result.testsRun == len(expected)
          and not loader.errors and not any(anomalies.values()))
report = {'schema': 'hia.combined-ci-custody-source-tests.v1',
          'status': 'SOURCE_GATE_AND_CONTRACT_TESTS_PASS' if passed else 'FAIL',
          'expected_ids': expected, 'loaded_ids': loaded, 'executed_ids': started,
          'tests_run': result.testsRun, 'anomaly_counts': anomalies,
          'loader_errors': loader.errors, 'runtime': sys.version,
          'native_or_cold_qualification_executed': False}
with (OUT / 'TEST-RESULT.json').open('x') as stream:
    json.dump(report, stream, indent=2, sort_keys=True)
    stream.write('\n')
print(json.dumps(report, sort_keys=True))
raise SystemExit(0 if passed else 1)

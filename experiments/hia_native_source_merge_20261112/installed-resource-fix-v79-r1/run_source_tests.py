"""Original source-resource and contract methods; no native installation claim."""
from pathlib import Path
import json
import sys
import unittest

ROOT = Path('/workspace/scratch/e26ed3e2edcf/installed-resource-v79-r1')
OUT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
expected = json.loads((OUT / 'EXPECTED-IDS.json').read_bytes())
loader = unittest.TestLoader()
suite = loader.loadTestsFromNames([
    'tests.test_hia_agent_installed_resources.AgentInstalledResourceSourceTests',
    'tests.test_hia_selfhost_contract.SelfhostContractTests',
])

def ids(test):
    if isinstance(test, unittest.TestSuite):
        return [name for child in test for name in ids(child)]
    return [test.id()]

loaded, executed = ids(suite), []

class Result(unittest.TextTestResult):
    def startTest(self, test):
        executed.append(test.id())
        super().startTest(test)

result = unittest.TextTestRunner(verbosity=2, resultclass=Result).run(suite)
anomalies = {name: len(getattr(result, name)) for name in (
    'errors', 'failures', 'skipped', 'expectedFailures', 'unexpectedSuccesses')}
passed = (expected == loaded == executed and result.testsRun == len(expected)
          and not loader.errors and not any(anomalies.values()))
report = {'schema': 'hia.installed-resource-source-controls.v1',
          'status': 'SOURCE_RESOURCE_AND_CONTRACT_CONTROLS_PASS' if passed else 'FAIL',
          'expected_ids': expected, 'loaded_ids': loaded, 'executed_ids': executed,
          'tests_run': result.testsRun, 'anomaly_counts': anomalies,
          'loader_errors': loader.errors, 'runtime': sys.version,
          'native_installation_executed': False, 'cold_qualification_executed': False}
with (OUT / 'TEST-RESULT.json').open('x') as stream:
    json.dump(report, stream, indent=2, sort_keys=True)
    stream.write('\n')
print(json.dumps(report, sort_keys=True))
raise SystemExit(0 if passed else 1)

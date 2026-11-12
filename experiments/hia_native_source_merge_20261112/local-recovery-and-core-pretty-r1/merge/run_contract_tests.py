"""Run the existing seven source-contract tests; no cold/native qualification."""
from pathlib import Path
import json
import sys
import unittest

REPO = Path('/workspace/scratch/e26ed3e2edcf/combined-native-r1')
OUT = Path('/workspace/scratch/e26ed3e2edcf/root/combined-native-r1')
sys.path.insert(0, str(REPO))
PREFIX = 'tests.test_hia_selfhost_contract.SelfhostContractTests.'
EXPECTED = [PREFIX + name for name in sorted((
    'test_hosted_agent_discovery_resources_are_in_actual_source_identity',
    'test_release_freeze_inventory_covers_the_complete_selfhost_closure',
    'test_contract_binds_support_and_complete_seed_source_closure',
    'test_capacity_growth_preserves_workspace_and_core_byte_limits',
    'test_upgrade_refuses_an_unpinned_historical_image_before_execution',
    'test_changed_loader_or_broadened_support_cannot_reuse_the_contract',
    'test_cold_output_refuses_existing_and_symbolic_paths_before_creating_artifacts',
))]
loader = unittest.TestLoader()
suite = loader.loadTestsFromName('tests.test_hia_selfhost_contract.SelfhostContractTests')
def ids(test):
    if isinstance(test, unittest.TestSuite):
        return [value for item in test for value in ids(item)]
    return [test.id()]
loaded = ids(suite)
started = []
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
passed = loaded == started == EXPECTED and result.testsRun == 7 and not loader.errors and not any(anomalies.values())
record = {'schema': 'hia.combined-source-contract-tests.v1', 'status': 'SOURCE_CONTRACT_TESTS_PASS' if passed else 'FAIL',
    'expected_ids': EXPECTED, 'loaded_ids': loaded, 'executed_ids': started,
    'tests_run': result.testsRun, 'anomaly_counts': anomalies, 'loader_errors': loader.errors,
    'runtime': sys.version, 'native_or_cold_qualification_executed': False}
with (OUT / 'CONTRACT-TESTS.json').open('x') as f:
    json.dump(record, f, indent=2); f.write('\n')
print(json.dumps(record, sort_keys=True))
raise SystemExit(0 if passed else 1)

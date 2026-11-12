"""Explicit development observation; never supplies cold or whole authority."""
from pathlib import Path
from hashlib import sha256
import argparse
import json
import os
import sys
import time
import unittest

root = Path(os.environ['HIA_CONTRACT_DEVELOPMENT_ROOT']).resolve()
parser = argparse.ArgumentParser()
parser.add_argument('--output', type=Path, required=True)
parser.add_argument('--compiler', type=Path, required=True)
parser.add_argument('selectors', nargs='+')
args = parser.parse_args()
folder = args.output.resolve()
folder.mkdir()
sys.path.insert(0, str(root / 'source'))
for key in tuple(os.environ):
    if key.startswith('HEPTA_HIA_'):
        del os.environ[key]
os.environ['HEPTA_HIA_AGENT_CONTRACT_DEVELOPMENT_COMPILER'] = str(args.compiler.resolve())
os.environ['HEPTA_HIA_AGENT_CONTRACT_EVIDENCE'] = str(folder / 'evidence')
from tests.hia_agent_contract_fixtures import inputs
before = inputs()
compiler_bytes = args.compiler.read_bytes()
def flatten(suite):
    for child in suite:
        if isinstance(child, unittest.TestSuite):
            yield from flatten(child)
        else:
            yield child.id()
loader = unittest.TestLoader()
suite = loader.loadTestsFromNames(args.selectors)
loaded = list(flatten(suite))
assert not loader.errors and loaded and len(loaded) == len(set(loaded)), loader.errors
executed = []
class Result(unittest.TextTestResult):
    def startTest(self, test):
        executed.append(test.id())
        super().startTest(test)
start = time.monotonic()
with (folder / 'unittest.log').open('w') as log:
    result = unittest.TextTestRunner(stream=log, verbosity=2, resultclass=Result).run(suite)
elapsed = time.monotonic() - start
after = inputs()
unchanged = before == after and args.compiler.read_bytes() == compiler_bytes
anomalies = {name: [(test.id(), str(value)) for test, value in getattr(result, name)]
             for name in ('errors', 'failures', 'skipped', 'expectedFailures')}
anomalies['unexpectedSuccesses'] = [test.id() for test in result.unexpectedSuccesses]
passed = result.wasSuccessful() and not any(anomalies.values()) and loaded == executed and unchanged
report = {'schema': 'hia.agent-contract.development-group.v1',
          'scope': 'EXPLICIT_COMPILER_DEVELOPMENT_ONLY', 'python': sys.version,
          'status': 'PASS' if passed else 'FAIL', 'selectors': args.selectors,
          'loaded_ids': loaded, 'executed_ids': executed, 'tests_run': result.testsRun,
          'elapsed_seconds': elapsed, 'anomalies': anomalies, 'inputs_unchanged': unchanged,
          'source_before': {k: sha256(v).hexdigest() for k, v in before.items()},
          'source_after': {k: sha256(v).hexdigest() for k, v in after.items()},
          'compiler_sha256': sha256(compiler_bytes).hexdigest(),
          'cold': False, 'whole': False, 'default': False, 'deletion': False}
(folder / 'REPORT.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps({k: report[k] for k in ('status', 'tests_run', 'elapsed_seconds', 'inputs_unchanged')}))
raise SystemExit(0 if passed else 1)

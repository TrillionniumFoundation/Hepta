"""Replay the retained original 98 controls plus three integration controls."""
from pathlib import Path
import argparse
import contextlib
import hashlib
import json
import sys
import time
import unittest

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    plans = json.loads((HERE / 'plans.json').read_bytes())
    names = [name for group in plans.values() for name in group]
    assert len(names) == len(set(names)) == 101
    start = time.monotonic_ns()
    log = args.output / 'controls.log'
    with log.open('w') as stream:
        with contextlib.redirect_stdout(stream), contextlib.redirect_stderr(stream):
            result = unittest.TextTestRunner(stream=stream, verbosity=2).run(
                unittest.TestLoader().loadTestsFromNames(names))
    summary = {
        'schema': 'hepta.hia.integrated-caller-source-controls.v1',
        'plans': plans, 'planned': len(names), 'tests_run': result.testsRun,
        'failures': len(result.failures), 'errors': len(result.errors),
        'skipped': len(result.skipped), 'elapsed_ns': time.monotonic_ns() - start,
        'log_sha256': hashlib.sha256(log.read_bytes()).hexdigest(),
        'python': sys.version, 'whole_native_delivery_qualified': False,
        'failure_details': [(test.id(), detail) for test, detail in result.failures + result.errors],
    }
    (args.output / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps({key: value for key, value in summary.items()
                      if key not in ('plans', 'failure_details')}))
    return 0 if result.wasSuccessful() and result.testsRun == 101 and not result.skipped else 1


if __name__ == '__main__':
    raise SystemExit(main())

#!/usr/bin/env python3
"""Strict exact-inventory integration gate; missing native compilers fail."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def sha(data):
    return hashlib.sha256(data).hexdigest()


def source_identity():
    return {str(p.relative_to(ROOT)): sha(p.read_bytes())
            for directory in ('hepta', 'tests', 'tools', 'docs', '.github')
            for p in sorted((ROOT / directory).rglob('*'))
            if p.is_file() and '__pycache__' not in p.parts and p.suffix != '.pyc'}


class StrictResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.started, self.finished, self.passed = [], [], []

    def startTest(self, test):
        self.started.append(test.id())
        super().startTest(test)

    def stopTest(self, test):
        self.finished.append(test.id())
        super().stopTest(test)

    def addSuccess(self, test):
        self.passed.append(test.id())
        super().addSuccess(test)


def main():
    if sys.flags.optimize:
        raise SystemExit('Run without Python -O: the independent oracles use assertions')
    os.environ['PYTHONDONTWRITEBYTECODE'] = '1'
    os.environ['PYTHONPATH'] = str(ROOT)
    os.chdir(ROOT)
    backend = os.environ.get('HEPTA_PACKAGE_TEST_BACKEND', 'c')
    if backend not in ('c', 'rust'):
        raise SystemExit('HEPTA_PACKAGE_TEST_BACKEND must be c or rust')
    if backend == 'rust':
        from hepta.backend import find_rustc, toolchain_info
        toolchain = toolchain_info(find_rustc())
    else:
        cc = os.environ.get('CC', 'gcc')
        version = subprocess.run([cc, '--version'], check=True, capture_output=True, text=True)
        toolchain = {'version': version.stdout.strip(), 'requested': cc}
    manifest = json.loads((ROOT/'tests/package_integration_components.json').read_text())
    for path, expected in manifest['preserved'].items():
        data = (ROOT/path).read_bytes()
        if sha(data) != expected['sha256']:
            raise SystemExit('Component bytes changed: ' + path)
        blob = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
        if blob != expected['git_blob']:
            raise SystemExit('Component Git blob changed: ' + path)
    planned = json.loads((ROOT/'tests/package_integration_inventory.json').read_text())
    if len(planned) != 65 or len(set(planned)) != len(planned):
        raise SystemExit('Expected 65 unique frozen method identities')
    before = source_identity()
    print('PACKAGE_IDENTITY ' + json.dumps({'python': sys.version, 'backend': backend,
          'toolchain': toolchain, 'components': manifest, 'source_sha256': before}, sort_keys=True), flush=True)
    suite = unittest.TestLoader().loadTestsFromNames(planned)
    result = unittest.TextTestRunner(verbosity=2, resultclass=StrictResult).run(suite)
    report = {'planned': planned, 'started': result.started, 'finished': result.finished,
              'passed': result.passed, 'failures': len(result.failures), 'errors': len(result.errors),
              'skips': len(result.skipped), 'expected_failures': len(result.expectedFailures),
              'unexpected_successes': len(result.unexpectedSuccesses)}
    print('PACKAGE_METHODS ' + json.dumps(report, sort_keys=True), flush=True)
    good = (result.wasSuccessful() and planned == result.started == result.finished == result.passed
            and not result.skipped and not result.expectedFailures and not result.unexpectedSuccesses)
    if before != source_identity():
        raise SystemExit('Source changed during tests')
    if not good:
        raise SystemExit('Strict package method inventory failed')
    for oracle in ('tests.package_resolution_oracle', 'tests.lock_diff_graph_oracle',
                   'tests.package_integration_oracle'):
        subprocess.run([sys.executable, '-B', '-m', oracle], check=True, cwd=ROOT)
    if before != source_identity():
        raise SystemExit('Source changed during oracles')
    print('PACKAGE_INTEGRATION_PASS ' + json.dumps({'methods': len(planned), 'backend': backend,
          'python': sys.version.split()[0], 'source_unchanged': True}), flush=True)


if __name__ == '__main__':
    main()

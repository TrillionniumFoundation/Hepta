"""Run all original full-cost callers from a real default-native installation.

No native selector is supplied by the harness. Product code comes from the
candidate wheel; original tests and their process-observer drivers are retained
unchanged. The report preserves all planned/started/stopped test identities.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ''}:
    sys.path.insert(0, str(ROOT))

from tools.build_hia_default_release import SCHEMA, WHEEL_TAG, encoded
from tools.build_hia_json_preflight import current_sources
from tools.qualify_hia_full_cost_callers import ORIGINAL_MODULES

CHILD = r'''
import json, os, sys, time, unittest
from pathlib import Path
from unittest.mock import patch
installed, repository, destination, expected_image = map(Path, sys.argv[1:5])
sys.path[:0] = [str(installed), str(repository)]
sys.dont_write_bytecode = True
from hepta import hia_full_cost_gate as owner
from hepta import hia_full_cost_native as native
assert Path(owner.__file__).resolve().is_relative_to(installed)
assert Path(native.__file__).resolve().is_relative_to(installed)
assert native.SOURCE.resolve().is_relative_to(installed)
assert not [key for key in os.environ if key.startswith('HEPTA_HIA_') and key.endswith('_MANIFEST')]
from tools.run_hia_unittest_gate import load_declared_suite
from tools.qualify_hia_full_cost_callers import ORIGINAL_MODULES
suite, planned = load_declared_suite(ORIGINAL_MODULES)
planned = list(planned)
started, stopped, entries = [], [], [0, 0]
class Result(unittest.TextTestResult):
    def startTest(self, test):
        started.append(test.id()); super().startTest(test)
    def stopTest(self, test):
        stopped.append(test.id()); super().stopTest(test)
def forbidden(*args, **kwargs):
    raise AssertionError('installed ordinary full-cost entered retained Python arithmetic')
arm, decide = native.NativeFullCost.arm, native.NativeFullCost.decide
def observed_arm(selected, *args):
    assert selected.image_sha256 == str(expected_image)
    entries[0] += 1
    return arm(selected, *args)
def observed_decide(selected, *args):
    assert selected.image_sha256 == str(expected_image)
    entries[1] += 1
    return decide(selected, *args)
begin = time.monotonic()
with patch.object(owner, '_reference_arm', forbidden, create=True), \
     patch.object(owner, '_reference_decision', forbidden, create=True), \
     patch.object(native.NativeFullCost, 'arm', observed_arm), \
     patch.object(native.NativeFullCost, 'decide', observed_decide), \
     (destination / 'tests.log').open('x') as stream:
    result = unittest.TextTestRunner(stream=stream, verbosity=2, resultclass=Result).run(suite)
clean = result.wasSuccessful() and not any(getattr(result, key) for key in
    ('errors', 'failures', 'skipped', 'expectedFailures', 'unexpectedSuccesses'))
unselected = not [key for key in os.environ if key.startswith('HEPTA_HIA_') and key.endswith('_MANIFEST')]
record = {'status': 'PASS' if clean and started == stopped == planned and
          result.testsRun == len(planned) and all(entries) and unselected else 'FAIL',
    'original_modules': list(ORIGINAL_MODULES), 'planned': planned, 'started': started, 'stopped': stopped,
    'actual_tests': result.testsRun, 'wall_seconds': time.monotonic() - begin,
    'errors': [(t.id(), e) for t, e in result.errors], 'failures': [(t.id(), e) for t, e in result.failures],
    'skipped': [(t.id(), e) for t, e in result.skipped],
    'expected_failures': [(t.id(), e) for t, e in result.expectedFailures],
    'unexpected_successes': [t.id() for t in result.unexpectedSuccesses],
    'native_arm_calls': entries[0], 'native_decision_calls': entries[1],
    'no_native_selector_environment': unselected, 'retained_python_arithmetic_forbidden': True,
    'product_module': str(Path(owner.__file__).resolve()), 'native_source': str(native.SOURCE.resolve()),
    'whole_native_delivery_qualified': False}
(destination / 'child-report.json').write_text(json.dumps(record, indent=2, sort_keys=True) + '\n')
raise SystemExit(record['status'] != 'PASS')
'''


def _files(root):
    return {str(path.relative_to(root)): sha256(path.read_bytes()).hexdigest()
            for path in sorted(root.rglob('*')) if path.is_file()}


def qualify(package_build, evidence):
    package_build, evidence = Path(package_build).resolve(strict=True), Path(evidence).absolute()
    build_bytes = package_build.read_bytes()
    record = json.loads(build_bytes)
    sources = current_sources()
    if (record.get('schema') != SCHEMA or record.get('wheel_tag') != WHEEL_TAG
            or record.get('source_manifest') != sources
            or record.get('scope') not in ('MATCHING_SOURCE_COLD_COMPONENT', 'DEVELOPMENT_COMPONENT')):
        raise ValueError('current-source default wheel construction is required')
    wheel = Path(record['wheel']).resolve(strict=True)
    wheel_bytes = wheel.read_bytes()
    if sha256(wheel_bytes).hexdigest() != record['wheel_sha256']:
        raise ValueError('constructed default wheel bytes changed')
    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)) or {name: sha256(archive.read(name)).hexdigest()
                                           for name in names} != record['members']:
            raise ValueError('constructed default wheel member inventory changed')
        prefix = 'hepta/_data/native/default/full_cost/'
        manifest = json.loads(archive.read(prefix + 'manifest.json'))
    caller_pins = {name.replace('.', '/') + '.py': sha256(
        (ROOT / (name.replace('.', '/') + '.py')).read_bytes()).hexdigest() for name in ORIGINAL_MODULES}
    evidence.mkdir(mode=0o700, parents=False, exist_ok=False)
    installed = evidence / 'installed'
    environment = {key: value for key, value in os.environ.items()
                   if key not in ('PYTHONPATH', 'PYTHONHOME') and not key.startswith('HEPTA_HIA_')}
    environment['PYTHONDONTWRITEBYTECODE'] = '1'
    command = [sys.executable, '-B', '-m', 'pip', 'install', '--no-deps', '--no-index',
               '--no-compile', '--target', str(installed), str(wheel)]
    install = subprocess.run(command, cwd=evidence, env=environment, capture_output=True, timeout=60)
    (evidence / 'install.stdout').write_bytes(install.stdout)
    (evidence / 'install.stderr').write_bytes(install.stderr)
    if install.returncode:
        raise ValueError('real default wheel installation failed')
    installation_before = _files(installed)
    child = subprocess.run([sys.executable, '-B', '-I', '-c', CHILD, str(installed), str(ROOT),
        str(evidence), manifest['image_sha256']], cwd=evidence, env=environment,
        capture_output=True, timeout=300)
    (evidence / 'child.stdout').write_bytes(child.stdout)
    (evidence / 'child.stderr').write_bytes(child.stderr)
    child_path = evidence / 'child-report.json'
    child_report = json.loads(child_path.read_bytes()) if child_path.is_file() else {'status': 'FAIL'}
    stable = (package_build.read_bytes() == build_bytes and wheel.read_bytes() == wheel_bytes
              and current_sources() == sources and _files(installed) == installation_before
              and all(sha256((ROOT / name).read_bytes()).hexdigest() == digest
                      for name, digest in caller_pins.items()))
    passed = child.returncode == 0 and child_report['status'] == 'PASS' and stable
    report = {**child_report, 'status': 'PASS' if passed else 'FAIL',
        'schema': 'hepta.hia.default-native-original-callers.v1',
        'scope': record['scope'], 'package_build_sha256': sha256(build_bytes).hexdigest(),
        'wheel_sha256': record['wheel_sha256'], 'default_bundle_sha256': record['default_bundle_sha256'],
        'compiler_sha256': record['compiler_sha256'], 'native_image_sha256': manifest['image_sha256'],
        'cold_report_sha256': record['cold_report_sha256'],
        'source_manifest': sources, 'original_caller_pins': caller_pins,
        'installation_before': installation_before, 'source_wheel_and_installation_unchanged': stable,
        'install_command': command, 'child_returncode': child.returncode,
        'retained_reference_bodies_removed': False, 'whole_native_delivery_qualified': False}
    (evidence / 'report.json').write_bytes(encoded(report))
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--package-build', type=Path, required=True)
    parser.add_argument('--evidence', type=Path, required=True)
    args = parser.parse_args()
    result = qualify(args.package_build, args.evidence)
    print(json.dumps({name: result.get(name) for name in ('status', 'scope', 'actual_tests', 'wall_seconds')}))
    return int(result['status'] != 'PASS')


if __name__ == '__main__':
    raise SystemExit(main())

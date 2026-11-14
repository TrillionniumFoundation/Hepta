"""Run the original runtime callers with the selected HIA scalar-profile owner.

The complete original modules retain their real Clang, Rust, Z3, sealed loading,
publication, lease and failure controls. Missing dependencies, skipped tests or
missing lifecycle/proof entries cannot qualify this caller gate.
"""
from __future__ import annotations

import argparse
from contextlib import ExitStack
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
import threading
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ''}:
    sys.path.insert(0, str(ROOT))

from tools.run_hia_unittest_gate import load_declared_suite

ORIGINAL_MODULES = ('tests.test_hia_multiversion',
                    'tests.test_hia_multiversion_totality',
                    'tests.test_hia_native_profile_convergence')
LOCAL_INPUTS = (
    'examples/hia_bootstrap/scalar_profile.hepta',
    'hepta/hia_scalar_profile_native.py', 'hepta/hia_multiversion.py',
    'tools/generate_hia_scalar_profile.py', 'tools/build_hia_scalar_profile.py',
    'tools/qualify_hia_scalar_profile_callers.py',
    'tests/fixtures/scalar_profile_698cc280.py.txt', 'tests/test_hia_scalar_profile_native.py',
    'tests/test_hia_multiversion.py', 'tests/test_hia_multiversion_totality.py',
    'tests/test_hia_native_profile_convergence.py', 'tests/test_hia_program.py',
    'tests/test_hia_program_composite.py',
    'tests/test_hia_scalar_totality.py', 'tests/test_hia_translation_validation.py',
    'tools/qualify_hia_native_lifecycle_convergence.py',
)


def _input_digests():
    from tools.hia_selfhost_contract import file_digests
    return file_digests(ROOT) | {name: sha256((ROOT / name).read_bytes()).hexdigest()
                                 for name in LOCAL_INPUTS}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument('--cold-report', type=Path)
    selection.add_argument('--development-manifest', type=Path)
    parser.add_argument('--evidence', type=Path, required=True)
    args = parser.parse_args()
    before = _input_digests()
    suite, planned = load_declared_suite(ORIGINAL_MODULES)
    planned = list(planned)
    args.evidence.mkdir(mode=0o700, parents=True, exist_ok=False)
    if args.cold_report:
        from tools.build_hia_scalar_profile import build
        cold = json.loads(args.cold_report.read_bytes())
        nested = json.loads(Path(cold['nested_report']).read_bytes())
        manifest = build(args.evidence / 'qualified',
                         Path(nested['generations'][-1]['produced_image']), args.cold_report)
        scope = 'MATCHING_SOURCE_COLD_ORIGINAL_SCALAR_PROFILE_CALLERS'
    else:
        manifest = args.development_manifest.resolve(strict=True)
        scope = 'EXPLICIT_DEVELOPMENT_COMPONENT_NOT_CURRENT_COLD'
    from hepta import hia_multiversion as owner
    from hepta import hia_scalar_totality as total
    from hepta.hia_scalar_profile_native import NativeScalarProfile, SELECTOR, installed_scalar_profile
    image = installed_scalar_profile(str(manifest))
    bundle = {str(path): sha256(path.read_bytes()).hexdigest()
              for path in sorted(manifest.parent.rglob('*')) if path.is_file()}
    started, stopped, entries, proofs = [], [], [], []
    context = threading.local()

    class Result(unittest.TextTestResult):
        def startTest(self, test):
            started.append(test.id())
            super().startTest(test)

        def stopTest(self, test):
            stopped.append(test.id())
            super().stopTest(test)

    def lifecycle(method, name):
        def observed(runtime, *arguments, **keywords):
            previous = getattr(context, 'lifecycle', None)
            context.lifecycle = name
            try:
                return method(runtime, *arguments, **keywords)
            finally:
                context.lifecycle = previous
        return observed

    admit = NativeScalarProfile.admit
    validate = total.validate_scalar_totality

    def observed_admit(selected, program, data, **keywords):
        row = {'image_sha256': selected.image_sha256,
               'native_source_sha256': selected.admitted_source_sha256,
               'program_sha256': program.sha256, 'input_sha256': program.input_sha256,
               'lifecycle': getattr(context, 'lifecycle', None),
               'prove_total': keywords.get('prove_total', False)}
        try:
            result = admit(selected, program, data, **keywords)
        except Exception as error:
            row.update(outcome='refused', error_type=type(error).__name__, error=str(error))
            raise
        else:
            row.update(outcome='admitted', functions=[signature.function for signature in result])
            return result
        finally:
            entries.append(row)

    def observed_validate(program, **keywords):
        # This invokes the original verifier/encoder/fresh Z3 context and retains
        # its complete actual receipt. It supplies no synthetic proof authority.
        result = validate(program, **keywords)
        proofs.append({'lifecycle': getattr(context, 'lifecycle', None),
                       'program_sha256': program.sha256, 'input_sha256': program.input_sha256,
                       'function': keywords.get('function'),
                       'timeout_ms': keywords.get('timeout_ms', 2000), 'receipt': result})
        return result

    start = time.monotonic()
    with ExitStack() as stack:
        stack.enter_context(patch.dict(os.environ, {SELECTOR: str(manifest)}))
        stack.enter_context(patch.object(owner, '_reference_scalar_profile',
            side_effect=AssertionError('retained scalar profile policy entered')))
        stack.enter_context(patch.object(NativeScalarProfile, 'admit', observed_admit))
        stack.enter_context(patch.object(total, 'validate_scalar_totality', observed_validate))
        for name in ('__init__', 'publish', 'publish_if_current'):
            stack.enter_context(patch.object(owner.ScalarMultiversionRuntime, name,
                lifecycle(getattr(owner.ScalarMultiversionRuntime, name), name)))
        with (args.evidence / 'tests.log').open('x') as stream:
            result = unittest.TextTestRunner(stream=stream, verbosity=2, resultclass=Result).run(suite)
    stable = (_input_digests() == before and all(sha256(Path(path).read_bytes()).hexdigest() == digest
                                               for path, digest in bundle.items()))
    entered = bool(entries) and all(row['image_sha256'] == image.image_sha256 for row in entries)
    actual_callers = {name: any(row['lifecycle'] == name and row['outcome'] == 'admitted'
                               for row in entries)
                      for name in ('__init__', 'publish', 'publish_if_current')}
    proved_callers = {name: any(row['lifecycle'] == name
                               and row['receipt'].get('status') == 'proved'
                               and row['receipt'].get('solver', {}).get('result') == 'unsat'
                               and len(row['receipt'].get('solver', {}).get('identity', {}).get('library_sha256', '')) == 64
                               for row in proofs)
                      for name in actual_callers}
    refusal = any(row['outcome'] == 'refused' for row in entries)
    real_counterexample = any(row['lifecycle'] is not None
                              and row['receipt'].get('status') == 'disproved'
                              and row['receipt'].get('solver', {}).get('result') == 'sat'
                              and row['receipt'].get('counterexample') is not None for row in proofs)
    clean = result.wasSuccessful() and all(not getattr(result, name) for name in
        ('errors', 'failures', 'skipped', 'expectedFailures', 'unexpectedSuccesses'))
    passed = (started == stopped == planned and result.testsRun == len(planned)
              and clean and stable and entered and all(actual_callers.values())
              and all(proved_callers.values()) and refusal and real_counterexample)
    report = {'status': 'PASS' if passed else 'FAIL', 'scope': scope,
        'original_modules': ORIGINAL_MODULES, 'planned': planned, 'started': started, 'stopped': stopped,
        'actual_tests': result.testsRun, 'wall_seconds': time.monotonic() - start,
        'errors': [(test.id(), error) for test, error in result.errors],
        'failures': [(test.id(), error) for test, error in result.failures],
        'skipped': [(test.id(), error) for test, error in result.skipped],
        'expected_failures': [(test.id(), error) for test, error in result.expectedFailures],
        'unexpected_successes': [test.id() for test in result.unexpectedSuccesses],
        'actual_native_entries': entries, 'actual_fresh_totality': proofs,
        'observed_lifecycle_admission': actual_callers, 'observed_fresh_Z3_proofs': proved_callers,
        'observed_profile_refusal': refusal, 'observed_real_totality_counterexample': real_counterexample,
        'all_original_modules_unfiltered': True, 'retained_profile_policy_forbidden': True,
        'source_and_bundle_unchanged': stable, 'source_pins': before, 'bundle_pins': bundle,
        'host_core_proofs_locks_effects_loader_retained': True,
        'whole_native_delivery_qualified': False, 'all_input_equivalence_proved': False}
    (args.evidence / 'report.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(json.dumps({key: report[key] for key in ('status', 'scope', 'actual_tests', 'wall_seconds')}))
    if not passed:
        print((args.evidence / 'tests.log').read_text())
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())

"""Run complete original cost, paired-replay and process-observer callers in HIA.

The original immutable-wire budgets, real ELF observations and all test IDs
are retained. Python sum/peak/decision bodies are forbidden; any skip fails.
"""
from __future__ import annotations

import argparse
from contextlib import ExitStack
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ''}:
    sys.path.insert(0, str(ROOT))

from tools.run_hia_unittest_gate import load_declared_suite

ORIGINAL_MODULES = (
    'tests.test_hia_full_cost_gate', 'tests.test_hia_paired_holdout',
    'tests.test_hia_bounded_research_wire', 'tests.test_hia_evidence_json_structure',
    'tests.test_hia_native_process_observer', 'tests.test_hia_native_paired_replay',
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument('--cold-report', type=Path)
    selection.add_argument('--development-manifest', type=Path)
    parser.add_argument('--evidence', type=Path, required=True)
    args = parser.parse_args()
    from tools.hia_selfhost_contract import file_digests
    from tools.build_hia_full_cost import INPUTS

    def source_pins():
        return {**file_digests(ROOT),
                'tools/qualify_hia_full_cost_callers.py': sha256(Path(__file__).read_bytes()).hexdigest(),
                **{path: sha256((ROOT / path).read_bytes()).hexdigest() for path in INPUTS},
                **{module.replace('.', '/') + '.py': sha256(
                    (ROOT / (module.replace('.', '/') + '.py')).read_bytes()).hexdigest()
                   for module in ORIGINAL_MODULES}}

    before = source_pins()
    suite, planned = load_declared_suite(ORIGINAL_MODULES)
    planned = list(planned)
    args.evidence.mkdir(mode=0o700, parents=True, exist_ok=False)
    if args.cold_report:
        from tools.build_hia_full_cost import build
        cold = json.loads(args.cold_report.read_bytes())
        nested = json.loads(Path(cold['nested_report']).read_bytes())
        manifest = build(args.evidence / 'qualified',
            Path(nested['generations'][-1]['produced_image']), args.cold_report)
        scope = 'MATCHING_SOURCE_COLD_ORIGINAL_FULL_COST_CALLERS'
    else:
        manifest = args.development_manifest.resolve(strict=True)
        scope = 'EXPLICIT_DEVELOPMENT_COMPONENT_NOT_CURRENT_COLD'
    from hepta import hia_full_cost_gate as owner
    from hepta.hia_full_cost_native import NativeFullCost, SELECTOR, installed_full_cost
    image = installed_full_cost(str(manifest))
    bundle = {str(path): sha256(path.read_bytes()).hexdigest()
              for path in sorted(manifest.parent.rglob('*')) if path.is_file()}
    started, stopped = [], []
    # Count actual native entries while retaining the original test storage budgets.
    entries = [0, 0]

    class Result(unittest.TextTestResult):
        def startTest(self, test):
            started.append(test.id())
            super().startTest(test)

        def stopTest(self, test):
            stopped.append(test.id())
            super().stopTest(test)

    arm = NativeFullCost.arm
    decide = NativeFullCost.decide

    def observed_arm(selected, *arguments):
        if selected.image_sha256 != image.image_sha256:
            raise AssertionError('selected full-cost image changed')
        entries[0] += 1
        return arm(selected, *arguments)

    def observed_decide(selected, *arguments):
        if selected.image_sha256 != image.image_sha256:
            raise AssertionError('selected full-cost image changed')
        entries[1] += 1
        return decide(selected, *arguments)

    start = time.monotonic()
    with ExitStack() as stack:
        stack.enter_context(patch.dict(os.environ, {SELECTOR: str(manifest)}))
        stack.enter_context(patch.object(owner, '_reference_arm',
            side_effect=AssertionError('retained Python sums or peaks entered')))
        stack.enter_context(patch.object(owner, '_reference_decision',
            side_effect=AssertionError('retained Python cost decisions entered')))
        stack.enter_context(patch.object(NativeFullCost, 'arm', observed_arm))
        stack.enter_context(patch.object(NativeFullCost, 'decide', observed_decide))
        with (args.evidence / 'tests.log').open('x') as stream:
            result = unittest.TextTestRunner(stream=stream, verbosity=2, resultclass=Result).run(suite)
    stable = source_pins() == before and all(sha256(Path(path).read_bytes()).hexdigest() == digest
                                           for path, digest in bundle.items())
    clean = result.wasSuccessful() and all(not getattr(result, name) for name in
        ('errors', 'failures', 'skipped', 'expectedFailures', 'unexpectedSuccesses'))
    passed = (started == stopped == planned and result.testsRun == len(planned)
              and clean and stable and all(entries))
    report = {'status': 'PASS' if passed else 'FAIL', 'scope': scope,
        'original_modules': ORIGINAL_MODULES, 'planned': planned, 'started': started, 'stopped': stopped,
        'actual_tests': result.testsRun, 'wall_seconds': time.monotonic() - start,
        'errors': [(test.id(), error) for test, error in result.errors],
        'failures': [(test.id(), error) for test, error in result.failures],
        'skipped': [(test.id(), error) for test, error in result.skipped],
        'expected_failures': [(test.id(), error) for test, error in result.expectedFailures],
        'unexpected_successes': [test.id() for test in result.unexpectedSuccesses],
        'native_arm_calls': entries[0], 'native_decision_calls': entries[1],
        'native_image_sha256': image.image_sha256,
        'all_original_modules_unfiltered': True, 'retained_python_arithmetic_bodies_forbidden': True,
        'source_and_bundle_unchanged': stable, 'source_pins': before, 'bundle_pins': bundle,
        'immutable_JSON_identity_field_admission_still_hosted': True,
        'whole_native_delivery_qualified': False}
    (args.evidence / 'report.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(json.dumps({key: report[key] for key in ('status', 'scope', 'actual_tests', 'wall_seconds')}))
    if not passed:
        print((args.evidence / 'tests.log').read_text())
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())

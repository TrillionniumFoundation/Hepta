"""Run ordinary plan, register, ELF and Agent callers with native owners required.

The original suites remain unchanged. A selected candidate cannot reach either
retained plan owner. Loaded/executed IDs and all unittest anomaly categories
are checked, including class-level skips and early termination.
"""
from __future__ import annotations

import argparse
from collections import Counter
from contextlib import ExitStack
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import struct
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ''}:
    sys.path.insert(0, str(ROOT))

DEFAULT_MODULES = (
    'tests.test_hia_machine_plan',
    'tests.test_hia_machine_registers',
    'tests.test_hia_machine_leaf_registers',
    'tests.test_hia_agent_native_machine_choices',
)


def flatten(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from flatten(item)
        else:
            yield item


def strict_pass(result, loaded, executed, native_entries):
    return (bool(loaded) and loaded == executed and result.testsRun == len(loaded)
            and native_entries > 0 and not result.errors and not result.failures
            and not result.skipped and not result.expectedFailures
            and not result.unexpectedSuccesses)


def source_snapshot():
    paths = {path for folder in ('hepta', 'tools', 'tests')
             for path in (ROOT / folder).glob('*.py')}
    paths.update((ROOT / 'examples/hia_bootstrap').glob('*.hepta'))
    return {str(path.relative_to(ROOT)): sha256(path.read_bytes()).hexdigest()
            for path in sorted(paths)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument('--manifest', type=Path)
    selection.add_argument('--cold-report', type=Path)
    parser.add_argument('--development', action='store_true')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--evidence-dir', type=Path,
                        help='new directory retaining the actual cold-built caller image and manifest')
    parser.add_argument('--module', action='append')
    args = parser.parse_args()
    if bool(args.manifest) != args.development:
        parser.error('--manifest requires --development; cold evidence cannot be relabelled')
    if args.output.exists():
        parser.error('output already exists; preserve prior observations')
    from hepta import hia_machine_plan as plans
    from hepta.hia_machine_plan_control_selection import SELECTOR, installed_machine_plan
    with ExitStack() as fixtures:
        if args.evidence_dir is not None:
            args.evidence_dir.mkdir(parents=True, exist_ok=False)
            temporary = str(args.evidence_dir.resolve())
        else:
            temporary = fixtures.enter_context(tempfile.TemporaryDirectory(prefix='hia-machine-plan-callers-'))
        if args.cold_report:
            from tools.build_hia_machine_plan_control import build
            report = json.loads(args.cold_report.read_bytes())
            nested = json.loads(Path(report['nested_report']).read_bytes())
            manifest = build(Path(temporary) / 'build',
                Path(nested['generations'][-1]['produced_image']), args.cold_report)
            scope = 'MATCHING_SOURCE_COLD_SELECTED_CALLERS'
        else:
            manifest = args.manifest.resolve(strict=True)
            scope = 'DEVELOPMENT_SELECTED_CALLERS_NOT_COLD_QUALIFICATION'
        manifest_bytes = manifest.read_bytes()
        image = installed_machine_plan(str(manifest))
        suite = unittest.defaultTestLoader.loadTestsFromNames(args.module or DEFAULT_MODULES)
        loaded = [test.id() for test in flatten(suite)]
        executed, entries, by_test = [], Counter(), {}
        current = ['outside-test']
        original = image._entry

        def entry(*arguments):
            command = struct.unpack_from('<Q', arguments[4])[0]
            entries[str(command)] += 1
            by_test[current[0]] = by_test.get(current[0], 0) + 1
            return original(*arguments)

        class Result(unittest.TextTestResult):
            def startTest(self, test):
                executed.append(test.id())
                current[0] = test.id()
                super().startTest(test)

            def stopTest(self, test):
                super().stopTest(test)
                current[0] = 'outside-test'

        before = source_snapshot()
        started = time.monotonic()
        with ExitStack() as stack:
            stack.enter_context(patch.dict(os.environ, {SELECTOR: str(manifest)}))
            stack.enter_context(patch.object(image, '_entry', entry))
            for name in ('_reference_validate_plan', '_reference_register_assignment_witness', '_reference_code_options', '_reference_preservation_checks'):
                stack.enter_context(patch.object(plans, name,
                    side_effect=AssertionError('retained machine-plan owner entered: ' + name)))
            result = unittest.TextTestRunner(verbosity=2, resultclass=Result).run(suite)
        elapsed = time.monotonic() - started
        after = source_snapshot()
        stable = before == after and manifest.read_bytes() == manifest_bytes
        passed = stable and strict_pass(result, loaded, executed, sum(entries.values()))
        report = {
            'schema': 'hepta.hia.machine-plan-selected-callers.v1',
            'status': 'PASS' if passed else 'FAIL_OR_INCOMPLETE', 'scope': scope,
            'python': sys.version, 'platform': platform.platform(),
            'image_sha256': image.image_sha256, 'manifest': json.loads(manifest_bytes),
            'source_before_sha256': before, 'source_after_sha256': after,
            'source_and_manifest_unchanged': stable, 'wall_seconds': elapsed,
            'loaded_test_ids': loaded, 'executed_test_ids': executed,
            'tests_loaded': len(loaded), 'tests_run': result.testsRun,
            'failures': [{'test': t.id(), 'trace': why} for t, why in result.failures],
            'errors': [{'test': t.id(), 'trace': why} for t, why in result.errors],
            'skipped': [{'test': t.id(), 'reason': why} for t, why in result.skipped],
            'expected_failures': [{'test': t.id(), 'trace': why} for t, why in result.expectedFailures],
            'unexpected_successes': [t.id() for t in result.unexpectedSuccesses],
            'retained_plan_owners_forbidden': True, 'native_stage_entries': dict(entries),
            'per_test_native_entries': by_test, 'subprocesses_inherit_selector': True,
            'subprocess_entries_in_parent_counts': False,
            'caller_build_evidence_directory': temporary if args.evidence_dir is not None else None,
            'actual_cold_build_retained': bool(args.cold_report and args.evidence_dir is not None),
            'externally_selected_development_bundle_copied': False,
            'whole_stack_or_default_regression_claimed': False,
        }
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
        print(json.dumps({'status': report['status'], 'scope': scope,
                          'tests_run': result.testsRun, 'report': str(args.output)}), flush=True)
        return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())

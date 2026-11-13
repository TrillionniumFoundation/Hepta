"""Observe numeric comparison during the unchanged UNPACK/Core116 qualifier.

The original UNPACK wrapper and original Core main each run exactly once.
The enclosing execution request must retain one original 180/3 caller owner.
This producer grants no mandatory gate and does not replace full UNPACK18 or
the separately required complete numeric finite controls and installed proof.
"""
from __future__ import annotations

import argparse
from collections import Counter
from contextlib import ExitStack, contextmanager
from contextvars import ContextVar
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
import time
import traceback
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ''}:
    sys.path.insert(0, str(ROOT))

SCHEMA = 'hepta.hia.core-compare-selected-callers.v1'
STEP_MEANING = 'NumericCompareSession.step returned from the admitted image; not a whole-method PASS.'


def pin(path):
    path = Path(path).resolve(strict=True)
    raw = path.read_bytes()
    return {'path': str(path), 'size': len(raw), 'sha256': sha256(raw).hexdigest()}


class NumericCallObservation:
    """Observe already-bound effects; never fetch either operand a second time."""
    def __init__(self, outer, primitive, groups):
        self.outer, self.primitive, self.groups = outer, primitive, dict(groups)
        self.current_test = ['outside-test', 'outside-group']
        self.current = ContextVar('numeric_qualification_current_effect', default=None)
        self.attempts, self.eligible, self.normal, self.failed = (Counter() for _ in range(4))
        self.eligible_normal, self.eligible_failed, self.failed_completions = (Counter() for _ in range(3))
        self.returns, self.unadmitted_VM = Counter(), Counter()
        self.retained = []

    @contextmanager
    def observe(self):
        outer, primitive = self.outer, self.primitive
        original_primitive = outer.LoweringSession._primitive
        original_eligible = outer._numeric_comparison_eligible
        original_step = primitive.NumericCompareSession.step
        original_start = unittest.TextTestResult.startTest
        original_stop = unittest.TextTestResult.__dict__.get('stopTest')
        original_run = unittest.TextTestRunner.run
        expected_groups = {label: tuple(name for name, group in self.groups.items() if group == label)
                           for label in dict.fromkeys(self.groups.values())}

        def flatten(suite):
            if isinstance(suite, unittest.TestSuite):
                for child in suite:
                    yield from flatten(child)
            elif isinstance(suite, unittest.TestCase):
                yield suite

        def run(runner, suite):
            ids = tuple(test.id() for test in flatten(suite))
            matched = [label for label, wanted in expected_groups.items() if ids == wanted]
            if len(matched) != 1:
                return original_run(runner, suite)
            previous = tuple(self.current_test)
            label = matched[0]
            self.current_test[:] = ['@fixture:' + label, label]
            try:
                return original_run(runner, suite)
            finally:
                self.current_test[:] = previous

        def start(result, test):
            name = test.id()
            if name in self.groups:
                self.current_test[:] = [name, self.groups[name]]
            return original_start(result, test)

        def stop(result, test):
            try:
                # Preserve a later ProgressRecorder hook on the inherited base.
                # An already-installed outer observer remains an explicit link.
                if original_stop is None:
                    return super(unittest.TextTestResult, result).stopTest(test)
                return original_stop(result, test)
            finally:
                if test.id() in self.groups:
                    label = self.groups[test.id()]
                    self.current_test[:] = ['@fixture:' + label, label]

        def eligible(operation, target, left, right):
            admitted = original_eligible(operation, target, left, right)
            current = self.current.get()
            if admitted and current is not None:
                current['target'] = target
                current['eligible'] = True
                self.eligible[current['key']] += 1
            return admitted

        def profile(frame, event, value):
            if event != 'c_call':
                return
            current = self.current.get()
            if current is not None and value is current['target']:
                self.retained.append(list(current['key']))
                raise AssertionError('eligible numeric effect entered its retained builtin operator')

        def dispatch(session, opcode, arguments, vector):
            if opcode != 13:
                return original_primitive(session, opcode, arguments, vector)
            companion = session.owner.numeric_compare
            if companion is None:
                # The unchanged Core source method intentionally invokes its
                # independent Core VM owner without a native admitted bundle.
                # It remains in the 116 denominator and is never native proof.
                if (hasattr(session.owner, '_admitted_bundle')
                        or self.current_test[1] != 'component'
                        or '.CoreLoweringSourceTests.' not in self.current_test[0]):
                    raise AssertionError('selected ordinary numeric effect lost its companion')
                self.unadmitted_VM[(self.current_test[1], self.current_test[0], arguments[0])] += 1
                return original_primitive(session, opcode, arguments, vector)
            if session.pending or not hasattr(companion, '_admitted_compare'):
                raise AssertionError('numeric effect lacks consumed permission or admitted image')
            key = (self.current_test[1], self.current_test[0], arguments[0], companion.image.image_sha256)
            self.attempts[key] += 1
            state = {'key': key, 'target': None, 'eligible': False, 'completions': 0}
            token = self.current.set(state)
            old_profile = sys.getprofile()
            try:
                sys.setprofile(profile)
                result = original_primitive(session, opcode, arguments, vector)
                if state['eligible']:
                    if state['completions'] != 1:
                        raise AssertionError('eligible numeric dispatch returned without one native completion')
                    self.eligible_normal[key] += 1
                self.normal[key] += 1
                return result
            except BaseException:
                if state['eligible']:
                    self.eligible_failed[key] += 1
                    self.failed_completions[key] += state['completions']
                self.failed[key] += 1
                raise
            finally:
                sys.setprofile(old_profile)
                self.current.reset(token)

        def step(session, packet):
            result = original_step(session, packet)
            current = self.current.get()
            if current is not None:
                key = current['key']
                if (not current['eligible'] or session.operation != key[2]
                        or session.image.image_sha256 != key[3]):
                    raise AssertionError('actual numeric step is outside its eligible bound effect')
                self.returns[(*key, result)] += 1
                if result == 0:
                    current['completions'] += 1
                    if current['completions'] != 1:
                        raise AssertionError('numeric effect repeated its terminal return')
            return result

        with ExitStack() as stack:
            stack.enter_context(patch.object(outer.LoweringSession, '_primitive', dispatch))
            stack.enter_context(patch.object(outer, '_numeric_comparison_eligible', eligible))
            stack.enter_context(patch.object(primitive.NumericCompareSession, 'step', step))
            stack.enter_context(patch.object(unittest.TextTestResult, 'startTest', start))
            stack.enter_context(patch.object(unittest.TextTestResult, 'stopTest', stop))
            stack.enter_context(patch.object(unittest.TextTestRunner, 'run', run))
            yield self

    def report(self):
        def effects(counter):
            return [dict(group=k[0], test=k[1], operation=k[2], image_sha256=k[3], count=n)
                    for k, n in sorted(counter.items()) if n]
        return {'outer_opcode13_attempts': effects(self.attempts),
            'outer_opcode13_eligible': effects(self.eligible),
            'outer_opcode13_normal_returns': effects(self.normal),
            'outer_opcode13_exceptions': effects(self.failed),
            'eligible_normal_returns': effects(self.eligible_normal),
            'eligible_exceptions': effects(self.eligible_failed),
            'eligible_exception_terminal_returns': effects(self.failed_completions),
            'actual_numeric_step_returns': [dict(group=k[0], test=k[1], operation=k[2],
                image_sha256=k[3], status=k[4], count=n) for k, n in sorted(self.returns.items())],
            'independent_Core_VM_effects_not_native_proof': [dict(group=k[0], test=k[1], operation=k[2], count=n)
                for k, n in sorted(self.unadmitted_VM.items())],
            'retained_builtin_target_entries': self.retained}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--cold-report', type=Path)
    mode.add_argument('--core-development-manifest', type=Path)
    parser.add_argument('--unpack-development-manifest', type=Path)
    parser.add_argument('--numeric-development-manifest', type=Path)
    parser.add_argument('--integer-manifest', type=Path)
    parser.add_argument('--evidence', type=Path, required=True)
    args = parser.parse_args()
    development = (args.core_development_manifest, args.unpack_development_manifest,
                   args.numeric_development_manifest)
    if args.cold_report and any(development) or not args.cold_report and not all(development):
        parser.error('cold accepts no development manifests; development requires all three explicitly')
    if args.integer_manifest is not None and args.cold_report is None:
        parser.error('the additional integer manifest requires its matching-source cold report')
    from hepta import hia_core_lowering_native as outer
    from hepta import hia_core_compare_native as primitive
    from hepta import hia_core_compare_selection as selection
    from tools import qualify_hia_core_unpack_callers as unpack
    from tools import qualify_hia_core_lowering_callers as original
    from tools import hia_core_compare_qualification as reader
    from tools import hia_core_unpack_gates as unpack_reader
    runtime = unpack_reader.runtime_identity()
    directory = args.evidence.resolve()
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    groups = {test: label for label, ids in (
        ('component', original.COMPONENT_IDS), ('original-machine', original.ORIGINAL_IDS),
        ('original-core', original.CORE_IDS)) for test in ids}
    observer = NumericCallObservation(outer, primitive, groups)
    report = {'schema': SCHEMA, 'status': 'HOLD',
        'scope': 'MATCHING_SOURCE_COLD_SELECTED_CALLERS' if args.cold_report else 'EXPLICIT_DEVELOPMENT_ONLY',
        'original_groups': [15, 51, 50], 'original_complete_methods': 116,
        'original_Core_image_count': 39, 'additional_UNPACK_image_count': 1,
        'additional_numeric_image_count': 1, 'native_step_semantics': STEP_MEANING,
        'outer_return_semantics': 'Opcode13 dispatch returned before outer ACK registration; not whole-method success.',
        'fixture_step_rows_are_not_test_pass': True,
        'complete_original_qualifier_calls_required': 1, 'complete_UNPACK_wrapper_calls': 0,
        'complete_116_passed': False, 'UNPACK_observation_required': True,
        'runtime_before': runtime, 'runtime_after': None,
        'CPython_object_runtime_still_hosted': True, 'whole_native_delivery_qualified': False,
        'default_activated': False}
    started = time.monotonic()
    sources_before = original.source_pins()
    files, before, companion = [], [], None
    integer_path, integer_binding = None, None
    try:
        if args.cold_report:
            from tools.build_hia_core_compare import build
            context = unpack_reader.cold_inputs(args.cold_report)
            manifest = build(directory / 'numeric-build', Path(context['identities'][2]['path']), args.cold_report)
            compiler_sha = context['compiler_sha256']
            binding = reader.companion_build(manifest.parent, context)
            report['matching_cold_inputs'] = context['identities']
            report['matching_cold_build'] = binding
            if args.integer_manifest is not None:
                from tools.hia_core_integer_qualification import companion_build as integer_build
                integer_path = args.integer_manifest.resolve(strict=True)
                integer_binding = integer_build(integer_path.parent, context)
                if integer_binding['files'][0]['path'] != str(integer_path):
                    raise ValueError('explicit integer path is not its matching-cold manifest')
                report['matching_integer_build'] = integer_binding
            arguments = ['--cold-report', str(args.cold_report.resolve())]
        else:
            manifest = args.numeric_development_manifest.resolve(strict=True)
            compiler_sha = json.loads(args.core_development_manifest.read_bytes())['compiler_sha256']
            arguments = ['--core-development-manifest', str(args.core_development_manifest.resolve(strict=True)),
                         '--unpack-development-manifest', str(args.unpack_development_manifest.resolve(strict=True))]
        companion = selection.installed_compare(manifest, compiler_sha)
        files = [manifest, manifest.parent / 'core-compare.image.bin']
        if (manifest.parent / 'build.json').exists():
            files.append(manifest.parent / 'build.json')
        before = [pin(path) for path in files]
        report['companion_inputs_before'] = before
        report['admitted_companion'] = vars(companion._admitted_compare)
        report['identity_before'] = sha256(selection.implementation_identity(companion)).hexdigest()
        report['source_before'] = sources_before
        argv = ['qualify_hia_core_unpack_callers.py', *arguments, '--evidence', str(directory / 'callers')]
        report['original_UNPACK_qualifier_argv'] = argv
        with ExitStack() as stack:
            selectors = {selection.SELECTOR: str(manifest)}
            if integer_path is not None:
                from hepta.hia_core_integer_selection import SELECTOR as INTEGER_SELECTOR
                selectors[INTEGER_SELECTOR] = str(integer_path)
            stack.enter_context(patch.dict(os.environ, selectors))
            stack.enter_context(patch.object(sys, 'argv', argv))
            stack.enter_context(observer.observe())
            report['complete_UNPACK_wrapper_calls'] += 1
            returned = unpack.main()
        report['UNPACK_report'] = pin(directory / 'callers/report.json')
        unpack_value = json.loads((directory / 'callers/report.json').read_bytes())
        original_path = directory / 'callers/core-callers/report.json'
        report['original_report'] = pin(original_path)
        original_value = json.loads(original_path.read_bytes())
        ids = unpack.validate_original(original_value)
        if (returned != 0 or unpack_value.get('status') != 'PASS'
                or unpack_value.get('complete_116_passed') is not True or len(ids) != 116):
            raise ValueError('the complete original UNPACK/Core116 producer did not pass')
        report.update(observer.report())
        reader.validate_returns(report, groups, companion.image.image_sha256)
        installed_path = directory / 'callers/core-callers/component-fixture/installed-control/report.json'
        installed = json.loads(installed_path.read_bytes())
        report['installed_report'] = pin(installed_path)
        report['installed_numeric_observation'] = installed.get('numeric_compare_observations')
        report['installed_UNPACK_observation'] = installed.get('unpack_observations')
        report['installed_integer_observation'] = installed.get('integer_observations')
        if report['installed_UNPACK_observation'] != unpack_value.get('installed_observation'):
            raise ValueError('the installed dual-companion path lost the original UNPACK observation')
        if args.cold_report:
            reader.validate_installed(report['installed_numeric_observation'], binding)
            if integer_binding is not None:
                from tools.hia_core_integer_qualification import validate_installed as integer_installed
                integer_installed(report['installed_integer_observation'], integer_binding)
            report['independent_current_cold_readback'] = unpack_reader.inspect_callers(
                directory, args.cold_report, context, numeric_manifest=manifest,
                integer_manifest=integer_path)
        else:
            # This remains a development report. Its independent executor must
            # read all installed inputs, source refusals and the full originals.
            numeric = report['installed_numeric_observation']
            if (type(numeric) is not dict or numeric.get('image_sha256') != companion.image.image_sha256
                    or numeric.get('compiler_sha256') != compiler_sha
                    or numeric.get('retained_builtin_target_forbidden') is not True):
                raise ValueError('development installed numeric observation missing or from another image')
        report['complete_116_passed'] = True
        report['status'] = 'PASS'
    except BaseException:
        report['status'] = 'HOLD'
        report['error'] = traceback.format_exc()
    finally:
        report.update(observer.report())
        try:
            report['source_after'] = original.source_pins()
            report['companion_inputs_after'] = [pin(path) for path in files]
            report['identity_after'] = sha256(selection.implementation_identity(companion)).hexdigest()
            report['runtime_after'] = unpack_reader.runtime_identity()
            report['stable'] = bool(before) and (sources_before == report['source_after']
                and before == report['companion_inputs_after']
                and report.get('identity_before') == report['identity_after']
                and report['runtime_after'] == runtime)
            if not report['stable']:
                report['status'] = 'HOLD'
        except BaseException:
            report['status'] = 'HOLD'
            report['preservation_error'] = traceback.format_exc()
        report['seconds'] = time.monotonic() - started
        with (directory / 'numeric-report.json').open('x') as stream:
            json.dump(report, stream, indent=2, sort_keys=True)
            stream.write('\n')
        print(json.dumps({key: report.get(key) for key in ('schema', 'scope', 'status', 'seconds', 'stable', 'error')}, sort_keys=True))
    return 0 if report['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())

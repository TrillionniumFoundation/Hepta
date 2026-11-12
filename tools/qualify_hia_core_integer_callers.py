"""Observe exact integer ownership during one numeric/UNPACK/Core116 execution.

One existing 180/3 process owner encloses all three companions and the original
unsplit Core qualifier. Native DONE, returned materialization, outer primitive
return and whole-method success remain distinct observations. This module
does not add a mandatory gate or extend any qualification deadline.
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

SCHEMA = 'hepta.hia.core-integer-selected-callers.v1'


def pin(path):
    path = Path(path).resolve(strict=True)
    raw = path.read_bytes()
    return {'path': str(path), 'size': len(raw), 'sha256': sha256(raw).hexdigest()}


class IntegerCallObservation:
    """Observe original eligibility results without another lookup or operand read."""
    def __init__(self, outer, primitive, groups):
        self.outer, self.primitive, self.groups = outer, primitive, dict(groups)
        self.current_test = ['outside-test', 'outside-group']
        self.current = ContextVar('integer_qualification_current_effect', default=None)
        self.attempts, self.eligible, self.normal, self.failed = (Counter() for _ in range(4))
        self.eligible_normal, self.eligible_failed = Counter(), Counter()
        self.failed_done, self.failed_finish = Counter(), Counter()
        self.returns, self.finishes, self.unadmitted_VM = Counter(), Counter(), Counter()
        self.retained, self.unbound = [], []

    @contextmanager
    def observe(self):
        outer, primitive = self.outer, self.primitive
        original_primitive = outer.LoweringSession._primitive
        original_binary = outer._integer_binary_eligible
        original_unary = outer._integer_unary_eligible
        original_step, original_finish = primitive.IntegerSession.step, primitive.IntegerSession.finish
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

        def eligibility(opcode, operation, target, admitted):
            current = self.current.get()
            if admitted and current is not None:
                if current['key'][2:4] != (opcode, operation) or current['eligible']:
                    raise AssertionError('integer eligibility changed or repeated within one bound effect')
                current['target'], current['eligible'] = target, True
                current['native_operation'] = operation if opcode == 11 else operation + 1
                self.eligible[current['key']] += 1
            return admitted

        def binary(operation, target, left, right):
            admitted = original_binary(operation, target, left, right)
            return eligibility(11, operation, target, admitted)

        def unary(operation, target, value):
            admitted = original_unary(operation, target, value)
            return eligibility(12, operation, target, admitted)

        def profile(frame, event, value):
            current = self.current.get()
            if event == 'c_call' and current is not None and value is current['target']:
                self.retained.append(list(current['key']))
                raise AssertionError('eligible integer effect entered its original builtin operator')

        def dispatch(session, opcode, arguments, vector):
            if opcode not in (11, 12):
                return original_primitive(session, opcode, arguments, vector)
            companion = session.owner.integer
            if companion is None:
                if (hasattr(session.owner, '_admitted_bundle')
                        or self.current_test[1] != 'component'
                        or '.CoreLoweringSourceTests.' not in self.current_test[0]):
                    raise AssertionError('admitted ordinary Core lost its integer companion')
                self.unadmitted_VM[(self.current_test[1], self.current_test[0], opcode, arguments[0])] += 1
                return original_primitive(session, opcode, arguments, vector)
            if session.pending or not hasattr(companion, '_admitted_integer'):
                raise AssertionError('integer effect lacks consumed permission or an admitted image')
            key = (self.current_test[1], self.current_test[0], opcode, arguments[0], companion.image.image_sha256)
            self.attempts[key] += 1
            state = {'key': key, 'target': None, 'eligible': False,
                     'native_operation': None, 'completions': 0, 'finishes': 0}
            token = self.current.set(state)
            previous_profile = sys.getprofile()
            try:
                sys.setprofile(profile)
                result = original_primitive(session, opcode, arguments, vector)
                if state['eligible']:
                    if (state['completions'], state['finishes']) != (1, 1):
                        raise AssertionError('eligible integer returned without one native DONE and one finish')
                    self.eligible_normal[key] += 1
                self.normal[key] += 1
                return result
            except BaseException:
                if state['eligible']:
                    self.eligible_failed[key] += 1
                    self.failed_done[key] += state['completions']
                    self.failed_finish[key] += state['finishes']
                self.failed[key] += 1
                raise
            finally:
                sys.setprofile(previous_profile)
                self.current.reset(token)

        def bound(session, kind, result):
            current = self.current.get()
            if current is None:
                self.unbound.append({'kind': kind, 'native_operation': session.operation,
                                     'image_sha256': session.image.image_sha256})
                raise AssertionError('integer native return has no original eligible effect')
            key = current['key']
            if (not current['eligible'] or session.operation != current['native_operation']
                    or session.image.image_sha256 != key[4]):
                raise AssertionError('integer return escaped its exact opcode/operand/image binding')
            if kind == 'step':
                self.returns[(*key, session.operation, result)] += 1
                if result == 0:
                    current['completions'] += 1
                    if current['completions'] != 1:
                        raise AssertionError('integer effect repeated its normal DONE return')
            else:
                self.finishes[key] += 1
                current['finishes'] += 1
                if current['completions'] != 1 or current['finishes'] != 1:
                    raise AssertionError('integer finish repeated or preceded its normal DONE')

        def step(session, packet):
            status = original_step(session, packet)
            bound(session, 'step', status)
            return status

        def finish(session):
            value = original_finish(session)
            bound(session, 'finish', value)
            return value

        with ExitStack() as stack:
            stack.enter_context(patch.object(outer.LoweringSession, '_primitive', dispatch))
            stack.enter_context(patch.object(outer, '_integer_binary_eligible', binary))
            stack.enter_context(patch.object(outer, '_integer_unary_eligible', unary))
            stack.enter_context(patch.object(primitive.IntegerSession, 'step', step))
            stack.enter_context(patch.object(primitive.IntegerSession, 'finish', finish))
            stack.enter_context(patch.object(unittest.TextTestResult, 'startTest', start))
            stack.enter_context(patch.object(unittest.TextTestResult, 'stopTest', stop))
            stack.enter_context(patch.object(unittest.TextTestRunner, 'run', run))
            yield self

    def report(self):
        def effects(counter):
            return [dict(group=key[0], test=key[1], opcode=key[2], operation=key[3],
                         image_sha256=key[4], count=count)
                    for key, count in sorted(counter.items()) if count]
        return {'outer_integer_attempts': effects(self.attempts),
                'outer_integer_eligible': effects(self.eligible),
                'outer_integer_normal_returns': effects(self.normal),
                'outer_integer_exceptions': effects(self.failed),
                'eligible_normal_returns': effects(self.eligible_normal),
                'eligible_exceptions': effects(self.eligible_failed),
                'eligible_exception_terminal_returns': effects(self.failed_done),
                'eligible_exception_finish_returns': effects(self.failed_finish),
                'actual_integer_finish_returns': effects(self.finishes),
                'actual_integer_step_returns': [dict(group=key[0], test=key[1], opcode=key[2],
                    operation=key[3], image_sha256=key[4], native_operation=key[5], status=key[6], count=count)
                    for key, count in sorted(self.returns.items())],
                'independent_Core_VM_effects_not_native_proof': [dict(group=key[0], test=key[1],
                    opcode=key[2], operation=key[3], count=count)
                    for key, count in sorted(self.unadmitted_VM.items())],
                'retained_builtin_target_entries': self.retained, 'unbound_native_returns': self.unbound}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cold-report', type=Path, required=True)
    parser.add_argument('--evidence', type=Path, required=True)
    args = parser.parse_args()
    from hepta import hia_core_lowering_native as outer
    from hepta import hia_core_integer_native as primitive
    from hepta import hia_core_integer_selection as selection
    from tools import qualify_hia_core_compare_callers as numeric
    from tools import qualify_hia_core_lowering_callers as original
    from tools import hia_core_integer_qualification as reader
    from tools import hia_core_unpack_gates as gates
    from tools.build_hia_core_integer import build
    runtime = gates.runtime_identity()
    context = gates.cold_inputs(args.cold_report)
    gates.admit_dependencies(context)
    directory = args.evidence.resolve()
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    groups = {test: label for label, ids in (
        ('component', original.COMPONENT_IDS), ('original-machine', original.ORIGINAL_IDS),
        ('original-core', original.CORE_IDS)) for test in ids}
    observer = IntegerCallObservation(outer, primitive, groups)
    report = {'schema': SCHEMA, 'status': 'HOLD', 'scope': 'MATCHING_SOURCE_COLD_SELECTED_CALLERS',
              'original_groups': [15, 51, 50], 'original_complete_methods': 116,
              'original_Core_image_count': 39, 'additional_UNPACK_image_count': 1,
              'additional_numeric_image_count': 1, 'additional_integer_image_count': 1,
              'native_step_semantics': reader.STEP_MEANING, 'finish_return_semantics': reader.FINISH_MEANING,
              'outer_return_semantics': 'Opcode11/12 returned before outer ACK registration; not whole-method success.',
              'raw_entry_returns_counted_as_step_returns': False,
              'fixture_step_rows_are_not_test_pass': True,
              'complete_numeric_wrapper_calls_required': 1, 'complete_numeric_wrapper_calls': 0,
              'complete_116_passed': False, 'numeric_and_UNPACK_observation_required': True,
              'runtime_before': runtime, 'runtime_after': None,
              'CPython_object_runtime_still_hosted': True,
              'whole_native_delivery_qualified': False, 'default_activated': False}
    started = time.monotonic()
    sources_before = original.source_pins()
    files, before, companion = [], [], None
    try:
        manifest = build(directory / 'integer-build', Path(context['identities'][2]['path']), args.cold_report)
        binding = reader.companion_build(manifest.parent, context)
        companion = selection.installed_integer(manifest, context['compiler_sha256'])
        files = [manifest, manifest.parent / 'core-integer.image.bin', manifest.parent / 'build.json']
        before = [pin(path) for path in files]
        report.update(matching_cold_inputs=context['identities'], matching_cold_build=binding,
                      companion_inputs_before=before, admitted_companion=vars(companion._admitted_integer),
                      identity_before=sha256(selection.implementation_identity(companion)).hexdigest(),
                      source_before=sources_before)
        argv = ['qualify_hia_core_compare_callers.py', '--cold-report', str(args.cold_report.resolve(strict=True)),
                '--integer-manifest', str(manifest), '--evidence', str(directory / 'numeric')]
        report['original_numeric_qualifier_argv'] = argv
        with ExitStack() as stack:
            stack.enter_context(patch.dict(os.environ, {selection.SELECTOR: str(manifest)}))
            stack.enter_context(patch.object(sys, 'argv', argv))
            stack.enter_context(observer.observe())
            report['complete_numeric_wrapper_calls'] += 1
            returned = numeric.main()
        report['numeric_report'] = pin(directory / 'numeric/numeric-report.json')
        report['UNPACK_report'] = pin(directory / 'numeric/callers/report.json')
        report['original_report'] = pin(directory / 'numeric/callers/core-callers/report.json')
        numeric_value = json.loads((directory / 'numeric/numeric-report.json').read_bytes())
        if returned != 0 or numeric_value.get('status') != 'PASS' or numeric_value.get('complete_116_passed') is not True:
            raise ValueError('one complete original numeric/UNPACK/Core116 execution did not pass')
        report.update(observer.report())
        reader.validate_returns(report, groups, companion.image.image_sha256)
        installed_path = directory / 'numeric/callers/core-callers/component-fixture/installed-control/report.json'
        installed = json.loads(installed_path.read_bytes())
        report['installed_report'] = pin(installed_path)
        report['installed_integer_observation'] = installed.get('integer_observations')
        report['installed_numeric_observation'] = installed.get('numeric_compare_observations')
        report['installed_UNPACK_observation'] = installed.get('unpack_observations')
        reader.validate_installed(report['installed_integer_observation'], binding)
        if (report['installed_numeric_observation'] != numeric_value.get('installed_numeric_observation')
                or report['installed_UNPACK_observation'] != numeric_value.get('installed_UNPACK_observation')):
            raise ValueError('installed three-companion path lost an original companion observation')
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
            report['runtime_after'] = gates.runtime_identity()
            report['stable'] = bool(before) and (sources_before == report['source_after']
                and before == report['companion_inputs_after'] and runtime == report['runtime_after']
                and report.get('identity_before') == report['identity_after']
                and gates.cold_inputs(args.cold_report) == context)
            if not report['stable']:
                report['status'] = 'HOLD'
        except BaseException:
            report['status'] = 'HOLD'
            report['preservation_error'] = traceback.format_exc()
        report['seconds'] = time.monotonic() - started
        with (directory / 'integer-report.json').open('x') as stream:
            json.dump(report, stream, indent=2, sort_keys=True)
            stream.write('\n')
        print(json.dumps({key: report.get(key) for key in ('schema', 'scope', 'status', 'seconds', 'stable', 'error')}, sort_keys=True))
    return 0 if report['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())

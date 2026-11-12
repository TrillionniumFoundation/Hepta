"""Real native held-frame finish regression controls.

This is an external development fixture. Every owner is loaded from a freshly
compiled, byte-checked manifest; no mocked drive or business policy is used.
The original phase records the old ambient-exception retirement defect.
Fault injection only interrupts an actual native ACK or the terminal take
port, and never authorizes replay.
"""
from __future__ import annotations
import argparse
from hashlib import sha256
import importlib
import json
from pathlib import Path
import sys
import traceback
import unittest
import weakref

CONFIG = None
ROWS = []


def ambient():
    error = sys.exception()
    return None if error is None else [type(error).__name__, list(error.args)]


def under_handler(enabled, call):
    if not enabled:
        return call()
    try:
        raise LookupError('caller already handling')
    except LookupError:
        return call()


class ForeignFailure(Exception):
    pass


class Probe:
    structured_bytes = None

    def __init__(self, kind, trace, failures):
        self.kind, self.trace, self.failures = kind, trace, failures

    def _effect(self):
        self.trace.append(['effect', self.kind, ambient()])
        if self.failures:
            raise self.failures.pop()

    def __hash__(self):
        self._effect()
        return 0

    def __getitem__(self, key):
        from hepta.hia_machine_plan import LAYOUT_V1
        if key != 'schema':
            raise AssertionError('unexpected plan field: ' + str(key))
        self._effect()
        return LAYOUT_V1

    def as_dict(self):
        self._effect()
        return {'functions': [{'name': 'main',
                               'params': [{'name': 'a', 'type': 'readbuf'}],
                               'returns': ['u32']}]}

    def __del__(self):
        self.trace.append(['probe-del', self.kind, ambient()])


def prepare(owner, kind, trace, failures=()):
    value = Probe(kind, trace, list(failures))
    weak = weakref.ref(value)
    if kind == 'core':
        frame = owner.prepare('_words', (value,))
    elif kind == 'plan':
        frame = owner.prepare(3, (value,))
    elif kind == 'byte':
        frame = owner.prepare('normalize_exports', ((('main', 1),), value))
    else:
        raise AssertionError('unknown fixture owner')
    return frame, weak


def reference(kind, trace):
    from hepta import hia_program_native as backend
    from hepta import hia_machine_plan as plan
    from hepta import hia_native_byte_abi as byte
    if kind == 'core':
        return backend._reference_words(Probe(kind, trace, []))
    if kind == 'plan':
        return plan._reference_code_options(Probe(kind, trace, []))
    return byte._reference_normalize_exports((('main', 1),), Probe(kind, trace, []))


def capture(owner, frame):
    try:
        return True, owner.finish(frame)
    except BaseException as error:
        return False, error
    finally:
        # This catcher must not retain the caller's frame through its own TB.
        owner = frame = None


def tb_names(error):
    names = []
    current = error.__traceback__
    while current is not None:
        names.append(current.tb_frame.f_code.co_name)
        current = current.tb_next
    return names


def frame_state(frame, weak, trace):
    return {'closed': frame.closed, 'retired': frame._retired,
            'uncertain': frame._uncertain, 'alive': weak() is not None,
            'trace': list(trace)}


class NativeFinishTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from hepta import hia_program_native as backend
        from hepta.hia_core_lowering_native import NativeCoreLowering
        from hepta.hia_machine_plan_control_native import NativeMachinePlanControl
        cls.owners, cls.authority = {}, {}
        factories = {'core': NativeCoreLowering, 'plan': NativeMachinePlanControl}
        modules = {'core': 'hepta.hia_core_lowering_native',
                   'plan': 'hepta.hia_machine_plan_native',
                   'byte': 'hepta.hia_native_byte_abi_native'}
        for name, supplied in CONFIG['manifests'].items():
            if name == 'byte':
                from hepta.hia_native_byte_abi_native import NativeByteABI
                factories[name] = NativeByteABI
            path = Path(supplied).resolve(strict=True)
            raw = path.read_bytes()
            record = json.loads(raw)
            module = importlib.import_module(modules[name])
            source = Path(module.SOURCE).resolve(strict=True)
            image_path = (path.parent / record['image_path']).resolve(strict=True)
            image = image_path.read_bytes()
            if (sha256(image).hexdigest() != record['image_sha256']
                    or sha256(source.read_bytes()).hexdigest() != record['source_sha256']
                    or record['schema'] != module.SCHEMA):
                raise AssertionError('actual image/source/manifest differs: ' + name)
            cls.authority.update({path: raw, image_path: image, source: source.read_bytes()})
            cls.owners[name] = (factories[name](image, record['image_sha256'], vars(backend))
                                if name == 'core' else factories[name](image, record['image_sha256']))

    @classmethod
    def tearDownClass(cls):
        for path, raw in cls.authority.items():
            if path.read_bytes() != raw:
                raise AssertionError('actual native input changed: ' + str(path))

    def check_success(self, outer):
        for kind, owner in self.owners.items():
            with self.subTest(owner=kind, outer=outer):
                def observe():
                    expected_trace = []
                    expected = reference(kind, expected_trace)
                    trace = []
                    frame, weak = prepare(owner, kind, trace)
                    before = owner.entries
                    value = owner.finish(frame)
                    state = frame_state(frame, weak, trace)
                    row = {'case': 'success', 'owner': kind, 'outer': outer,
                           'result': value, 'expected': expected,
                           'reference_trace': expected_trace,
                           'before_explicit_close': state,
                           'native_entries': owner.entries - before,
                           'handled_after': ambient()}
                    ROWS.append(row)
                    self.assertEqual(value, expected)
                    self.assertGreater(row['native_entries'], 0)
                    self.assertTrue(frame.closed)
                    self.assertFalse(frame._uncertain)
                    if CONFIG['phase'] == 'original' and outer:
                        # This is an observed old behavior, never a native PASS.
                        self.assertFalse(state['retired'])
                        self.assertTrue(state['alive'])
                        self.assertEqual(trace, expected_trace[:-1])
                        row['old_retirement_defect_observed'] = True
                    else:
                        self.assertTrue(state['retired'])
                        self.assertFalse(state['alive'])
                        self.assertEqual(trace, expected_trace)
                    # Explicit cleanup is after the held-frame observation.
                    frame.close()
                    row['after_explicit_close'] = frame_state(frame, weak, trace)
                    self.assertTrue(frame._retired)
                    self.assertIsNone(weak())
                    self.assertEqual(trace, expected_trace)
                    self.assertEqual(ambient(), ['LookupError', ['caller already handling']] if outer else None)
                under_handler(outer, observe)

    def test_successful_held_frame_without_outer_handler(self):
        self.check_success(False)

    def test_successful_held_frame_inside_outer_handler(self):
        self.check_success(True)

    def test_foreign_error_keeps_original_exception_tb_and_live_operand(self):
        for kind, owner in self.owners.items():
            for outer in (False, True):
                with self.subTest(owner=kind, outer=outer):
                    def observe():
                        failure = ForeignFailure('actual foreign operation')
                        trace = []
                        frame, weak = prepare(owner, kind, trace, (failure,))
                        before = owner.entries
                        success, error = capture(owner, frame)
                        state = frame_state(frame, weak, trace)
                        names = tb_names(error)
                        ROWS.append({'case': 'foreign-error', 'owner': kind,
                                     'outer': outer, 'success': success, 'state': state,
                                     'error_identity': error is failure,
                                     'exception_type': type(error).__name__,
                                     'exception_args': list(error.args),
                                     'context': None if error.__context__ is None else
                                         [type(error.__context__).__name__, list(error.__context__.args)],
                                     'tb_names': names, 'native_entries': owner.entries - before})
                        self.assertFalse(success)
                        self.assertIs(error, failure)
                        self.assertIn('_effect', names)
                        self.assertIn('finish', names)
                        self.assertGreater(owner.entries - before, 0)
                        self.assertTrue(frame.closed)
                        self.assertFalse(frame._retired)
                        self.assertFalse(frame._uncertain)
                        self.assertTrue(state['alive'])
                        self.assertEqual(sum(event[0] == 'effect' for event in trace), 1)
                        self.assertFalse(any(event[0] == 'probe-del' for event in trace))
                        if outer:
                            self.assertIs(error.__context__, sys.exception())
                        else:
                            self.assertIsNone(error.__context__)
                        # No explicit retirement while the original error is held.
                        frame = error = failure = None
                    under_handler(outer, observe)

    def test_take_failure_resets_completed_without_replacing_exception(self):
        for kind, owner in self.owners.items():
            for outer in (False, True):
                with self.subTest(owner=kind, outer=outer):
                    def observe():
                        trace = []
                        frame, weak = prepare(owner, kind, trace)
                        failure = KeyboardInterrupt('terminal take interrupted')
                        takes = []
                        def take_failure():
                            takes.append('take')
                            raise failure
                        frame.take = take_failure
                        before = owner.entries
                        success, error = capture(owner, frame)
                        state = frame_state(frame, weak, trace)
                        ROWS.append({'case': 'take-error', 'owner': kind, 'outer': outer,
                                     'state': state, 'takes': list(takes), 'success': success,
                                     'error_identity': error is failure,
                                     'tb_names': tb_names(error), 'native_entries': owner.entries - before})
                        self.assertFalse(success)
                        self.assertIs(error, failure)
                        self.assertIn('take_failure', tb_names(error))
                        self.assertEqual(takes, ['take'])
                        self.assertGreater(owner.entries - before, 0)
                        self.assertTrue(frame.closed)
                        self.assertFalse(frame._retired)
                        self.assertFalse(frame._uncertain)
                        self.assertTrue(state['alive'])
                        self.assertEqual(sum(event[0] == 'effect' for event in trace), 1)
                        # Remove only the test port replacement; retain the held
                        # error and original native frame until observation ends.
                        del frame.take
                        frame = error = failure = None
                    under_handler(outer, observe)

    def test_lost_actual_native_ack_retains_unknown_and_rejects_replay(self):
        from hepta import hia_machine_plan_control_native as protocol
        for kind, owner in self.owners.items():
            for outer in (False, True):
                with self.subTest(owner=kind, outer=outer):
                    def observe():
                        trace = []
                        frame, weak = prepare(owner, kind, trace)
                        original_invoke = frame._invoke
                        failure = KeyboardInterrupt('after real foreign-effect ACK')
                        acknowledgements, issued = [], []
                        def interrupted(command, *args, **kwargs):
                            pending = frame.pending
                            result = original_invoke(command, *args, **kwargs)
                            if command == 1 and sum(e[0] == 'effect' for e in trace) == 1:
                                acknowledgements.append(result)
                                issued.append(pending)
                                raise failure
                            return result
                        frame._invoke = interrupted
                        before = owner.entries
                        success, error = capture(owner, frame)
                        state = frame_state(frame, weak, trace)
                        row = {'case': 'lost-ack', 'owner': kind, 'outer': outer,
                               'state': state, 'success': success,
                               'error_identity': error is failure,
                               'actual_ack_returns': list(acknowledgements),
                               'native_entries': owner.entries - before}
                        ROWS.append(row)
                        self.assertFalse(success)
                        self.assertIs(error, failure)
                        self.assertEqual(len(acknowledgements), 1)
                        self.assertGreater(owner.entries - before, 0)
                        self.assertTrue(frame.closed and frame._uncertain)
                        self.assertFalse(frame._retired)
                        self.assertTrue(state['alive'])
                        self.assertEqual(sum(e[0] == 'effect' for e in trace), 1)
                        entries = owner.entries
                        for replay in (frame.drive, frame.take, frame.step,
                                       lambda: frame.service(issued[0])):
                            with self.assertRaises(RuntimeError):
                                replay()
                        frame.close()
                        self.assertIs(protocol._UNCONFIRMED_RETIREMENTS[frame.nonce], frame)
                        self.assertEqual(owner.entries, entries)
                        self.assertEqual(sum(e[0] == 'effect' for e in trace), 1)
                        self.assertFalse(any(e[0] == 'probe-del' for e in trace))
                        row['retained_after_replays'] = frame_state(frame, weak, trace)
                        row['replay_native_entries'] = owner.entries - entries
                    under_handler(outer, observe)


def main():
    global CONFIG
    parser = argparse.ArgumentParser()
    parser.add_argument('--manifests', type=Path, required=True)
    parser.add_argument('--phase', choices=('original', 'fixed'), required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    manifests = json.loads(args.manifests.read_bytes())
    if (type(manifests) is not dict or not manifests
            or set(manifests) - {'core', 'plan', 'byte'}):
        raise ValueError('explicit nonempty reviewed owner map required')
    CONFIG = {'manifests': manifests, 'phase': args.phase}
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(NativeFinishTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    report = {'schema': 'hia.native-finish.held-frame.v1', 'phase': args.phase,
              'status': ('ORIGINAL_BEHAVIOR_OBSERVED' if args.phase == 'original' else 'PASS')
                        if result.wasSuccessful() and result.testsRun == 5 else 'HOLD',
              'runtime': {'implementation': sys.implementation.name, 'python': sys.version},
              'tests_run': result.testsRun, 'failures': len(result.failures),
              'errors': len(result.errors), 'skipped': len(result.skipped),
              'expected_failures': len(result.expectedFailures),
              'unexpected_successes': len(result.unexpectedSuccesses),
              'rows': ROWS, 'current_cold': False, 'whole_native': False,
              'default_changed': False, 'old_owners_removed': False}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    print(json.dumps({'status': report['status'], 'phase': args.phase,
                      'tests_run': result.testsRun, 'observations': len(ROWS)}), flush=True)
    return 0 if result.wasSuccessful() and result.testsRun == 5 and not result.skipped else 1


if __name__ == '__main__':
    raise SystemExit(main())

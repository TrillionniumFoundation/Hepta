"""Independent original-worker and real observed-loss controls.

Only the original worker text supplies ordinary expected behavior. These
source controls lose an actual foreign-result ACK; they do not claim a native
entry. Installed controls separately withhold a real selected native receipt.
No control assigns record.loss, clears custody, or retries a resource close.
"""
from __future__ import annotations

import argparse
from contextlib import ExitStack
from contextvars import copy_context
from hashlib import sha256
import io
import json
import os
from pathlib import Path
import sys
import threading
from types import ModuleType, SimpleNamespace
from unittest.mock import patch
import uuid

ROOT = Path(__file__).resolve().parents[1]
if __package__ in (None, ''):
    sys.path.insert(0, str(ROOT))
FIXTURE = ROOT / 'tests/fixtures/worker_unknown_original_r17b'
CASES = ROOT / 'tests/fixtures/worker_unknown_cases.json'


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('utf-8')


def pin(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}


def write(path, value):
    raw = canonical(value) + b'\n'
    with Path(path).open('xb') as stream:
        stream.write(raw)
    return pin(raw)


def capture_inputs():
    raw = (FIXTURE / 'manifest.json').read_bytes()
    frozen = json.loads(raw)
    captured = {str(FIXTURE / 'manifest.json'): raw}
    for name, expected in frozen['originals'].items():
        path = FIXTURE / name
        source = path.read_bytes()
        if pin(source) != expected:
            raise ValueError('original worker input drift: ' + name)
        captured[str(path)] = source
    for name, expected in frozen['candidate_runtime'].items():
        path = ROOT / name
        source = path.read_bytes()
        if pin(source) != expected:
            raise ValueError('current worker runtime differs: ' + name)
        captured[str(path)] = source
    generator = ROOT / 'tools/generate_hia_worker_report.py'
    generator_raw = generator.read_bytes()
    if pin(generator_raw) != frozen['HIA_policy_generator_unchanged']:
        raise ValueError('original HIA worker policy generator changed')
    captured[str(generator)] = generator_raw
    case_raw = CASES.read_bytes()
    if pin(case_raw) != frozen['cases']:
        raise ValueError('worker control cases differ')
    captured[str(CASES)] = case_raw
    return frozen, json.loads(case_raw), captured


def unchanged(captured):
    for name, raw in captured.items():
        if Path(name).read_bytes() != raw:
            raise ValueError('worker control input changed: ' + name)


def original_worker(captured):
    module = ModuleType('hepta._worker_unknown_frozen_original')
    module.__package__ = 'hepta'
    path = FIXTURE / 'hia_agent_worker.py.txt'
    module.__file__ = str(path)
    exec(compile(captured[str(path)], str(path), 'exec'), module.__dict__)
    return module


class Resource:
    pass


def observed_loss(events, resource=None):
    from hepta import hia_native_delivery as delivery
    fault = ValueError('real foreign result acknowledgement withheld')
    record = delivery.DeliveryRecord(('worker-source-observation', events))
    if resource is not None:
        record.associate(resource)
    try:
        with record.foreign():
            events.append('actual-foreign-return')
        try:
            raise fault
        except BaseException as error:
            if not record.failed(error):
                raise AssertionError('the completed provider outcome was not pending')
    finally:
        record.retire()
    if record.loss is None or record.loss.error is not fault:
        raise AssertionError('actual observed result did not retain its real loss')
    return record, fault


class Fixture:
    def __init__(self, case):
        from hepta import hia_native_delivery as delivery
        self.case = case
        self.events = []
        self.resource = Resource()
        self.registration = delivery.bind_resource_lifetime(self.resource)
        self.foreign_events = []
        self.records = []
        self.primary = self.cleanup = self.injected = None
        self.close_attempts = self.close_effects = 0
        self.reads = 0
        self.identity = {'worker_sha256': 'a' * 64,
                         'backend_sha256': 'b' * 64,
                         'catalog_sha256': 'c' * 64}
        self.request = {'schema': 'hia-agent-worker-request-v1',
                        'tool': 'hia_describe', 'arguments': {'section': 'manifest'},
                        'profile_sha256': 'd' * 64, 'catalog_sha256': 'c' * 64}
        from hepta.hia_agent_store import wire
        self.request['request_sha256'] = sha256(wire(self.request)).hexdigest()
        self.raw = wire(self.request)
        self.fault = self.make_error(case.get('error', 'RuntimeError'),
                                     'ordinary-' + case.get('location', 'none'))

    @staticmethod
    def make_error(name, message):
        import builtins
        if name == 'SameNamedUnknown':
            kind = type('NativeDeliveryUnknown', (RuntimeError,), {})
            return kind(message)
        return getattr(builtins, name)(message)

    def actual_loss(self, *, associated=False):
        record, error = observed_loss(self.foreign_events,
                                     self.resource if associated else None)
        self.records.append(record)
        self.injected = error
        return record

    def run(self, module):
        from hepta import hia_agent_service as service_api
        from hepta import hia_native_delivery as delivery
        from hepta.hia_agent_store import wire as original_wire
        stdout, stderr = io.BytesIO(), io.StringIO()
        fixture = self
        mode = self.case['mode']
        if mode in ('old-unrelated-loss', 'old-same-resource'):
            other = self.resource if mode == 'old-same-resource' else Resource()
            if other is not self.resource:
                delivery.bind_resource_lifetime(other)
            record, unused = observed_loss(self.foreign_events, other)
            self.records.append(record)
        class Input:
            def read(self, size):
                fixture.events.append(['read', size])
                return fixture.raw[:size]
        class Output:
            def write(self, raw):
                fixture.events.append(['stdout', len(raw)])
                return stdout.write(raw)
        class Service:
            def __init__(self, state, *, artifact_roots):
                fixture.events.append(['construct', state, list(artifact_roots)])
                if fixture.case.get('location') == 'construct':
                    raise fixture.fault
                if mode == 'constructor-loss':
                    record = fixture.actual_loss()
                    record.check()
            def call(self, tool, arguments):
                fixture.events.append(['call', tool])
                try:
                    if fixture.case.get('location') == 'call':
                        raise fixture.fault
                    if mode == 'ordinary-named-unknown':
                        raise fixture.make_error('SameNamedUnknown', 'no real delivery loss')
                    if mode == 'safe-preentry':
                        record = delivery.DeliveryRecord('safe-preentry')
                        if record.failed(fixture.fault):
                            raise AssertionError('safe preparation invented loss')
                        record.retire()
                        raise fixture.fault
                    if mode == 'post-confirmed':
                        record = delivery.DeliveryRecord('confirmed-foreign-result')
                        with record.foreign():
                            fixture.foreign_events.append('actual-confirmed-foreign-return')
                        record.confirmed(terminal=True)
                        if record.failed(fixture.fault):
                            raise AssertionError('post-terminal exception invented loss')
                        record.retire()
                        raise fixture.fault
                    if mode in ('lost-raise', 'lost-swallowed', 'lost-replaced',
                                'lost-no-resource', 'lost-system-exit',
                                'lost-memory-error', 'lost-observer-exit'):
                        record = fixture.actual_loss(associated=mode not in ('lost-no-resource', 'lost-observer-exit'))
                        if mode in ('lost-swallowed', 'lost-no-resource', 'lost-observer-exit'):
                            return {'status': 'completed', 'result': {'value': 1}}
                        if mode == 'lost-replaced':
                            raise ValueError('replacement after real receipt loss')
                        if mode == 'lost-system-exit':
                            raise SystemExit(73)
                        if mode == 'lost-memory-error':
                            raise MemoryError('actual loss then foreign memory error')
                        record.check()
                    if mode == 'two-ordinary-errors':
                        raise RuntimeError('ordinary primary')
                    return {'status': 'completed', 'result': {'value': 1}}
                except BaseException as error:
                    fixture.primary = error
                    raise
            def close(self):
                fixture.close_attempts += 1
                fixture.events.append(['close-attempt'])
                try:
                    if mode == 'cleanup-loss':
                        record = fixture.actual_loss(associated=True)
                        record.check()
                    delivery.check_resource_retirement(fixture.resource)
                    if fixture.case.get('location') == 'close':
                        raise fixture.fault
                    if mode == 'two-ordinary-errors':
                        raise ValueError('ordinary cleanup')
                    fixture.close_effects += 1
                    fixture.events.append(['close-effect'])
                except BaseException as error:
                    fixture.cleanup = error
                    raise
        def installation():
            fixture.reads += 1
            fixture.events.append(['manifest', fixture.reads])
            location = fixture.case.get('location')
            if (location == 'initial' and fixture.reads == 1) or (
                    location == 'after' and fixture.reads == 2):
                raise fixture.fault
            return dict(fixture.identity)
        def encoding(value):
            raw = original_wire(value)
            if mode == 'encoding-loss' and type(value) is dict and value.get('schema') == 'hia-agent-worker-report-v1':
                fixture.actual_loss()
            return raw
        diagnostics = []
        original_diagnostic = getattr(module, '_unknown_request_exit', None)
        def diagnostic(observation, error):
            diagnostics.append({
                'origin_is_actual': any(observation.origin is item.loss for item in fixture.records),
                'origin_error_is_injected': observation.origin.error is fixture.injected,
                'primary_is_actual': observation.primary_error is fixture.primary,
                'cleanup_is_actual': observation.cleanup_error is fixture.cleanup,
                'terminal_is_actual_cleanup': error is fixture.cleanup,
                'primary': None if observation.primary_error is None else type(observation.primary_error).__name__,
                'cleanup': None if observation.cleanup_error is None else type(observation.cleanup_error).__name__,
                'origin': type(observation.origin).__name__,
            })
            return original_diagnostic(observation, error)
        fake_sys = SimpleNamespace(stdin=SimpleNamespace(buffer=Input()),
                                   stdout=SimpleNamespace(buffer=Output()),
                                   stderr=stderr, modules=sys.modules)
        with ExitStack() as stack:
            stack.enter_context(patch.dict(os.environ, {}, clear=True))
            stack.enter_context(patch.object(module, 'sys', fake_sys))
            stack.enter_context(patch.object(module, 'installation_manifest', installation))
            stack.enter_context(patch.object(module, 'wire', encoding))
            stack.enter_context(patch.object(module.uuid, 'uuid4', lambda: uuid.UUID(int=1)))
            stack.enter_context(patch.object(service_api, 'HIAAgentService', Service))
            if mode == 'lost-observer-exit':
                original_exit = delivery.RequestDeliveryObservation.__exit__
                def exit_with_error(observation, *arguments):
                    original_exit(observation, *arguments)
                    raise MemoryError('actual observer retirement interruption')
                stack.enter_context(patch.object(delivery.RequestDeliveryObservation,
                                                '__exit__', exit_with_error))
            if original_diagnostic is not None:
                stack.enter_context(patch.object(module, '_unknown_request_exit', diagnostic))
            try:
                code = module.main(['--state-root', '/unused-source-control',
                                    '--request-json-stdin'])
                outcome = {'kind': 'return', 'value': code}
            except BaseException as error:
                outcome = {'kind': 'raise', 'type': type(error).__name__,
                           'message': str(error),
                           'same_primary': error is self.primary,
                           'same_cleanup': error is self.cleanup,
                           'same_injected_ordinary': error is self.fault}
        return {
            'id': self.case['id'], 'outcome': outcome,
            'stdout_hex': stdout.getvalue().hex(), 'stderr': stderr.getvalue(),
            'events': self.events, 'close_attempts': self.close_attempts,
            'close_effects': self.close_effects, 'diagnostics': diagnostics,
            'foreign_events': self.foreign_events,
            'retained_actual_losses': sum(record.loss is not None for record in self.records),
        }


def ordinary_controls(cases, captured):
    from hepta import hia_agent_worker as current
    rows = []
    for case in cases['ordinary']:
        expected = Fixture(case).run(original_worker(captured))
        actual = Fixture(case).run(current)
        if actual != expected:
            raise AssertionError({'id': case['id'], 'original': expected, 'candidate': actual})
        rows.append({'id': case['id'], 'original': expected, 'candidate': actual,
                     'byte_equal': canonical(expected) == canonical(actual)})
    return rows


def unknown_controls(cases, captured):
    from hepta import hia_agent_worker as current
    rows = []
    for case in cases['unknown']:
        # Preserve what the complete original actually does. Never rewrite it
        # into the successor contract or borrow candidate fields as expected.
        expected = Fixture(case).run(original_worker(captured))
        actual = Fixture(case).run(current)
        unknown = case['expected_unknown']
        if unknown:
            if actual['outcome'] != {'kind': 'return', 'value': 2} or actual['stdout_hex']:
                raise AssertionError({'id': case['id'], 'candidate': actual})
            if len(actual['diagnostics']) != 1:
                raise AssertionError('unknown has no unique actual terminal observation')
            evidence = actual['diagnostics'][0]
            if not evidence['origin_is_actual'] or not evidence['primary_is_actual'] or not evidence['cleanup_is_actual']:
                raise AssertionError({'id': case['id'], 'evidence': evidence})
            if actual['retained_actual_losses'] <= 0:
                raise AssertionError('unknown erased its real record')
            if 'HIA_WORKER_DELIVERY_UNKNOWN' not in actual['stderr']:
                raise AssertionError('unknown diagnostic missing')
        elif actual != expected:
            raise AssertionError({'id': case['id'], 'original': expected, 'candidate': actual})
        if (actual['close_attempts'], actual['close_effects']) != tuple(case['close']):
            raise AssertionError({'id': case['id'], 'close': actual})
        rows.append({'id': case['id'], 'original': expected, 'candidate': actual,
                     'expected_unknown': unknown})
    return rows


def scope_controls(cases):
    from hepta import hia_native_delivery as delivery
    rows = []
    for label in cases['scope']:
        events = []
        if label == 'actual-observation':
            with delivery.RequestDeliveryObservation() as scope:
                record, error = observed_loss(events)
            assert scope.origin is record.loss and scope.origin.error is error
        elif label == 'old-unrelated':
            record, error = observed_loss(events)
            with delivery.RequestDeliveryObservation() as scope:
                assert scope.origin is None
                assert delivery.guard_request_output(b'ordinary') == b'ordinary'
            assert scope.origin is None and record.loss.error is error
        elif label == 'exact-resource':
            resource = Resource()
            delivery.bind_resource_lifetime(resource)
            record, error = observed_loss(events, resource)
            with delivery.RequestDeliveryObservation() as scope:
                try:
                    delivery.check_resource_retirement(resource)
                except delivery.NativeDeliveryUnknown:
                    pass
                else:
                    raise AssertionError('actual lost resource was retired')
            assert scope.origin is record.loss
        elif label == 'resource-observation':
            resource = Resource()
            delivery.bind_resource_lifetime(resource)
            token = delivery.reserve_resource_observation('body-result', resource)
            with delivery.RequestDeliveryObservation() as scope:
                events.append('actual body return')
                token.observed()
                error = MemoryError('body result could not be delivered')
                assert token.failed(error)
            assert scope.origin is token.loss and token.loss.error is error
        elif label == 'ended-copy':
            with delivery.RequestDeliveryObservation() as scope:
                context = copy_context()
            record, error = context.run(observed_loss, events)
            assert scope.origin is None and record.loss.error is error
        elif label == 'foreign-thread-copy':
            with delivery.RequestDeliveryObservation() as scope:
                context = copy_context()
                results = []
                failures = []
                def run():
                    try:
                        results.append(context.run(observed_loss, events))
                    except BaseException as error:
                        failures.append(error)
                thread = threading.Thread(target=run)
                thread.start()
                thread.join(5)
                assert not thread.is_alive() and not failures and len(results) == 1
            assert scope.origin is None and results[0][0].loss is not None
        elif label == 'fork-copy':
            import signal
            import time
            with delivery.RequestDeliveryObservation() as scope:
                pid = os.fork()
                if pid == 0:
                    try:
                        record, error = observed_loss(events)
                        code = 0 if scope.origin is None and record.loss is not None else 1
                    except BaseException:
                        code = 1
                    os._exit(code)
                reaped = False
                try:
                    deadline = time.monotonic() + 5
                    while True:
                        ended, status = os.waitpid(pid, os.WNOHANG)
                        if ended == pid:
                            reaped = True
                            assert os.waitstatus_to_exitcode(status) == 0
                            break
                        if time.monotonic() >= deadline:
                            raise AssertionError('new fork-observer control timed out')
                        time.sleep(.01)
                finally:
                    if not reaped:
                        try:
                            os.kill(pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        os.waitpid(pid, 0)
                assert scope.origin is None
        elif label == 'fresh-inner-no-inherit':
            with delivery.RequestDeliveryObservation() as outer:
                record, error = observed_loss(events)
                with delivery.RequestDeliveryObservation() as inner:
                    assert inner.origin is None
                    assert delivery.guard_request_output(7) == 7
                assert inner.origin is None
            assert outer.origin is record.loss
        elif label == 'actual-nested-loss':
            with delivery.RequestDeliveryObservation() as outer:
                with delivery.RequestDeliveryObservation() as inner:
                    record, error = observed_loss(events)
            assert outer.origin is record.loss and inner.origin is record.loss
        elif label == 'ordinary-name-not-fact':
            with delivery.RequestDeliveryObservation() as scope:
                fault = type('ServiceVerificationUnknown', (RuntimeError,), {})('ordinary')
                try:
                    raise fault
                except BaseException as error:
                    delivery.note_request_failure(error)
                delivery.release_healthy_request_failures()
                assert scope.origin is None and scope.primary_error is None
            assert scope.origin is None
        elif label == 'safe-before-entry':
            with delivery.RequestDeliveryObservation() as scope:
                record = delivery.DeliveryRecord('safe')
                assert not record.failed(MemoryError('before any provider or entry'))
                record.retire()
            assert scope.origin is None
        elif label == 'post-confirmed':
            with delivery.RequestDeliveryObservation() as scope:
                record = delivery.DeliveryRecord('complete')
                with record.foreign():
                    events.append('real foreign return')
                record.confirmed(terminal=True)
                assert not record.failed(RuntimeError('after complete receipt'))
                record.retire()
            assert scope.origin is None
        elif label == 'cleanup-not-new-ancestor':
            with delivery.RequestDeliveryObservation() as scope:
                record, error = observed_loss(events)
                assert delivery.current_record() is None
                # A fresh unrelated healthy close is still actually callable;
                # this terminal observer cannot pretend it is a causal parent.
                healthy = delivery.DeliveryRecord('real independent cleanup')
                with healthy.foreign():
                    events.append('actual healthy close provider')
                healthy.confirmed(terminal=True)
                healthy.retire()
            assert scope.origin is record.loss
        else:
            raise ValueError('undeclared source scope control')
        rows.append({'id': label, 'events': events, 'status': 'PASS'})
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', choices=('ordinary', 'unknown', 'scope'), required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    frozen, cases, captured = capture_inputs()
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    planned = cases[args.mode] if args.mode == 'scope' else [x['id'] for x in cases[args.mode]]
    write(args.output / 'planned.json', {'mode': args.mode, 'ordered_ids': planned,
          'source': {path: pin(raw) for path, raw in captured.items()}})
    import traceback
    rows, started, stopped, failures = [], [], [], []
    with (args.output / 'events.jsonl').open('xb') as journal:
        for index, identifier in enumerate(planned):
            started.append(identifier)
            journal.write(canonical({'event': 'started', 'id': identifier}) + b'\n')
            journal.flush()
            try:
                if args.mode == 'ordinary':
                    row, = ordinary_controls({'ordinary': [cases['ordinary'][index]]}, captured)
                elif args.mode == 'unknown':
                    row, = unknown_controls({'unknown': [cases['unknown'][index]]}, captured)
                else:
                    row, = scope_controls({'scope': [identifier]})
                row['control_status'] = 'PASS'
            except BaseException as error:
                traceback.print_exception(error, file=sys.stderr)
                row = {'id': identifier, 'control_status': 'FAIL',
                       'error_type': type(error).__name__, 'error_message': str(error)}
                failures.append(identifier)
            rows.append(row)
            stopped.append(identifier)
            journal.write(canonical({'event': 'stopped', 'id': identifier,
                                     'status': row['control_status']}) + b'\n')
            journal.flush()
    if [row['id'] for row in rows] != planned:
        raise AssertionError('complete source control inventory differs')
    observations_pin = write(args.output / 'observations.json', rows)
    unchanged(captured)
    report = {'schema': 'hepta.hia.worker-unknown-source-controls.v1',
              'mode': args.mode, 'status': 'HOLD' if failures else 'PASS', 'planned': planned,
              'started': started, 'stopped': stopped, 'failures': failures,
              'source_before': {path: pin(raw) for path, raw in captured.items()},
              'source_after': {path: pin(raw) for path, raw in captured.items()},
              'observations': observations_pin, 'actual_native_entries': 0,
              'source_foreign_outcome_loss_only': True,
              'whole_native_stack_qualified': False}
    report_pin = write(args.output / 'report.json', report)
    sys.stdout.buffer.write(canonical({'report': report_pin, 'count': len(rows)}) + b'\n')
    return 1 if failures else 0


if __name__ == '__main__':
    raise SystemExit(main())
